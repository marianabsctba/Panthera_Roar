"""Laço da ingestão: percorre os gerenciadores, um cliente de cada vez.

    python -m roar_ingestao.ciclo [--uma-vez] [--desde 2026-11-01T00:00:00+00:00]

O dono de um alerta é o gerenciador em cujo índice ele está. O alerta pode chegar ao
indexer depois de alertas mais novos, então cada ciclo relê uma janela para trás. Isso
não duplica nada; o que chegar atrasado além da janela só entra reprocessando com --desde.
"""

import argparse
import logging
import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from .armazenamento import Armazenamento
from .fonte_wazuh import Indexer
from .normalizar import momento_do_alerta

JANELA = timedelta(minutes=5)
INICIO_DOS_TEMPOS = datetime(2000, 1, 1, tzinfo=timezone.utc)
PREFIXO = "wazuh-alerts-4.x-"
# Um cliente com muito volume não segura os outros: o resto fica para o próximo ciclo.
LOTES_POR_CICLO = 40
INTERVALO_DAS_REGRAS = 3600
log = logging.getLogger("roar.ingestao")


def rodar_gerenciador(indexer, banco, gerenciador_id, cliente, desde=None, limite=LOTES_POR_CICLO):
    total = Counter()
    checkpoint = banco.ler_checkpoint(gerenciador_id)
    inicio = desde or (checkpoint - JANELA if checkpoint else INICIO_DOS_TEMPOS)

    for numero, lote in enumerate(indexer.alertas_desde(f"{PREFIXO}{gerenciador_id}-*", inicio), 1):
        total.update(banco.gravar_lote(lote, gerenciador_id, cliente))
        total["lidos"] += len(lote)
        # Só avança depois de gravar: uma queda aqui relê o lote, sem perder nada.
        ultimo = next((a.get("timestamp") for _, a in reversed(lote) if a.get("timestamp")), None)
        if ultimo:
            banco.gravar_checkpoint(gerenciador_id, momento_do_alerta(ultimo))
        if numero >= limite:
            break
    return total


def rodar_ciclo(indexer, banco, desde=None, limite=LOTES_POR_CICLO):
    """Falha em um gerenciador não impede os outros clientes de receberem alertas."""
    total, falhas = Counter(), {}
    for gerenciador_id, cliente in banco.gerenciadores():
        try:
            total.update(rodar_gerenciador(indexer, banco, gerenciador_id, cliente, desde, limite))
        except Exception as erro:
            falhas[gerenciador_id] = erro
            log.exception("gerenciador %s falhou", gerenciador_id)
    return total, falhas


def ler_env(caminho):
    valores = {}
    with open(caminho, encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if linha and not linha.startswith("#") and "=" in linha:
                k, v = linha.split("=", 1)
                valores[k] = v
    return valores


def conexoes(caminho_env=None):
    env = ler_env(caminho_env or os.getenv("ROAR_ENV", "/opt/panthera-roar/.env"))
    indexer = Indexer(
        os.getenv("ROAR_INDEXER_URL", "https://127.0.0.1:9200"),
        "roar_leitor",
        env["ROAR_LEITOR_SENHA"],
        os.getenv("ROAR_INDEXER_CA",
                  "/opt/panthera-roar/wazuh/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem"),
    )
    url = (f"postgresql://roar_ingestao:{env['ROAR_INGESTAO_SENHA']}@"
           f"{os.getenv('ROAR_BANCO_ENDERECO', '127.0.0.1:5433')}/roar")
    return indexer, Armazenamento(url), env


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--uma-vez", action="store_true")
    args.add_argument("--desde", type=datetime.fromisoformat)
    args.add_argument("--intervalo", type=float, default=5.0)
    a = args.parse_args()

    from .attack import sincronizar_attack
    from .regras import sincronizar

    indexer, banco, _ = conexoes()
    desde = a.desde
    proxima_sincronizacao = 0.0
    while True:
        if time.monotonic() >= proxima_sincronizacao:
            try:
                sincronizar_attack(banco)
            except Exception:
                # Base pública fora do ar não atrapalha a detecção.
                log.exception("matriz do ATT&CK não foi carregada")
            sincronizar(banco)
            proxima_sincronizacao = time.monotonic() + INTERVALO_DAS_REGRAS
        total, falhas = rodar_ciclo(indexer, banco, desde=desde)
        desde = None
        if total["lidos"]:
            log.info("ciclo: %s", dict(total))
        if a.uma_vez:
            raise SystemExit(1 if falhas else 0)
        time.sleep(a.intervalo)


if __name__ == "__main__":
    main()
