"""Laço da ingestão.

    python -m roar_ingestao.ciclo [--uma-vez] [--desde 2026-11-01T00:00:00+00:00]

O alerta pode chegar ao indexer depois de alertas mais novos, então cada ciclo relê uma
janela para trás. Isso não duplica nada; o que chegar atrasado além da janela só entra
reprocessando com --desde.
"""

import argparse
import logging
import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from .armazenamento import Armazenamento
from .fonte_wazuh import Indexer
from .normalizar import _momento

JANELA = timedelta(minutes=5)
INICIO_DOS_TEMPOS = datetime(2000, 1, 1, tzinfo=timezone.utc)
log = logging.getLogger("roar.ingestao")


def rodar_ciclo(indexer, banco, fonte="wazuh", desde=None):
    mapa = banco.mapa_de_agentes()
    total = Counter()
    total["recuperados"] = banco.recuperar_quarentena(mapa)

    checkpoint = banco.ler_checkpoint(fonte)
    inicio = desde or (checkpoint - JANELA if checkpoint else INICIO_DOS_TEMPOS)

    for lote in indexer.alertas_desde(inicio):
        total.update(banco.gravar_lote(lote, mapa))
        total["lidos"] += len(lote)
        # Só avança depois de gravar: uma queda aqui relê o lote, sem perder nada.
        ultimo = next((a.get("timestamp") for _, a in reversed(lote) if a.get("timestamp")), None)
        if ultimo:
            banco.gravar_checkpoint(fonte, _momento(ultimo))
    return total


def ler_env(caminho):
    valores = {}
    with open(caminho, encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if linha and not linha.startswith("#") and "=" in linha:
                k, v = linha.split("=", 1)
                valores[k] = v
    return valores


def conexoes(caminho_env="/opt/panthera-roar/.env"):
    env = ler_env(caminho_env)
    indexer = Indexer(
        os.getenv("ROAR_INDEXER_URL", "https://127.0.0.1:9200"),
        env["WAZUH_INDEXER_USERNAME"],
        env["WAZUH_INDEXER_PASSWORD"],
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

    indexer, banco, _ = conexoes()
    desde = a.desde
    while True:
        try:
            total = rodar_ciclo(indexer, banco, desde=desde)
            desde = None
            if total["lidos"] or total["recuperados"]:
                log.info("ciclo: %s", dict(total))
        except Exception:
            # A fonte ou o banco fora do ar não derruba o serviço; o ciclo seguinte retoma.
            log.exception("ciclo falhou")
            if a.uma_vez:
                raise
        if a.uma_vez:
            return
        time.sleep(a.intervalo)


if __name__ == "__main__":
    main()
