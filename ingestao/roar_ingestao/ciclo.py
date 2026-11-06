"""Laço da ingestão: percorre os gerenciadores, um cliente de cada vez.

    python -m roar_ingestao.ciclo [--uma-vez] [--desde 2026-11-01T00:00:00+00:00]

Com ROAR_ALERTAS_DO_ARMAZEM=1, os alertas vêm do armazém de eventos (docs/clickhouse.md, etapa 3) em vez do indexer,
gravados em lote. O Postgres guarda só os últimos ROAR_DIAS_DE_ALERTAS dias; o histórico inteiro fica no armazém.

O dono de um alerta é o gerenciador em cujo índice ele está. O alerta pode chegar ao
indexer depois de alertas mais novos, então cada ciclo relê uma janela para trás. Isso
não duplica nada; o que chegar atrasado além da janela só entra reprocessando com --desde.
"""

import argparse
import json
import logging
import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from . import armazem as armazem_de_eventos
from .armazenamento import Armazenamento
from .fonte_wazuh import Indexer
from .normalizar import momento_do_alerta

JANELA = timedelta(minutes=5)
INICIO_DOS_TEMPOS = datetime(2000, 1, 1, tzinfo=timezone.utc)
PREFIXO = "wazuh-alerts-4.x-"
# Um cliente com muito volume não segura os outros: o resto fica para o próximo ciclo.
LOTES_POR_CICLO = 40
INTERVALO_DAS_REGRAS = 3600
# Leitura do armazém: lote, folga para a gravação recém-feita ficar visível, e o piso de hora para achar só os dias certos.
LOTE_DO_ARMAZEM = 5000
SEGUNDOS_DE_FOLGA = 10
DIAS_DE_ATRASO_ACEITO = 7
POSICAO_INICIAL = ("1970-01-01 00:00:00.000", "00000000-0000-0000-0000-000000000000")
DIAS_DE_ALERTAS_PADRAO = 90
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


def _posicao_inicial(leitor, banco, gerenciador_id, nome_do_banco):
    """Na troca do indexer para o armazém, começa no que o indexer já entregou menos a janela de releitura."""
    checkpoint = banco.ler_checkpoint(gerenciador_id)
    if not checkpoint:
        return POSICAO_INICIAL
    linha = leitor.linhas(f"""SELECT toString(min(recebido_em)) AS r, count() AS n FROM {nome_do_banco}.alertas
                              WHERE gerenciador = {{g:String}} AND ocorrido_em >= parseDateTime64BestEffort({{d:String}}, 3)""",
                          {"g": gerenciador_id, "d": (checkpoint - JANELA).isoformat()})[0]
    if not int(linha["n"]):
        return POSICAO_INICIAL
    return (linha["r"], POSICAO_INICIAL[1])


def _sem_os_ja_entregues(banco, cliente, gerenciador_id, documentos):
    """Os alertas da janela de troca que o indexer já tinha entregue (com outro id) não entram de novo. O id do próprio
    Wazuh, dentro do log, é o mesmo dos dois lados."""
    checkpoint = banco.ler_checkpoint(gerenciador_id)
    da_janela = [d for d in documentos if checkpoint and d[2] <= checkpoint]
    if not da_janela:
        return [(i, a) for i, a, _ in documentos]
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        ja = {l[0] for l in banco.con.execute(
            "SELECT bruto->>'id' FROM eventos WHERE gerenciador_id = %s AND ocorrido_em >= %s AND ocorrido_em <= %s AND origem_id !~ '^[0-9a-f-]{36}$'",
            (gerenciador_id, min(d[2] for d in da_janela), checkpoint)).fetchall()}
    return [(i, a) for i, a, quando in documentos if not (checkpoint and quando <= checkpoint and a.get("id") in ja)]


def rodar_gerenciador_do_armazem(leitor, banco, gerenciador_id, cliente, limite=LOTES_POR_CICLO):
    """Lê os alertas do armazém pela ordem em que chegaram ((recebido_em, id)), em lotes, e grava em lote. A posição só
    avança depois de gravar: uma queda relê o lote, e a regra de não repetir segura."""
    from roar_api.leitor_armazem import COLUNAS_DO_DOCUMENTO, documento

    total = Counter()
    fonte = f"armazem:{gerenciador_id}"
    nome_do_banco = armazem_de_eventos.banco_do(cliente)
    guardada = banco.ler_posicao(fonte)
    recebido, ultimo_id = json.loads(guardada[1]) if guardada and guardada[1] else _posicao_inicial(leitor, banco, gerenciador_id, nome_do_banco)
    for _ in range(limite):
        linhas = leitor.linhas(f"""SELECT toString(id) AS id_texto, toString(recebido_em) AS recebido, {COLUNAS_DO_DOCUMENTO}
                                   FROM {nome_do_banco}.alertas
                                   WHERE gerenciador = {{g:String}}
                                     AND ocorrido_em >= parseDateTime64BestEffort({{r:String}}, 3) - INTERVAL {DIAS_DE_ATRASO_ACEITO} DAY
                                     AND recebido_em < now64(3) - INTERVAL {SEGUNDOS_DE_FOLGA} SECOND
                                     AND (recebido_em, id) > (parseDateTime64BestEffort({{r:String}}, 3), toUUID({{i:String}}))
                                   ORDER BY recebido_em, id LIMIT {LOTE_DO_ARMAZEM}""", {"g": gerenciador_id, "r": recebido, "i": ultimo_id})
        if not linhas:
            break
        documentos = []
        for l in linhas:
            alerta = documento(l)
            try:
                quando = momento_do_alerta(alerta.get("timestamp"))
            except Exception:
                quando = datetime.now(timezone.utc)
            documentos.append((l["id_texto"], alerta, quando))
        total.update(banco.gravar_em_lote(_sem_os_ja_entregues(banco, cliente, gerenciador_id, documentos), gerenciador_id, cliente))
        total["lidos"] += len(linhas)
        recebido, ultimo_id = linhas[-1]["recebido"], linhas[-1]["id_texto"]
        banco.gravar_posicao(fonte, datetime.fromisoformat(recebido).replace(tzinfo=timezone.utc), json.dumps([recebido, ultimo_id]))
        if len(linhas) < LOTE_DO_ARMAZEM:
            break
    return total


def rodar_ciclo(indexer, banco, desde=None, limite=LOTES_POR_CICLO, leitor=None):
    """Falha em um gerenciador não impede os outros clientes de receberem alertas. Com `leitor`, os gerenciadores cuja
    organização já tem o armazém leem dele; os outros seguem no indexer."""
    total, falhas = Counter(), {}
    com_armazem = {l["name"] for l in leitor.linhas("SELECT name FROM system.databases")} if leitor else set()
    for gerenciador_id, cliente in banco.gerenciadores():
        try:
            if armazem_de_eventos.banco_do(cliente) in com_armazem:
                total.update(rodar_gerenciador_do_armazem(leitor, banco, gerenciador_id, cliente, limite))
                continue
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

    indexer, banco, env = conexoes()
    leitor = armazem_de_eventos.leitor(env) if env.get("ROAR_ALERTAS_DO_ARMAZEM") == "1" else None
    dias_de_alertas = int(env.get("ROAR_DIAS_DE_ALERTAS") or DIAS_DE_ALERTAS_PADRAO)
    desde = a.desde
    proxima_sincronizacao = 0.0
    while True:
        if time.monotonic() >= proxima_sincronizacao:
            try:
                # Cria os dias seguintes da tabela de alertas e descarta os vencidos: o histórico inteiro está no armazém.
                if banco.manter_dias(dias_de_alertas):
                    log.info("dias de alertas vencidos descartados do Postgres")
            except Exception:
                log.exception("manutenção dos dias de alertas falhou")
            try:
                sincronizar_attack(banco)
            except Exception:
                # Base pública fora do ar não atrapalha a detecção.
                log.exception("matriz do ATT&CK não foi carregada")
            sincronizar(banco)
            proxima_sincronizacao = time.monotonic() + INTERVALO_DAS_REGRAS
        total, falhas = rodar_ciclo(indexer, banco, desde=desde, leitor=leitor)
        desde = None
        if total["lidos"]:
            log.info("ciclo: %s", dict(total))
        if a.uma_vez:
            raise SystemExit(1 if falhas else 0)
        time.sleep(a.intervalo)


if __name__ == "__main__":
    main()
