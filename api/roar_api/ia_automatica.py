"""Parecer automático: a IA local lê sozinha os alertas a partir do nível que cada organização escolheu (tela IA local).

    python -m roar_api.ia_automatica

Roda como serviço (infra/servicos.sh, roar-ia-automatica), com o mesmo usuário e a mesma senha de banco da API: lê só o
que a API leria, organização por organização. A cada volta pega os alertas mais graves que chegaram desde que o
automático foi ligado, um por grupo da Fila, sem parecer ainda, e dá o parecer de cada um do mesmo jeito que o botão.
Um por vez: o modelo ocupa a placa de vídeo inteira.

Sem IA_MODELO no .env, o serviço só espera: a instalação não tem IA.
"""

import logging
import os
import time
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from roar_api import investigacao, parecer
from roar_ingestao import armazem as armazem_de_eventos

log = logging.getLogger("roar.ia_automatica")
SEGUNDOS_ENTRE_VOLTAS = 30
# Por volta e por organização: com muito alerta grave, a fila anda sem uma organização tomar a IA das outras.
POR_ORGANIZACAO = 3
# Só o recente: um alerta de ontem que ninguém olhou não fica mais útil com parecer agora.
HORAS_PARA_TRAS = 6
NOME = "Parecer automático"


def _ler_env():
    arquivo = os.getenv("ROAR_ENV", "/opt/panthera-roar/api.env")
    return dict(l.strip().split("=", 1) for l in Path(arquivo).read_text(encoding="utf-8").splitlines() if "=" in l and not l.startswith("#"))


def pendentes(con, nivel, desde):
    """Os alertas que esperam parecer: o mais grave e mais novo de cada grupo da Fila, e só grupo que ainda não tem parecer."""
    return [l["id"] for l in con.execute(
        """SELECT id FROM (
             SELECT DISTINCT ON (coalesce(e.grupo_id, -e.id)) e.id, e.nivel, e.ocorrido_em FROM eventos e
             WHERE e.nivel >= %s AND e.ocorrido_em >= greatest(%s, now() - make_interval(hours => %s))
               AND NOT EXISTS (SELECT 1 FROM pareceres p JOIN eventos x ON x.id = p.evento_id
                               WHERE x.id = e.id OR (e.grupo_id IS NOT NULL AND x.grupo_id = e.grupo_id))
             ORDER BY coalesce(e.grupo_id, -e.id), e.nivel DESC, e.ocorrido_em DESC) a
           ORDER BY nivel DESC, ocorrido_em DESC LIMIT %s""",
        (nivel, desde, HORAS_PARA_TRAS, POR_ORGANIZACAO)).fetchall()]


def volta(banco, ia, armazem):
    """Uma passada por todas as organizações com o automático ligado. Devolve quantos pareceres deu."""
    with banco.transaction():
        organizacoes = banco.execute("SELECT cliente_id, nivel, desde FROM roar_ia_automatica()").fetchall()
    dados = 0
    for org in organizacoes:
        cliente = str(org["cliente_id"])
        with banco.transaction():
            banco.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
            modelo = (banco.execute("SELECT modelo FROM ia_instalacao").fetchone() or {}).get("modelo") or ia[1]
            ler_do_armazem = banco.execute("SELECT ler_do_armazem FROM clientes").fetchone()["ler_do_armazem"]
            ids = pendentes(banco, org["nivel"], org["desde"])
        nome_do_banco = armazem_de_eventos.banco_do(cliente) if armazem is not None and ler_do_armazem else None
        for alerta in ids:
            with banco.transaction():
                banco.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
                pacote = investigacao.investigar(banco, alerta, armazem if nome_do_banco else None, nome_do_banco)
            if pacote is None:
                continue
            novo = parecer.dar(pacote, ia[0], modelo)
            with banco.transaction():
                banco.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
                banco.execute(
                    """INSERT INTO pareceres (cliente_id, evento_id, modelo, veredito, confianca, resumo, motivos, proximos_passos, avisos, segundos, pedido_por_nome)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (cliente, alerta, novo["modelo"], novo["veredito"], novo["confianca"], novo["resumo"], Jsonb(novo["motivos"]),
                     Jsonb(novo["proximos_passos"]), Jsonb(novo["avisos"]), novo["segundos"], NOME))
            dados += 1
    return dados


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    env = _ler_env()
    ia = parecer.configuracao(env)
    if ia is None:
        log.info("sem IA_MODELO no .env: a instalação não tem IA local")
        while True:
            time.sleep(3600)
    armazem = armazem_de_eventos.leitor(env)
    url = f"postgresql://roar_api:{env['ROAR_API_SENHA']}@{os.getenv('ROAR_BANCO_ENDERECO', '127.0.0.1:5433')}/roar"
    while True:
        try:
            with psycopg.connect(url, autocommit=True, row_factory=dict_row) as banco:
                while True:
                    dados = volta(banco, ia, armazem)
                    if dados:
                        log.info("%d pareceres automáticos", dados)
                    time.sleep(SEGUNDOS_ENTRE_VOLTAS)
        except (psycopg.Error, requests.RequestException) as erro:
            # IA ou banco fora do ar: espera e tenta de novo, sem derrubar o serviço.
            log.warning("parecer automático parado: %s", type(erro).__name__)
            time.sleep(SEGUNDOS_ENTRE_VOLTAS)


if __name__ == "__main__":
    main()
