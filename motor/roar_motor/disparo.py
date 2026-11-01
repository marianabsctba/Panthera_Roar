"""Compara o que aconteceu com os playbooks de cada cliente e manda executar o que casou.

    python -m roar_motor.disparo

O dono de um alerta é a linha do banco, lida sob o RLS do cliente, nunca o conteúdo do alerta.
"""

import asyncio
import json
import os
import subprocess
import sys
import time

import psycopg
from psycopg.rows import dict_row
from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from . import blocos, fatos
from .playbook import fila_do_cliente

EVENTOS_POR_CICLO = 2000
SEGUNDOS_ENTRE_CICLOS = 10
# Muitos alvos em pouco tempo podem ser um atacante forjando a origem nos logs:
# passando disso, mesmo o playbook automático volta a pedir uma pessoa.
LIMITE_AUTOMATICO_POR_HORA = 20


def _ler_env():
    valores = {}
    with open(os.getenv("ROAR_ENV", "/opt/panthera-roar/.env"), encoding="utf-8") as f:
        for linha in f:
            if "=" in linha and not linha.startswith("#"):
                k, v = linha.strip().split("=", 1)
                valores[k] = v
    return valores


def url_do_banco():
    endereco = os.getenv("ROAR_BANCO_ENDERECO", "127.0.0.1:5433")
    return f"postgresql://roar_soar:{_ler_env()['ROAR_SOAR_SENHA']}@{endereco}/roar"


def _eventos_novos(con, cliente):
    linha = con.execute("SELECT ultimo_evento FROM soar_cursor").fetchone()
    if linha is None:
        # Começa no primeiro playbook: o histórico não pode virar uma rajada de respostas,
        # e o que chegou entre criar o playbook e este ciclo não pode se perder.
        inicio = con.execute(
            "SELECT coalesce(max(id), 0) AS m FROM eventos WHERE recebido_em < (SELECT min(criado_em) FROM playbooks)"
        ).fetchone()["m"]
        con.execute("INSERT INTO soar_cursor (cliente_id, ultimo_evento) VALUES (%s, %s)", (cliente, inicio))
        linha = {"ultimo_evento": inicio}
    novos = fatos.eventos_depois_de(con, linha["ultimo_evento"], EVENTOS_POR_CICLO)
    if novos:
        con.execute("UPDATE soar_cursor SET ultimo_evento = %s", (novos[-1]["id"],))
    return novos


def avaliar(con, cliente):
    """Cria as execuções do que casou. Devolve quantas criou."""
    playbooks = con.execute("SELECT * FROM playbooks WHERE ativo ORDER BY id").fetchall()
    lista = _eventos_novos(con, cliente)
    if not playbooks:
        return 0
    if any(p["definicao"]["quando"]["tipo"] == "risco" for p in playbooks):
        lista += fatos.riscos_abertos(con)
    criadas = 0
    for fato in lista:
        for playbook in playbooks:
            if not blocos.atende(playbook["definicao"], fato):
                continue
            # A mesma resposta, para o mesmo alvo, não se repete dentro do intervalo.
            if con.execute(
                """SELECT 1 FROM execucoes WHERE playbook_id = %s AND alvo IS NOT DISTINCT FROM %s
                   AND criada_em > now() - make_interval(mins => %s) LIMIT 1""",
                (playbook["id"], fato["alvo"], playbook["intervalo_minutos"]),
            ).fetchone():
                continue
            definicao = playbook["definicao"]
            if not blocos.tem_aprovacao(definicao["blocos"]):
                automaticas = con.execute(
                    "SELECT count(*) AS n FROM execucoes WHERE playbook_id = %s AND criada_em > now() - interval '1 hour'",
                    (playbook["id"],),
                ).fetchone()["n"]
                if automaticas >= LIMITE_AUTOMATICO_POR_HORA:
                    definicao = {**definicao, "blocos": [{"tipo": "aprovacao"}, *definicao["blocos"]]}
            contexto = {"playbook": playbook["nome"], "alvo": fato["alvo"], "agente_id": fato["agente_id"],
                        "origem_tipo": fato["origem_tipo"], "origem_id": fato["origem_id"], "titulo": fato["titulo"],
                        "nivel": fato.get("nivel"), "severidade": fato.get("severidade")}
            nova = con.execute(
                """INSERT INTO execucoes (cliente_id, playbook_id, gerenciador_id, origem_tipo, origem_id, alvo, agente_id, titulo, definicao, contexto)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (cliente_id, playbook_id, origem_tipo, origem_id) DO NOTHING RETURNING id""",
                (cliente, playbook["id"], fato["gerenciador_id"], fato["origem_tipo"], fato["origem_id"], fato["alvo"],
                 fato["agente_id"], fato["titulo"], json.dumps(definicao), json.dumps(contexto)),
            ).fetchone()
            criadas += 1 if nova else 0
    return criadas


def _id_do_workflow(cliente, execucao_id):
    return f"resposta-{cliente}-{execucao_id}"


async def iniciar_novas(con, temporal, cliente):
    """Inicia com id fixo: se cair entre iniciar e gravar, o próximo ciclo não executa de novo."""
    novas = con.execute("SELECT * FROM execucoes WHERE estado = 'nova' ORDER BY id").fetchall()
    for x in novas:
        pedido = {"cliente": cliente, "execucao_id": x["id"], "gerenciador_id": x["gerenciador_id"],
                  "contexto": x["contexto"], "blocos": x["definicao"]["blocos"]}
        try:
            await temporal.start_workflow(
                "ExecutarResposta", pedido, id=_id_do_workflow(cliente, x["id"]), task_queue=fila_do_cliente(cliente),
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
        except WorkflowAlreadyStartedError:
            pass
        con.execute("UPDATE execucoes SET estado = 'executando' WHERE id = %s AND estado = 'nova'", (x["id"],))
    return len(novas)


async def avisar_decisoes(con, temporal, cliente):
    """A tela só grava a decisão. Quem acorda a execução é este ciclo."""
    decididas = con.execute(
        "SELECT id, execucao_id, chave, estado FROM aprovacoes WHERE estado IN ('aprovada', 'recusada') AND NOT avisada"
    ).fetchall()
    for a in decididas:
        await temporal.get_workflow_handle(_id_do_workflow(cliente, a["execucao_id"])).signal("decidir", args=[a["chave"], a["estado"]])
        con.execute("UPDATE aprovacoes SET avisada = true WHERE id = %s", (a["id"],))
    return len(decididas)


async def ciclo_do_cliente(url, temporal, cliente):
    # Transações separadas: uma falha ao iniciar não pode desfazer execuções que já foram criadas,
    # senão o ciclo seguinte criaria outras, com outro id, para o mesmo alerta.
    with psycopg.connect(url, row_factory=dict_row) as con:
        con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
        avaliar(con, cliente)
    with psycopg.connect(url, row_factory=dict_row) as con:
        con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
        await iniciar_novas(con, temporal, cliente)
    with psycopg.connect(url, row_factory=dict_row) as con:
        con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
        await avisar_decisoes(con, temporal, cliente)


def clientes_com_playbook(url):
    """O percurso passa pelo id de cada cliente; os playbooks só aparecem sob o RLS de cada um."""
    with psycopg.connect(url) as con:
        ids = [str(l[0]) for l in con.execute("SELECT id FROM clientes").fetchall()]
    ativos = []
    for cliente in ids:
        with psycopg.connect(url) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
            if con.execute("SELECT 1 FROM playbooks LIMIT 1").fetchone():
                ativos.append(cliente)
    return ativos


def garantir_workers(clientes, workers):
    """Um processo e uma fila por cliente; quem caiu volta no ciclo seguinte."""
    for cliente in clientes:
        if cliente not in workers or workers[cliente].poll() is not None:
            workers[cliente] = subprocess.Popen([sys.executable, "-m", "roar_motor.worker", "--cliente", cliente])


async def rodar():
    temporal = await Client.connect(os.getenv("ROAR_TEMPORAL", "127.0.0.1:7233"), namespace="roar")
    url, workers = url_do_banco(), {}
    while True:
        inicio = time.monotonic()
        clientes = clientes_com_playbook(url)
        garantir_workers(clientes, workers)
        for cliente in clientes:
            try:
                await ciclo_do_cliente(url, temporal, cliente)
            except Exception as erro:  # Um cliente com problema não pode parar a resposta dos outros.
                print(json.dumps({"cliente": cliente, "erro": str(erro)[:300]}), file=sys.stderr, flush=True)
        await asyncio.sleep(max(1, SEGUNDOS_ENTRE_CICLOS - (time.monotonic() - inicio)))


if __name__ == "__main__":
    asyncio.run(rodar())
