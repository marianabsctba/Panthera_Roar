"""Worker de um cliente: só atende a fila dele e recusa trabalho de outro.

    python -m roar_motor.worker --cliente acme
"""

import argparse
import asyncio
import concurrent.futures
import json
import os

import psycopg
from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.worker import Worker

from . import acoes, blocos, integracoes
from .conexao import conectar
from .disparo import url_do_banco
from .playbook import ExecutarPlaybook, ExecutarResposta, fila_do_cliente


def _conferir_cliente(cliente, cliente_do_worker):
    if cliente != cliente_do_worker:
        raise ApplicationError(
            "Passo de outro cliente nesta fila", type="ClienteIncorreto", non_retryable=True
        )


def criar_acao(cliente_do_worker):
    @activity.defn(name="executar_acao")
    def executar_acao(cliente, passo):
        _conferir_cliente(cliente, cliente_do_worker)
        try:
            resultado = integracoes.chamar(
                passo["integracao"], passo["versao"], passo["acao"], passo.get("parametros", {})
            )
        except integracoes.IntegracaoInvalida as erro:
            raise ApplicationError(str(erro), type="IntegracaoInvalida", non_retryable=True)
        # O Temporal guarda o resultado no histórico, então precisa ser serializável.
        return json.loads(json.dumps(resultado, default=str))

    return executar_acao


def criar_resposta(cliente_do_worker):
    @activity.defn(name="executar_resposta")
    def executar_resposta(cliente, gerenciador_id, contexto, passo):
        _conferir_cliente(cliente, cliente_do_worker)
        # O RLS só mostra os gerenciadores deste cliente: a credencial de outro nunca é lida.
        with psycopg.connect(url_do_banco()) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
            if not con.execute("SELECT 1 FROM gerenciadores WHERE id = %s", (gerenciador_id,)).fetchone():
                raise ApplicationError("Gerenciador de outro cliente", type="ClienteIncorreto", non_retryable=True)
        funcao = acoes.ACOES.get(passo.get("acao"))
        if not funcao:
            raise ApplicationError("Ação desconhecida", type="AcaoRecusada", non_retryable=True)
        try:
            return funcao(gerenciador_id, contexto, passo.get("parametros", {}))
        except acoes.AcaoRecusada as erro:
            raise ApplicationError(str(erro), type="AcaoRecusada", non_retryable=True)

    return executar_resposta


def criar_conclusao(cliente_do_worker):
    @activity.defn(name="concluir_execucao")
    def concluir_execucao(cliente, execucao_id, final):
        _conferir_cliente(cliente, cliente_do_worker)
        with psycopg.connect(url_do_banco()) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
            con.execute(
                "UPDATE execucoes SET estado = %s, resultado = %s, concluida_em = now() WHERE id = %s",
                (final["estado"], json.dumps(final["passos"]), execucao_id),
            )

    return concluir_execucao


def _resumo_do_que_vem(definicao, contexto):
    acoes_previstas = [b["acao"] for b in blocos.plano(definicao["blocos"], contexto) if b["tipo"] == "acao"]
    return ",".join(acoes_previstas)


def criar_pedido_de_aprovacao(cliente_do_worker):
    @activity.defn(name="pedir_aprovacao")
    def pedir_aprovacao(cliente, execucao_id, chave):
        _conferir_cliente(cliente, cliente_do_worker)
        with psycopg.connect(url_do_banco()) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
            definicao, contexto = con.execute("SELECT definicao, contexto FROM execucoes WHERE id = %s", (execucao_id,)).fetchone()
            con.execute(
                """INSERT INTO aprovacoes (cliente_id, execucao_id, chave, descricao) VALUES (%s, %s, %s, %s)
                   ON CONFLICT (cliente_id, execucao_id, chave) DO NOTHING""",
                (cliente, execucao_id, chave, _resumo_do_que_vem(definicao, contexto)),
            )
            con.execute("UPDATE execucoes SET estado = 'aguardando_aprovacao' WHERE id = %s", (execucao_id,))

    return pedir_aprovacao


def criar_registro_de_decisao(cliente_do_worker):
    @activity.defn(name="registrar_decisao")
    def registrar_decisao(cliente, execucao_id, chave, decisao):
        _conferir_cliente(cliente, cliente_do_worker)
        with psycopg.connect(url_do_banco()) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
            if decisao == "expirada":
                con.execute(
                    "UPDATE aprovacoes SET estado = 'expirada' WHERE execucao_id = %s AND chave = %s AND estado = 'pendente'",
                    (execucao_id, chave),
                )
            con.execute(
                """UPDATE execucoes SET estado = 'executando' WHERE id = %s AND NOT EXISTS (
                     SELECT 1 FROM aprovacoes WHERE execucao_id = %s AND estado = 'pendente')""",
                (execucao_id, execucao_id),
            )

    return registrar_decisao


async def rodar(cliente):
    conexao = await conectar()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        await Worker(
            conexao,
            task_queue=fila_do_cliente(cliente),
            workflows=[ExecutarPlaybook, ExecutarResposta],
            activities=[criar_acao(cliente), criar_resposta(cliente), criar_conclusao(cliente),
                        criar_pedido_de_aprovacao(cliente), criar_registro_de_decisao(cliente)],
            activity_executor=executor,
        ).run()


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--cliente", required=True)
    asyncio.run(rodar(args.parse_args().cliente))


if __name__ == "__main__":
    main()
