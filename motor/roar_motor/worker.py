"""Worker de um cliente: só atende a fila dele e recusa trabalho de outro.

    python -m roar_motor.worker --cliente acme
"""

import argparse
import asyncio
import concurrent.futures
import json
import os

from temporalio import activity
from temporalio.client import Client
from temporalio.exceptions import ApplicationError
from temporalio.worker import Worker

from . import integracoes
from .playbook import ExecutarPlaybook, fila_do_cliente


def criar_acao(cliente_do_worker):
    @activity.defn(name="executar_acao")
    def executar_acao(cliente, passo):
        if cliente != cliente_do_worker:
            raise ApplicationError(
                "Passo de outro cliente nesta fila", type="ClienteIncorreto", non_retryable=True
            )
        try:
            resultado = integracoes.chamar(
                passo["integracao"], passo["versao"], passo["acao"], passo.get("parametros", {})
            )
        except integracoes.IntegracaoInvalida as erro:
            raise ApplicationError(str(erro), type="IntegracaoInvalida", non_retryable=True)
        # O Temporal guarda o resultado no histórico, então precisa ser serializável.
        return json.loads(json.dumps(resultado, default=str))

    return executar_acao


async def rodar(cliente):
    conexao = await Client.connect(
        os.getenv("ROAR_TEMPORAL", "127.0.0.1:7233"), namespace="roar"
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        await Worker(
            conexao,
            task_queue=fila_do_cliente(cliente),
            workflows=[ExecutarPlaybook],
            activities=[criar_acao(cliente)],
            activity_executor=executor,
        ).run()


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--cliente", required=True)
    asyncio.run(rodar(args.parse_args().cliente))


if __name__ == "__main__":
    main()
