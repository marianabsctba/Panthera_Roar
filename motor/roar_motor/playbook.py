"""Execução durável de um playbook. Só código determinístico, como o Temporal exige."""

import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError

from . import blocos

# Ninguém decidiu nesse tempo: conta como recusa, nunca como aprovação.
PRAZO_DA_APROVACAO = timedelta(hours=72)


def fila_do_cliente(cliente: str) -> str:
    return f"cliente-{cliente}"


@workflow.defn(name="ExecutarPlaybook")
class ExecutarPlaybook:
    @workflow.run
    async def run(self, playbook: dict) -> dict:
        resultados = {}
        for passo in playbook["passos"]:
            resultados[passo["id"]] = await workflow.execute_activity(
                "executar_acao",
                args=[playbook["cliente"], passo],
                task_queue=fila_do_cliente(playbook["cliente"]),
                start_to_close_timeout=timedelta(seconds=passo.get("limite_s", 60)),
                retry_policy=RetryPolicy(
                    maximum_attempts=passo.get("tentativas", 3),
                    non_retryable_error_types=["ClienteIncorreto", "IntegracaoInvalida"],
                ),
            )
        return resultados


class _Parar(Exception):
    def __init__(self, estado):
        self.estado = estado


@workflow.defn(name="ExecutarResposta")
class ExecutarResposta:
    """Percorre a pilha de blocos. Uma falha ou recusa interrompe o resto e fica registrada."""

    def __init__(self):
        self.decisoes = {}

    @workflow.signal(name="decidir")
    def decidir(self, chave: str, decisao: str):
        self.decisoes[chave] = decisao

    async def _atividade(self, nome, *args, limite=30, tentativas=5):
        return await workflow.execute_activity(
            nome,
            args=list(args),
            task_queue=fila_do_cliente(self.pedido["cliente"]),
            start_to_close_timeout=timedelta(seconds=limite),
            retry_policy=RetryPolicy(
                maximum_attempts=tentativas,
                non_retryable_error_types=["ClienteIncorreto", "AcaoRecusada"],
            ),
        )

    async def _aprovacao(self, chave, caminho):
        cliente, execucao = self.pedido["cliente"], self.pedido["execucao_id"]
        await self._atividade("pedir_aprovacao", cliente, execucao, chave)
        try:
            await workflow.wait_condition(lambda: chave in self.decisoes, timeout=PRAZO_DA_APROVACAO)
            decisao = self.decisoes[chave]
        except asyncio.TimeoutError:
            decisao = "expirada"
        await self._atividade("registrar_decisao", cliente, execucao, chave, decisao)
        self.resultados.append({"caminho": caminho, "aprovacao": decisao})
        if decisao != "aprovada":
            raise _Parar("recusada")

    async def _acao(self, bloco, caminho):
        try:
            resultado = await self._atividade(
                "executar_resposta", self.pedido["cliente"], self.pedido["gerenciador_id"],
                self.pedido["contexto"], bloco, limite=120, tentativas=3,
            )
        except ActivityError as erro:
            causa = getattr(erro.cause, "message", None) or str(erro.cause)
            self.resultados.append({"caminho": caminho, "acao": bloco["acao"], "erro": causa})
            raise _Parar("falhou")
        self.resultados.append({"caminho": caminho, "acao": bloco["acao"], "resultado": resultado})

    async def _rodar(self, lista, prefixo):
        for i, bloco in enumerate(lista):
            caminho = f"{prefixo}{i}"
            if bloco["tipo"] == "aprovacao":
                await self._aprovacao(caminho, caminho)
            elif bloco["tipo"] == "acao":
                await self._acao(bloco, caminho)
            elif bloco["tipo"] == "se":
                verdadeira = blocos.condicao_verdadeira(bloco["condicao"], self.pedido["contexto"])
                self.resultados.append({"caminho": caminho, "se": verdadeira})
                if verdadeira:
                    await self._rodar(bloco["entao"], f"{caminho}.entao.")
                else:
                    await self._rodar(bloco.get("senao", []), f"{caminho}.senao.")
            elif bloco["tipo"] == "paralelo":
                ramos = [self._rodar(r, f"{caminho}.ramo{j}.") for j, r in enumerate(bloco["ramos"])]
                fins = await asyncio.gather(*ramos, return_exceptions=True)
                for fim in fins:
                    if isinstance(fim, BaseException):
                        raise fim

    @workflow.run
    async def run(self, pedido: dict) -> dict:
        self.pedido, self.resultados = pedido, []
        estado = "concluida"
        try:
            await self._rodar(pedido["blocos"], "")
        except _Parar as parada:
            estado = parada.estado
        final = {"estado": estado, "passos": self.resultados}
        await self._atividade("concluir_execucao", pedido["cliente"], pedido["execucao_id"], final)
        return final
