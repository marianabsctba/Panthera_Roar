"""Execução durável de um playbook. Só código determinístico, como o Temporal exige."""

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy


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
