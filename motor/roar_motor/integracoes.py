"""Carrega e chama integrações no formato de apps MIT, sem nada do backend do Shuffle."""

import importlib.util
import logging
import os
import re
from pathlib import Path

# O SDK usa os servidores da Shuffle como padrão quando estas variáveis faltam.
# Apontar para um endereço morto garante que nenhum dado saia por esse caminho.
for variavel in ("BASE_URL", "CALLBACK_URL"):
    os.environ[variavel] = "http://127.0.0.1:9"
os.environ["SHUFFLE_LOGS_DISABLED"] = "true"
os.environ["SHUFFLE_STATS_DISABLED"] = "true"

PASTA_APPS = Path(os.getenv("ROAR_APPS", "/opt/panthera-roar/apps"))
NOME_VALIDO = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
VERSAO_VALIDA = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
ACAO_VALIDA = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


class IntegracaoInvalida(Exception):
    pass


def _carregar_classe(integracao, versao):
    if not NOME_VALIDO.match(integracao) or not VERSAO_VALIDA.match(versao):
        raise IntegracaoInvalida(f"integração inválida: {integracao} {versao}")
    caminho = PASTA_APPS / integracao / versao / "src" / "app.py"
    if not caminho.is_file():
        raise IntegracaoInvalida(f"integração não instalada: {integracao} {versao}")

    especificacao = importlib.util.spec_from_file_location(f"roar_app_{integracao}", caminho)
    modulo = importlib.util.module_from_spec(especificacao)
    especificacao.loader.exec_module(modulo)

    from shuffle_sdk import AppBase

    for valor in vars(modulo).values():
        if isinstance(valor, type) and issubclass(valor, AppBase) and valor is not AppBase:
            return valor
    raise IntegracaoInvalida(f"nenhuma classe de app em {integracao} {versao}")


def chamar(integracao, versao, acao, parametros):
    if not ACAO_VALIDA.match(acao) or acao.startswith("_"):
        raise IntegracaoInvalida(f"ação inválida: {acao}")
    classe = _carregar_classe(integracao, versao)
    # Só ações definidas pela própria integração, nunca métodos herdados do SDK.
    if acao not in vars(classe) or not callable(vars(classe)[acao]):
        raise IntegracaoInvalida(f"{integracao} não tem a ação {acao}")
    app = classe(redis=None, logger=logging.getLogger(f"roar.{integracao}"))
    return getattr(app, acao)(**parametros)
