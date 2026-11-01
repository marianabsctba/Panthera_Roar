"""Regras escritas à mão no formato do Wazuh.

O gerenciador faz a validação final; aqui entra só o que protege as outras regras: nada de
substituir regra existente, e os números são reatribuídos para ficarem na faixa do cliente.
"""

import re
from xml.etree import ElementTree

LIMITE_DE_REGRAS = 32
RULE_ABERTURA = re.compile(r"<rule\b[^>]*>")


class XmlInvalido(Exception):
    pass


def analisar(texto):
    """Devolve as regras encontradas: [(descrição, nível)]. Recusa o que não pode entrar."""
    # Sem DOCTYPE não há entidade para expandir.
    if re.search(r"<!DOCTYPE|<!ENTITY", texto, re.IGNORECASE):
        raise XmlInvalido("O XML não pode ter DOCTYPE nem ENTITY.")
    try:
        raiz = ElementTree.fromstring(f"<raiz>{texto}</raiz>")
    except ElementTree.ParseError as erro:
        raise XmlInvalido(f"XML inválido: {erro}")
    regras = raiz.findall(".//rule")
    if not regras:
        raise XmlInvalido('Nenhuma regra encontrada. Use <group name="..."><rule ...>.')
    if len(regras) > LIMITE_DE_REGRAS:
        raise XmlInvalido(f"Use no máximo {LIMITE_DE_REGRAS} regras por vez.")
    resultado = []
    for regra in regras:
        if regra.get("overwrite"):
            raise XmlInvalido("Por enquanto não é possível substituir regras existentes.")
        nivel = regra.get("level", "")
        if not nivel.isdigit() or int(nivel) > 16:
            raise XmlInvalido("Toda regra precisa de um level de 0 a 16.")
        descricao = regra.findtext("description")
        if not descricao or not descricao.strip():
            raise XmlInvalido("Toda regra precisa de uma description.")
        resultado.append((descricao.strip(), int(nivel)))
    return resultado


def renumerar(texto, id_inicial):
    """Troca os ids pelos da faixa do cliente, ajustando referências entre as regras do arquivo."""
    mapa = {}

    def trocar(encontro):
        abertura = encontro.group(0)
        antigo = re.search(r'\bid="(\d+)"', abertura)
        if not antigo:
            raise XmlInvalido("Toda regra precisa de um id numérico.")
        mapa[antigo.group(1)] = str(id_inicial + len(mapa))
        return abertura.replace(antigo.group(0), f'id="{mapa[antigo.group(1)]}"')

    novo = RULE_ABERTURA.sub(trocar, texto)
    for marca in ("if_sid", "if_matched_sid"):
        def referencia(encontro, marca=marca):
            ids = [mapa.get(i.strip(), i.strip()) for i in re.split(r"[,\s]+", encontro.group(1)) if i.strip()]
            return f"<{marca}>{', '.join(ids)}</{marca}>"
        novo = re.sub(rf"<{marca}>([^<]*)</{marca}>", referencia, novo)
    return novo


def trecho_da_regra(arquivo, regra_id):
    """O bloco de uma regra dentro do arquivo original, envolvido no grupo para poder ser editado."""
    encontro = re.search(rf'<rule\b[^>]*\bid="{re.escape(str(regra_id))}"[^>]*>.*?</rule>', arquivo, re.DOTALL)
    return encontro.group(0) if encontro else None
