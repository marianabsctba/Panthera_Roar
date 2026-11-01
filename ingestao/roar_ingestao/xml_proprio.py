"""Regras escritas à mão no formato do Wazuh.

O gerenciador faz a validação final; aqui entra só o que protege as outras regras: nada de
substituir regra existente, e os números são reatribuídos para ficarem na faixa do cliente.
"""

import re
from xml.etree import ElementTree

LIMITE_DE_REGRAS = 32
RULE_ABERTURA = re.compile(r"<rule\b[^>]*>")
CAMPOS_FIXOS = ("if_sid", "if_group", "if_level", "if_matched_sid", "if_matched_group")


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


def _regra_unica(texto):
    if re.search(r"<!DOCTYPE|<!ENTITY", texto, re.IGNORECASE):
        raise XmlInvalido("O XML não pode ter DOCTYPE nem ENTITY.")
    try:
        raiz = ElementTree.fromstring(f"<raiz>{texto}</raiz>")
    except ElementTree.ParseError as erro:
        raise XmlInvalido(f"XML inválido: {erro}")
    regras = raiz.findall(".//rule")
    if len(regras) != 1:
        raise XmlInvalido("Edite uma regra por vez.")
    return regras[0]


def validar_substituicao(texto, regra_id, original):
    """Devolve só o bloco <rule>, sem grupo em volta. Nunca deixa mexer em outra regra do catálogo."""
    regra = _regra_unica(texto)
    if regra.get("id") != str(regra_id):
        raise XmlInvalido(f"O número da regra precisa continuar {regra_id}.")
    nivel = regra.get("level", "")
    if not nivel.isdigit() or int(nivel) > 16:
        raise XmlInvalido("A regra precisa de um level de 0 a 16.")
    if not (regra.findtext("description") or "").strip():
        raise XmlInvalido("A regra precisa de uma description.")
    # Ao sobrescrever, o gerenciador ignora estes campos: aceitar faria a tela mentir sobre a regra.
    base = _regra_unica(original)
    for campo in CAMPOS_FIXOS:
        if [(e.text or "").strip() for e in regra.findall(campo)] != [(e.text or "").strip() for e in base.findall(campo)]:
            raise XmlInvalido(f"O campo {campo} não pode mudar ao editar uma regra existente. Crie uma regra nova para isso.")
    return re.search(r"<rule\b.*</rule>", texto, re.DOTALL).group(0)


def substituicao(origem, regra_id, desligada=False):
    """O que vai para o gerenciador: mesmo número, com a marca de sobrescrever. Desligada é nível 0."""
    abertura = RULE_ABERTURA.search(origem).group(0)
    nova = re.sub(r'\s+overwrite="[^"]*"', "", abertura)
    if desligada:
        nova = re.sub(r'\blevel="\d+"', 'level="0"', nova)
    nova = nova[:-1] + ' overwrite="yes">'
    return f'<group name="roar_catalogo_ajustado,">\n{origem.replace(abertura, nova, 1)}\n</group>\n'


def trecho_da_regra(arquivo, regra_id):
    """O bloco de uma regra dentro do arquivo original, envolvido no grupo para poder ser editado."""
    encontro = re.search(rf'<rule\b[^>]*\bid="{re.escape(str(regra_id))}"[^>]*>.*?</rule>', arquivo, re.DOTALL)
    return encontro.group(0) if encontro else None
