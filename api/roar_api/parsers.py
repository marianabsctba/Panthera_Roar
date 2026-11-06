"""Parsers próprios: o guiado vira XML de decodificador aqui, e o escrito à mão é conferido antes de ir ao gerenciador.

Cada campo vira um decodificador irmão com a mesma regra de reconhecimento: o gerenciador aplica todos, então os
campos podem vir em qualquer ordem no log, e um campo que falta não impede os outros.
"""

import re
from xml.etree import ElementTree
from xml.sax.saxutils import escape

# Como o valor termina, em expressão PCRE2. "resto" pega até o fim da linha.
VALORES = {
    "palavra": r"(\S+)",
    "ip": r"([0-9A-Fa-f:.]+)",
    "numero": r"(\d+)",
    "aspas": r'"([^"]*)"',
    "resto": r"(.+)$",
}
NOMES_DE_VALOR = {"palavra": "Uma palavra", "ip": "Endereço IP", "numero": "Número", "aspas": "Entre aspas", "resto": "Até o fim da linha"}
# Os campos que as regras do catálogo já conhecem. Outros nomes também valem.
CAMPOS_CONHECIDOS = ("srcip", "dstip", "srcport", "dstport", "srcuser", "dstuser", "protocol", "action", "url", "status", "id", "system_name", "extra_data")
CAMPO = re.compile(r"[a-z][a-z0-9_.]{0,39}")
FILHOS_PERMITIDOS = {"parent", "prematch", "program_name", "regex", "order", "plugin_decoder", "use_own_name", "json_null_field",
                     "json_array_structure", "fts", "ftscomment", "type", "accumulate", "prematch_offset", "regex_offset"}
TAMANHO_MAXIMO = 64000


class ParserInvalido(ValueError):
    pass


def nome_do_decodificador(nome):
    return f"roar_{nome}"


def _pcre(texto):
    """Texto literal dentro de uma expressão PCRE2."""
    return re.escape(texto)


def gerar_xml(nome, definicao):
    """definicao: {"reconhecer": "programa" | "texto", "valor": str, "campos": [{"nome", "antes", "tipo"}]}."""
    base = nome_do_decodificador(nome)
    reconhecer, valor = definicao.get("reconhecer"), str(definicao.get("valor") or "").strip()
    if not valor or len(valor) > 200 or "\n" in valor:
        raise ParserInvalido("Diga como reconhecer o log: o nome do programa ou um texto que sempre aparece nele.")
    if reconhecer == "programa":
        if not re.fullmatch(r"[\w.\-/]{1,100}", valor):
            raise ParserInvalido("O nome do programa tem só letras, números, ponto, hífen, barra ou sublinhado.")
        pai = f"  <program_name>{escape(valor)}</program_name>\n"
    elif reconhecer == "texto":
        pai = f'  <prematch type="pcre2">{escape(_pcre(valor))}</prematch>\n'
    else:
        raise ParserInvalido("Escolha como reconhecer o log.")
    campos = definicao.get("campos") or []
    if not campos or len(campos) > 40:
        raise ParserInvalido("Diga pelo menos um campo para tirar do log, e no máximo 40.")
    vistos, filhos = set(), []
    for campo in campos:
        nome_do_campo, antes, tipo = str(campo.get("nome") or "").strip(), str(campo.get("antes") or ""), campo.get("tipo")
        if not CAMPO.fullmatch(nome_do_campo):
            raise ParserInvalido(f"O nome de campo {nome_do_campo or '(vazio)'} precisa começar com letra minúscula e ter só letras, números, ponto ou sublinhado.")
        if nome_do_campo in vistos:
            raise ParserInvalido(f"O campo {nome_do_campo} aparece duas vezes.")
        if tipo not in VALORES:
            raise ParserInvalido(f"Escolha que tipo de valor o campo {nome_do_campo} tem.")
        if not antes.strip() or len(antes) > 100 or "\n" in antes:
            raise ParserInvalido(f"Diga o texto que vem logo antes do campo {nome_do_campo}, como user= ou src:.")
        vistos.add(nome_do_campo)
        filhos.append(f'<decoder name="{base}_campos">\n  <parent>{base}</parent>\n'
                      f'  <regex type="pcre2">{escape(_pcre(antes) + VALORES[tipo])}</regex>\n  <order>{nome_do_campo}</order>\n</decoder>\n')
    return f'<decoder name="{base}">\n{pai}</decoder>\n' + "".join(filhos)


def conferir_xml(nome, xml):
    """Só decodificadores com o nome deste parser, e só com os elementos que um decodificador tem."""
    if not xml.strip() or len(xml) > TAMANHO_MAXIMO:
        raise ParserInvalido("O XML está vazio ou é grande demais.")
    if "<!" in xml or "<?" in xml:
        raise ParserInvalido("O XML não pode ter declarações, comentários especiais ou entidades.")
    try:
        raiz = ElementTree.fromstring(f"<raiz>{xml}</raiz>")
    except ElementTree.ParseError as erro:
        raise ParserInvalido(f"O XML não está bem formado: {erro}.") from None
    base = nome_do_decodificador(nome)
    if not len(raiz):
        raise ParserInvalido("O XML não tem nenhum decodificador.")
    for decodificador in raiz:
        if decodificador.tag != "decoder":
            raise ParserInvalido(f"Só vale <decoder> no primeiro nível, e veio <{decodificador.tag}>.")
        nome_dele = decodificador.get("name", "")
        if nome_dele != base and not nome_dele.startswith(base + "_"):
            raise ParserInvalido(f"Todo decodificador deste parser precisa se chamar {base} ou começar com {base}_.")
        for filho in decodificador:
            if filho.tag not in FILHOS_PERMITIDOS:
                raise ParserInvalido(f"<{filho.tag}> não é um elemento de decodificador.")
            if filho.tag == "parent" and not (filho.text or "").startswith(base):
                raise ParserInvalido(f"O pai precisa ser um decodificador deste parser, que começa com {base}.")
    return xml.strip() + "\n"


def xml_do_pedido(nome, modo, definicao, xml):
    if modo == "guiado":
        return gerar_xml(nome, definicao or {})
    if modo == "xml":
        return conferir_xml(nome, xml or "")
    raise ParserInvalido("Modo desconhecido.")
