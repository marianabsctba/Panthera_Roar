"""Linguagem de consulta dos logs, em português ou em inglês.

    ativo=srv-rh E origem!=10.* E "falha de login" | contar por usuario | limite 10
    agent.name=srv-rh AND NOT data.srcip=10.* | stats count by data.srcuser | head 10

O texto nunca chega ao indexer: vira uma estrutura montada aqui, só com comparações de campo.
"""

import re
from dataclasses import dataclass, field

LIMITE_DE_TAMANHO = 2000
LIMITE_DE_PROFUNDIDADE = 12
LIMITE_DE_TERMOS = 40
LIMITE_DE_LINHAS = 1000
LIMITE_DE_GRUPOS = 100

APELIDOS = {
    "ativo": "agent.name", "host": "agent.name", "agente": "agent.name",
    "origem": "data.srcip", "ip": "data.srcip", "destino": "data.dstip",
    "usuario": "data.srcuser", "usuário": "data.srcuser", "usuario_destino": "data.dstuser", "usuário_destino": "data.dstuser",
    "fonte": "location", "tipo": "decoder.name", "programa": "predecoder.program_name", "protocolo": "data.protocol",
    "log": "full_log", "texto": "full_log", "quando": "timestamp", "regra": "rule.id", "nivel": "rule.level", "nível": "rule.level",
    "pais": "GeoLocation.country_name", "país": "GeoLocation.country_name", "cidade": "GeoLocation.city_name",
    "estado": "GeoLocation.region_name",
}
PALAVRAS_E = {"e", "and"}
PALAVRAS_OU = {"ou", "or"}
PALAVRAS_NAO = {"nao", "não", "not"}
CAMPO_VALIDO = re.compile(r"[A-Za-z0-9@][A-Za-z0-9_.@-]{0,120}")
TOKEN = re.compile(r"""
    \s*(?:
      (?P<texto>"(?:[^"\\]|\\.)*")
    | (?P<operador>!=|>=|<=|=|>|<|~)
    | (?P<simbolo>[(),])
    | (?P<palavra>[^\s()=!<>~",]+)
    )""", re.VERBOSE)


class ConsultaInvalida(Exception):
    pass


@dataclass
class Consulta:
    filtro: dict
    colunas: list = field(default_factory=list)
    ordem: tuple | None = None
    limite: int | None = None
    contar_por: str | None = None
    contar: bool = False


def _fatias(texto):
    tokens, posicao = [], 0
    while posicao < len(texto):
        if not texto[posicao:].strip():
            break
        encontro = TOKEN.match(texto, posicao)
        if not encontro or encontro.end() == posicao:
            raise ConsultaInvalida(f"Não entendi a consulta perto de: {texto[posicao:posicao + 30]}")
        tipo = encontro.lastgroup
        valor = encontro.group(tipo)
        if tipo == "texto":
            valor = re.sub(r"\\(.)", r"\1", valor[1:-1])
        tokens.append((tipo, valor))
        posicao = encontro.end()
    return tokens


def _campo(nome):
    real = APELIDOS.get(nome.lower(), nome)
    if not CAMPO_VALIDO.fullmatch(real):
        raise ConsultaInvalida(f"Campo inválido: {nome}")
    return real


class _Analisador:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0
        self.termos = 0

    def _olhar(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def _avancar(self):
        token = self._olhar()
        self.i += 1
        return token

    def _e_palavra(self, conjunto):
        tipo, valor = self._olhar()
        return tipo == "palavra" and valor.lower() in conjunto

    def ou(self, profundidade=0):
        if profundidade > LIMITE_DE_PROFUNDIDADE:
            raise ConsultaInvalida("A consulta tem parênteses demais.")
        partes = [self.e(profundidade)]
        while self._e_palavra(PALAVRAS_OU):
            self._avancar()
            partes.append(self.e(profundidade))
        return partes[0] if len(partes) == 1 else {"bool": {"should": partes, "minimum_should_match": 1}}

    def e(self, profundidade):
        partes = [self.nao(profundidade)]
        while True:
            if self._e_palavra(PALAVRAS_E):
                self._avancar()
            elif self._olhar()[0] is None or self._olhar()[1] == ")" or self._e_palavra(PALAVRAS_OU):
                break
            partes.append(self.nao(profundidade))
        return partes[0] if len(partes) == 1 else {"bool": {"filter": partes}}

    def nao(self, profundidade):
        if self._e_palavra(PALAVRAS_NAO):
            self._avancar()
            return {"bool": {"must_not": [self.nao(profundidade + 1)]}}
        return self.primario(profundidade)

    def primario(self, profundidade):
        tipo, valor = self._avancar()
        if tipo is None:
            raise ConsultaInvalida("A consulta terminou antes da hora.")
        if valor == "(" and tipo == "simbolo":
            interno = self.ou(profundidade + 1)
            if self._avancar()[1] != ")":
                raise ConsultaInvalida("Faltou fechar um parêntese.")
            return interno
        if tipo not in ("palavra", "texto"):
            raise ConsultaInvalida(f"Não esperava {valor} aqui.")
        if tipo == "palavra" and valor.lower() in PALAVRAS_E | PALAVRAS_OU | PALAVRAS_NAO:
            raise ConsultaInvalida(f'Falta uma condição perto de {valor}. Para buscar essa palavra, use aspas: "{valor}".')
        self.termos += 1
        if self.termos > LIMITE_DE_TERMOS:
            raise ConsultaInvalida(f"Use no máximo {LIMITE_DE_TERMOS} condições.")
        if tipo == "palavra" and self._olhar()[0] == "operador":
            _, operador = self._avancar()
            tipo_valor, alvo = self._avancar()
            if tipo_valor not in ("palavra", "texto"):
                raise ConsultaInvalida(f"Faltou o valor depois de {valor}{operador}.")
            return _comparacao(_campo(valor), operador, alvo)
        return _texto_livre(valor)


def _texto_livre(valor):
    return {"match_phrase": {"full_log": valor}}


def _comparacao(campo, operador, valor):
    if operador in (">", ">=", "<", "<="):
        chave = {">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}[operador]
        return {"range": {campo: {chave: valor}}}
    if campo == "full_log":
        positivo = _texto_livre(valor.replace("*", " ").strip())
    elif operador == "~":
        positivo = {"wildcard": {campo: {"value": f"*{valor}*", "case_insensitive": True}}}
    elif "*" in valor or "?" in valor:
        positivo = {"wildcard": {campo: {"value": valor, "case_insensitive": True}}}
    else:
        positivo = {"term": {campo: valor}}
    return {"bool": {"must_not": [positivo]}} if operador == "!=" else positivo


def _inteiro(texto, limite, nome):
    if not texto or not texto.isdigit() or not 1 <= int(texto) <= limite:
        raise ConsultaInvalida(f"{nome} precisa ser um número de 1 a {limite}.")
    return int(texto)


def _comando(texto, consulta):
    tokens = _fatias(texto)
    if not tokens or tokens[0][0] != "palavra":
        raise ConsultaInvalida("Faltou um comando depois da barra.")
    nome = tokens[0][1].lower()
    resto = [v for _, v in tokens[1:] if v != ","]
    if nome in ("campos", "fields"):
        if not resto:
            raise ConsultaInvalida("Diga quais campos mostrar.")
        consulta.colunas = [_campo(c) for c in resto[:30]]
    elif nome in ("ordenar", "sort"):
        if len(resto) != 1:
            raise ConsultaInvalida("Use: ordenar -campo, ou ordenar campo.")
        descendente = resto[0].startswith("-")
        consulta.ordem = (_campo(resto[0].lstrip("+-")), "desc" if descendente else "asc")
    elif nome in ("limite", "head", "limit"):
        consulta.limite = _inteiro(resto[0] if resto else "", LIMITE_DE_LINHAS, "O limite")
    elif nome in ("contar", "stats", "count"):
        if nome == "stats":
            if not resto or resto[0].lower() != "count":
                raise ConsultaInvalida("Use: stats count by campo.")
            resto = resto[1:]
        if resto and resto[0].lower() in ("por", "by"):
            if len(resto) != 2:
                raise ConsultaInvalida("Use: contar por campo.")
            consulta.contar_por = _campo(resto[1])
        elif resto:
            raise ConsultaInvalida("Use: contar, ou contar por campo.")
        consulta.contar = True
    elif nome in ("top", "maiores"):
        if len(resto) != 1:
            raise ConsultaInvalida("Use: top campo.")
        consulta.contar_por = _campo(resto[0])
        consulta.contar = True
    else:
        raise ConsultaInvalida(f"Comando desconhecido: {tokens[0][1]}. Use contar, campos, ordenar ou limite.")


def _dividir_pipes(texto):
    """Separa por barra vertical, respeitando o que está entre aspas."""
    partes, atual, em_aspas, escapado = [], [], False, False
    for c in texto:
        if escapado:
            escapado = False
        elif c == "\\" and em_aspas:
            escapado = True
        elif c == '"':
            em_aspas = not em_aspas
        elif c == "|" and not em_aspas:
            partes.append("".join(atual))
            atual = []
            continue
        atual.append(c)
    if em_aspas:
        raise ConsultaInvalida("Faltou fechar aspas.")
    partes.append("".join(atual))
    return partes


def analisar(texto):
    texto = (texto or "").strip()
    if len(texto) > LIMITE_DE_TAMANHO:
        raise ConsultaInvalida(f"A consulta passa de {LIMITE_DE_TAMANHO} caracteres.")
    filtro_texto, *comandos = _dividir_pipes(texto)
    tokens = _fatias(filtro_texto)
    if tokens:
        analisador = _Analisador(tokens)
        filtro = analisador.ou()
        if analisador.i != len(tokens):
            raise ConsultaInvalida(f"Sobrou algo no fim da consulta: {tokens[analisador.i][1]}")
    else:
        filtro = {"match_all": {}}
    consulta = Consulta(filtro)
    for comando in comandos:
        _comando(comando, consulta)
    return consulta
