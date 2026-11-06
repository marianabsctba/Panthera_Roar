"""A mesma linguagem de consulta, traduzida para o armazém de eventos (ClickHouse). Desenho em docs/clickhouse.md.

A linguagem (consulta.py) monta um filtro com poucas formas: frase no texto, comparação, curinga, faixa, e/ou/não. Aqui
cada forma vira SQL com os valores sempre como parâmetros ({p0:String}); o nome do campo vira uma coluna conhecida ou,
fora delas, um caminho dentro do log original, também por parâmetro. Nada do que a pessoa digitou entra no texto do SQL.
"""

import re

from roar_api.consulta import ConsultaInvalida

# Campo do Wazuh -> (expressão no armazém, tipo). Os que a tela e os painéis mais usam têm coluna própria.
COLUNAS = {
    "timestamp": ("ocorrido_em", "tempo"),
    "agent.name": ("agente_nome", "texto"), "agent.id": ("agente_id", "texto"), "agent.ip": ("agente_ip", "texto"),
    "data.srcip": ("ip_origem", "texto"), "data.dstip": ("ip_destino", "texto"),
    "data.srcuser": ("usuario", "texto"), "data.dstuser": ("usuario_destino", "texto"),
    "location": ("local", "texto"), "decoder.name": ("decoder", "texto"),
    "rule.id": ("regra_id", "texto"), "rule.level": ("nivel", "numero"), "rule.description": ("regra_descricao", "texto"),
    "rule.groups": ("regra_grupos", "lista"), "rule.mitre.id": ("mitre", "lista"),
    "rule.mitre.technique": ("mitre_tecnicas", "lista"), "rule.mitre.tactic": ("mitre_taticas", "lista"),
    "full_log": ("full_log", "texto"), "id": ("origem_id", "texto"),
    "GeoLocation.country_name": ("pais", "texto"), "GeoLocation.city_name": ("cidade", "texto"), "GeoLocation.region_name": ("regiao", "texto"),
    "Operadora.organization_name": ("operadora", "texto"), "Operadora.asn": ("asn", "texto"),
}
OPERADORES = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
AGORA_MENOS = re.compile(r"now-(\d{1,5})([mhd])")


class Tradutor:
    def __init__(self):
        self.parametros = {}

    def p(self, valor, tipo="String"):
        nome = f"p{len(self.parametros)}"
        self.parametros[nome] = valor
        return f"{{{nome}:{tipo}}}"

    def campo(self, nome):
        """(expressão, tipo) do campo. Fora das colunas, o valor sai do log original: dados.a.b vira o caminho a, b."""
        if nome in COLUNAS:
            return COLUNAS[nome]
        partes = nome.split(".")
        if len(partes) > 8 or not all(partes):
            raise ConsultaInvalida(f"Campo inválido: {nome}")
        caminho = ", ".join(self.p(parte) for parte in partes)
        # O valor vem cru (com aspas quando é texto): tira as aspas para comparar como a pessoa escreveu.
        return f"replaceRegexpAll(JSONExtractRaw(dados, {caminho}), '^\"|\"$', '')", "texto"

    def _valor_de_tempo(self, valor):
        m = AGORA_MENOS.fullmatch(str(valor))
        if m:
            unidade = {"m": "MINUTE", "h": "HOUR", "d": "DAY"}[m.group(2)]
            return f"now64(3) - INTERVAL {int(m.group(1))} {unidade}"
        return f"parseDateTime64BestEffortOrNull({self.p(str(valor))}, 3)"

    def _comparar(self, expressao, tipo, operador, valor):
        if tipo == "numero":
            return f"{expressao} {operador} toFloat64OrNull({self.p(str(valor))})"
        if tipo == "tempo":
            return f"{expressao} {operador} {self._valor_de_tempo(valor)}"
        if tipo == "lista":
            return f"arrayExists(x -> x {operador} {self.p(str(valor))}, {expressao})"
        return f"{expressao} {operador} {self.p(str(valor))}"

    def onde(self, filtro):
        """O WHERE do filtro da linguagem de consulta."""
        if not isinstance(filtro, dict) or len(filtro) != 1:
            raise ConsultaInvalida("Consulta em formato inesperado.")
        forma, corpo = next(iter(filtro.items()))
        if forma == "match_all":
            return "1"
        if forma == "match_none":
            return "0"
        if forma == "bool":
            partes = [f"({self.onde(f)})" for f in corpo.get("filter", [])]
            if corpo.get("should"):
                partes.append("(" + " OR ".join(f"({self.onde(f)})" for f in corpo["should"]) + ")")
            partes += [f"NOT ({self.onde(f)})" for f in corpo.get("must_not", [])]
            return " AND ".join(partes) or "1"
        if forma == "match_phrase":
            (nome, valor), = corpo.items()
            expressao, _ = self.campo(nome)
            # Igual ao texto livre do índice antigo: sem diferença de maiúscula, e o índice de n-gramas ajuda a achar.
            return f"lower({expressao}) LIKE {self.p('%' + escapar_like(str(valor).lower()) + '%')}"
        if forma == "term":
            (nome, valor), = corpo.items()
            expressao, tipo = self.campo(nome)
            if tipo == "lista":
                return f"has({expressao}, {self.p(str(valor))})"
            return self._comparar(expressao, tipo, "=", valor)
        if forma == "wildcard":
            (nome, regra), = corpo.items()
            expressao, tipo = self.campo(nome)
            valor = str(regra["value"] if isinstance(regra, dict) else regra)
            if tipo in ("numero", "tempo"):
                expressao, tipo = f"toString({expressao})", "texto"
            if valor.strip("*") == "":
                # campo=* é "o campo existe": no armazém, campo que não veio fica vazio.
                return f"notEmpty({expressao})"
            padrao = self.p(_curinga_para_like(valor))
            if tipo == "lista":
                return f"arrayExists(x -> x ILIKE {padrao}, {expressao})"
            return f"{expressao} ILIKE {padrao}"
        if forma == "range":
            (nome, limites), = corpo.items()
            expressao, tipo = self.campo(nome)
            return " AND ".join(self._comparar(expressao, tipo, OPERADORES[op], v) for op, v in limites.items() if op in OPERADORES) or "1"
        raise ConsultaInvalida("Esta busca ainda não funciona no armazém novo.")

    def agrupar(self, nome):
        """A expressão para contar por um campo: lista conta cada item."""
        expressao, tipo = self.campo(nome)
        return f"arrayJoin({expressao})" if tipo == "lista" else expressao


def escapar_like(texto):
    return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _curinga_para_like(valor):
    return escapar_like(valor).replace("*", "%").replace("?", "_")

