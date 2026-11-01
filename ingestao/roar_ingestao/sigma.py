"""Converte regras Sigma em regras do Wazuh, sem alterar as que já vêm com ele.

Regra do Wazuh é um E de campos. Sigma tem E, OU e NÃO em qualquer profundidade, então a
condição vira forma normal disjuntiva: cada ramo do OU é uma regra. O que não dá para
expressar com fidelidade é recusado com o motivo, nunca convertido pela metade.
"""

import re
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.types import SigmaNumber, SigmaRegularExpression, SigmaString, SpecialChars

ID_INICIAL = 200000
LIMITE_DE_RAMOS = 16
NIVEIS = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 15}
# Grupo de regras do Wazuh que precisa ter casado antes, por origem do log.
ORIGENS = {
    ("windows", "process_creation", None): "sysmon_event1",
    ("windows", None, "security"): "windows",
    ("linux", None, "syslog"): "syslog",
    ("linux", None, "auth"): "syslog",
    ("linux", None, "sshd"): "sshd",
    ("linux", None, "vsftpd"): "syslog",
    ("linux", None, None): "syslog",
}
CAMPOS_DE_SISTEMA = {
    "EventID": "win.system.eventID",
    "Provider_Name": "win.system.providerName",
    "Channel": "win.system.channel",
    "Computer": "win.system.computer",
}


class NaoConvertivel(Exception):
    pass


@dataclass
class Resultado:
    titulo: str
    xml: list = field(default_factory=list)
    motivo: str | None = None


@dataclass(frozen=True)
class Literal:
    campo: str | None  # None é palavra-chave, que procura no log inteiro
    padrao: str
    negado: bool = False


def _padrao_de_texto(valor):
    partes = []
    for parte in valor.s:
        if parte == SpecialChars.WILDCARD_MULTI:
            partes.append(".*")
        elif parte == SpecialChars.WILDCARD_SINGLE:
            partes.append(".")
        elif isinstance(parte, str):
            partes.append(re.escape(parte))
        else:
            raise NaoConvertivel("marcador especial no valor")
    return "".join(partes)


def _padrao(valor, inteiro=True):
    """Sigma compara o valor inteiro, sem diferenciar maiúsculas."""
    if isinstance(valor, SigmaString):
        corpo = _padrao_de_texto(valor)
    elif isinstance(valor, SigmaNumber):
        corpo = re.escape(str(valor.number))
    elif isinstance(valor, SigmaRegularExpression):
        return valor.regexp.original if hasattr(valor.regexp, "original") else str(valor.regexp)
    else:
        raise NaoConvertivel(f"tipo de valor {type(valor).__name__}")
    return f"^{corpo}$" if inteiro else corpo


def _campo(nome, produto):
    if nome in CAMPOS_DE_SISTEMA and produto == "windows":
        return CAMPOS_DE_SISTEMA[nome]
    if produto == "windows":
        return f"win.eventdata.{nome[0].lower()}{nome[1:]}"
    raise NaoConvertivel(f"campo {nome} sem correspondência no Wazuh para {produto}")


def _forma_normal(no, produto, negado=False):
    """Devolve uma lista de ramos; cada ramo é uma lista de literais."""
    if isinstance(no, ConditionNOT):
        return _forma_normal(no.args[0], produto, not negado)
    if isinstance(no, (ConditionAND, ConditionOR)):
        # De Morgan: negar um E vira um OU de negações, e vice-versa.
        e_logico = isinstance(no, ConditionAND) != negado
        filhos = [_forma_normal(a, produto, negado) for a in no.args]
        if not e_logico:
            return [ramo for filho in filhos for ramo in filho]
        ramos = [[]]
        for filho in filhos:
            ramos = [r + s for r in ramos for s in filho]
            if len(ramos) > 4096:
                raise NaoConvertivel("condição gera ramos demais")
        return ramos
    if isinstance(no, ConditionFieldEqualsValueExpression):
        return [[Literal(_campo(no.field, produto), _padrao(no.value), negado)]]
    if isinstance(no, ConditionValueExpression):
        return [[Literal(None, _padrao(no.value, inteiro=False), negado)]]
    raise NaoConvertivel(f"condição {type(no).__name__}")


def _juntar_ramos(ramos):
    """Ramos iguais a menos de um campo viram uma alternância, o que economiza muitas regras."""
    grupos = {}
    for ramo in ramos:
        fixos = frozenset(ramo)
        grupos.setdefault(fixos, ramo)
    ramos = list(grupos.values())
    mudou = True
    while mudou and len(ramos) > 1:
        mudou = False
        por_chave = {}
        for ramo in ramos:
            for literal in ramo:
                if literal.negado:
                    continue
                resto = frozenset(x for x in ramo if x is not literal)
                por_chave.setdefault((resto, literal.campo), []).append((ramo, literal))
        for (resto, campo), itens in por_chave.items():
            if len(itens) < 2 or len({id(r) for r, _ in itens}) < 2:
                continue
            padrao = "(?:" + "|".join(sorted({l.padrao for _, l in itens})) + ")"
            usados = {id(r) for r, _ in itens}
            ramos = [r for r in ramos if id(r) not in usados] + [list(resto) + [Literal(campo, padrao)]]
            mudou = True
            break
    return ramos


def _juntar_campos(ramo):
    """Uma regra não repete campo: positivos viram lookahead, e negativos vêm junto."""
    por_campo = {}
    for literal in ramo:
        por_campo.setdefault(literal.campo, []).append(literal)
    linhas = []
    for campo, literais in por_campo.items():
        positivos = [l.padrao for l in literais if not l.negado]
        negativos = [l.padrao for l in literais if l.negado]
        if len(positivos) == 1 and not negativos:
            linhas.append((campo, f"(?is){positivos[0]}", False))
        elif not positivos:
            padrao = negativos[0] if len(negativos) == 1 else "(?:" + "|".join(negativos) + ")"
            linhas.append((campo, f"(?is){padrao}", True))
        else:
            antes = "".join(f"(?=.*(?:{p}))" for p in positivos) + "".join(f"(?!.*(?:{p}))" for p in negativos)
            linhas.append((campo, f"(?is){antes}", False))
    return linhas


def _sem_marcacao(padrao):
    """O leitor de XML do Wazuh é restrito: o regex aceita esses caracteres como código."""
    return padrao.replace("&", r"\x26").replace("<", r"\x3c").replace(">", r"\x3e")


def _xml_da_regra(identificador, nivel, grupo_pai, linhas, titulo, sigma_id, tecnicas):
    corpo = [f'  <rule id="{identificador}" level="{nivel}">', f"    <if_group>{grupo_pai}</if_group>"]
    for campo, padrao, negado in linhas:
        atributo = ' negate="yes"' if negado else ""
        if campo is None:
            corpo.append(f'    <match type="pcre2"{atributo}>{_sem_marcacao(padrao)}</match>')
        else:
            corpo.append(f'    <field name="{escape(campo)}" type="pcre2"{atributo}>{_sem_marcacao(padrao)}</field>')
    corpo.append(f"    <description>{re.sub(r'[&<>]', ' ', titulo[:200])}</description>")
    if sigma_id:
        corpo.append(f'    <info type="text">sigma:{escape(str(sigma_id))}</info>')
    if tecnicas:
        corpo.append("    <mitre>" + "".join(f"<id>{escape(t)}</id>" for t in tecnicas) + "</mitre>")
    corpo.append("    <group>sigma,</group>")
    corpo.append("  </rule>")
    return "\n".join(corpo)


def converter_regra(regra, proximo_id):
    """Devolve (Resultado, próximo id livre)."""
    resultado = Resultado(regra.title or "Sem título")
    try:
        origem = regra.logsource
        chave = (origem.product, origem.category, origem.service)
        if chave not in ORIGENS:
            raise NaoConvertivel(f"origem de log {origem.product}/{origem.category}/{origem.service}")
        if len(regra.detection.parsed_condition) != 1:
            raise NaoConvertivel("mais de uma condição")
        ramos = _forma_normal(regra.detection.parsed_condition[0].parsed, origem.product)
        ramos = _juntar_ramos(ramos)
        if len(ramos) > LIMITE_DE_RAMOS:
            raise NaoConvertivel(f"{len(ramos)} ramos na condição, limite de {LIMITE_DE_RAMOS}")
        nivel = NIVEIS.get(str(regra.level.name).lower() if regra.level else "medium", 8)
        tecnicas = sorted({f"{t.name}".upper() for t in regra.tags if t.namespace == "attack" and re.fullmatch(r"t\d{4}(\.\d{3})?", t.name)})
        for ramo in ramos:
            resultado.xml.append(_xml_da_regra(proximo_id, nivel, ORIGENS[chave], _juntar_campos(ramo),
                                               resultado.titulo, regra.id, tecnicas))
            proximo_id += 1
    except (NaoConvertivel, SigmaError, AttributeError, TypeError) as erro:
        resultado.xml = []
        resultado.motivo = str(erro) or type(erro).__name__
    return resultado, proximo_id


def converter_textos(textos, id_inicial=ID_INICIAL):
    """Recebe o YAML de cada regra. Um arquivo ruim não derruba os outros."""
    resultados, proximo = [], id_inicial
    for texto in textos:
        try:
            regras = SigmaCollection.from_yaml(texto, collect_errors=True).rules
        except Exception as erro:
            resultados.append(Resultado("Arquivo inválido", motivo=f"YAML inválido: {erro}"[:200]))
            continue
        for regra in regras:
            if regra.errors:
                resultados.append(Resultado(regra.title or "Regra inválida", motivo=str(regra.errors[0])[:200]))
                continue
            resultado, proximo = converter_regra(regra, proximo)
            resultados.append(resultado)
    return resultados


CAMPOS_GUIADOS = {
    "windows_processo": {"Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "OriginalFileName", "CurrentDirectory"},
    "windows_seguranca": {"EventID", "TargetUserName", "SubjectUserName", "IpAddress", "LogonType", "WorkstationName", "ServiceName"},
    "linux_syslog": set(),
}
ORIGENS_GUIADAS = {
    "windows_processo": {"product": "windows", "category": "process_creation"},
    "windows_seguranca": {"product": "windows", "service": "security"},
    "linux_syslog": {"product": "linux", "service": "syslog"},
}
OPERADORES = {"igual": "", "contem": "|contains", "comeca": "|startswith", "termina": "|endswith"}


def sigma_da_regra_guiada(titulo, origem, nivel, condicoes, tecnicas=()):
    """Monta um Sigma a partir do formulário: a regra guiada passa pelo mesmo conversor das outras."""
    if origem not in ORIGENS_GUIADAS:
        raise NaoConvertivel("origem de log desconhecida")
    if nivel not in NIVEIS:
        raise NaoConvertivel("severidade desconhecida")
    if not condicoes or len(condicoes) > 10:
        raise NaoConvertivel("informe de 1 a 10 condições")
    selecao, palavras = {}, []
    for c in condicoes:
        valor = str(c.get("valor", "")).strip()
        if not valor:
            raise NaoConvertivel("condição sem valor")
        if origem == "linux_syslog":
            palavras.append(valor)
            continue
        campo, operador = c.get("campo"), c.get("operador", "igual")
        if campo not in CAMPOS_GUIADOS[origem]:
            raise NaoConvertivel(f"campo {campo} não disponível para esta origem")
        if operador not in OPERADORES:
            raise NaoConvertivel(f"operador {operador} desconhecido")
        chave = f"{campo}{OPERADORES[operador]}"
        if chave in selecao:
            raise NaoConvertivel(f"condição repetida em {campo}")
        selecao[chave] = valor
    regra = {
        "title": str(titulo).strip()[:200] or "Regra sem título",
        "status": "experimental",
        "logsource": ORIGENS_GUIADAS[origem],
        "detection": {"selecao": palavras if palavras else selecao, "condition": "selecao"},
        "level": nivel,
    }
    marcas = [f"attack.{t.lower()}" for t in tecnicas if re.fullmatch(r"T\d{4}(\.\d{3})?", t)]
    if marcas:
        regra["tags"] = marcas
    return yaml.safe_dump(regra, allow_unicode=True, sort_keys=False)


def arquivo_de_regras(resultados):
    regras = "\n".join(x for r in resultados for x in r.xml)
    return f'<group name="sigma,">\n{regras}\n</group>\n'
