"""O formato do playbook: "quando", "se" e uma pilha de blocos.

    quando: {tipo: evento, regra_id: "5712"}
    se:
      - {campo: alvo_externo, op: igual, valor: true}
    blocos:
      - {tipo: aprovacao}
      - {tipo: acao, acao: bloquear_ip, parametros: {protegidos: ["8.8.8.8"]}}
      - tipo: se
        condicao: {campo: nivel, op: minimo, valor: 12}
        entao: [{tipo: acao, acao: registrar, parametros: {texto: "grave"}}]
        senao: []
      - tipo: paralelo
        ramos: [[...], [...]]

Só código puro e determinístico: o workflow, o disparo e a simulação usam as mesmas funções,
para a simulação nunca prometer algo diferente do que a execução faz.
"""

import ipaddress

ACOES_CONHECIDAS = ("bloquear_ip", "desativar_conta", "webhook", "registrar")
ORDEM_DE_SEVERIDADE = {"alta": 1, "critica": 2}
PROFUNDIDADE_MAXIMA = 4
BLOCOS_MAXIMOS = 30
CAMPOS = {
    "alvo_externo": ("igual",),
    "nivel": ("minimo", "maximo"),
    "severidade": ("minimo",),
    "alvo": ("na_rede", "fora_da_rede"),
    "pais": ("e", "nao_e"),
}


class DefinicaoInvalida(Exception):
    """A mensagem aparece na tela, então precisa explicar o que corrigir."""


def alvo_externo(texto):
    try:
        ip = ipaddress.ip_address(texto)
    except (TypeError, ValueError):
        return False
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_global and not ip.is_multicast


def condicao_verdadeira(condicao, fato):
    """Um campo ausente nunca faz a condição passar."""
    campo, op, valor = condicao["campo"], condicao["op"], condicao["valor"]
    if campo == "alvo_externo":
        return alvo_externo(fato.get("alvo")) is bool(valor)
    if campo == "nivel":
        nivel = fato.get("nivel")
        if nivel is None:
            return False
        return nivel >= valor if op == "minimo" else nivel <= valor
    if campo == "severidade":
        return ORDEM_DE_SEVERIDADE.get(fato.get("severidade"), 0) >= ORDEM_DE_SEVERIDADE[valor]
    if campo == "pais":
        # Endereço interno ou desconhecido não tem país: não é "fora do Brasil", é sem informação.
        pais = fato.get("pais")
        if not pais:
            return False
        return pais == valor if op == "e" else pais != valor
    if campo == "alvo":
        try:
            dentro = ipaddress.ip_address(fato.get("alvo")) in ipaddress.ip_network(valor, strict=False)
        except (TypeError, ValueError):
            return False
        return dentro if op == "na_rede" else not dentro
    return False


def atende(definicao, fato):
    quando = definicao["quando"]
    if quando["tipo"] != fato["origem_tipo"]:
        return False
    if quando["tipo"] == "evento" and fato.get("regra_id") != quando["regra_id"]:
        return False
    if quando["tipo"] == "risco" and ORDEM_DE_SEVERIDADE.get(fato.get("severidade"), 0) < ORDEM_DE_SEVERIDADE[quando["severidade"]]:
        return False
    return all(condicao_verdadeira(c, fato) for c in definicao.get("se", []))


def plano(blocos, fato):
    """O que aconteceria com este fato, supondo aprovações concedidas."""
    saida = []
    for bloco in blocos:
        if bloco["tipo"] == "acao":
            saida.append(bloco)
        elif bloco["tipo"] == "aprovacao":
            saida.append(bloco)
        elif bloco["tipo"] == "se":
            saida += plano(bloco["entao"] if condicao_verdadeira(bloco["condicao"], fato) else bloco.get("senao", []), fato)
        elif bloco["tipo"] == "paralelo":
            for ramo in bloco["ramos"]:
                saida += plano(ramo, fato)
    return saida


def tem_aprovacao(blocos):
    for bloco in blocos:
        if bloco["tipo"] == "aprovacao":
            return True
        if bloco["tipo"] == "se" and (tem_aprovacao(bloco["entao"]) or tem_aprovacao(bloco.get("senao", []))):
            return True
        if bloco["tipo"] == "paralelo" and any(tem_aprovacao(r) for r in bloco["ramos"]):
            return True
    return False


def _validar_condicao(condicao):
    if not isinstance(condicao, dict) or set(condicao) != {"campo", "op", "valor"}:
        raise DefinicaoInvalida("Toda condição precisa de campo, op e valor.")
    campo, op, valor = condicao["campo"], condicao["op"], condicao["valor"]
    if campo not in CAMPOS or op not in CAMPOS[campo]:
        raise DefinicaoInvalida(f"Condição desconhecida: {campo} {op}.")
    if campo == "alvo_externo" and not isinstance(valor, bool):
        raise DefinicaoInvalida("A condição de endereço externo aceita só sim ou não.")
    if campo == "nivel" and (isinstance(valor, bool) or not isinstance(valor, int) or not 0 <= valor <= 16):
        raise DefinicaoInvalida("O nível vai de 0 a 16.")
    if campo == "pais" and (not isinstance(valor, str) or not valor.strip() or len(valor) > 100):
        raise DefinicaoInvalida("Escolha o país da condição.")
    if campo == "severidade" and valor not in ORDEM_DE_SEVERIDADE:
        raise DefinicaoInvalida("A severidade precisa ser alta ou crítica.")
    if campo == "alvo":
        try:
            ipaddress.ip_network(str(valor), strict=False)
        except ValueError:
            raise DefinicaoInvalida(f"Rede inválida: {valor}.")


def _garante_externo(condicao):
    return condicao == {"campo": "alvo_externo", "op": "igual", "valor": True}


def _validar_blocos(blocos, profundidade, externo, contagem, validar_acao, aprovado=False, de_fora=False):
    if not isinstance(blocos, list):
        raise DefinicaoInvalida("Os blocos precisam ser uma lista.")
    if profundidade > PROFUNDIDADE_MAXIMA:
        raise DefinicaoInvalida(f"No máximo {PROFUNDIDADE_MAXIMA} níveis de blocos, um dentro do outro.")
    for bloco in blocos:
        contagem[0] += 1
        if contagem[0] > BLOCOS_MAXIMOS:
            raise DefinicaoInvalida(f"No máximo {BLOCOS_MAXIMOS} blocos por playbook.")
        tipo = bloco.get("tipo") if isinstance(bloco, dict) else None
        if tipo == "aprovacao":
            aprovado = True
            continue
        if tipo == "acao":
            if bloco.get("acao") not in ACOES_CONHECIDAS or not isinstance(bloco.get("parametros", {}), dict):
                raise DefinicaoInvalida("Ação desconhecida.")
            if bloco["acao"] == "bloquear_ip" and not externo:
                raise DefinicaoInvalida("Bloquear um endereço exige, antes, a condição de endereço externo.")
            # A lista vem de terceiros: se ela vier errada ou adulterada, quem decide o bloqueio ainda é uma pessoa.
            if bloco["acao"] == "bloquear_ip" and de_fora and not aprovado:
                raise DefinicaoInvalida("Bloquear por indicador de ameaça exige, antes, um bloco de pedir aprovação.")
            # Um alerta errado derrubaria uma pessoa de verdade: aqui, sempre passa por alguém.
            if bloco["acao"] == "desativar_conta" and not aprovado:
                raise DefinicaoInvalida("Desativar uma conta exige, antes, um bloco de pedir aprovação.")
            validar_acao(bloco["acao"], bloco.get("parametros", {}))
        elif tipo == "se":
            _validar_condicao(bloco.get("condicao"))
            _validar_blocos(bloco.get("entao"), profundidade + 1, externo or _garante_externo(bloco["condicao"]), contagem, validar_acao, aprovado, de_fora)
            _validar_blocos(bloco.get("senao", []), profundidade + 1, externo, contagem, validar_acao, aprovado, de_fora)
        elif tipo == "paralelo":
            ramos = bloco.get("ramos")
            if not isinstance(ramos, list) or not 2 <= len(ramos) <= 5:
                raise DefinicaoInvalida("Um bloco paralelo precisa de 2 a 5 ramos.")
            for ramo in ramos:
                _validar_blocos(ramo, profundidade + 1, externo, contagem, validar_acao, aprovado, de_fora)
        else:
            raise DefinicaoInvalida(f"Bloco desconhecido: {tipo}.")


def validar(definicao, validar_acao=lambda acao, parametros: None):
    """Recusa na criação o que só falharia na hora do incidente."""
    if not isinstance(definicao, dict) or not set(definicao) <= {"quando", "se", "blocos"}:
        raise DefinicaoInvalida("O playbook aceita só quando, se e blocos.")
    quando = definicao.get("quando")
    if not isinstance(quando, dict):
        raise DefinicaoInvalida("Falta dizer quando o playbook dispara.")
    if quando.get("tipo") == "risco":
        if set(quando) != {"tipo", "severidade"} or quando["severidade"] not in ORDEM_DE_SEVERIDADE:
            raise DefinicaoInvalida("Escolha a severidade do risco.")
    elif quando.get("tipo") == "evento":
        regra = quando.get("regra_id")
        if set(quando) != {"tipo", "regra_id"} or not isinstance(regra, str) or not regra.isascii() or not regra.isdigit() or len(regra) > 8:
            raise DefinicaoInvalida("Informe o número da regra.")
    elif quando.get("tipo") == "indicador":
        if set(quando) != {"tipo"}:
            raise DefinicaoInvalida("Este gatilho não tem opções.")
    else:
        raise DefinicaoInvalida("O gatilho precisa ser um risco, um alerta de regra ou um indicador de ameaça.")
    condicoes = definicao.get("se", [])
    if not isinstance(condicoes, list) or len(condicoes) > 10:
        raise DefinicaoInvalida("No máximo 10 condições.")
    for condicao in condicoes:
        _validar_condicao(condicao)
    if not definicao.get("blocos"):
        raise DefinicaoInvalida("Coloque pelo menos um bloco em Então.")
    _validar_blocos(definicao["blocos"], 1, any(_garante_externo(c) for c in condicoes), [0], validar_acao, de_fora=quando["tipo"] == "indicador")
    return definicao
