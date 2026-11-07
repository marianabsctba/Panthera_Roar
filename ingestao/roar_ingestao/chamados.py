"""Chamados em ferramentas de ITSM: ServiceNow, Jira Service Management e GLPI.

A tela pede o chamado de um caso (tabela chamados, estado pedido). Este módulo roda no ciclo das fontes, que é quem abre
o cofre: cria o chamado na ferramenta, guarda o número e o endereço, e escreve no histórico do caso. Depois, de tempos em
tempos, confere o andamento; quando a ferramenta resolve ou fecha, o chamado vira resolvido e o caso ganha uma nota. O
caso não é encerrado sozinho: quem decide é o analista.

    ServiceNow: Table API (incident), com usuário e senha.
    Jira Service Management: REST API v3 (issue), com e-mail e token da API.
    GLPI: API REST (Ticket), com o token do aplicativo e o token do usuário, os dois no cofre (JSON).

O chamado leva o título, a severidade, o prazo e o número do caso, e um link de volta para o Roar. Nada dos alertas vai
junto: o que o analista quiser contar, ele escreve na ferramenta.
"""

import base64
import json
import logging
import os
import re
from urllib.parse import urlsplit

from . import rede_externa

log = logging.getLogger("roar.chamados")
TIPOS = ("servicenow", "jira", "glpi")
NOMES = {"servicenow": "ServiceNow", "jira": "Jira", "glpi": "GLPI"}
MINUTOS_ENTRE_CONFERENCIAS = 5
TENTATIVAS = 3
TAMANHO_MAXIMO_DA_RESPOSTA = 2_000_000
INSTANCIA_DO_SERVICENOW = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\.service-now\.com")
SITE_DO_JIRA = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\.atlassian\.net")
PROJETO_DO_JIRA = re.compile(r"[A-Z][A-Z0-9_]{1,19}")
EMAIL = re.compile(r"[^@\s]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,}")
USUARIO = re.compile(r"[A-Za-z0-9._@-]{1,100}")
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{8,400}")
# Severidade do caso para o que cada ferramenta entende.
IMPACTO_E_URGENCIA = {"critica": (1, 1), "alta": (2, 1), "media": (2, 2), "baixa": (3, 3)}
URGENCIA_DO_GLPI = {"critica": 5, "alta": 4, "media": 3, "baixa": 2}
# ServiceNow: 6 resolvido, 7 fechado, 8 cancelado. GLPI: 5 solucionado, 6 fechado.
RESOLVIDOS_DO_SERVICENOW = {"6": "Resolvido", "7": "Fechado", "8": "Cancelado"}
SITUACOES_DO_SERVICENOW = {"1": "Novo", "2": "Em andamento", "3": "Em espera", **RESOLVIDOS_DO_SERVICENOW}
SITUACOES_DO_GLPI = {1: "Novo", 2: "Em atendimento (atribuído)", 3: "Em atendimento (planejado)", 4: "Pendente", 5: "Solucionado", 6: "Fechado"}


class ChamadoComProblema(Exception):
    """A mensagem aparece na tela do caso: diz o que conferir, sem citar endereço interno."""


def _basico(usuario, senha):
    return "Basic " + base64.b64encode(f"{usuario}:{senha}".encode()).decode()


def _pedir(chamar, metodo, endereco, cabecalhos, **kwargs):
    resposta, corpo = chamar(metodo, endereco, {"Accept": "application/json", **cabecalhos}, limite_de_bytes=TAMANHO_MAXIMO_DA_RESPOSTA, **kwargs)
    if resposta.status_code in (401, 403):
        raise ChamadoComProblema("A ferramenta recusou a credencial. Confira o usuário, o token e a permissão de criar chamados.")
    if resposta.status_code == 404:
        raise ChamadoComProblema("A ferramenta não achou o endereço, o projeto ou o chamado. Confira o cadastro.")
    if resposta.status_code == 429:
        raise ChamadoComProblema("A ferramenta pediu para esperar (limite de chamadas). O Roar tenta de novo.")
    if resposta.status_code >= 300:
        raise ChamadoComProblema(f"A ferramenta respondeu {resposta.status_code}.")
    try:
        return json.loads(corpo) if corpo else {}
    except ValueError:
        raise ChamadoComProblema("A resposta da ferramenta não é JSON.")


def _texto(caso, link):
    return (f"Caso nº {caso['id']} do Panthera Roar, severidade {caso['severidade']}, prazo {caso['prazo']:%d/%m/%Y %H:%M} (UTC).\n"
            f"Os alertas, as provas e o histórico estão no caso: {link}")


# ------------------------------------------------------------------ cadastro

def validar(tipo, campos):
    """A configuração que fica visível na tela. A credencial vai à parte, para o cofre."""
    def campo(nome, padrao, mensagem, transformar=str.strip):
        valor = transformar(str(campos.get(nome, "")))
        if not padrao.fullmatch(valor):
            raise ValueError(mensagem)
        return valor

    def endereco_sem_esquema(valor):
        return valor.strip().lower().removeprefix("https://").rstrip("/")

    if tipo == "servicenow":
        return {"instancia": campo("instancia", INSTANCIA_DO_SERVICENOW, "Informe a instância, como empresa.service-now.com.", endereco_sem_esquema),
                "usuario": campo("usuario", USUARIO, "Informe o usuário de integração do ServiceNow.")}
    if tipo == "jira":
        return {"site": campo("site", SITE_DO_JIRA, "Informe o site, como empresa.atlassian.net.", endereco_sem_esquema),
                "email": campo("email", EMAIL, "Informe o e-mail da conta que cria os chamados.", lambda v: v.strip().lower()),
                "projeto": campo("projeto", PROJETO_DO_JIRA, "Informe a chave do projeto, como SOC.", lambda v: v.strip().upper()),
                "tipo_de_item": str(campos.get("tipo_de_item") or "Task").strip()[:60]}
    if tipo == "glpi":
        endereco = str(campos.get("endereco", "")).strip().rstrip("/")
        partes = urlsplit(endereco)
        if partes.scheme != "https" or not partes.hostname or not endereco.endswith("/apirest.php"):
            raise ValueError("Informe o endereço da API do GLPI, em https e terminando em /apirest.php.")
        return {"endereco": endereco}
    raise ValueError("Tipo de ferramenta desconhecido.")


def validar_segredo(tipo, segredo):
    if tipo == "glpi":
        _tokens_do_glpi(segredo)
        return
    if "\n" in segredo or "\r" in segredo or not segredo.strip():
        raise ValueError("A credencial não pode ter quebra de linha nem ficar vazia.")


def _tokens_do_glpi(segredo):
    """(token do aplicativo, token do usuário): os dois vêm juntos, em JSON, da tela."""
    try:
        dados = json.loads(segredo)
    except ValueError:
        raise ValueError("A credencial do GLPI são o token do aplicativo e o do usuário.")
    tokens = (dados.get("app_token"), dados.get("usuario")) if isinstance(dados, dict) else (None, None)
    if not all(isinstance(t, str) and TOKEN.fullmatch(t) for t in tokens):
        raise ValueError("Os tokens do GLPI têm só letras e números.")
    return tokens


# ------------------------------------------------------------------ cada ferramenta

def criar(tipo, config, segredo, caso, link, chamar=rede_externa.chamar):
    """(id na API, número que a pessoa vê, endereço do chamado)."""
    titulo = f"[Roar] {caso['titulo']}"[:160]
    descricao = _texto(caso, link)
    if tipo == "servicenow":
        base = f"https://{config['instancia']}"
        impacto, urgencia = IMPACTO_E_URGENCIA[caso["severidade"]]
        dados = _pedir(chamar, "POST", f"{base}/api/now/table/incident?sysparm_fields=sys_id,number", {"Authorization": _basico(config["usuario"], segredo)},
                       json={"short_description": titulo, "description": descricao, "impact": impacto, "urgency": urgencia, "category": "security"})
        r = dados.get("result") or {}
        if not r.get("sys_id"):
            raise ChamadoComProblema("O ServiceNow não devolveu o chamado criado.")
        return r["sys_id"], r.get("number") or r["sys_id"], f"{base}/nav_to.do?uri=incident.do?sys_id={r['sys_id']}"
    if tipo == "jira":
        base = f"https://{config['site']}"
        documento = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": linha}]}
                                                               for linha in descricao.split("\n")]}
        dados = _pedir(chamar, "POST", f"{base}/rest/api/3/issue", {"Authorization": _basico(config["email"], segredo)},
                       json={"fields": {"project": {"key": config["projeto"]}, "summary": titulo, "description": documento,
                                        "issuetype": {"name": config.get("tipo_de_item") or "Task"},
                                        "labels": ["panthera-roar", f"severidade-{caso['severidade']}"]}})
        if not dados.get("key"):
            raise ChamadoComProblema("O Jira não devolveu o chamado criado.")
        return dados["key"], dados["key"], f"{base}/browse/{dados['key']}"
    if tipo == "glpi":
        base = config["endereco"]
        aplicativo, sessao = _sessao_do_glpi(base, segredo, chamar)
        try:
            dados = _pedir(chamar, "POST", f"{base}/Ticket", {"App-Token": aplicativo, "Session-Token": sessao},
                           json={"input": {"name": titulo, "content": descricao, "urgency": URGENCIA_DO_GLPI[caso["severidade"]], "type": 1}})
        finally:
            _encerrar_sessao_do_glpi(base, aplicativo, sessao, chamar)
        if not dados.get("id"):
            raise ChamadoComProblema("O GLPI não devolveu o chamado criado.")
        return str(dados["id"]), str(dados["id"]), f"{base.removesuffix('/apirest.php')}/front/ticket.form.php?id={dados['id']}"
    raise ChamadoComProblema("Tipo de ferramenta desconhecido.")


def consultar(tipo, config, segredo, id_externo, chamar=rede_externa.chamar):
    """(situação como a ferramenta chama, se já está resolvido)."""
    if tipo == "servicenow":
        dados = _pedir(chamar, "GET", f"https://{config['instancia']}/api/now/table/incident/{id_externo}?sysparm_fields=state",
                       {"Authorization": _basico(config["usuario"], segredo)})
        estado = str((dados.get("result") or {}).get("state", ""))
        return SITUACOES_DO_SERVICENOW.get(estado, estado or "desconhecida"), estado in RESOLVIDOS_DO_SERVICENOW
    if tipo == "jira":
        dados = _pedir(chamar, "GET", f"https://{config['site']}/rest/api/3/issue/{id_externo}?fields=status", {"Authorization": _basico(config["email"], segredo)})
        situacao = ((dados.get("fields") or {}).get("status") or {})
        return situacao.get("name") or "desconhecida", (situacao.get("statusCategory") or {}).get("key") == "done"
    if tipo == "glpi":
        aplicativo, sessao = _sessao_do_glpi(config["endereco"], segredo, chamar)
        try:
            dados = _pedir(chamar, "GET", f"{config['endereco']}/Ticket/{id_externo}", {"App-Token": aplicativo, "Session-Token": sessao})
        finally:
            _encerrar_sessao_do_glpi(config["endereco"], aplicativo, sessao, chamar)
        estado = dados.get("status")
        return SITUACOES_DO_GLPI.get(estado, str(estado)), estado in (5, 6)
    raise ChamadoComProblema("Tipo de ferramenta desconhecido.")


def _sessao_do_glpi(base, segredo, chamar):
    """(token do aplicativo, sessão aberta)."""
    try:
        aplicativo, usuario = _tokens_do_glpi(segredo)
    except ValueError as erro:
        raise ChamadoComProblema(str(erro))
    dados = _pedir(chamar, "GET", f"{base}/initSession", {"App-Token": aplicativo, "Authorization": f"user_token {usuario}"})
    if not dados.get("session_token"):
        raise ChamadoComProblema("O GLPI não abriu a sessão. Confira o token do usuário e o do aplicativo.")
    return aplicativo, dados["session_token"]


def _encerrar_sessao_do_glpi(base, aplicativo, sessao, chamar):
    try:
        chamar("GET", f"{base}/killSession", {"App-Token": aplicativo, "Session-Token": sessao})
    except Exception:
        # A sessão vence sozinha no GLPI; não vale perder o chamado por isso.
        pass


# ------------------------------------------------------------------ o ciclo

def processar(banco, gerenciador_id, cliente, chamar=rede_externa.chamar, endereco_do_roar=None):
    """Os chamados pedidos deste gerenciador são criados; os abertos, conferidos. Um com problema não para os outros."""
    from . import cofre

    endereco_do_roar = endereco_do_roar or os.getenv("ROAR_ENDERECO_PUBLICO", "localhost")
    link = f"https://{endereco_do_roar}/casos"

    def transacao(sql, *args):
        with banco.con.transaction():
            banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            cursor = banco.con.execute(sql, args)
            return cursor.fetchall() if cursor.description else None

    def nota(caso_id, texto):
        transacao("INSERT INTO casos_notas (cliente_id, caso_id, autor_nome, automatica, texto) VALUES (%s, %s, 'Panthera Roar', true, %s)",
                  cliente, caso_id, texto[:4000])

    linhas = transacao(
        f"""SELECT ch.id, ch.caso_id, ch.estado, ch.id_externo, ch.numero, ch.endereco, ch.tentativas, f.tipo, f.config,
                   c.titulo, c.severidade, c.prazo
            FROM chamados ch JOIN fontes f ON f.id = ch.fonte_id JOIN casos c ON c.id = ch.caso_id
            WHERE f.gerenciador_id = %s AND f.estado = 'ativa' AND (ch.estado = 'pedido'
               OR (ch.estado = 'aberto' AND (ch.conferido_em IS NULL OR ch.conferido_em < now() - make_interval(mins => {MINUTOS_ENTRE_CONFERENCIAS}))))""",
        gerenciador_id)
    feitos = 0
    for (chamado, caso_id, estado, id_externo, numero, endereco, tentativas, tipo, config, titulo, severidade, prazo) in linhas or []:
        nome = NOMES[tipo]
        try:
            selado = transacao("SELECT selado FROM segredos WHERE nome = %s", config["segredo"])
            if not selado:
                raise ChamadoComProblema("A credencial desta ferramenta não foi encontrada.")
            segredo = cofre.abrir(cofre.ler_privada(), cliente, config["segredo"], selado[0][0])
            if estado == "pedido":
                id_externo, numero, endereco = criar(tipo, config, segredo, {"id": caso_id, "titulo": titulo, "severidade": severidade, "prazo": prazo}, link, chamar)
                transacao("""UPDATE chamados SET estado = 'aberto', id_externo = %s, numero = %s, endereco = %s, aberto_em = now(), conferido_em = now(),
                                                 mensagem = NULL, situacao_externa = 'Novo' WHERE id = %s""", id_externo, numero, endereco, chamado)
                nota(caso_id, f"Chamado {numero} aberto no {nome}: {endereco}")
            else:
                situacao, resolvido = consultar(tipo, config, segredo, id_externo, chamar)
                if resolvido:
                    transacao("""UPDATE chamados SET estado = 'resolvido', situacao_externa = %s, resolvido_em = now(), conferido_em = now(), mensagem = NULL
                                 WHERE id = %s""", situacao, chamado)
                    nota(caso_id, f"O chamado {numero} ficou {situacao.lower()} no {nome}. Confira se o caso também pode ser encerrado.")
                else:
                    transacao("UPDATE chamados SET situacao_externa = %s, conferido_em = now(), mensagem = NULL WHERE id = %s", situacao, chamado)
            feitos += 1
        except (ChamadoComProblema, rede_externa.DestinoRecusado) as erro:
            _registrar_falha(transacao, chamado, estado, tentativas, str(erro), nota, caso_id, nome)
        except Exception as erro:
            # A exceção pode citar endereço interno: a tela recebe só o aviso.
            log.warning("chamado %s falhou: %s", chamado, type(erro).__name__)
            _registrar_falha(transacao, chamado, estado, tentativas, f"Não foi possível falar com o {nome}. O Roar tenta de novo.", nota, caso_id, nome)
    return feitos


def _registrar_falha(transacao, chamado, estado, tentativas, mensagem, nota, caso_id, nome):
    if estado == "pedido" and tentativas + 1 >= TENTATIVAS:
        transacao("UPDATE chamados SET estado = 'falhou', tentativas = tentativas + 1, mensagem = %s WHERE id = %s", mensagem[:300], chamado)
        nota(caso_id, f"Não foi possível abrir o chamado no {nome}: {mensagem}")
    else:
        transacao("UPDATE chamados SET tentativas = tentativas + %s, mensagem = %s, conferido_em = now() WHERE id = %s",
                  1 if estado == "pedido" else 0, mensagem[:300], chamado)
