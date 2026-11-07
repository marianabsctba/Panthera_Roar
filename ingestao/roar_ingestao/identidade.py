"""Fontes de identidade: o log do sistema do Okta e os relatórios de auditoria do Google Workspace.

    Okta: GET /api/v1/logs, com o token da API (cabeçalho SSWS), página por página pelo cabeçalho Link.
    Google Workspace: a conta de serviço assina um pedido (JWT) em nome de um administrador, com delegação no domínio, e
    lê os relatórios de login, administração e Drive (Admin SDK, Reports API), página por página.

Os eventos viram JSON plano, com os nomes que o Roar já entende (srcip, srcuser), e vão ao gerenciador do mesmo jeito que
a busca em API: as regras de fabricantes/regras.xml avisam login recusado, MFA negado, conta bloqueada, mudança de
privilégio e o resto. Cada fonte guarda de onde a próxima busca recomeça (fontes.posicao), e os já entregues não voltam.
Nenhum endereço vem de fora: o Okta é o domínio cadastrado, e o Google, os endereços oficiais.
"""

import base64
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode, urlsplit

from . import rede_externa

log = logging.getLogger("roar.identidade")
TIPOS = ("okta", "workspace")
MINUTOS_ENTRE_BUSCAS = 5
PAGINAS_POR_BUSCA = 20
TAMANHO_MAXIMO_DA_RESPOSTA = 20_000_000
TAMANHO_MAXIMO_DO_EVENTO = 60_000
EVENTOS_POR_LOTE = 100
# Na primeira busca, o último dia: o resto do histórico continua no próprio serviço.
PRIMEIRA_JANELA = timedelta(days=1)
VISTOS_GUARDADOS = 2000
DOMINIO_DO_OKTA = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\.(?:okta|oktapreview|okta-emea|okta-gov)\.com")
EMAIL = re.compile(r"[^@\s]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,}")
# Os relatórios do Workspace chegam com atraso: cada busca volta um pouco e descarta o que já foi entregue.
VOLTA_DO_WORKSPACE = timedelta(hours=3)
APLICACOES_DO_WORKSPACE = ("login", "admin", "drive")
ENDERECO_DO_TOKEN = "https://oauth2.googleapis.com/token"
ENDERECO_DOS_RELATORIOS = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{aplicacao}"
ESCOPO_DO_WORKSPACE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"


class FonteComProblema(Exception):
    """A mensagem aparece na tela: diz o que conferir, sem citar endereço interno."""


def _iso(momento):
    return momento.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _quando(texto):
    return datetime.fromisoformat(str(texto).replace("Z", "+00:00"))


def _pedir(chamar, metodo, endereco, cabecalhos, **kwargs):
    resposta, corpo = chamar(metodo, endereco, cabecalhos, limite_de_bytes=TAMANHO_MAXIMO_DA_RESPOSTA, **kwargs)
    if resposta.status_code in (401, 403):
        raise FonteComProblema("O serviço recusou a credencial. Confira o token ou a delegação da conta de serviço.")
    if resposta.status_code == 429:
        raise FonteComProblema("O serviço pediu para esperar (limite de chamadas). A próxima busca continua de onde parou.")
    if resposta.status_code != 200:
        raise FonteComProblema(f"O serviço respondeu {resposta.status_code}.")
    try:
        return resposta, json.loads(corpo)
    except ValueError:
        raise FonteComProblema("A resposta do serviço não é JSON.")


# ------------------------------------------------------------------ Okta

def evento_do_okta(e):
    """Um evento do log do sistema do Okta, plano e com os nomes que o Roar entende."""
    cliente = e.get("client") or {}
    lugar = cliente.get("geographicalContext") or {}
    resultado = e.get("outcome") or {}
    ator = e.get("actor") or {}
    return {
        "roar_fonte": "okta", "id": e.get("uuid"), "momento": e.get("published"), "evento": e.get("eventType"),
        "mensagem": e.get("displayMessage"), "severidade": e.get("severity"), "resultado": resultado.get("result"), "motivo": resultado.get("reason"),
        "srcuser": ator.get("alternateId"), "srcip": cliente.get("ipAddress"), "pais": lugar.get("country"), "cidade": lugar.get("city"),
        "navegador": (cliente.get("userAgent") or {}).get("rawUserAgent"),
        "alvos": [{"tipo": a.get("type"), "nome": a.get("alternateId") or a.get("displayName")} for a in (e.get("target") or []) if isinstance(a, dict)],
    }


def _proxima_do_okta(resposta, dominio):
    """O endereço da próxima página, do cabeçalho Link, desde que seja do mesmo domínio."""
    for parte in resposta.headers.get("Link", "").split(","):
        achado = re.match(r'\s*<([^>]+)>;\s*rel="next"', parte)
        if achado and urlsplit(achado.group(1)).hostname == dominio:
            return achado.group(1)
    return None


def buscar_okta(dominio, token, posicao, chamar=rede_externa.chamar, agora=None, base=None):
    """(eventos, nova posição). A posição é a hora do último evento entregue e os ids dessa hora."""
    agora = agora or datetime.now(timezone.utc)
    desde = posicao.get("desde") or _iso(agora - PRIMEIRA_JANELA)
    vistos = set(posicao.get("vistos") or [])
    endereco = f"{base or 'https://' + dominio}/api/v1/logs?since={quote(desde)}&limit=1000&sortOrder=ASCENDING"
    cabecalhos = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
    eventos, ultimo, ids_do_ultimo = [], desde, set(vistos)
    for _ in range(PAGINAS_POR_BUSCA):
        resposta, itens = _pedir(chamar, "GET", endereco, cabecalhos)
        if not isinstance(itens, list) or not itens:
            break
        for e in itens:
            if not isinstance(e, dict) or e.get("uuid") in vistos:
                continue
            eventos.append(evento_do_okta(e))
            momento = e.get("published") or ultimo
            if momento > ultimo:
                ultimo, ids_do_ultimo = momento, set()
            ids_do_ultimo.add(e.get("uuid"))
        endereco = _proxima_do_okta(resposta, urlsplit(endereco).hostname)
        if not endereco:
            break
    return eventos, {"desde": ultimo, "vistos": sorted(i for i in ids_do_ultimo if i)[-VISTOS_GUARDADOS:]}


# ------------------------------------------------------------------ Google Workspace

def _b64(dados):
    return base64.urlsafe_b64encode(dados).rstrip(b"=").decode()


def assertiva_do_google(chave, administrador, agora=None):
    """O JWT assinado pela conta de serviço, em nome do administrador (delegação no domínio)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    agora = int((agora or datetime.now(timezone.utc)).timestamp())
    cabecalho = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    corpo = _b64(json.dumps({"iss": chave["client_email"], "sub": administrador, "scope": ESCOPO_DO_WORKSPACE,
                             "aud": ENDERECO_DO_TOKEN, "iat": agora, "exp": agora + 3600}).encode())
    privada = serialization.load_pem_private_key(chave["private_key"].encode(), password=None)
    assinatura = privada.sign(f"{cabecalho}.{corpo}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{cabecalho}.{corpo}.{_b64(assinatura)}"


def eventos_do_workspace(atividade, aplicacao):
    """Uma atividade dos relatórios tem vários eventos: cada um vira um evento plano."""
    ident = atividade.get("id") or {}
    ator = atividade.get("actor") or {}
    planos = []
    for e in atividade.get("events") or []:
        if not isinstance(e, dict):
            continue
        parametros = {}
        for p in e.get("parameters") or []:
            if isinstance(p, dict) and p.get("name"):
                parametros[p["name"]] = next((p[k] for k in ("value", "boolValue", "intValue", "multiValue") if k in p), None)
        planos.append({"roar_fonte": "google_workspace", "id": f"{ident.get('uniqueQualifier')}-{e.get('name')}", "momento": ident.get("time"),
                       "aplicacao": aplicacao, "evento": e.get("name"), "tipo": e.get("type"), "srcuser": ator.get("email"),
                       "srcip": atividade.get("ipAddress"), "parametros": parametros})
    return planos


def buscar_workspace(chave, administrador, posicao, chamar=rede_externa.chamar, agora=None, base_do_token=None, base_dos_relatorios=None):
    """(eventos, nova posição). Uma posição por aplicação: a hora do mais novo e os ids recentes, para a volta não repetir."""
    agora = agora or datetime.now(timezone.utc)
    resposta, dados = _pedir(chamar, "POST", base_do_token or ENDERECO_DO_TOKEN, {"Content-Type": "application/x-www-form-urlencoded"},
                             data=urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertiva_do_google(chave, administrador, agora)}))
    acesso = dados.get("access_token") if isinstance(dados, dict) else None
    if not acesso:
        raise FonteComProblema("O Google não devolveu o acesso. Confira a delegação da conta de serviço no domínio.")
    cabecalhos = {"Authorization": f"Bearer {acesso}", "Accept": "application/json"}
    eventos, nova = [], {}
    for aplicacao in APLICACOES_DO_WORKSPACE:
        anterior = posicao.get(aplicacao) or {}
        desde = _quando(anterior["desde"]) - VOLTA_DO_WORKSPACE if anterior.get("desde") else agora - PRIMEIRA_JANELA
        vistos, mais_novo = list(anterior.get("vistos") or []), anterior.get("desde")
        ja = set(vistos)
        endereco = (base_dos_relatorios or ENDERECO_DOS_RELATORIOS).format(aplicacao=aplicacao)
        pagina = None
        for _ in range(PAGINAS_POR_BUSCA):
            parametros = {"startTime": _iso(desde), "maxResults": 1000, **({"pageToken": pagina} if pagina else {})}
            _, corpo = _pedir(chamar, "GET", f"{endereco}?{urlencode(parametros)}", cabecalhos)
            for atividade in corpo.get("items") or []:
                for e in eventos_do_workspace(atividade, aplicacao):
                    if e["id"] in ja:
                        continue
                    ja.add(e["id"])
                    vistos.append(e["id"])
                    eventos.append(e)
                    if e["momento"] and (not mais_novo or e["momento"] > mais_novo):
                        mais_novo = e["momento"]
            pagina = corpo.get("nextPageToken")
            if not pagina:
                break
        nova[aplicacao] = {"desde": mais_novo, "vistos": vistos[-VISTOS_GUARDADOS:]}
    return eventos, nova


# ------------------------------------------------------------------ o ciclo

def validar(tipo, campos):
    if tipo == "okta":
        dominio = str(campos.get("dominio", "")).strip().lower().removeprefix("https://").rstrip("/")
        if not DOMINIO_DO_OKTA.fullmatch(dominio):
            raise ValueError("Informe o domínio do Okta, como empresa.okta.com.")
        return {"dominio": dominio}
    administrador = str(campos.get("administrador", "")).strip().lower()
    if not EMAIL.fullmatch(administrador):
        raise ValueError("Informe o e-mail de um administrador do Google Workspace.")
    return {"administrador": administrador}


def validar_segredo(tipo, segredo):
    if tipo == "okta":
        if not re.fullmatch(r"[A-Za-z0-9_\-]{20,120}", segredo):
            raise ValueError("O token da API do Okta tem só letras, números, - e _.")
        return
    try:
        chave = json.loads(segredo)
    except ValueError:
        raise ValueError("A credencial do Google Workspace é o arquivo JSON da conta de serviço.")
    if not isinstance(chave, dict) or chave.get("type") != "service_account" or not chave.get("private_key") or not chave.get("client_email"):
        raise ValueError("A credencial do Google Workspace precisa ser a chave de uma conta de serviço.")


def coletar(banco, gerenciador_id, cliente, enviar=None, chamar=rede_externa.chamar):
    """As fontes de identidade vencidas deste gerenciador. Uma com problema fica com o motivo na tela e não para as outras."""
    from . import cofre, provisao

    enviar = enviar or provisao.enviar_eventos

    def transacao(sql, *args):
        with banco.con.transaction():
            banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            cursor = banco.con.execute(sql, args)
            return cursor.fetchall() if cursor.description else None

    prontas = transacao("""SELECT id, tipo, config, posicao FROM fontes WHERE gerenciador_id = %s AND tipo = ANY(%s) AND estado = 'ativa'
                           AND (proxima_busca IS NULL OR proxima_busca <= now())""", gerenciador_id, list(TIPOS))
    entregues = 0
    for fonte, tipo, config, posicao in prontas:
        transacao("UPDATE fontes SET proxima_busca = now() + make_interval(mins => %s) WHERE id = %s", MINUTOS_ENTRE_BUSCAS, fonte)
        try:
            selado = transacao("SELECT selado FROM segredos WHERE nome = %s", config["segredo"])
            if not selado:
                raise FonteComProblema("A credencial desta fonte não foi encontrada.")
            segredo = cofre.abrir(cofre.ler_privada(), cliente, config["segredo"], selado[0][0])
            if tipo == "okta":
                eventos, nova = buscar_okta(config["dominio"], segredo, posicao or {}, chamar)
            else:
                eventos, nova = buscar_workspace(json.loads(segredo), config["administrador"], posicao or {}, chamar)
            linhas = [l for l in (json.dumps(e, ensure_ascii=False, separators=(",", ":")) for e in eventos) if len(l.encode()) <= TAMANHO_MAXIMO_DO_EVENTO]
            for inicio in range(0, len(linhas), EVENTOS_POR_LOTE):
                enviar(gerenciador_id, linhas[inicio:inicio + EVENTOS_POR_LOTE])
            # A posição só anda depois da entrega: se o gerenciador recusar, a próxima busca pega de novo.
            transacao("UPDATE fontes SET posicao = %s, mensagem = NULL, ultimo_dado_em = CASE WHEN %s THEN now() ELSE ultimo_dado_em END WHERE id = %s",
                      json.dumps(nova), bool(linhas), fonte)
            entregues += len(linhas)
        except (FonteComProblema, rede_externa.DestinoRecusado) as erro:
            transacao("UPDATE fontes SET mensagem = %s WHERE id = %s", str(erro)[:300], fonte)
        except Exception as erro:
            # A exceção pode citar endereço interno: a tela recebe só o aviso.
            log.warning("fonte de identidade %s falhou: %s", fonte, type(erro).__name__)
            transacao("UPDATE fontes SET mensagem = %s WHERE id = %s", "Não foi possível falar com o serviço. A próxima busca tenta de novo.", fonte)
    return entregues

