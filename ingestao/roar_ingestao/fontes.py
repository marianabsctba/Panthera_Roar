"""Aplica no gerenciador as fontes de dados pedidas na tela.

    python -m roar_ingestao.fontes

O dono de um log de syslog é o gerenciador cuja porta recebeu o log, nunca o conteúdo da mensagem.
"""

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from pathlib import Path
from xml.sax.saxutils import escape

import requests

from . import rede_externa

log = logging.getLogger("roar.fontes")
EVENTOS_POR_LOTE = 100
LOTES_POR_CICLO = 5
INTERVALO_MINIMO = 5
TAMANHO_MAXIMO_DA_RESPOSTA = 5_000_000
TAMANHO_MAXIMO_DO_ITEM = 60_000
MAXIMO_DE_VISTOS = 5000
CAMINHO_NO_JSON = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){0,9}")
NOME_DE_CABECALHO = re.compile(r"[A-Za-z0-9-]{1,64}")
# Quem controla o Host ou a conexão poderia desviar a chamada do endereço conferido.
CABECALHOS_PROIBIDOS = ("host", "connection", "transfer-encoding", "content-length", "upgrade", "proxy-authorization")
PASTA_GERENCIADORES = Path("/opt/panthera-roar/gerenciadores")
PROTOCOLOS = ("tcp", "udp")
TIPOS_DE_AVISO = ("slack", "pagerduty", "virustotal", "maltiverse")
TIPOS_DE_NUVEM = ("github", "office365", "msgraph", "aws", "azure", "gcp", *TIPOS_DE_AVISO)
NIVEL_PADRAO_DO_AVISO = 10
PASTA_DE_CREDENCIAIS = "/var/ossec/etc/roar-credenciais"
CREDENCIAIS_DA_AWS = "/root/.aws/credentials"
BUCKET_DA_AWS = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
CHAVE_DE_ACESSO_DA_AWS = re.compile(r"[A-Z0-9]{16,128}")
DOMINIO_DO_AZURE = re.compile(r"[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,5}")
PROJETO_DO_GOOGLE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
ASSINATURA_DO_GOOGLE = re.compile(r"[A-Za-z][A-Za-z0-9._~+%-]{2,254}")
TOKEN_SIMPLES = re.compile(r"[A-Za-z0-9._+=/-]{8,512}")
RECURSOS_DO_GRAPH = (("security", "alerts_v2"), ("security", "incidents"), ("auditLogs", "signIns"), ("auditLogs", "directoryAudits"))
ORGANIZACAO_DO_GITHUB = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
IDENTIFICADOR_MICROSOFT = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
ASSINATURAS_DO_OFFICE365 = ("Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.General", "Audit.SharePoint", "DLP.All")
ORIGENS_MAXIMAS = 200
# Mais aberto que isso, qualquer um na internet escreveria nos logs do cliente.
MENOR_PREFIXO_IPV4 = 8


class FonteInvalida(Exception):
    """A mensagem aparece na tela, então precisa explicar o que corrigir."""


def validar_syslog(protocolo, origens):
    """Devolve as redes normalizadas: só isso chega ao XML, nunca o texto que a pessoa digitou."""
    if protocolo not in PROTOCOLOS:
        raise FonteInvalida("O protocolo precisa ser TCP ou UDP.")
    if not isinstance(origens, list) or not 1 <= len(origens) <= ORIGENS_MAXIMAS:
        raise FonteInvalida(f"Informe de 1 a {ORIGENS_MAXIMAS} endereços ou redes de origem.")
    redes = []
    for origem in origens:
        try:
            rede = ipaddress.ip_network(str(origem).strip(), strict=False)
        except ValueError:
            raise FonteInvalida(f"Endereço ou rede inválida: {str(origem)[:60]}")
        if rede.version != 4:
            raise FonteInvalida("Por enquanto, o syslog aceita só endereços IPv4.")
        if rede.prefixlen < MENOR_PREFIXO_IPV4:
            raise FonteInvalida(f"A rede {rede} é aberta demais: use /{MENOR_PREFIXO_IPV4} ou menor.")
        redes.append(str(rede))
    return sorted(set(redes))


def _campo(campos, nome, padrao, mensagem, minusculo=False):
    valor = str(campos.get(nome, "")).strip()
    if not padrao.fullmatch(valor):
        raise FonteInvalida(mensagem)
    return valor.lower() if minusculo else valor


def _guid(campos, nome, rotulo):
    return _campo(campos, nome, IDENTIFICADOR_MICROSOFT, f"O identificador do {rotulo} precisa ter o formato de um GUID.", minusculo=True)


def validar_nuvem(tipo, campos):
    """Devolve só os campos conhecidos, já conferidos. Nenhum texto livre chega ao XML sem escape."""
    if tipo == "github":
        return {"organizacao": _campo(campos, "organizacao", ORGANIZACAO_DO_GITHUB, "Informe o nome da organização no GitHub.")}
    if tipo in ("office365", "msgraph"):
        return {"locatario": _guid(campos, "locatario", "locatário (tenant)"), "aplicativo": _guid(campos, "aplicativo", "aplicativo (client)")}
    if tipo == "aws":
        return {"bucket": _campo(campos, "bucket", BUCKET_DA_AWS, "Informe o nome do bucket com os registros do CloudTrail."),
                "chave_de_acesso": _campo(campos, "chave_de_acesso", CHAVE_DE_ACESSO_DA_AWS, "A chave de acesso da AWS tem só letras maiúsculas e números.")}
    if tipo == "azure":
        return {"dominio": _campo(campos, "dominio", DOMINIO_DO_AZURE, "Informe o domínio do locatário, como empresa.onmicrosoft.com."),
                "aplicativo": _guid(campos, "aplicativo", "aplicativo (client)"), "workspace": _guid(campos, "workspace", "workspace")}
    if tipo == "gcp":
        return {"projeto": _campo(campos, "projeto", PROJETO_DO_GOOGLE, "Informe o identificador do projeto no Google Cloud."),
                "assinatura": _campo(campos, "assinatura", ASSINATURA_DO_GOOGLE, "Informe o nome da assinatura do Pub/Sub.")}
    if tipo in TIPOS_DE_AVISO:
        try:
            nivel = int(campos.get("nivel", NIVEL_PADRAO_DO_AVISO))
        except (TypeError, ValueError):
            raise FonteInvalida("O nível vai de 0 a 16.")
        if not 0 <= nivel <= 16:
            raise FonteInvalida("O nível vai de 0 a 16.")
        return {"nivel": nivel}
    raise FonteInvalida("Tipo de fonte desconhecido.")


def validar_segredo(tipo, segredo):
    """O que dá para conferir sem chamar o serviço. Uma URL de aviso errada mandaria alertas para outro lugar."""
    if tipo == "gcp":
        try:
            dados = json.loads(segredo)
        except ValueError:
            raise FonteInvalida("A credencial do Google Cloud é o arquivo JSON da conta de serviço.")
        if not isinstance(dados, dict) or dados.get("type") != "service_account":
            raise FonteInvalida("A credencial do Google Cloud precisa ser de uma conta de serviço.")
    elif tipo == "slack":
        if not segredo.startswith("https://hooks.slack.com/") and os.getenv("ROAR_DESTINO_INTERNO") != "1":
            raise FonteInvalida("O endereço do Slack começa com https://hooks.slack.com/.")
    elif tipo in ("pagerduty", "virustotal", "maltiverse") and not TOKEN_SIMPLES.fullmatch(segredo):
        raise FonteInvalida("A chave tem caracteres inesperados.")
    # Estes viram linhas de um arquivo: uma quebra de linha criaria outra configuração.
    if tipo in ("aws", "azure") and ("\n" in segredo or "\r" in segredo):
        raise FonteInvalida("O segredo não pode ter quebra de linha.")


def _bloco_de_nuvem(fonte):
    config, tipo, identificador = fonte["config"], fonte["tipo"], fonte.get("id", 0)
    segredo = escape(fonte["segredo_aberto"])
    if tipo == "github":
        return (f"  <github>\n    <enabled>yes</enabled>\n    <interval>1m</interval>\n    <time_delay>1m</time_delay>\n"
                f"    <only_future_events>yes</only_future_events>\n    <api_auth>\n      <org_name>{escape(config['organizacao'])}</org_name>\n"
                f"      <api_token>{segredo}</api_token>\n    </api_auth>\n    <api_parameters>\n      <event_type>all</event_type>\n"
                f"    </api_parameters>\n  </github>\n")
    if tipo == "office365":
        assinaturas = "".join(f"      <subscription>{a}</subscription>\n" for a in ASSINATURAS_DO_OFFICE365)
        return (f"  <office365>\n    <enabled>yes</enabled>\n    <interval>1m</interval>\n    <only_future_events>yes</only_future_events>\n"
                f"    <api_auth>\n      <tenant_id>{escape(config['locatario'])}</tenant_id>\n      <client_id>{escape(config['aplicativo'])}</client_id>\n"
                f"      <client_secret>{segredo}</client_secret>\n      <api_type>commercial</api_type>\n    </api_auth>\n"
                f"    <subscriptions>\n{assinaturas}    </subscriptions>\n  </office365>\n")
    if tipo == "msgraph":
        recursos = "".join(f"    <resource>\n      <name>{n}</name>\n      <relationship>{r}</relationship>\n    </resource>\n" for n, r in RECURSOS_DO_GRAPH)
        return (f"  <ms-graph>\n    <enabled>yes</enabled>\n    <only_future_events>yes</only_future_events>\n    <interval>5m</interval>\n"
                f"    <version>v1.0</version>\n    <api_auth>\n      <client_id>{escape(config['aplicativo'])}</client_id>\n"
                f"      <tenant_id>{escape(config['locatario'])}</tenant_id>\n      <secret_value>{segredo}</secret_value>\n"
                f"      <api_type>global</api_type>\n    </api_auth>\n{recursos}  </ms-graph>\n")
    if tipo == "aws":
        return (f'  <wodle name="aws-s3">\n    <disabled>no</disabled>\n    <interval>10m</interval>\n    <run_on_start>yes</run_on_start>\n'
                f'    <skip_on_error>yes</skip_on_error>\n    <bucket type="cloudtrail">\n      <name>{escape(config["bucket"])}</name>\n'
                f"      <aws_profile>roar-{identificador}</aws_profile>\n    </bucket>\n  </wodle>\n")
    if tipo == "azure":
        return (f'  <wodle name="azure-logs">\n    <disabled>no</disabled>\n    <interval>10m</interval>\n    <run_on_start>yes</run_on_start>\n'
                f"    <log_analytics>\n      <auth_path>{PASTA_DE_CREDENCIAIS}/azure-{identificador}</auth_path>\n"
                f"      <tenantdomain>{escape(config['dominio'])}</tenantdomain>\n      <request>\n        <tag>azure-activity</tag>\n"
                f"        <query>AzureActivity</query>\n        <workspace>{escape(config['workspace'])}</workspace>\n"
                f"        <time_offset>1h</time_offset>\n      </request>\n    </log_analytics>\n  </wodle>\n")
    if tipo == "gcp":
        return (f"  <gcp-pubsub>\n    <enabled>yes</enabled>\n    <pull_on_start>yes</pull_on_start>\n    <interval>5m</interval>\n"
                f"    <project_id>{escape(config['projeto'])}</project_id>\n    <subscription_name>{escape(config['assinatura'])}</subscription_name>\n"
                f"    <credentials_file>{PASTA_DE_CREDENCIAIS}/gcp-{identificador}.json</credentials_file>\n  </gcp-pubsub>\n")
    if tipo == "slack":
        return (f"  <integration>\n    <name>slack</name>\n    <hook_url>{segredo}</hook_url>\n    <level>{int(config['nivel'])}</level>\n"
                f"    <alert_format>json</alert_format>\n  </integration>\n")
    if tipo == "pagerduty":
        return (f"  <integration>\n    <name>pagerduty</name>\n    <api_key>{segredo}</api_key>\n    <level>{int(config['nivel'])}</level>\n"
                f"    <alert_format>json</alert_format>\n  </integration>\n")
    if tipo == "maltiverse":
        return (f"  <integration>\n    <name>maltiverse</name>\n    <hook_url>https://api.maltiverse.com</hook_url>\n    <api_key>{segredo}</api_key>\n"
                f"    <level>{int(config['nivel'])}</level>\n    <alert_format>json</alert_format>\n  </integration>\n")
    # Só eventos de integridade de arquivo: é o hash que sai, nunca o arquivo.
    return (f"  <integration>\n    <name>virustotal</name>\n    <api_key>{segredo}</api_key>\n    <group>syscheck</group>\n"
            f"    <alert_format>json</alert_format>\n  </integration>\n")


def arquivos_de_credenciais(fontes):
    """Alguns módulos só leem a credencial de um arquivo: caminho no gerenciador e conteúdo."""
    arquivos, perfis = {}, []
    for fonte in sorted(fontes, key=lambda f: f.get("id", 0)):
        identificador = fonte.get("id", 0)
        if fonte["tipo"] == "azure":
            arquivos[f"{PASTA_DE_CREDENCIAIS}/azure-{identificador}"] = (
                f"application_id = {fonte['config']['aplicativo']}\napplication_key = {fonte['segredo_aberto']}\n")
        elif fonte["tipo"] == "gcp":
            arquivos[f"{PASTA_DE_CREDENCIAIS}/gcp-{identificador}.json"] = fonte["segredo_aberto"]
        elif fonte["tipo"] == "aws":
            perfis.append(f"[roar-{identificador}]\naws_access_key_id = {fonte['config']['chave_de_acesso']}\n"
                          f"aws_secret_access_key = {fonte['segredo_aberto']}\n")
    if perfis:
        arquivos[CREDENCIAIS_DA_AWS] = "\n".join(perfis)
    return arquivos


def fragmento_de_configuracao(fontes):
    """Uma entrada de syslog por protocolo, porque a porta interna é a mesma para todas as fontes do cliente."""
    por_protocolo, blocos = {}, []
    for fonte in fontes:
        if fonte["tipo"] != "syslog":
            continue
        config = fonte["config"]
        por_protocolo.setdefault(config["protocolo"], set()).update(validar_syslog(config["protocolo"], config["origens"]))
    for protocolo in sorted(por_protocolo):
        permitidos = "".join(f"    <allowed-ips>{rede}</allowed-ips>\n" for rede in sorted(por_protocolo[protocolo]))
        blocos.append(f"  <remote>\n    <connection>syslog</connection>\n    <port>514</port>\n    <protocol>{protocolo}</protocol>\n{permitidos}  </remote>\n")
    blocos += [_bloco_de_nuvem(f) for f in sorted(fontes, key=lambda f: f.get("id", 0)) if f["tipo"] in TIPOS_DE_NUVEM]
    if not blocos:
        return ""
    return "\n<ossec_config>\n" + "".join(blocos) + "</ossec_config>\n"


def _abrir_segredos(banco, cliente, fontes):
    """Só aqui a credencial fica aberta, para entrar na configuração do gerenciador daquele cliente."""
    from . import cofre

    nuvem = [f for f in fontes if f["tipo"] in TIPOS_DE_NUVEM]
    if not nuvem:
        return
    privada = cofre.ler_privada()
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        for fonte in nuvem:
            selado = banco.con.execute("SELECT selado FROM segredos WHERE nome = %s", (fonte["config"]["segredo"],)).fetchone()
            if not selado:
                raise FonteInvalida("A credencial desta fonte não foi encontrada.")
            fonte["segredo_aberto"] = cofre.abrir(privada, cliente, fonte["config"]["segredo"], selado[0])


def aplicar_fontes(banco, gerenciador_id, cliente):
    """Só reinicia o gerenciador se a configuração mudou. Reprovou: volta ao anterior e avisa na tela."""
    from . import provisao

    def com_cliente(sql, *args):
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        return banco.con.execute(sql, args)

    with banco.con.transaction():
        linhas = com_cliente(
            "SELECT id, tipo, config, estado FROM fontes WHERE gerenciador_id = %s AND estado IN ('pendente', 'ativa', 'desativada')",
            gerenciador_id).fetchall()
    pendentes = [l[0] for l in linhas if l[3] == "pendente"]
    em_uso = [{"id": l[0], "tipo": l[1], "config": l[2]} for l in linhas if l[3] != "desativada"]
    pasta = PASTA_GERENCIADORES / gerenciador_id
    marca = pasta / "fontes.aplicadas"
    _abrir_segredos(banco, cliente, em_uso)
    fragmento = fragmento_de_configuracao(em_uso)
    arquivos = arquivos_de_credenciais(em_uso)
    resumo = hashlib.sha256((fragmento + json.dumps(arquivos, sort_keys=True) if arquivos else fragmento).encode()).hexdigest()
    anterior = marca.read_text() if marca.exists() else hashlib.sha256(b"").hexdigest()
    if resumo == anterior and not pendentes:
        return 0
    ok, detalhe = (True, {}) if resumo == anterior else provisao.aplicar_configuracao(gerenciador_id, fragmento, arquivos)
    if ok:
        marca.write_text(resumo)
    with banco.con.transaction():
        for fonte in pendentes:
            if ok:
                com_cliente("UPDATE fontes SET estado = 'ativa', mensagem = NULL, aplicada_em = now() WHERE id = %s", fonte)
            else:
                # O motivo vem do validador e pode citar caminhos internos: a tela recebe só o aviso.
                log.error("gerenciador %s recusou a configuração: %s", gerenciador_id, re.sub(r"\s+", " ", str(detalhe))[:400])
                com_cliente("UPDATE fontes SET estado = 'recusada', mensagem = %s WHERE id = %s",
                            "O gerenciador recusou esta configuração. Nada mudou.", fonte)
    return len(pendentes)


def encaminhar_webhooks(banco, gerenciador_id, cliente):
    """Só apaga da fila o que o gerenciador aceitou. Se ele limitar, o resto espera o próximo ciclo."""
    from . import provisao

    entregues = 0
    for _ in range(LOTES_POR_CICLO):
        with banco.con.transaction():
            banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            lote = banco.con.execute(
                "SELECT id, corpo FROM entrada_webhook WHERE gerenciador_id = %s ORDER BY id LIMIT %s",
                (gerenciador_id, EVENTOS_POR_LOTE)).fetchall()
        if not lote:
            break
        try:
            provisao.enviar_eventos(gerenciador_id, [corpo for _, corpo in lote])
        except requests.HTTPError as erro:
            if erro.response is not None and erro.response.status_code == 429:
                break
            raise
        with banco.con.transaction():
            banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            banco.con.execute("DELETE FROM entrada_webhook WHERE id = ANY(%s)", ([i for i, _ in lote],))
        entregues += len(lote)
    return entregues


def validar_api(config):
    """Devolve só os campos conhecidos. O endereço é conferido aqui e de novo a cada busca."""
    endereco = str(config.get("endereco", "")).strip()
    if not endereco.startswith("https://") and not (endereco.startswith("http://") and os.getenv("ROAR_DESTINO_INTERNO") == "1"):
        raise FonteInvalida("O endereço precisa começar com https.")
    try:
        rede_externa.resolver(endereco)
    except rede_externa.DestinoRecusado as erro:
        raise FonteInvalida(str(erro))
    caminho = str(config.get("caminho", "")).strip()
    if caminho and not CAMINHO_NO_JSON.fullmatch(caminho):
        raise FonteInvalida("O caminho até a lista usa só letras, números, _ e pontos, como data.itens.")
    cabecalho = str(config.get("cabecalho", "")).strip()
    if cabecalho and not NOME_DE_CABECALHO.fullmatch(cabecalho):
        raise FonteInvalida("Nome de cabeçalho inválido.")
    if cabecalho.lower() in CABECALHOS_PROIBIDOS:
        raise FonteInvalida(f"O cabeçalho {cabecalho} não pode ser usado.")
    try:
        intervalo = int(config.get("intervalo_minutos", 15))
    except (TypeError, ValueError):
        raise FonteInvalida("O intervalo precisa ser um número de minutos.")
    if not INTERVALO_MINIMO <= intervalo <= 1440:
        raise FonteInvalida(f"O intervalo vai de {INTERVALO_MINIMO} a 1440 minutos.")
    return {"endereco": endereco, "caminho": caminho, "cabecalho": cabecalho, "intervalo_minutos": intervalo}


def _itens_da_resposta(corpo, caminho):
    """O conteúdo é de fora, então nada aqui confia no formato. Devolve as linhas de JSON de cada item."""
    try:
        dados = json.loads(corpo)
    except (ValueError, RecursionError):
        raise FonteInvalida("A resposta não é JSON.")
    for parte in caminho.split(".") if caminho else []:
        if not isinstance(dados, dict) or parte not in dados:
            raise FonteInvalida(f"O caminho {caminho} não existe na resposta.")
        dados = dados[parte]
    itens = dados if isinstance(dados, list) else [dados]
    linhas = [json.dumps(i, ensure_ascii=False, separators=(",", ":"), sort_keys=True) for i in itens if isinstance(i, dict)]
    return [l for l in linhas if len(l.encode()) <= TAMANHO_MAXIMO_DO_ITEM]


def buscar_apis(banco, gerenciador_id, cliente):
    """Uma fonte com problema fica com o motivo na tela e tenta de novo no próximo intervalo."""
    from . import cofre, provisao

    def transacao(sql, *args):
        with banco.con.transaction():
            banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            cursor = banco.con.execute(sql, args)
            return cursor.fetchall() if cursor.description else None

    prontas = transacao(
        """SELECT id, config, vistos FROM fontes WHERE gerenciador_id = %s AND tipo = 'api' AND estado = 'ativa'
           AND (proxima_busca IS NULL OR proxima_busca <= now())""", gerenciador_id)
    for fonte, config, vistos in prontas:
        transacao("UPDATE fontes SET proxima_busca = now() + make_interval(mins => %s) WHERE id = %s", config["intervalo_minutos"], fonte)
        try:
            cabecalhos = {"Accept": "application/json"}
            if config.get("segredo"):
                selado = transacao("SELECT selado FROM segredos WHERE nome = %s", config["segredo"])
                if not selado:
                    raise FonteInvalida("A credencial desta fonte não foi encontrada.")
                cabecalhos[config["cabecalho"] or "Authorization"] = cofre.abrir(cofre.ler_privada(), cliente, config["segredo"], selado[0][0])
            resposta, corpo = rede_externa.chamar("GET", config["endereco"], cabecalhos, limite_de_bytes=TAMANHO_MAXIMO_DA_RESPOSTA)
            if resposta.status_code != 200:
                raise FonteInvalida(f"O sistema respondeu {resposta.status_code}.")
            linhas = _itens_da_resposta(corpo, config["caminho"])
            ja_vistos, novos = set(vistos), []
            resumos = []
            for linha in linhas:
                resumo = hashlib.sha256(linha.encode()).hexdigest()[:32]
                resumos.append(resumo)
                if resumo not in ja_vistos:
                    novos.append(linha)
            for inicio in range(0, len(novos), EVENTOS_POR_LOTE):
                provisao.enviar_eventos(gerenciador_id, novos[inicio:inicio + EVENTOS_POR_LOTE])
            # A lista fica com o que veio agora: o que saiu da resposta não volta a ser comparado.
            transacao("UPDATE fontes SET vistos = %s, mensagem = NULL, ultimo_dado_em = CASE WHEN %s THEN now() ELSE ultimo_dado_em END WHERE id = %s",
                      resumos[-MAXIMO_DE_VISTOS:], bool(novos), fonte)
        except (FonteInvalida, rede_externa.DestinoRecusado) as erro:
            transacao("UPDATE fontes SET mensagem = %s WHERE id = %s", str(erro)[:300], fonte)
        except requests.RequestException as erro:
            # A exceção pode citar a URL interna da conexão: a tela recebe só o tipo do problema.
            log.warning("busca da fonte %s falhou: %s", fonte, type(erro).__name__)
            transacao("UPDATE fontes SET mensagem = %s WHERE id = %s", "Não foi possível falar com o sistema.", fonte)


def ciclo(banco):
    from .regras import aplicar_regras_proprias

    for gerenciador_id, cliente in banco.gerenciadores():
        if not (PASTA_GERENCIADORES / gerenciador_id).is_dir():
            continue
        try:
            encaminhar_webhooks(banco, gerenciador_id, cliente)
            buscar_apis(banco, gerenciador_id, cliente)
            aplicar_fontes(banco, gerenciador_id, cliente)
            # No mesmo ciclo curto: regra criada ou editada na tela não pode esperar a sincronização de hora em hora.
            aplicar_regras_proprias(banco, gerenciador_id, cliente)
        except Exception:  # Um gerenciador com problema não pode travar a configuração dos outros.
            log.exception("fontes do gerenciador %s falharam", gerenciador_id)


def main():
    from .ciclo import conexoes

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--intervalo", type=float, default=15.0)
    a = args.parse_args()
    _, banco, _ = conexoes()
    while True:
        ciclo(banco)
        time.sleep(a.intervalo)


if __name__ == "__main__":
    main()
