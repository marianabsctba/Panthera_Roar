"""Superfície externa: o que os domínios da organização deixam à vista na internet, conferido aos poucos e sem parar.

    python -m roar_ingestao.superficie

Nada roda tudo de uma vez. Uma instância só (trava no banco); a descoberta pega um domínio por vez para listar os nomes;
cada nome entra numa fila com hora marcada e é conferido sozinho, com poucas conexões ao mesmo tempo, e o resultado
dele é gravado na hora. As horas da fila ficam espalhadas, então o serviço está sempre fazendo um pouco.

A conferência é leve: portas perigosas abertas, certificado e HTTPS. Endereço que o DNS aponta para a rede interna não
é conferido, porque o servidor do Roar estaria olhando a própria rede. Os achados vão para Vulnerabilidades com o mesmo
ciclo das outras fontes: abre, reabre se voltar e fecha quando some.
"""

import concurrent.futures
import ipaddress
import logging
import random
import re
import secrets
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import requests
from psycopg.types.json import Jsonb
from cryptography import x509

from . import distribuicoes, email_dominio, rede_externa, tomada
from .ciclo import conexoes
from .cves import PRODUTOS_RECONHECIDOS
from .vulnerabilidades import _ativo, _historico

log = logging.getLogger("roar.superficie")

FONTE = "externa"
TRAVA = 7_310_001  # pg_advisory_lock: com outra instância no ar, esta espera
NOMES_POR_VOLTA = 3
CONEXOES_AO_MESMO_TEMPO = 8
SEGUNDOS_SEM_TRABALHO = 15
SEGUNDOS_COM_TRABALHO = 1
TEMPO_DA_PORTA = 2.5
NOMES_POR_DOMINIO = 200
# Nome com vários endereços (balanceador, CDN) tem cada um conferido, até este tanto; o IPv4 vem primeiro.
IPS_POR_NOME = 4
DIAS_DE_MUDANCAS = 180
# Uma conferência travada (o serviço caiu no meio) volta para a fila depois disto.
MINUTOS_DE_CONFERENCIA = 10
# Nomes que quase toda empresa tem, testados no DNS além do que o registro de certificados mostra.
NOMES_COMUNS = ("www", "mail", "webmail", "smtp", "vpn", "remote", "acesso", "portal", "api", "app", "dev", "hml", "homolog", "staging", "teste", "test",
                "ftp", "sftp", "admin", "intranet", "autodiscover", "owa", "sso", "login", "rh", "erp", "crm", "blog", "loja", "shop", "status", "git", "jira",
                "jenkins", "grafana", "kibana", "db", "sql", "backup", "cloud", "files", "nuvem", "suporte", "help")
# Porta aberta para a internet que não deveria estar: o que é, a severidade e como corrigir.
PORTAS_PERIGOSAS = {
    21: ("FTP", "alta", "O FTP manda senha e arquivo sem cifra. Use SFTP, ou feche a porta para a internet."),
    23: ("Telnet", "critica", "O Telnet manda tudo sem cifra, inclusive a senha. Desligue e use SSH, só pela VPN."),
    445: ("SMB (compartilhamento do Windows)", "critica", "Compartilhamento de arquivos aberto para a internet é porta de entrada de ransomware. Feche no firewall."),
    3389: ("RDP (área de trabalho remota)", "critica", "RDP aberto para a internet é a porta de entrada mais usada por ransomware. Deixe só pela VPN e com MFA."),
    5900: ("VNC", "critica", "Acesso remoto de tela aberto para a internet. Deixe só pela VPN."),
    3306: ("MySQL", "critica", "Banco de dados aberto para a internet. Feche no firewall e deixe só para a aplicação."),
    5432: ("PostgreSQL", "critica", "Banco de dados aberto para a internet. Feche no firewall e deixe só para a aplicação."),
    1433: ("SQL Server", "critica", "Banco de dados aberto para a internet. Feche no firewall e deixe só para a aplicação."),
    1521: ("Oracle", "critica", "Banco de dados aberto para a internet. Feche no firewall e deixe só para a aplicação."),
    27017: ("MongoDB", "critica", "Banco de dados aberto para a internet. Feche no firewall e exija senha."),
    6379: ("Redis", "critica", "Redis aberto para a internet costuma aceitar comando sem senha. Feche no firewall."),
    9200: ("Elasticsearch ou OpenSearch", "critica", "Índice de dados aberto para a internet. Feche no firewall."),
    11211: ("Memcached", "critica", "Memcached aberto é usado para ataques de negação de serviço. Feche no firewall."),
    2375: ("API do Docker sem cifra", "critica", "Quem alcança esta porta controla os contêineres do servidor. Feche agora."),
    5601: ("Kibana", "alta", "Painel de dados aberto para a internet. Deixe atrás de login e VPN."),
    22: ("SSH", "baixa", "SSH aberto para a internet é comum, mas atrai tentativa de senha o dia todo. Prefira chave, e limite por endereço ou VPN."),
}
PORTAS = tuple(PORTAS_PERIGOSAS) + (80, 443)
DIAS_PARA_AVISAR = 30
# Portas em que o serviço se apresenta sozinho, ou com um pedido simples, dizendo o nome e a versão.
SONDAS = {21: "le", 22: "le", 3306: "le", 80: "http", 443: "https", 9200: "http", 5601: "http"}
# (o que procurar na resposta, produtos no CPE, nome na tela)
RECONHECER = (
    (re.compile(r"SSH-[\d.]+-OpenSSH_([\w.]+)"), ("openbsd:openssh",), "OpenSSH"),
    (re.compile(r"SSH-[\d.]+-dropbear_([\d.]+)"), ("dropbear_ssh_project:dropbear_ssh",), "Dropbear SSH"),
    (re.compile(r"ProFTPD ([\d.]+[a-z]?)"), ("proftpd:proftpd",), "ProFTPD"),
    (re.compile(r"\(vsFTPd ([\d.]+)\)"), ("beasts:vsftpd",), "vsftpd"),
    (re.compile(r"FileZilla Server(?: version)? ([\d.]+)"), ("filezilla-project:filezilla_server",), "FileZilla Server"),
    (re.compile(r"(?im)^server:.*?\bApache/([\d.]+)"), ("apache:http_server",), "Apache httpd"),
    (re.compile(r"(?im)^server:.*?\bnginx/([\d.]+)"), ("f5:nginx", "nginx:nginx"), "nginx"),
    (re.compile(r"(?im)^server:.*?\bMicrosoft-IIS/([\d.]+)"), ("microsoft:internet_information_services",), "IIS"),
    (re.compile(r"(?im)^server:.*?\blighttpd/([\d.]+)"), ("lighttpd:lighttpd",), "lighttpd"),
    (re.compile(r"(?im)^server:.*?\bJetty\(([\d.]+)"), ("eclipse:jetty",), "Jetty"),
    (re.compile(r"(?im)^x-powered-by:.*?\bPHP/([\d.]+)"), ("php:php",), "PHP"),
    (re.compile(r"(\d+\.\d+\.\d+)-MariaDB"), ("mariadb:mariadb",), "MariaDB"),
    # O MySQL abre com 4 bytes de tamanho, o protocolo 10 e a versão.
    (re.compile(r"^.{4}\n(\d+\.\d+\.\d+)(?![\w.-]*MariaDB)", re.S), ("oracle:mysql",), "MySQL"),
    # O OpenSearch responde igual, com "distribution": "opensearch", e as falhas do Elasticsearch não valem para ele.
    (re.compile(r'^(?![\s\S]*"distribution"\s*:\s*"opensearch")[\s\S]*"number"\s*:\s*"([\d.]+)"[\s\S]*"lucene_version"'), ("elastic:elasticsearch",), "Elasticsearch"),
)
# Distribuição que corrige a falha sem trocar o número da versão: a versão anunciada não prova a falha.
DISTRIBUICAO = re.compile(r"ubuntu|debian|deb\d|\bel\d|centos|red ?hat|rhel|fedora|suse|amzn|raspbian|freebsd", re.I)
# Produtos que a página mostra mesmo sem dizer a versão no cabeçalho: (como reconhecer, de onde tirar a versão, produtos no
# CPE, nome na tela, tipo). "borda" é VPN e acesso remoto, o alvo preferido de ataques, cuja versão não aparece sem login;
# "painel" é tela de administração, que não deveria estar aberta para a internet.
WEB = (
    (re.compile(r"/wp-(?:content|includes)/"), re.compile(r'<meta name="generator" content="WordPress ([\d.]+)'), ("wordpress:wordpress",), "WordPress", "app"),
    (re.compile(r"(?im)^x-owa-version:|/owa/auth/"), re.compile(r"(?im)^x-owa-version:\s*([\d.]+)"), ("microsoft:exchange_server",), "Exchange (OWA)", "borda"),
    (re.compile(r"/remote/login|ftnt-fortinet|fgt_lang"), None, ("fortinet:fortios",), "Fortinet SSL VPN", "borda"),
    (re.compile(r"Citrix Gateway|NetScaler|/logon/LogonPoint/|/vpn/index\.html"), None,
     ("citrix:netscaler_gateway", "citrix:netscaler_application_delivery_controller"), "Citrix NetScaler", "borda"),
    (re.compile(r"GlobalProtect|/global-protect/"), None, ("paloaltonetworks:pan-os",), "Palo Alto GlobalProtect", "borda"),
    (re.compile(r"/dana-na/|Ivanti Connect Secure|Pulse Connect Secure"), None, ("ivanti:connect_secure", "pulsesecure:pulse_connect_secure"), "Ivanti Connect Secure", "borda"),
    (re.compile(r'content="GitLab"|gon\.gitlab_url'), None, ("gitlab:gitlab",), "GitLab", "app"),
    (re.compile(r"(?im)^x-jenkins:"), re.compile(r"(?im)^x-jenkins:\s*([\d.]+)"), ("jenkins:jenkins",), "Jenkins", "painel"),
    (re.compile(r"grafanaBootData|<title>Grafana"), re.compile(r'"buildInfo":\{[^}]*?"version":"([\d.]+)"'), ("grafana:grafana",), "Grafana", "painel"),
    (re.compile(r"ajs-version-number|com-atlassian-confluence"), re.compile(r'name="ajs-version-number" content="([\d.]+)"'),
     ("atlassian:confluence_server", "atlassian:confluence_data_center"), "Confluence", "app"),
    (re.compile(r"rcmloginuser|roundcube_sessid"), re.compile(r'"rcversion":\s*(\d{5,6})'), ("roundcube:webmail",), "Roundcube", "app"),
    (re.compile(r"<title>phpMyAdmin|pma_navigation|phpmyadmin\.css"), re.compile(r"[?&;]v=(\d+\.\d+\.\d+)"), ("phpmyadmin:phpmyadmin",), "phpMyAdmin", "painel"),
    (re.compile(r"(?im)^kbn-name:|^kbn-version:"), re.compile(r"(?im)^kbn-version:\s*([\d.]+)"), ("elastic:kibana",), "Kibana", "painel"),
)
TIPOS = {nome: tipo for _, _, _, nome, tipo in WEB}
PRODUTOS_DO_SERVICO = {nome: list(produtos) for _, produtos, nome in RECONHECER} | {nome: list(produtos) for _, _, produtos, nome, _ in WEB}
assert all(set(produtos) <= PRODUTOS_RECONHECIDOS for produtos in PRODUTOS_DO_SERVICO.values())


# ------------------------------------------------------------------ descoberta

def nomes_pelos_certificados(dominio, buscar=requests.get):
    """Os nomes que já ganharam certificado público com este domínio. Fora do ar, segue só com o DNS."""
    try:
        r = buscar(f"https://crt.sh/?q=%25.{dominio}&output=json", timeout=40, headers={"User-Agent": "PantheraRoar"})
        r.raise_for_status()
        linhas = r.json()
    except (requests.RequestException, ValueError):
        return set()
    nomes = set()
    for linha in linhas[:5000]:
        for nome in str(linha.get("name_value", "")).lower().split("\n"):
            nome = nome.strip().lstrip("*.").rstrip(".")
            if nome == dominio or nome.endswith("." + dominio):
                nomes.add(nome)
    return nomes


def resolver(nome):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(nome, None, type=socket.SOCK_STREAM)})
    except (socket.gaierror, UnicodeError, OSError):
        return []


def publico(ip):
    try:
        return rede_externa.e_publico(ipaddress.ip_address(ip.split("%")[0]))
    except ValueError:
        return False


def descobrir(dominio, buscar=requests.get, resolver_nome=resolver, cname_de=None):
    """{nome: (origem, ips)} dos nomes do domínio que respondem no DNS. Domínio que responde qualquer nome (curinga)
    não aceita os nomes comuns, que resolveriam todos para o mesmo lugar."""
    candidatos = {dominio: "dominio", **{n: "certificados" for n in nomes_pelos_certificados(dominio, buscar)}}
    for comum in NOMES_COMUNS:
        candidatos.setdefault(f"{comum}.{dominio}", "dns")
    curinga = set(resolver_nome(f"roar-{secrets.token_hex(6)}.{dominio}"))
    achados, sem_endereco = {}, []
    with concurrent.futures.ThreadPoolExecutor(CONEXOES_AO_MESMO_TEMPO) as fila:
        for (nome, origem), ips in zip(candidatos.items(), fila.map(resolver_nome, candidatos)):
            if ips and not (origem == "dns" and curinga and set(ips) <= curinga):
                achados[nome] = (origem, ips)
                if len(achados) >= NOMES_POR_DOMINIO:
                    break
            elif not ips:
                sem_endereco.append((nome, origem))
        # Sem endereço mas ainda apelido de outro nome: o CNAME pendurado é justamente o que pode ser tomado.
        cname_de = cname_de or tomada.cname
        for (nome, origem), destino in zip(sem_endereco, fila.map(lambda c: cname_de(c[0]), sem_endereco)):
            if destino and len(achados) < NOMES_POR_DOMINIO:
                achados[nome] = (origem, [])
    return achados


# ------------------------------------------------------------------ conferência de um nome

def porta_aberta(ip, porta, tempo=TEMPO_DA_PORTA):
    try:
        with socket.create_connection((ip, porta), timeout=tempo):
            return True
    except OSError:
        return False


def certificado(nome, ip, porta=443, contexto=None):
    """(vence, emissor, problema). O problema é None quando o certificado vale e confere com o nome."""
    contexto = contexto or ssl.create_default_context()
    problema = None
    try:
        with socket.create_connection((ip, porta), timeout=8) as bruto, contexto.wrap_socket(bruto, server_hostname=nome) as tls:
            der = tls.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as erro:
        texto = str(erro.verify_message or erro).lower()
        problema = "vencido" if "expired" in texto else "nome" if "hostname" in texto or "mismatch" in texto else "nao_confiavel"
        sem_conferir = ssl.create_default_context()
        sem_conferir.check_hostname, sem_conferir.verify_mode = False, ssl.CERT_NONE
        try:
            with socket.create_connection((ip, porta), timeout=8) as bruto, sem_conferir.wrap_socket(bruto, server_hostname=nome) as tls:
                der = tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            return None, None, problema
    except (OSError, ssl.SSLError):
        return None, None, "sem_tls"
    cert = x509.load_der_x509_certificate(der)
    emissor = next((a.value for a in cert.issuer if a.oid == x509.NameOID.ORGANIZATION_NAME), None) or cert.issuer.rfc4514_string()
    return cert.not_valid_after_utc, str(emissor)[:200], problema


def _ler(nome, ip, porta, modo, caminho="/", tempo=5, limite=65536):
    with socket.create_connection((ip, porta), timeout=tempo) as bruto:
        conexao = bruto
        if modo == "https":
            sem_conferir = ssl.create_default_context()
            sem_conferir.check_hostname, sem_conferir.verify_mode = False, ssl.CERT_NONE
            conexao = sem_conferir.wrap_socket(bruto, server_hostname=nome)
        if modo != "le":
            conexao.sendall(f"GET {caminho} HTTP/1.1\r\nHost: {nome}\r\nUser-Agent: PantheraRoar\r\nConnection: close\r\n\r\n".encode())
        dados = b""
        while len(dados) < limite:
            pedaco = conexao.recv(8192)
            if not pedaco:
                break
            dados += pedaco
            if modo == "le":
                break
    return dados[:limite].decode("latin-1")


def resposta_da_porta(nome, ip, porta, tempo=5):
    """O que o serviço diz ao conectar: SSH, FTP e banco falam primeiro; o servidor web responde a um GET da página
    inicial. Se ela manda para outra página do mesmo nome (como /owa/ ou /remote/login), segue uma vez. Só leitura."""
    modo = SONDAS[porta]
    try:
        resposta = _ler(nome, ip, porta, modo, tempo=tempo)
        if modo != "le":
            destino = re.search(r"(?im)^location:\s*(\S+)", resposta.split("\r\n\r\n", 1)[0])
            if destino and re.match(r"HTTP/1\.[01] 30[1278]", resposta):
                partes = urlsplit(destino.group(1))
                mesmo_lugar = (not partes.hostname or partes.hostname.lower() == nome.lower()) and partes.scheme in ("", "https" if modo == "https" else "http")
                if mesmo_lugar and partes.path.startswith("/"):
                    caminho = partes.path + (f"?{partes.query}" if partes.query else "")
                    resposta += "\n" + _ler(nome, ip, porta, modo, caminho[:300], tempo=tempo)
    except (OSError, ssl.SSLError):
        return None
    return resposta


def _versao_do_roundcube(numero):
    # O Roundcube conta a versão como número: 10604 é a 1.6.4.
    n = int(numero)
    return f"{n // 10000}.{n // 100 % 100}.{n % 100}"


def reconhecer(resposta):
    """[(produtos, nome, versão)] do que a resposta anuncia. A versão é None quando o produto não a mostra."""
    achados = []
    for padrao, produtos, nome in RECONHECER:
        m = padrao.search(resposta or "")
        if m:
            achados.append((produtos, nome, m.group(1).rstrip(".")))
    for achar, versao, produtos, nome, _ in WEB:
        if achar.search(resposta or ""):
            m = versao.search(resposta) if versao else None
            numero = m.group(1).rstrip(".") if m else None
            if numero and nome == "Roundcube":
                numero = _versao_do_roundcube(numero)
            achados.append((produtos, nome, numero))
    return achados


def _linha_da_resposta(resposta, nome):
    """A linha que mostra a versão, para a evidência: o cabeçalho, não a página toda."""
    for linha in (resposta or "").splitlines():
        if nome.split()[0].lower() in linha.lower():
            return "".join(c for c in linha if c.isprintable()).strip()[:200]
    return "".join(c for c in (resposta or "")[:120] if c.isprintable()).strip()


def identificar(nome, ip, portas, ler=resposta_da_porta):
    """[{porta, produtos, nome, versao, resposta, distribuicao}] das portas abertas que se apresentam."""
    servicos = []
    for porta in portas:
        if porta not in SONDAS:
            continue
        resposta = ler(nome, ip, porta)
        for produtos, servico, versao in reconhecer(resposta):
            linha = _linha_da_resposta(resposta, servico)
            servicos.append({"porta": porta, "produtos": list(produtos), "nome": servico, "versao": versao, "resposta": linha,
                             "tipo": TIPOS.get(servico, "servico"), "distribuicao": bool(versao and DISTRIBUICAO.search(linha)),
                             "pacote": distribuicoes.pacote_anunciado(servico, versao, resposta) if versao else None})
    return servicos


def chave_de_versao(versao):
    """2.4.49 < 2.4.50 < 2.4.100, e 8.2 < 8.2p1. Número compara como número, letra como texto."""
    return [(1, int(t)) if t.isdigit() else (0, t) for t in re.findall(r"\d+|[a-z]+", str(versao).lower())]


def afeta(versao, exata, desde, desde_incluida, ate, ate_incluida):
    v = chave_de_versao(versao)
    if exata:
        return v == chave_de_versao(exata)
    if desde and (v < chave_de_versao(desde) or (v == chave_de_versao(desde) and not desde_incluida)):
        return False
    if ate and (v > chave_de_versao(ate) or (v == chave_de_versao(ate) and not ate_incluida)):
        return False
    return True


def cves_da_versao(con, produtos, versao):
    """[{cve, cvss, explorada}] das CVEs da base que pegam esta versão: as exploradas primeiro, depois pela nota."""
    linhas = con.execute("""SELECT v.cve, v.exata, v.desde, v.desde_incluida, v.ate, v.ate_incluida, c.cvss, c.kev_desde IS NOT NULL
                            FROM cves_versoes v JOIN cves c ON c.cve = v.cve WHERE v.produto = ANY(%s) AND NOT c.rejeitado""", (list(produtos),)).fetchall()
    vistas = {}
    for cve, exata, desde, desde_incluida, ate, ate_incluida, cvss, explorada in linhas:
        if cve not in vistas and afeta(versao, exata, desde, desde_incluida, ate, ate_incluida):
            vistas[cve] = {"cve": cve, "cvss": cvss, "explorada": explorada}
    return sorted(vistas.values(), key=lambda c: (not c["explorada"], -(c["cvss"] or 0), c["cve"]))


def exploradas_do_produto(con, produtos):
    """Quantas CVEs do produto, em qualquer versão, já foram exploradas por atacantes."""
    return con.execute("""SELECT count(DISTINCT v.cve) FROM cves_versoes v JOIN cves c ON c.cve = v.cve
                          WHERE v.produto = ANY(%s) AND c.kev_desde IS NOT NULL""", (list(produtos),)).fetchone()[0]


def pacote_na_distribuicao(banco, pacote, serie=None, falhas=None):
    """(ecossistemas, [CVEs que ainda pegam o pacote]) pelo OSV, guardado por um dia; None quando não dá para saber."""
    chave = (pacote["distribuicao"], pacote["nomes"][0], pacote["versao"])
    with banco.con.transaction():
        guardada = banco.con.execute("""SELECT ecossistemas, cves FROM distro_consultas WHERE distribuicao = %s AND pacote = %s AND versao = %s
                                        AND consultado_em > now() - interval '1 day'""", chave).fetchone()
    if guardada:
        return (guardada[0], guardada[1]) if guardada[0] else None
    serie, falhas = serie or distribuicoes.serie, falhas or distribuicoes.falhas
    try:
        achada = serie(pacote)
        resultado = (achada[2], falhas(achada[0], achada[1], achada[2])) if achada else None
    except (requests.RequestException, ValueError, KeyError) as erro:
        # Fora do ar não é "sem falha": fica como suspeita, e a próxima conferência tenta de novo.
        log.warning("pacote %s %s sem resposta da distribuição: %s", chave[1], chave[2], type(erro).__name__)
        return None
    with banco.con.transaction():
        banco.con.execute("""INSERT INTO distro_consultas (distribuicao, pacote, versao, versao_com_epoca, ecossistemas, cves) VALUES (%s, %s, %s, %s, %s, %s)
                             ON CONFLICT (distribuicao, pacote, versao) DO UPDATE SET versao_com_epoca = EXCLUDED.versao_com_epoca,
                               ecossistemas = EXCLUDED.ecossistemas, cves = EXCLUDED.cves, consultado_em = now()""",
                          (*chave, achada[1] if achada else None, resultado[0] if resultado else None, resultado[1] if resultado else None))
    return resultado


def _severidade_da_nota(cvss):
    return "critica" if cvss >= 9 else "alta" if cvss >= 7 else "media" if cvss >= 4 else "baixa"


def conferir_nome(nome, ips, aberta=porta_aberta, ler_certificado=certificado, identificar_=None):
    """{"portas", "portas_por_ip", "tls_*", "servicos"} de um nome público. Cada endereço é conferido (até IPS_POR_NOME),
    sempre com poucas conexões ao mesmo tempo; o serviço e o certificado são lidos no primeiro endereço que abre a porta."""
    identificar_ = identificar_ or identificar
    enderecos = sorted(dict.fromkeys(ips), key=lambda ip: ":" in ip)[:IPS_POR_NOME]
    pares = [(ip, porta) for ip in enderecos for porta in PORTAS]
    with concurrent.futures.ThreadPoolExecutor(CONEXOES_AO_MESMO_TEMPO) as fila:
        abertos = [par for par, aberto in zip(pares, fila.map(lambda par: aberta(*par), pares)) if aberto]
    portas_por_ip = {ip: sorted(p for i, p in abertos if i == ip) for ip in enderecos}
    portas = sorted({p for _, p in abertos})
    primeiro = {p: next(ip for ip in enderecos if p in portas_por_ip[ip]) for p in portas}
    vence = emissor = problema = None
    if 443 in portas:
        vence, emissor, problema = ler_certificado(nome, primeiro[443])
    servicos = [s for p in portas for s in identificar_(nome, primeiro[p], [p])]
    return {"portas": portas, "portas_por_ip": portas_por_ip, "tls_vence": vence, "tls_emissor": emissor, "tls_problema": problema, "servicos": servicos}


def achados_do_nome(nome, ips, interno, visto, agora=None):
    """[(regra, título, severidade, evidência, solução, cves, cvss)] do que se viu neste nome. Cada serviço de
    `visto["servicos"]` traz em "cves" as CVEs da versão, postas por quem chama."""
    agora = agora or datetime.now(timezone.utc)
    if interno:
        internos = ", ".join(ip for ip in ips if not publico(ip))
        return [("dns-interno", f"O DNS público de {nome} aponta para a rede interna", "informativa", f"{nome} resolve para {internos}.",
                 "Tire o nome do DNS público, ou use um DNS só para a rede interna. O endereço interno ajuda quem prepara um ataque.")]
    saida, portas, vence = [], visto["portas"], visto["tls_vence"]
    for porta in portas:
        if porta in PORTAS_PERIGOSAS:
            servico, severidade, solucao = PORTAS_PERIGOSAS[porta]
            onde = [ip for ip, abertas in (visto.get("portas_por_ip") or {}).items() if porta in abertas] or ips[:1]
            saida.append((f"porta|{porta}", f"{servico} aberto para a internet", severidade, f"A porta {porta} de {nome} ({', '.join(onde)}) aceita conexão de fora.", solucao))
    if 80 in portas and 443 not in portas:
        saida.append(("sem-https", f"Site sem HTTPS em {nome}", "media", f"{nome} responde na porta 80 e não na 443.",
                      "Ligue o HTTPS, com um certificado gratuito se preciso, e redirecione o HTTP para ele."))
    if visto["tls_problema"] == "vencido" or (vence and vence <= agora):
        saida.append(("certificado|vencido", f"Certificado vencido em {nome}", "alta", f"O certificado venceu em {vence:%d/%m/%Y}." if vence else "O certificado está vencido.",
                      "Renove o certificado. O navegador avisa quem acessa, e muita integração para de funcionar."))
    elif vence and vence <= agora + timedelta(days=DIAS_PARA_AVISAR):
        dias = (vence - agora).days
        saida.append(("certificado|vencendo", f"Certificado de {nome} vence em {dias} dias", "media" if dias <= 14 else "baixa",
                      f"Vence em {vence:%d/%m/%Y}, emitido por {visto['tls_emissor'] or 'emissor desconhecido'}.", "Renove antes do vencimento, ou ligue a renovação automática."))
    if visto["tls_problema"] == "nome":
        saida.append(("certificado|nome", f"Certificado de {nome} não é para este nome", "media", "O certificado apresentado é de outro nome.",
                      "Instale um certificado que inclua este nome, ou tire o nome do DNS."))
    elif visto["tls_problema"] == "nao_confiavel":
        saida.append(("certificado|confianca", f"Certificado de {nome} não é de uma autoridade reconhecida", "media", f"Emitido por {visto['tls_emissor'] or 'emissor desconhecido'}.",
                      "Use um certificado de uma autoridade reconhecida. Certificado próprio acostuma as pessoas a ignorar o aviso do navegador."))
    for servico in visto.get("servicos") or []:
        porta, tipo, versao = servico["porta"], servico.get("tipo", "servico"), servico.get("versao")
        mostrada = f" (versão {versao})" if versao else ""
        if tipo == "borda":
            exploradas_do_produto_ = servico.get("exploradas_do_produto") or 0
            saida.append((f"exposto|{porta}|{servico['nome']}", f"{servico['nome']} aberto para a internet em {nome}", "baixa",
                          f"A porta {porta} de {nome} mostra a tela de acesso do {servico['nome']}{mostrada}."
                          + (f" {exploradas_do_produto_} falhas deste produto já foram exploradas por atacantes." if exploradas_do_produto_ else ""),
                          "Este tipo de equipamento é o alvo preferido de ataques. Mantenha na versão mais nova, acompanhe os avisos do fabricante e, "
                          "se der, limite quem alcança a tela de acesso. A versão não aparece sem login: confira no próprio equipamento."))
        elif tipo == "painel":
            saida.append((f"painel|{porta}|{servico['nome']}", f"Painel do {servico['nome']} aberto para a internet em {nome}", "media",
                          f"A porta {porta} de {nome} mostra a tela do {servico['nome']}{mostrada}.",
                          "Painel de administração não deveria estar na internet. Deixe só pela VPN ou limite por endereço, e exija MFA."))
        cves = servico.get("cves") or []
        if not cves:
            continue
        nota = max((c["cvss"] or 0) for c in cves)
        exploradas = [c["cve"] for c in cves if c["explorada"]]
        rotulo, regra = f"{servico['nome']} {servico['versao']}", f"versao|{porta}|{servico['nome']}"
        exemplos = ", ".join(c["cve"] for c in cves[:5]) + (f" e mais {len(cves) - 5}" if len(cves) > 5 else "")
        evidencia = f"A porta {porta} de {nome} responde: {servico['resposta']}. A versão {servico['versao']} aparece em {len(cves)} CVE(s): {exemplos}."
        if exploradas:
            evidencia += f" Já exploradas por atacantes: {', '.join(exploradas[:5])}."
        solucao = (f"Atualize o {servico['nome']} para a versão mais nova suportada. Se não der agora, tire a porta {porta} da internet ou deixe só pela VPN. "
                   "Esconder a versão na resposta ajuda a não chamar atenção, mas não corrige.")
        pacote = servico.get("pacote") or {}
        if pacote.get("confirmado"):
            evidencia += (f" Confirmado pelo pacote {pacote['versao']} da distribuição ({', '.join(pacote['ecossistemas'])}): "
                          f"estas CVEs ainda pegam o pacote instalado.")
            solucao = f"Atualize o pacote {pacote['nome']} pela distribuição (apt upgrade). " + solucao.split(". ", 1)[1]
        elif servico.get("distribuicao"):
            # A distribuição corrige sem mudar o número: sem olhar o pacote no servidor, é suspeita, não falha confirmada.
            saida.append((regra, f"{rotulo} em {nome} pode ter falhas conhecidas", "media" if nota >= 4 else "baixa",
                          evidencia + " A resposta é de uma distribuição Linux, que costuma corrigir sem trocar o número da versão: confira o pacote no servidor.",
                          solucao, [], None))
            continue
        severidade = "critica" if exploradas else _severidade_da_nota(nota)
        saida.append((regra, f"{rotulo} com falhas conhecidas em {nome}", severidade, evidencia, solucao, [c["cve"] for c in cves][:200], nota or None))
    return saida


# ------------------------------------------------------------------ gravação

def _fechar(con, cliente, ativo, motivo, mantidas=()):
    """Fecha os achados externos abertos deste ativo que não estão em `mantidas`."""
    fechados = con.execute("""UPDATE vuln_achados SET estado = 'corrigido', corrigido_em = now()
                              WHERE ativo_id = %s AND fonte = %s AND estado IN ('aberto', 'correcao_informada') AND NOT (chave = ANY(%s)) RETURNING id""",
                           (ativo, FONTE, list(mantidas))).fetchall()
    for (achado,) in fechados:
        _historico(con, cliente, achado, None, "corrigido", None, motivo)
    return len(fechados)


def gravar_nome(con, cliente, nome, achados):
    """Em transação, com o cliente definido. Abre, reabre e fecha os achados de um nome. Devolve [(regra, título,
    severidade)] dos que abriram ou reabriram agora."""
    ativo = _ativo(con, cliente, nome, nome)
    novos, chaves = [], []
    for regra, titulo, severidade, evidencia, solucao, *extra in achados:
        cves, cvss = (list(extra) + [[], None])[:2]
        chave = f"{FONTE}|{regra}"
        chaves.append(chave)
        existente = con.execute("SELECT id, estado FROM vuln_achados WHERE ativo_id = %s AND chave = %s", (ativo, chave)).fetchone()
        if existente is None:
            achado = con.execute("""INSERT INTO vuln_achados (cliente_id, ativo_id, chave, fonte, titulo, severidade, evidencia, solucao, porta, cves, cvss)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                                 (cliente, ativo, chave, FONTE, titulo[:500], severidade, evidencia[:4000], solucao[:4000],
                                  regra.split("|")[1] if regra.startswith(("porta|", "versao|", "exposto|", "painel|")) else None, cves, cvss)).fetchone()[0]
            _historico(con, cliente, achado, None, "aberto", None, "A varredura externa encontrou.")
            novos.append((regra, titulo, severidade))
            continue
        achado, estado = existente
        voltou = estado in ("corrigido", "correcao_informada")
        con.execute("""UPDATE vuln_achados SET titulo = %s, severidade = %s, evidencia = %s, solucao = %s, cves = %s, cvss = %s, ultima_vez = now(),
                         estado = CASE WHEN %s THEN 'aberto' ELSE estado END, corrigido_em = CASE WHEN %s THEN NULL ELSE corrigido_em END WHERE id = %s""",
                    (titulo[:500], severidade, evidencia[:4000], solucao[:4000], cves, cvss, voltou, voltou, achado))
        if voltou:
            _historico(con, cliente, achado, estado, "aberto", None, "A varredura externa encontrou de novo.")
            novos.append((regra, titulo, severidade))
    _fechar(con, cliente, ativo, "A varredura externa não encontrou mais.", chaves)
    return novos


def achados_abertos(con, nome, prefixo):
    """Os achados abertos do nome com a regra começando em `prefixo`, para manter quando a conferência não teve resposta."""
    return [(chave.split("|", 1)[1], titulo, severidade, evidencia, solucao) for chave, titulo, severidade, evidencia, solucao in con.execute(
        """SELECT a.chave, a.titulo, a.severidade, a.evidencia, a.solucao FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id
           WHERE t.host = %s AND a.chave LIKE %s AND a.estado IN ('aberto', 'correcao_informada')""", (nome, f"{FONTE}|{prefixo}%")).fetchall()]


def _servico_da_porta(porta):
    return PORTAS_PERIGOSAS[porta][0] if porta in PORTAS_PERIGOSAS else "site" if porta in (80, 443) else "serviço"


def mudancas(nome, antes, depois):
    """[(tipo, detalhe)] do que mudou entre a conferência anterior e esta."""
    saida = []
    for porta in sorted(set(depois["portas"]) - set(antes["portas"] or [])):
        saida.append(("porta_abriu", f"A porta {porta}, {_servico_da_porta(porta)}, abriu."))
    for porta in sorted(set(antes["portas"] or []) - set(depois["portas"])):
        saida.append(("porta_fechou", f"A porta {porta}, {_servico_da_porta(porta)}, fechou."))
    if antes["tls_vence"] and depois["tls_vence"] and (antes["tls_vence"], antes["tls_emissor"]) != (depois["tls_vence"], depois["tls_emissor"]):
        saida.append(("certificado_trocou", f"Certificado novo, de {depois['tls_emissor'] or 'emissor desconhecido'}, vence em {depois['tls_vence']:%d/%m/%Y}."))
    versoes_antes = {(s["porta"], s["nome"]): s.get("versao") for s in antes["servicos"] or []}
    for s in depois["servicos"]:
        chave, versao = (s["porta"], s["nome"]), s.get("versao")
        if chave not in versoes_antes and s["porta"] in (antes["portas"] or []):
            saida.append(("servico_mudou", f"{s['nome']}{' ' + versao if versao else ''} apareceu na porta {s['porta']}."))
        elif chave in versoes_antes and versoes_antes[chave] != versao and versao and versoes_antes[chave]:
            saida.append(("servico_mudou", f"{s['nome']} passou de {versoes_antes[chave]} para {versao} na porta {s['porta']}."))
    if antes["cname"] and antes["cname"] != depois["cname"]:
        saida.append(("cname_mudou", f"Passou a apontar para {depois['cname'] or 'nenhum apelido'}, antes {antes['cname']}."))
    return saida


def _com_cliente(banco, cliente):
    banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))


# ------------------------------------------------------------------ o trabalho, um passo por vez

def _mudou(con, cliente, dominio_id, nome, tipo, detalhe):
    con.execute("INSERT INTO superficie_mudancas (cliente_id, dominio_id, nome, tipo, detalhe) VALUES (%s, %s, %s, %s, %s)",
                (cliente, dominio_id, nome, tipo, detalhe[:500]))


def passo_de_descoberta(banco, descobrir_=descobrir):
    """Lista os nomes de um domínio vencido. Nome novo entra na fila; nome que sumiu fecha os achados. Devolve se trabalhou."""
    with banco.con.transaction():
        proximo = banco.con.execute("SELECT * FROM roar_superficie_proxima_descoberta()").fetchone()
    if not proximo:
        return False
    cliente, dominio_id = proximo
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        dominio, horas, ja_descoberto = banco.con.execute("SELECT dominio, descobrir_a_cada_horas, ultima_descoberta IS NOT NULL FROM superficie_dominios WHERE id = %s",
                                                          (dominio_id,)).fetchone()
        # Marca já a próxima: se a descoberta falhar no meio, o domínio não volta para a frente da fila a cada volta.
        banco.con.execute("UPDATE superficie_dominios SET proxima_descoberta = now() + make_interval(hours => %s) WHERE id = %s", (horas, dominio_id))
    erro = None
    try:
        nomes = descobrir_(dominio)
    except Exception as e:
        log.exception("descoberta de %s falhou", dominio)
        nomes, erro = None, f"A descoberta não terminou ({type(e).__name__}). Ela roda de novo na próxima vez."
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        if nomes is not None:
            for posicao, (nome, (origem, ips)) in enumerate(sorted(nomes.items())):
                interno = not all(publico(ip) for ip in ips)
                # Nome novo entra na fila espalhado de 20 em 20 segundos, para a primeira volta não juntar todos.
                novo = banco.con.execute("""INSERT INTO superficie_hosts (cliente_id, dominio_id, nome, ips, origem, interno, proxima_conferencia)
                                            VALUES (%s, %s, %s, %s, %s, %s, now() + make_interval(secs => %s))
                                            ON CONFLICT (dominio_id, nome) DO UPDATE SET ips = EXCLUDED.ips, interno = EXCLUDED.interno, sumiu = false, ultima_vez = now()
                                            RETURNING xmax = 0""",
                                         (cliente, dominio_id, nome, ips, origem, interno, posicao * 20)).fetchone()[0]
                if novo and ja_descoberto:
                    _mudou(banco.con, cliente, dominio_id, nome, "nome_novo", f"Apareceu no DNS{', em ' + ', '.join(ips[:3]) if ips else ', só como apelido (CNAME)'}.")
            for (nome,) in banco.con.execute("""UPDATE superficie_hosts SET sumiu = true WHERE dominio_id = %s AND NOT sumiu AND NOT (nome = ANY(%s))
                                                RETURNING nome""", (dominio_id, list(nomes))).fetchall():
                ativo = banco.con.execute("SELECT id FROM vuln_ativos WHERE host = %s", (nome,)).fetchone()
                if ativo:
                    _fechar(banco.con, cliente, ativo[0], "O nome saiu do DNS: não está mais na internet.")
                _mudou(banco.con, cliente, dominio_id, nome, "nome_sumiu", "Saiu do DNS.")
            banco.con.execute("DELETE FROM superficie_hosts WHERE dominio_id = %s AND sumiu AND ultima_vez < now() - interval '30 days'", (dominio_id,))
            banco.con.execute("DELETE FROM superficie_mudancas WHERE dominio_id = %s AND em < now() - make_interval(days => %s)", (dominio_id, DIAS_DE_MUDANCAS))
        banco.con.execute("UPDATE superficie_dominios SET ultima_descoberta = now(), ultimo_erro = %s WHERE id = %s", (erro, dominio_id))
    log.info("descoberta de %s: %s nomes", dominio, "?" if nomes is None else len(nomes))
    return True


def completar_servico(con, servico):
    """Põe em `servico` as CVEs: as da versão pela base e, com o pacote da distribuição conhecido, só as que ainda pegam
    o pacote instalado. Produto de borda não tem versão sem login: conta as falhas já exploradas dele."""
    tipo, versao = servico.get("tipo", "servico"), servico.get("versao")
    servico["cves"] = cves_da_versao(con, servico["produtos"], versao) if versao and tipo != "borda" else []
    if tipo == "borda":
        servico["exploradas_do_produto"] = exploradas_do_produto(con, servico["produtos"])
    pacote = servico.get("pacote")
    situacao = pacote.pop("situacao", None) if pacote else None
    if pacote and situacao:
        ecossistemas, abertas = situacao
        linhas = con.execute("SELECT cve, cvss, kev_desde IS NOT NULL FROM cves WHERE cve = ANY(%s) AND NOT rejeitado", (abertas,)).fetchall()
        pela_versao = {c["cve"] for c in servico["cves"]}
        servico["cves"] = sorted(({"cve": c, "cvss": n, "explorada": k} for c, n, k in linhas), key=lambda c: (not c["explorada"], -(c["cvss"] or 0), c["cve"]))
        pacote.update(nome=pacote["nomes"][0], ecossistemas=ecossistemas, confirmado=True,
                      corrigidas=len(pela_versao - {c["cve"] for c in servico["cves"]}))


def conferir_email(dominio):
    return email_dominio.conferir(dominio)


def conferir_cname(nome):
    return tomada.cname(nome)


def pagina_do_nome(nome, ips):
    """O que o nome responde na web, para reconhecer a página de "site não existe" do provedor."""
    for porta, modo in ((443, "https"), (80, "http")):
        try:
            return _ler(nome, ips[0], porta, modo, limite=16384)
        except (OSError, ssl.SSLError):
            continue
    return None


def passo_de_conferencia(banco, conferir=conferir_nome):
    """Confere os poucos nomes que venceram na fila, um de cada vez. Devolve quantos conferiu."""
    with banco.con.transaction():
        fila = banco.con.execute("SELECT * FROM roar_superficie_proximos_nomes(%s)", (NOMES_POR_VOLTA,)).fetchall()
    feitos = 0
    for cliente, host_id in fila:
        with banco.con.transaction():
            _com_cliente(banco, cliente)
            # Empurra a hora já: se a conferência cair no meio, o nome volta só daqui a alguns minutos, e não a cada volta.
            linha = banco.con.execute("""UPDATE superficie_hosts SET conferindo_desde = now(), proxima_conferencia = now() + make_interval(mins => %s)
                                         WHERE id = %s
                                         RETURNING nome, ips, interno, (SELECT conferir_a_cada_horas FROM superficie_dominios d WHERE d.id = dominio_id), origem,
                                                   dominio_id, conferido_em IS NOT NULL, portas, tls_vence, tls_emissor, servicos, cname""",
                                      (MINUTOS_DE_CONFERENCIA, host_id)).fetchone()
        if not linha:
            continue
        nome, ips, interno, horas, origem, dominio_id, ja_conferido = linha[:7]
        antes = dict(zip(("portas", "tls_vence", "tls_emissor", "servicos", "cname"), linha[7:]))
        visto = {"portas": [], "tls_vence": None, "tls_emissor": None, "tls_problema": None, "servicos": []}
        if not interno and ips:
            try:
                visto = conferir(nome, ips)
            except Exception:
                # Sem resposta não é "tudo fechado": os achados ficam como estão, e o nome volta em alguns minutos.
                log.exception("conferência de %s falhou", nome)
                with banco.con.transaction():
                    _com_cliente(banco, cliente)
                    banco.con.execute("UPDATE superficie_hosts SET conferindo_desde = NULL WHERE id = %s", (host_id,))
                continue
        try:
            destino = conferir_cname(nome)
            visto["cname"] = destino
            pagina = (lambda: pagina_do_nome(nome, ips)) if ips else None
            visto["tomada"] = tomada.avaliar(nome, destino, pagina=pagina) if destino else None
        except Exception:
            # DNS fora do ar não é "não pode ser tomado": o achado fica como está.
            log.exception("CNAME de %s não conferido", nome)
            visto["cname"], visto["tomada"] = antes["cname"], "manter"
        if origem == "dominio":
            try:
                visto["email"] = conferir_email(nome)
            except Exception:
                # DNS fora do ar não é "sem SPF": os achados de e-mail ficam como estão.
                log.exception("e-mail de %s não conferido", nome)
                visto["email"] = None
        for servico in visto.get("servicos") or []:
            if servico.get("pacote"):
                servico["pacote"]["situacao"] = pacote_na_distribuicao(banco, servico["pacote"])
        # A próxima conferência volta espalhada em até 10% do intervalo, para os nomes não se juntarem de novo.
        espalhar = int(horas * 3600 * random.uniform(0, 0.1))
        with banco.con.transaction():
            _com_cliente(banco, cliente)
            servicos = visto.get("servicos") or []
            for servico in servicos:
                completar_servico(banco.con, servico)
            achados = achados_do_nome(nome, ips, interno, visto)
            email = visto.get("email")
            if origem == "dominio" and email is None:
                # Sem resposta do DNS, mantém os achados de e-mail abertos em vez de fechá-los.
                achados += achados_abertos(banco.con, nome, "email|")
            elif email:
                achados += email["achados"]
            if visto.get("tomada") == "manter":
                achados += achados_abertos(banco.con, nome, "tomada|")
            elif visto.get("tomada"):
                achados.append(visto["tomada"])
            novos = gravar_nome(banco.con, cliente, nome, achados)
            # Na tela, só o que respondeu e quantas falhas: as CVEs ficam no achado.
            guardar = [{**{k: v for k, v in sv.items() if k not in ("cves", "produtos", "pacote")}, "falhas": len(sv["cves"]),
                        "pacote": {k: v for k, v in sv["pacote"].items() if k in ("nome", "versao", "distribuicao", "ecossistemas", "confirmado", "corrigidas")}
                        if sv.get("pacote") else None} for sv in servicos]
            if email:
                banco.con.execute("UPDATE superficie_hosts SET email = %s WHERE id = %s",
                                  (Jsonb({k: email[k] for k in ("spf", "dmarc", "dkim")} | {"problemas": len(email["achados"])}), host_id))
            banco.con.execute("""UPDATE superficie_hosts SET portas = %s, tls_vence = %s, tls_emissor = %s, tls_problema = %s, servicos = %s, cname = %s,
                                   conferindo_desde = NULL, conferido_em = now(), proxima_conferencia = now() + make_interval(hours => %s, secs => %s) WHERE id = %s""",
                              (visto["portas"], visto["tls_vence"], visto["tls_emissor"], visto["tls_problema"], Jsonb(guardar), visto.get("cname"), horas, espalhar, host_id))
            if ja_conferido and not interno:
                for tipo, detalhe in mudancas(nome, antes, {**visto, "servicos": guardar}):
                    _mudou(banco.con, cliente, dominio_id, nome, tipo, detalhe)
            # O sino avisa do que é grave e acabou de aparecer (ou voltou): porta perigosa aberta e nome que pode ser tomado.
            for regra, titulo, severidade in novos:
                if regra.startswith(("porta|", "tomada|")) and severidade in ("critica", "alta"):
                    texto = titulo if nome in titulo else f"{nome}: {titulo}"
                    banco.con.execute("SELECT roar_avisar(%s, 'exposicao_externa', %s)", (cliente, texto))
        feitos += 1
    return feitos


def _travar(banco, funcao):
    # Em transação própria: fora dela, a conexão ficaria com uma transação aberta e nada do passo seria gravado.
    with banco.con.transaction():
        return banco.con.execute(f"SELECT {funcao}(%s)", (TRAVA,)).fetchone()[0]


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    _, banco, _ = conexoes()
    while True:
        trabalhou = False
        # Um trabalhando por vez: com outra instância (ou um teste) no meio de uma volta, esta espera a próxima.
        if _travar(banco, "pg_try_advisory_lock"):
            try:
                trabalhou = passo_de_descoberta(banco)
                trabalhou = passo_de_conferencia(banco) > 0 or trabalhou
            except Exception:
                log.exception("volta da superfície externa falhou")
            finally:
                _travar(banco, "pg_advisory_unlock")
        time.sleep(SEGUNDOS_COM_TRABALHO if trabalhou else SEGUNDOS_SEM_TRABALHO)


if __name__ == "__main__":
    main()
