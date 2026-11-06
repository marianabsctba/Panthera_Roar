#!/usr/bin/env python3
"""Superfície externa: a fila confere poucos nomes por volta, um trabalhando por vez, e os achados abrem, reabrem e fecham.

    sudo bash testes/rodar.sh testes/fase4/testar_superficie.py

A rede é de mentira: o teste diz que nomes o domínio tem e que portas cada um abre. O banco é o real.
"""

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_ingestao import superficie  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
CVES = ["CVE-1999-9900001", "CVE-1999-9900002", "CVE-1999-9900003"]
TABELAS = ("superficie_hosts", "superficie_dominios", "vuln_historico", "vuln_achados", "vuln_ativos", "notificacoes")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def sem_nada():
    return {"portas": [], "tls_vence": None, "tls_emissor": None, "tls_problema": None}


def testar_regras():
    print("== O que vira achado", flush=True)
    agora = datetime.now(timezone.utc)
    visto = {**sem_nada(), "portas": [3389, 443], "tls_vence": agora + timedelta(days=10), "tls_emissor": "Exemplo"}
    regras = {a[0]: a[2] for a in superficie.achados_do_nome("vpn.exemplo.test", ["93.184.216.5"], False, visto, agora)}
    registrar("RDP aberto é crítico", regras.get("porta|3389") == "critica", str(regras))
    registrar("certificado perto de vencer avisa", regras.get("certificado|vencendo") == "media")
    registrar("443 aberto não é achado", "porta|443" not in regras and "sem-https" not in regras)
    so_http = superficie.achados_do_nome("www.exemplo.test", ["93.184.216.6"], False, {**sem_nada(), "portas": [80]}, agora)
    registrar("site só em HTTP pede HTTPS", [a[0] for a in so_http] == ["sem-https"])
    vencido = superficie.achados_do_nome("a.exemplo.test", ["93.184.216.7"], False, {**sem_nada(), "portas": [443], "tls_problema": "vencido"}, agora)
    registrar("certificado vencido é alto", [(a[0], a[2]) for a in vencido] == [("certificado|vencido", "alta")])
    interno = superficie.achados_do_nome("db.exemplo.test", ["10.0.0.5"], True, sem_nada(), agora)
    registrar("nome que aponta para a rede interna vira um aviso só", [a[0] for a in interno] == ["dns-interno"] and "10.0.0.5" in interno[0][3])

    print("\n== Produtos pela página", flush=True)
    paginas = {
        'HTTP/1.1 200 OK\r\n\r\n<link href="/wp-content/a.css"><meta name="generator" content="WordPress 6.4.2" />': ("WordPress", "6.4.2"),
        "HTTP/1.1 302 Found\r\nLocation: /owa/\r\n\r\n\nHTTP/1.1 200 OK\r\nX-OWA-Version: 15.2.1258.12\r\n\r\n": ("Exchange (OWA)", "15.2.1258.12"),
        'HTTP/1.1 200 OK\r\n\r\n<script src="/remote/fgt_lang?lang=en"></script>': ("Fortinet SSL VPN", None),
        "HTTP/1.1 403 Forbidden\r\nX-Jenkins: 2.401.3\r\n\r\n": ("Jenkins", "2.401.3"),
        'HTTP/1.1 200 OK\r\n\r\n<script>rcmail.set_env({"rcversion":10604});</script><input id="rcmloginuser">': ("Roundcube", "1.6.4"),
        'HTTP/1.1 200 OK\r\n\r\n<title>Grafana</title><script>window.grafanaBootData = {"settings":{"buildInfo":{"commit":"a","version":"10.1.0"}}}</script>': ("Grafana", "10.1.0"),
        'HTTP/1.1 200 OK\r\n\r\n<title>phpMyAdmin</title><link href="themes/pmahomme/css/theme.css?v=5.2.1">': ("phpMyAdmin", "5.2.1"),
    }
    for pagina, esperado in paginas.items():
        visto = [(r[1], r[2]) for r in superficie.reconhecer(pagina)]
        registrar(f"reconhece {esperado[0]}" + (f" {esperado[1]}" if esperado[1] else ", sem versão"), visto == [esperado], str(visto))
    servicos_web = [{"porta": 443, "produtos": ["fortinet:fortios"], "nome": "Fortinet SSL VPN", "versao": None, "resposta": "", "tipo": "borda",
                     "distribuicao": False, "cves": [], "exploradas_do_produto": 18},
                    {"porta": 8443, "produtos": ["jenkins:jenkins"], "nome": "Jenkins", "versao": "2.401.3", "resposta": "X-Jenkins: 2.401.3", "tipo": "painel",
                     "distribuicao": False, "cves": []}]
    feito = {a[0]: a for a in superficie.achados_do_nome("vpn.exemplo.test", ["93.184.216.7"], False, {**sem_nada(), "portas": [443], "servicos": servicos_web}, agora)}
    borda = feito.get("exposto|443|Fortinet SSL VPN")
    registrar("VPN de borda vira aviso de exposição, com as falhas já exploradas do produto", borda and borda[2] == "baixa" and "18 falhas" in borda[3], str(borda)[:200])
    painel = feito.get("painel|8443|Jenkins")
    registrar("painel de administração aberto vira achado médio", painel and painel[2] == "media", str(painel)[:200])

    print("\n== Pacote da distribuição", flush=True)
    from roar_ingestao import distribuicoes
    pacote = distribuicoes.pacote_anunciado("OpenSSH", "8.2p1", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
    registrar("lê o pacote no que o SSH anuncia", pacote == {"nomes": ["openssh"], "versao": "8.2p1-4ubuntu0.5", "epoca": "1:", "distribuicao": "ubuntu"}, str(pacote))
    registrar("sem a revisão, não há pacote", distribuicoes.pacote_anunciado("OpenSSH", "9.6", "SSH-2.0-OpenSSH_9.6\r\n") is None)
    debian = distribuicoes.pacote_anunciado("MariaDB", "10.5.12", "J\x00\x00\x00\n5.5.5-10.5.12-MariaDB-0+deb11u1\x00")
    registrar("a revisão do Debian já diz a versão dele, sem perguntar a ninguém",
              distribuicoes.serie(debian, buscar=None) == ("mariadb-10.5", "1:10.5.12-0+deb11u1", ["Debian:11"]))

    class Resposta:
        def __init__(self, dados, codigo=200):
            self.dados, self.status_code = dados, codigo

        def raise_for_status(self):
            if self.status_code >= 400:
                raise superficie.requests.HTTPError(str(self.status_code))

        def json(self):
            return self.dados
    pedidos = []

    def launchpad(url, timeout, headers, params):
        pedidos.append(params["version"])
        achou = params["version"] == "1:8.2p1-4ubuntu0.5"
        return Resposta({"entries": [{"distro_series_link": "https://api.launchpad.net/devel/ubuntu/focal"}] if achou else []})
    registrar("o Launchpad diz de qual Ubuntu é o pacote", distribuicoes.serie(pacote, buscar=launchpad)
              == ("openssh", "1:8.2p1-4ubuntu0.5", ["Ubuntu:20.04:LTS", "Ubuntu:Pro:20.04:LTS"]) and pedidos == ["1:8.2p1-4ubuntu0.5"], str(pedidos))
    paginas_do_osv = []

    def osv(url, json, timeout, headers):
        paginas_do_osv.append((json["package"]["ecosystem"], json.get("page_token")))
        if json["package"]["ecosystem"].startswith("Ubuntu:Pro") or json.get("page_token"):
            return Resposta({"vulns": [{"id": "UBUNTU-CVE-2023-48795", "upstream": ["CVE-2023-48795"]}]})
        return Resposta({"vulns": [{"id": "UBUNTU-CVE-2023-38408", "upstream": ["CVE-2023-38408"]}], "next_page_token": "b"})
    registrar("o OSV junta as páginas e as duas visões do Ubuntu",
              distribuicoes.falhas("openssh", "1:8.2p1-4ubuntu0.5", ["Ubuntu:20.04:LTS", "Ubuntu:Pro:20.04:LTS"], postar=osv) == ["CVE-2023-38408", "CVE-2023-48795"]
              and len(paginas_do_osv) == 3, str(paginas_do_osv))

    print("\n== Subdomínio abandonado", flush=True)
    from roar_ingestao import tomada
    azure = tomada.avaliar("app.exemplo.test", "velho.azurewebsites.net", existe_=lambda n: False)
    registrar("apelido para Azure apagado pode ser tomado", azure and azure[0] == "tomada|subdominio" and azure[2] == "alta", str(azure))
    registrar("Azure que ainda existe não é achado", tomada.avaliar("app.exemplo.test", "vivo.azurewebsites.net", existe_=lambda n: True) is None)
    paginas = []
    github = tomada.avaliar("docs.exemplo.test", "empresa.github.io", existe_=lambda n: True,
                            pagina=lambda: paginas.append(1) or "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>")
    registrar("GitHub Pages apagado se reconhece pela página", github and github[2] == "alta" and paginas == [1], str(github))
    registrar("e a página só é lida quando o provedor precisa dela",
              tomada.avaliar("app.exemplo.test", "velho.azurewebsites.net", existe_=lambda n: False, pagina=lambda: paginas.append(2)) and paginas == [1])
    solto = tomada.avaliar("loja.exemplo.test", "loja.dominio-que-venceu.test", existe_=lambda n: False)
    registrar("apelido para nome que não existe é médio", solto and solto[2] == "media", str(solto))
    registrar("sem apelido não há o que tomar", tomada.avaliar("a.exemplo.test", None) is None)
    pendurados = superficie.descobrir("exemplo.test", buscar=lambda *a, **k: (_ for _ in ()).throw(superficie.requests.ConnectionError()),
                                      resolver_nome=lambda n: ["93.184.216.1"] if n == "exemplo.test" else [],
                                      cname_de=lambda n: "velho.azurewebsites.net" if n == "app.exemplo.test" or n == "www.exemplo.test" else None)
    registrar("a descoberta guarda o nome sem endereço que ainda é apelido", pendurados.get("www.exemplo.test") == ("dns", []), str(pendurados))

    print("\n== Todos os endereços", flush=True)
    abertas = {("93.184.216.1", 443), ("93.184.216.2", 443), ("93.184.216.2", 3389)}
    tentadas = []

    def aberta(ip, porta):
        tentadas.append(ip)
        return (ip, porta) in abertas
    visto = superficie.conferir_nome("lb.exemplo.test", ["2606:2800::1", "93.184.216.1", "93.184.216.2", "93.184.216.3", "93.184.216.4"], aberta=aberta,
                                     ler_certificado=lambda n, ip: (None, None, None), identificar_=lambda n, ip, ps: [{"porta": ps[0], "ip": ip}])
    registrar("confere cada endereço, até o limite, com o IPv4 primeiro", sorted(set(tentadas)) == ["93.184.216.1", "93.184.216.2", "93.184.216.3", "93.184.216.4"],
              str(sorted(set(tentadas))))
    registrar("a porta aberta em só um endereço aparece", visto["portas"] == [443, 3389] and visto["portas_por_ip"]["93.184.216.2"] == [443, 3389])
    registrar("o serviço é lido no primeiro endereço que abre a porta", visto["servicos"] == [{"porta": 443, "ip": "93.184.216.1"}, {"porta": 3389, "ip": "93.184.216.2"}])
    rdp = [a for a in superficie.achados_do_nome("lb.exemplo.test", ["93.184.216.1", "93.184.216.2"], False, visto, agora) if a[0] == "porta|3389"]
    registrar("a evidência diz em qual endereço a porta abre", rdp and "93.184.216.2" in rdp[0][3] and "93.184.216.1" not in rdp[0][3], str(rdp))

    print("\n== O que mudou", flush=True)
    vence = datetime(2027, 1, 10, tzinfo=timezone.utc)
    antes = {"portas": [22, 443], "tls_vence": vence, "tls_emissor": "A", "servicos": [{"porta": 22, "nome": "OpenSSH", "versao": "8.2p1"}], "cname": "a.cdn.test"}
    depois = {"portas": [443, 3389], "tls_vence": vence + timedelta(days=90), "tls_emissor": "B", "servicos": [{"porta": 443, "nome": "nginx", "versao": "1.24.0"}],
              "cname": "b.cdn.test"}
    tipos = [t for t, _ in superficie.mudancas("x.exemplo.test", antes, depois)]
    registrar("porta que abriu, porta que fechou, certificado e apelido novos", tipos == ["porta_abriu", "porta_fechou", "certificado_trocou", "servico_mudou", "cname_mudou"],
              str(superficie.mudancas("x.exemplo.test", antes, depois)))
    trocou = superficie.mudancas("x.exemplo.test", antes, {**antes, "servicos": [{"porta": 22, "nome": "OpenSSH", "versao": "9.6p1"}]})
    registrar("versão do serviço que mudou", trocou == [("servico_mudou", "OpenSSH passou de 8.2p1 para 9.6p1 na porta 22.")], str(trocou))
    registrar("sem mudança, nada", superficie.mudancas("x.exemplo.test", antes, antes) == [])

    print("\n== Descoberta", flush=True)
    dns = {"exemplo.test": ["93.184.216.1"], "www.exemplo.test": ["93.184.216.2"], "loja.exemplo.test": ["93.184.216.3"]}
    achados = superficie.descobrir("exemplo.test", buscar=lambda *a, **k: (_ for _ in ()).throw(superficie.requests.ConnectionError()),
                                   resolver_nome=lambda n: dns.get(n, []))
    registrar("com o registro de certificados fora do ar, segue pelo DNS", set(achados) == {"exemplo.test", "www.exemplo.test", "loja.exemplo.test"}, str(achados))
    curinga = superficie.descobrir("curinga.test", buscar=lambda *a, **k: (_ for _ in ()).throw(superficie.requests.ConnectionError()),
                                   resolver_nome=lambda n: ["93.184.216.9"])
    registrar("domínio que responde qualquer nome não ganha os nomes comuns", set(curinga) == {"curinga.test"}, str(sorted(curinga))[:200])

    print("\n== Serviço e versão", flush=True)
    casos = {
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n": [("openbsd:openssh",), "OpenSSH", "8.2p1"],
        "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nX-Powered-By: PHP/7.4.3\r\n\r\n": [("apache:http_server",), "Apache httpd", "2.4.49"],
        "HTTP/1.1 301\r\nServer: nginx/1.18.0\r\n\r\n": [("f5:nginx", "nginx:nginx"), "nginx", "1.18.0"],
        "220 ProFTPD 1.3.5 Server (Debian)\r\n": [("proftpd:proftpd",), "ProFTPD", "1.3.5"],
        "J\x00\x00\x00\n5.5.5-10.5.12-MariaDB-0+deb11u1\x00": [("mariadb:mariadb",), "MariaDB", "10.5.12"],
        "J\x00\x00\x00\n8.0.33\x00": [("oracle:mysql",), "MySQL", "8.0.33"],
    }
    for resposta, esperado in casos.items():
        registrar(f"reconhece {esperado[1]} {esperado[2]}", list(superficie.reconhecer(resposta)[0]) == esperado, str(superficie.reconhecer(resposta)))
    registrar("o PHP do cabeçalho também conta", [r[1] for r in superficie.reconhecer("Server: Apache/2.4.49\r\nX-Powered-By: PHP/7.4.3\r\n")] == ["Apache httpd", "PHP"])
    registrar("servidor que esconde a versão não é reconhecido", superficie.reconhecer("HTTP/1.1 200 OK\r\nServer: nginx\r\n") == [])
    registrar("OpenSearch não passa por Elasticsearch",
              superficie.reconhecer('{"version":{"distribution":"opensearch","number":"2.11.0","lucene_version":"9.7"}}') == [])
    registrar("versão compara número como número", superficie.chave_de_versao("2.4.9") < superficie.chave_de_versao("2.4.49") < superficie.chave_de_versao("2.4.100"))
    registrar("e a correção vem depois da versão", superficie.chave_de_versao("8.2") < superficie.chave_de_versao("8.2p1") < superficie.chave_de_versao("8.3"))
    registrar("faixa até, sem incluir", superficie.afeta("2.4.49", None, "2.4.0", True, "2.4.50", False) and not superficie.afeta("2.4.50", None, "2.4.0", True, "2.4.50", False))
    registrar("faixa desde, sem incluir", not superficie.afeta("2.4.0", None, "2.4.0", False, None, False) and superficie.afeta("2.4.1", None, "2.4.0", False, None, False))
    from roar_ingestao import cves as base
    item = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionStartIncluding": "8.5", "versionEndExcluding": "9.8"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:outro:produto:1.0:*:*:*:*:*:*:*"}]}]}]}
    registrar("da NVD saem só as faixas dos produtos reconhecidos, com a correção junto da versão",
              base._versoes_da_nvd("CVE-2024-6387", item) == [("CVE-2024-6387", "openbsd:openssh", None, "8.5", True, "9.8", False),
                                                             ("CVE-2024-6387", "openbsd:openssh", "8.2p1", None, True, None, False)],
              str(base._versoes_da_nvd("CVE-2024-6387", item)))
    servico = {"porta": 22, "nome": "OpenSSH", "versao": "8.2p1", "resposta": "SSH-2.0-OpenSSH_8.2p1", "distribuicao": False,
               "cves": [{"cve": "CVE-2000-1", "cvss": 9.8, "explorada": True}, {"cve": "CVE-2000-2", "cvss": 5.0, "explorada": False}]}
    feito = superficie.achados_do_nome("a.exemplo.test", ["93.184.216.7"], False, {**sem_nada(), "portas": [22], "servicos": [servico]}, agora)
    versao = [a for a in feito if a[0] == "versao|22|OpenSSH"]
    registrar("versão com falha explorada vira achado crítico com as CVEs", versao and versao[0][2] == "critica" and versao[0][5] == ["CVE-2000-1", "CVE-2000-2"]
              and versao[0][6] == 9.8, str(versao)[:300])
    feito = superficie.achados_do_nome("a.exemplo.test", ["93.184.216.7"], False, {**sem_nada(), "portas": [22], "servicos": [{**servico, "distribuicao": True}]}, agora)
    versao = [a for a in feito if a[0] == "versao|22|OpenSSH"]
    registrar("com distribuição Linux, é suspeita: média e sem CVE ligada", versao and versao[0][2] == "media" and versao[0][5] == [] and "pode ter" in versao[0][1],
              str(versao)[:300])


def main():
    testar_regras()

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    outro = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"superficie-{uuid.uuid4().hex[:8]}",)).fetchone()[0])
    usuario = uuid.uuid4()

    nomes = {"exemplo.test": ("dominio", ["93.184.216.1"]), "vpn.exemplo.test": ("certificados", ["93.184.216.2"]),
             "www.exemplo.test": ("dns", ["93.184.216.3"]), "db.exemplo.test": ("dns", ["10.0.0.5"]), "loja.exemplo.test": ("certificados", ["93.184.216.4"])}
    portas = {"vpn.exemplo.test": [3389, 443], "www.exemplo.test": [80]}
    servicos = {}
    conferidos = []

    def conferir(nome, ips):
        conferidos.append(nome)
        if nome == "loja.exemplo.test":
            raise OSError("caiu no meio")
        return {**sem_nada(), "portas": portas.get(nome, []), "servicos": [dict(x) for x in servicos.get(nome, [])]}

    def abertos():
        return dict(admin.execute("""SELECT t.host || ' ' || a.chave, a.estado FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id
                                     WHERE a.cliente_id = %s""", (cliente,)).fetchall())

    def hosts():
        return {n: (s, c, p) for n, s, c, p in admin.execute("SELECT nome, sumiu, conferido_em, proxima_conferencia FROM superficie_hosts WHERE cliente_id = %s",
                                                              (cliente,)).fetchall()}

    superficie.conferir_email = lambda dominio: {"spf": "v=spf1 -all", "dmarc": None, "dkim": [], "achados": [
        ("email|dmarc-ausente", f"{dominio} não tem DMARC", "alta", "Sem DMARC.", "Publique um DMARC.")]} if dominio == "exemplo.test" else None

    apelidos = {}
    superficie.conferir_cname = lambda nome: apelidos.get(nome)
    avaliar_original = superficie.tomada.avaliar
    superficie.tomada.avaliar = lambda nome, destino, pagina=None: avaliar_original(nome, destino, existe_=lambda n: "vivo" in n, pagina=pagina)

    def vencer_tudo():
        admin.execute("UPDATE superficie_hosts SET proxima_conferencia = now() - interval '1 second' WHERE cliente_id = %s AND NOT sumiu", (cliente,))

    try:
        print("\n== Um trabalhando por vez", flush=True)
        registrar("o primeiro pega a vez", superficie._travar(banco, "pg_try_advisory_lock"))
        registrar("o segundo espera", not superficie._travar(outro, "pg_try_advisory_lock"))
        superficie._travar(banco, "pg_advisory_unlock")
        registrar("depois da volta, o outro consegue", superficie._travar(outro, "pg_try_advisory_lock"))
        superficie._travar(outro, "pg_advisory_unlock")

        dominio = admin.execute("""INSERT INTO superficie_dominios (cliente_id, dominio, autorizado_por, autorizado_por_nome)
                                   VALUES (%s, 'exemplo.test', %s, 'Teste') RETURNING id""", (cliente, usuario)).fetchone()[0]

        print("\n== Descoberta na fila", flush=True)
        registrar("a descoberta trabalha", superficie.passo_de_descoberta(banco, lambda d: dict(nomes)))
        h = hosts()
        registrar("cada nome entra na fila", set(h) == set(nomes), str(sorted(h)))
        espalhados = sorted(p for _, _, p in h.values())
        registrar("as horas da primeira conferência ficam espalhadas", all((b - a).total_seconds() >= 19 for a, b in zip(espalhados, espalhados[1:])))
        proxima = admin.execute("SELECT proxima_descoberta - now() FROM superficie_dominios WHERE id = %s", (dominio,)).fetchone()[0]
        registrar("a próxima descoberta fica para o dia seguinte", timedelta(hours=23) < proxima <= timedelta(hours=24))
        registrar("sem domínio vencido, a descoberta não trabalha", not superficie.passo_de_descoberta(banco, lambda d: dict(nomes)))

        print("\n== Conferência aos poucos", flush=True)
        vencer_tudo()
        feitos = superficie.passo_de_conferencia(banco, conferir)
        registrar(f"uma volta pega só {superficie.NOMES_POR_VOLTA} nomes", feitos <= superficie.NOMES_POR_VOLTA and len(conferidos) <= superficie.NOMES_POR_VOLTA, str(conferidos))
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        h = hosts()
        agora = datetime.now(timezone.utc)
        registrar("as outras voltas terminam a fila", all(c is not None for n, (_, c, _) in h.items() if n != "loja.exemplo.test"), str({n: c for n, (_, c, _) in h.items()}))
        registrar("nome da rede interna não é conferido", "db.exemplo.test" not in conferidos)
        registrar("a próxima conferência fica para daqui a umas 6 horas",
                  all(timedelta(hours=5, minutes=59) < p - agora <= timedelta(hours=6, minutes=37) for n, (_, _, p) in h.items() if n != "loja.exemplo.test"))
        registrar("conferência sem resposta volta em alguns minutos, sem contar como conferida",
                  h["loja.exemplo.test"][1] is None and timedelta(minutes=9) < h["loja.exemplo.test"][2] - agora <= timedelta(minutes=10))
        a = abertos()
        registrar("RDP aberto virou achado", a.get("vpn.exemplo.test externa|porta|3389") == "aberto", str(a))
        registrar("site sem HTTPS virou achado", a.get("www.exemplo.test externa|sem-https") == "aberto")
        registrar("o DNS interno virou aviso", a.get("db.exemplo.test externa|dns-interno") == "aberto")
        registrar("conferência que caiu não inventa achado", not any(k.startswith("loja.") for k in a))
        avisos = [r[0] for r in admin.execute("SELECT alvo FROM notificacoes WHERE cliente_id = %s AND tipo = 'exposicao_externa'", (cliente,)).fetchall()]
        registrar("exposição crítica avisa no sino", avisos == ["vpn.exemplo.test: RDP (área de trabalho remota) aberto para a internet"], str(avisos))

        registrar("o nome do domínio confere o e-mail", a.get("exemplo.test externa|email|dmarc-ausente") == "aberto", str(a))
        email = admin.execute("SELECT email FROM superficie_hosts WHERE cliente_id = %s AND nome = 'exemplo.test'", (cliente,)).fetchone()[0]
        registrar("e a tela recebe o resumo do e-mail", email == {"spf": "v=spf1 -all", "dmarc": None, "dkim": [], "problemas": 1}, str(email))

        print("\n== Fecha e reabre", flush=True)
        portas["vpn.exemplo.test"] = [443]
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        registrar("porta fechada fecha o achado", abertos().get("vpn.exemplo.test externa|porta|3389") == "corrigido")
        portas["vpn.exemplo.test"] = [3389, 443]
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        registrar("porta aberta de novo reabre", abertos().get("vpn.exemplo.test externa|porta|3389") == "aberto")
        historia = [r[0] for r in admin.execute("""SELECT h.para FROM vuln_historico h JOIN vuln_achados a ON a.id = h.achado_id
                                                   WHERE a.chave = 'externa|porta|3389' AND a.cliente_id = %s ORDER BY h.id""", (cliente,)).fetchall()]
        registrar("a história mostra o vaivém", historia == ["aberto", "corrigido", "aberto"], str(historia))
        vistas = [r[0] for r in admin.execute("SELECT detalhe FROM superficie_mudancas WHERE cliente_id = %s AND nome = 'vpn.exemplo.test' ORDER BY id", (cliente,)).fetchall()]
        registrar("o que mudou fica registrado: a porta fechou e abriu de novo",
                  vistas[:2] == ["A porta 3389, RDP (área de trabalho remota), fechou.", "A porta 3389, RDP (área de trabalho remota), abriu."], str(vistas))
        registrar("a primeira conferência não vira mudança",
                  admin.execute("SELECT count(*) FROM superficie_mudancas WHERE cliente_id = %s AND nome = 'www.exemplo.test'", (cliente,)).fetchone()[0] == 0)

        print("\n== Apelido pendurado", flush=True)
        apelidos["www.exemplo.test"] = "velho.azurewebsites.net"
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        registrar("nome que aponta para serviço apagado vira achado", abertos().get("www.exemplo.test externa|tomada|subdominio") == "aberto", str(abertos()))
        sino = [r[0] for r in admin.execute("SELECT alvo FROM notificacoes WHERE cliente_id = %s AND tipo = 'exposicao_externa' AND alvo LIKE '%%tomado%%'", (cliente,)).fetchall()]
        registrar("e avisa no sino", len(sino) == 1, str(sino))
        guardado = admin.execute("SELECT cname FROM superficie_hosts WHERE cliente_id = %s AND nome = 'www.exemplo.test'", (cliente,)).fetchone()[0]
        registrar("o apelido fica guardado para a tela", guardado == "velho.azurewebsites.net")

        def dns_caiu(nome):
            raise superficie.tomada.dns.exception.Timeout()
        superficie.conferir_cname = dns_caiu
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        registrar("DNS fora do ar não fecha o achado de apelido", abertos().get("www.exemplo.test externa|tomada|subdominio") == "aberto")
        superficie.conferir_cname = lambda nome: apelidos.get(nome)
        apelidos["www.exemplo.test"] = "vivo.azurewebsites.net"
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        registrar("serviço recriado fecha o achado", abertos().get("www.exemplo.test externa|tomada|subdominio") == "corrigido")
        mudou = admin.execute("SELECT detalhe FROM superficie_mudancas WHERE cliente_id = %s AND tipo = 'cname_mudou'", (cliente,)).fetchone()
        registrar("e a troca do apelido vira mudança", mudou and "vivo.azurewebsites.net" in mudou[0], str(mudou))
        apelidos.clear()

        print("\n== Versão com falha conhecida", flush=True)
        for cve, cvss, explorada in ((CVES[0], 9.8, True), (CVES[1], 5.3, False), (CVES[2], 7.5, False)):
            admin.execute("INSERT INTO cves (cve, cvss, kev_desde, prioridade) VALUES (%s, %s, %s, 'alta')", (cve, cvss, "2020-01-01" if explorada else None))
        admin.execute("""INSERT INTO cves_versoes (cve, produto, exata, desde, desde_incluida, ate, ate_incluida) VALUES
                         (%s, 'proftpd:proftpd', NULL, '1.3.0', true, '1.3.6', false), (%s, 'proftpd:proftpd', '1.3.5', NULL, true, NULL, false),
                         (%s, 'proftpd:proftpd', NULL, NULL, true, '1.3.5', false)""", CVES)
        ftp = {"porta": 21, "produtos": ["proftpd:proftpd"], "nome": "ProFTPD", "versao": "1.3.5", "resposta": "220 ProFTPD 1.3.5 Server", "distribuicao": False}
        servicos["vpn.exemplo.test"] = [ftp]
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        linha = admin.execute("""SELECT a.severidade, a.cves, a.cvss, a.porta, a.estado FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id
                                 WHERE a.cliente_id = %s AND t.host = 'vpn.exemplo.test' AND a.chave = 'externa|versao|21|ProFTPD'""", (cliente,)).fetchone()
        registrar("ProFTPD 1.3.5 vira achado com as CVEs que pegam a versão, a explorada primeiro",
                  linha and linha[0] == "critica" and [c for c in linha[1] if c in CVES] == CVES[:2] and linha[3] == "21" and linha[4] == "aberto", str(linha))
        registrar("a falha explorada avisa no sino",
                  admin.execute("SELECT count(*) FROM notificacoes WHERE cliente_id = %s AND tipo = 'falha_explorada_no_ativo'", (cliente,)).fetchone()[0] == 1)
        guardado = admin.execute("SELECT servicos FROM superficie_hosts WHERE cliente_id = %s AND nome = 'vpn.exemplo.test'", (cliente,)).fetchone()[0]
        registrar("a tela recebe o serviço e quantas falhas, sem a lista de CVEs", len(guardado) == 1 and guardado[0]["nome"] == "ProFTPD"
                  and guardado[0]["falhas"] >= 2 and "cves" not in guardado[0], str(guardado))
        servicos["vpn.exemplo.test"] = [{**ftp, "versao": "1.3.6"}]
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        estado = admin.execute("""SELECT a.estado FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id
                                  WHERE a.cliente_id = %s AND t.host = 'vpn.exemplo.test' AND a.chave = 'externa|versao|21|ProFTPD'""", (cliente,)).fetchone()[0]
        reais = [c for c in superficie.cves_da_versao(admin, ["proftpd:proftpd"], "1.3.6") if c["cve"] not in CVES]
        registrar("atualizar a versão fecha o achado", estado == "corrigido" or (reais and estado == "aberto"), estado)
        servicos.clear()

        print("\n== Confirmação pelo pacote", flush=True)
        admin.execute("DELETE FROM distro_consultas WHERE pacote = 'proftpd-teste'")
        perguntas = []

        def serie_falsa(p):
            perguntas.append(p["versao"])
            return ("proftpd-teste", p["versao"], ["Debian:12"])

        def falhas_falsas(nome, versao, ecossistemas):
            return [CVES[1], CVES[2]] if versao.endswith("u1") else []
        pacote_ftp = {"nomes": ["proftpd-teste"], "versao": "1.3.5-2+deb12u1", "epoca": "", "distribuicao": "debian"}
        original = superficie.pacote_na_distribuicao
        superficie.pacote_na_distribuicao = lambda b, p: original(b, p, serie_falsa, falhas_falsas)
        try:
            servicos["vpn.exemplo.test"] = [{**ftp, "distribuicao": True, "resposta": "220 ProFTPD 1.3.5 Server (Debian)", "pacote": dict(pacote_ftp)}]
            vencer_tudo()
            for _ in range(3):
                superficie.passo_de_conferencia(banco, conferir)
            linha = admin.execute("""SELECT a.severidade, a.cves, a.titulo, a.estado FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id
                                     WHERE a.cliente_id = %s AND t.host = 'vpn.exemplo.test' AND a.chave = 'externa|versao|21|ProFTPD'""", (cliente,)).fetchone()
            registrar("com o pacote conferido, valem só as CVEs que a distribuição ainda não corrigiu, mesmo fora da faixa da versão",
                      linha and linha[1] == [CVES[2], CVES[1]] and linha[3] == "aberto" and "pode ter" not in linha[2], str(linha))
            guardado = admin.execute("SELECT servicos FROM superficie_hosts WHERE cliente_id = %s AND nome = 'vpn.exemplo.test'", (cliente,)).fetchone()[0][0]
            registrar("a tela recebe o pacote conferido e quantas a distribuição corrigiu",
                      guardado["pacote"]["confirmado"] and guardado["pacote"]["corrigidas"] >= 1 and guardado["falhas"] == 2, str(guardado))
            vencer_tudo()
            for _ in range(3):
                superficie.passo_de_conferencia(banco, conferir)
            registrar("a resposta da distribuição fica guardada por um dia", perguntas == ["1.3.5-2+deb12u1"], str(perguntas))
            servicos["vpn.exemplo.test"] = [{**servicos["vpn.exemplo.test"][0], "pacote": {**pacote_ftp, "versao": "1.3.5-2+deb12u2"}}]
            vencer_tudo()
            for _ in range(3):
                superficie.passo_de_conferencia(banco, conferir)
            estado = admin.execute("""SELECT a.estado FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id
                                      WHERE a.cliente_id = %s AND t.host = 'vpn.exemplo.test' AND a.chave = 'externa|versao|21|ProFTPD'""", (cliente,)).fetchone()[0]
            registrar("pacote atualizado fecha o achado, mesmo com a mesma versão anunciada", estado == "corrigido", estado)

            def fora_do_ar(p):
                raise superficie.requests.ConnectionError()
            superficie.pacote_na_distribuicao = lambda b, p: original(b, p, fora_do_ar, falhas_falsas)
            servicos["vpn.exemplo.test"] = [{**servicos["vpn.exemplo.test"][0], "pacote": {**pacote_ftp, "versao": "1.3.5-2+deb12u9"}}]
            vencer_tudo()
            for _ in range(3):
                superficie.passo_de_conferencia(banco, conferir)
            linha = admin.execute("""SELECT a.titulo, a.estado FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id
                                     WHERE a.cliente_id = %s AND t.host = 'vpn.exemplo.test' AND a.chave = 'externa|versao|21|ProFTPD'""", (cliente,)).fetchone()
            registrar("distribuição fora do ar volta a ser suspeita, sem afirmar nada", linha and "pode ter" in linha[0] and linha[1] == "aberto", str(linha))
        finally:
            superficie.pacote_na_distribuicao = original
            admin.execute("DELETE FROM distro_consultas WHERE pacote = 'proftpd-teste'")
        servicos.clear()

        print("\n== E-mail do domínio", flush=True)

        def dns_fora(dominio):
            raise superficie.email_dominio.dns.exception.Timeout()
        superficie.conferir_email = dns_fora
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        registrar("DNS fora do ar não fecha os achados de e-mail", abertos().get("exemplo.test externa|email|dmarc-ausente") == "aberto")
        superficie.conferir_email = lambda dominio: {"spf": "v=spf1 -all", "dmarc": "reject", "dkim": ["selector1"], "achados": []}
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        registrar("DMARC publicado fecha o achado", abertos().get("exemplo.test externa|email|dmarc-ausente") == "corrigido")

        print("\n== Nome que sai do DNS", flush=True)
        admin.execute("UPDATE superficie_dominios SET proxima_descoberta = now() WHERE id = %s", (dominio,))
        sem_www = {n: v for n, v in nomes.items() if n != "www.exemplo.test"}
        superficie.passo_de_descoberta(banco, lambda d: sem_www)
        registrar("o nome fica marcado como fora do DNS", hosts()["www.exemplo.test"][0])
        registrar("e vira mudança", admin.execute("SELECT count(*) FROM superficie_mudancas WHERE cliente_id = %s AND nome = 'www.exemplo.test' AND tipo = 'nome_sumiu'",
                                                  (cliente,)).fetchone()[0] == 1)
        registrar("e os achados dele fecham", abertos().get("www.exemplo.test externa|sem-https") == "corrigido")
        conferidos.clear()
        vencer_tudo()
        for _ in range(3):
            superficie.passo_de_conferencia(banco, conferir)
        registrar("e ele sai da fila", "www.exemplo.test" not in conferidos, str(conferidos))

        print("\n== Falhas", flush=True)
        admin.execute("UPDATE superficie_dominios SET proxima_descoberta = now() WHERE id = %s", (dominio,))

        def quebra(d):
            raise TimeoutError()
        superficie.passo_de_descoberta(banco, quebra)
        linha = admin.execute("SELECT ultimo_erro, proxima_descoberta > now() + interval '23 hours' FROM superficie_dominios WHERE id = %s", (dominio,)).fetchone()
        registrar("descoberta que falha fica registrada e não volta para a frente da fila", linha[0] and "não terminou" in linha[0] and linha[1], str(linha))
        registrar("e não marca nomes como fora do DNS", not hosts()["vpn.exemplo.test"][0])
        admin.execute("UPDATE superficie_hosts SET proxima_conferencia = now() - interval '1 second' WHERE cliente_id = %s AND nome = 'vpn.exemplo.test'", (cliente,))

        def trava(nome, ips):
            raise KeyboardInterrupt()
        try:
            superficie.passo_de_conferencia(banco, trava)
        except KeyboardInterrupt:
            pass
        espera = admin.execute("SELECT proxima_conferencia - now() FROM superficie_hosts WHERE cliente_id = %s AND nome = 'vpn.exemplo.test'", (cliente,)).fetchone()[0]
        registrar("nome cuja conferência parou no meio volta só daqui a alguns minutos", timedelta(minutes=9) < espera <= timedelta(minutes=10), str(espera))

        admin.execute("UPDATE superficie_dominios SET ativo = false WHERE id = %s", (dominio,))
        vencer_tudo()
        admin.execute("UPDATE superficie_dominios SET proxima_descoberta = now() WHERE id = %s", (dominio,))
        conferidos.clear()
        registrar("domínio pausado não é procurado nem conferido",
                  not superficie.passo_de_descoberta(banco, lambda d: dict(nomes)) and superficie.passo_de_conferencia(banco, conferir) == 0 and not conferidos)
    finally:
        superficie.tomada.avaliar = avaliar_original
        for tabela in TABELAS:
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))
        admin.execute("DELETE FROM cves_versoes WHERE cve = ANY(%s)", (CVES,))
        admin.execute("DELETE FROM cves WHERE cve = ANY(%s)", (CVES,))
        admin.close()
        banco.fechar()
        outro.fechar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
