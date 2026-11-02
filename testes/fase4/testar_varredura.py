#!/usr/bin/env python3
"""Ponta a ponta com as ferramentas de verdade, num alvo descartável criado aqui, em rede interna do Docker.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_varredura.py

Demora alguns minutos, e baixa os modelos do Nuclei e a base do Trivy na primeira vez.
"""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

REDE = f"roar-teste-rede-{uuid.uuid4().hex[:6]}"
os.environ["ROAR_VARREDURA_REDE"] = REDE
# Pasta vazia: a primeira execução num servidor novo também precisa funcionar.
os.environ["ROAR_VARREDURA_PASTA"] = tempfile.mkdtemp(prefix="varredura-", dir="/opt/panthera-roar")
# O catálogo inteiro leva muito tempo; aqui basta o que acha o que foi plantado.
os.environ["ROAR_NUCLEI_ETIQUETAS"] = "exposure,config,git,env"

from roar_api import app as modulo  # noqa: E402
from roar_ingestao import varredura as v  # noqa: E402
from roar_ingestao import vulnerabilidades as vuln  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
ALVO = f"roar-teste-web-{SUFIXO}"
URL = f"http://{ALVO}"


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)


def main():
    print("== Validação de alvo", flush=True)
    for texto, ferramenta in (("https://exemplo.test", "web"), ("http://10.0.0.5:8080/app", "web"), ("nginx:1.27", "conteiner"), ("ghcr.io/x/y:1", "conteiner"), ("aws", "nuvem"), ("10.0.0.0/24", "rede")):
        registrar(f"aceita {texto} em {ferramenta}", vuln.validar_alvo(texto, ferramenta))
    for texto, ferramenta in (("-t x", "web"), ("ftp://x", "web"), ("http://a b", "web"), ("https://u:s@x", "web"), ('http://x"y', "web"), ("10.0.0.5", "web"), ("--privileged", "conteiner"), ("x y", "conteiner"), ("x;id", "conteiner"), ("ibm", "nuvem"), ("-oX", "rede")):
        try:
            vuln.validar_alvo(texto, ferramenta)
            registrar(f"recusa {texto!r} em {ferramenta}", False)
        except vuln.HostInvalido:
            registrar(f"recusa {texto!r} em {ferramenta}", True)

    print("\n== Tradução", flush=True)
    a = v.ler_nuclei(json.dumps({"template-id": "t", "matched-at": "https://x.test:8443/a", "info": {"name": "N", "severity": "high", "classification": {"cvss-score": 7.5, "cve-id": ["CVE-2024-1"]}}}))[0]
    registrar("Nuclei: host, porta, nota e CVE", (a.host, a.porta, a.cvss, a.cves) == ("x.test", "8443/tcp", 7.5, ["CVE-2024-1"]), str(a))
    a = v.ler_nuclei(json.dumps({"template-id": "t", "matched-at": "http://x.test/a", "info": {"name": "N", "severity": "medium", "classification": {"cve-id": None}}}))[0]
    registrar("Nuclei sem nota usa a severidade dele", a.cvss is None and a.severidade == "media" and a.cves == [])
    registrar("Nuclei vazio não quebra", v.ler_nuclei("") == [])
    z = v.ler_zap(json.dumps({"site": [{"@name": "http://x", "@host": "X.test", "@port": "80", "alerts": [{"alertRef": "1", "pluginid": "1", "name": "A", "riskcode": "3", "solution": "<p>Faça</p>", "instances": [{"method": "GET", "uri": "http://x/"}]}]}]}))[0]
    registrar("ZAP: alto, sem HTML na solução", z.severidade == "alta" and z.solucao == "Faça" and z.host == "x.test", str(z))
    t = v.ler_trivy(json.dumps({"Results": [{"Target": "img", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-2", "PkgName": "curl", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH", "CVSS": {"redhat": {"V3Score": 7.1}}}, {"VulnerabilityID": "GHSA-x", "PkgName": "y", "Severity": "LOW"}]}]}), "img:1")
    registrar("Trivy: nota de outra fonte, e correção", t[0].cvss == 7.1 and "versão 2" in t[0].solucao and t[0].cves == ["CVE-2024-2"])
    registrar("Trivy: identificador que não é CVE fica fora da lista de CVEs", t[1].cves == [] and t[1].severidade == "baixa")
    registrar("Trivy sem resultado não quebra", v.ler_trivy("{}", "img") == [])
    with tempfile.TemporaryDirectory() as pasta:
        (Path(pasta) / "known_services.log").write_text('{"host":"10.0.0.1","port_num":80,"port_proto":"tcp","service":["HTTP"]}\n{"host":"10.0.0.1","port_num":81,"port_proto":"tcp","service":[""]}\n')
        (Path(pasta) / "software.log").write_text('{"host":"10.0.0.1","host_p":80,"software_type":"HTTP::SERVER","name":"nginx","unparsed_version":"nginx/1.29"}\n{"host":"10.0.0.9","software_type":"HTTP::BROWSER","unparsed_version":"Mozilla"}\n')
        z = v.ler_zeek(pasta)
        registrar("Zeek: serviço e programa, sem o navegador de quem acessou", sorted(x.titulo for x in z) == ["Programa visto na escuta: nginx/1.29", "Serviço visto na escuta: HTTP"], str([x.titulo for x in z]))

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    site = tempfile.mkdtemp(prefix="site-", dir="/opt/panthera-roar")
    os.chmod(site, 0o755)
    Path(site, ".git").mkdir()
    Path(site, "index.html").write_text("<html><body>teste</body></html>")
    Path(site, ".env").write_text("DB_PASSWORD=valor-falso-de-teste\nAPP_KEY=valor-falso-de-teste\n")
    Path(site, ".git", "config").write_text('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://exemplo.test/x.git\n')
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"varredura-{SUFIXO}",)).fetchone()[0])
    senha, email = secrets.token_urlsafe(18), f"varredura-{SUFIXO}@exemplo.test"
    admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Pessoa', %s, 'administrador')", (cliente, email, PasswordHasher().hash(senha)))

    try:
        docker("network", "create", REDE)
        docker("run", "-d", "--name", ALVO, "--network", REDE, "-v", f"{site}:/usr/share/nginx/html:ro", "nginx:alpine")
        with TestClient(modulo.app, base_url="https://testserver") as http:
            http.post("/api/entrar", json={"email": email, "senha": senha})

            print("\n== Tela", flush=True)
            web = http.post("/api/vuln/modelos", json={"nome": "Web", "ferramenta": "web"}).json()["id"]
            imagem = http.post("/api/vuln/modelos", json={"nome": "Imagem", "ferramenta": "conteiner"}).json()["id"]
            rede = http.post("/api/vuln/modelos", json={"nome": "Rede", "ferramenta": "rede"}).json()["id"]
            registrar("modelo web recusa endereço sem esquema", http.post("/api/vuln/alvos", json={"nome": "Ruim", "hosts": ["10.0.0.5"], "modelo_id": web}).status_code == 422)
            registrar("modelo de imagem recusa opção", http.post("/api/vuln/alvos", json={"nome": "Ruim", "hosts": ["--privileged"], "modelo_id": imagem}).status_code == 422)
            alvo_web = http.post("/api/vuln/alvos", json={"nome": "Site", "hosts": [URL], "modelo_id": web, "a_cada_dias": 0}).json()["id"]
            alvo_img = http.post("/api/vuln/alvos", json={"nome": "Imagem", "hosts": ["nginx:alpine"], "modelo_id": imagem, "a_cada_dias": 0}).json()["id"]
            alvo_rede = http.post("/api/vuln/alvos", json={"nome": "Rede", "hosts": ["10.0.0.5"], "modelo_id": rede, "a_cada_dias": 0}).json()["id"]

            print("\n== Web: Nuclei e ZAP de verdade", flush=True)
            http.post("/api/vuln/varreduras", json={"alvo_id": alvo_web})
            registrar("o serviço executa a fila", v.processar_cliente(banco, cliente) == 1)
            ultima = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            registrar("a varredura termina bem", ultima["estado"] == "concluida", str(ultima))
            achados = http.get("/api/vuln/achados").json()["achados"]
            titulos = " ".join(a["titulo"] for a in achados)
            registrar("achou o .env exposto", any("env" in a["titulo"].lower() for a in achados), titulos[:300])
            registrar("achou o .git exposto", any("git" in a["titulo"].lower() for a in achados))
            registrar("o ZAP também entrou", any("header" in a["titulo"].lower() or "policy" in a["titulo"].lower() for a in achados))
            registrar("o achado é do ativo certo", {a["host"] for a in achados} == {ALVO}, str({a["host"] for a in achados}))
            graves = [a for a in achados if a["severidade"] in ("alta", "critica")]
            registrar("o .env exposto é grave", any("env" in a["titulo"].lower() for a in graves), str([a["titulo"] for a in graves])[:200])
            registrar("o segredo plantado não entra no achado", "valor-falso-de-teste" not in json.dumps([http.get(f"/api/vuln/achados/{a['id']}").json() for a in achados], default=str))

            print("\n== Corrigir de verdade", flush=True)
            Path(site, ".env").unlink()
            http.post("/api/vuln/varreduras", json={"alvo_id": alvo_web})
            v.processar_cliente(banco, cliente)
            ultima = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            registrar("a nova varredura fecha o que foi corrigido", ultima["estado"] == "concluida" and ultima["corrigidos"] >= 1, str(ultima))
            abertos = " ".join(a["titulo"].lower() for a in http.get("/api/vuln/achados").json()["achados"])
            registrar("o .env saiu dos abertos", "env" not in abertos, abertos[:200])
            registrar("o .git continua aberto", "git" in abertos)
            corrigidos = http.get("/api/vuln/achados", params={"estado": "corrigido"}).json()["achados"]
            registrar("o .env aparece como corrigido", any("env" in a["titulo"].lower() for a in corrigidos))

            print("\n== Alvo fora do ar não fecha nada", flush=True)
            antes = len(http.get("/api/vuln/achados").json()["achados"])
            docker("stop", "-t", "2", ALVO)
            http.post("/api/vuln/varreduras", json={"alvo_id": alvo_web})
            v.processar_cliente(banco, cliente)
            ultima = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            depois = len(http.get("/api/vuln/achados").json()["achados"])
            registrar("com o alvo caído, nenhum achado foi fechado", depois == antes, f"{antes} para {depois}, {ultima}")
            docker("start", ALVO)

            print("\n== Contêiner: Trivy de verdade", flush=True)
            http.post("/api/vuln/varreduras", json={"alvo_id": alvo_img})
            v.processar_cliente(banco, cliente)
            ultima = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            registrar("analisa a imagem", ultima["estado"] == "concluida", str(ultima))
            do_trivy = [a for a in http.get("/api/vuln/achados", params={"busca": "nginx:alpine"}).json()["achados"] if a["fonte"] == "conteiner"]
            registrar("acha falhas com CVE", any(a["cves"] for a in do_trivy) or ultima["novos"] == 0, f"{len(do_trivy)} achados")
            print(f"   {len(do_trivy)} achados na imagem", flush=True)

            print("\n== Sem scanner ligado", flush=True)
            http.post("/api/vuln/varreduras", json={"alvo_id": alvo_rede})
            v.processar_cliente(banco, cliente)
            ultima = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            registrar("rede ainda sem scanner diz isso na tela, sem fingir", ultima["estado"] == "falhou" and "não está ligado" in ultima["mensagem"], str(ultima))

            print("\n== Falhas", flush=True)
            http.post("/api/vuln/varreduras", json={"alvo_id": alvo_web})

            def explode(*_):
                raise RuntimeError("/caminho/interno com segredo")

            v.processar_cliente(banco, cliente, explode)
            ultima = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            registrar("erro interno não vaza para a tela", ultima["estado"] == "falhou" and "caminho" not in ultima["mensagem"], str(ultima["mensagem"]))
            http.post("/api/vuln/varreduras", json={"alvo_id": alvo_web})
            admin.execute("UPDATE vuln_varreduras SET estado = 'em_andamento' WHERE cliente_id = %s AND estado = 'pendente'", (cliente,))
            v.recuperar_interrompidas(banco, [cliente])
            registrar("serviço reiniciado libera o alvo preso", http.post("/api/vuln/varreduras", json={"alvo_id": alvo_web}).status_code == 201)
            v.processar_cliente(banco, cliente, lambda *_: vuln.Resultado("web", [], []))

            print("\n== Escuta passiva", flush=True)
            with tempfile.TemporaryDirectory() as pasta:
                (Path(pasta) / "known_services.log").write_text('{"host":"10.77.0.1","port_num":443,"port_proto":"tcp","service":["SSL"]}\n')
                registrar("registra o que viu", v.ingerir_sensor(banco, cliente, pasta) == 1)
                registrar("rodar de novo não duplica", v.ingerir_sensor(banco, cliente, pasta) == 1 and len(http.get("/api/vuln/achados", params={"busca": "10.77.0.1", "severidade": "informativa"}).json()["achados"]) == 1)
    finally:
        docker("rm", "-f", ALVO)
        docker("network", "rm", REDE)
        subprocess.run(["rm", "-rf", site, os.environ["ROAR_VARREDURA_PASTA"]], check=False)
        for tabela in ("vuln_historico", "vuln_achados", "vuln_ativos", "vuln_varreduras", "vuln_alvos", "vuln_modelos"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM auditoria WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = %s)", (cliente,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))
        admin.close()
        banco.fechar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
