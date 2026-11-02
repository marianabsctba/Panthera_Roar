#!/usr/bin/env python3
"""Ponte do scanner de rede, com varreduras reais num Ubuntu antigo descartável. Leva cerca de uma hora.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_greenbone.py

Precisa do módulo ligado: infra/greenbone.sh
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

from lxml import etree  # noqa: E402

from roar_api import app as modulo  # noqa: E402
from roar_ingestao import varredura as v  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
ALVO = f"roar-teste-rede-{SUFIXO}"
REDE = "roar-greenbone_default"
PACOTE = "libxml2"


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)


def main():
    print("== Tradução", flush=True)
    xml = etree.fromstring("""<get_reports_response><report><report><host><ip>10.0.0.1</ip><detail><name>Auth-SSH-Success</name><value>x</value></detail><detail><name>hostname</name><value>srv</value></detail></host><host><ip>10.0.0.2</ip></host>
      <results><result><name>Falha</name><host>10.0.0.1</host><port>22/tcp</port><severity>9.8</severity><description>  evidencia </description><nvt oid="1.2.3"><solution type="VendorFix">Atualize</solution><refs><ref type="cve" id="CVE-2024-1"/><ref type="url" id="http://x"/></refs></nvt></result></results></report></report></get_reports_response>""")
    achados, respondendo, autenticados = v.ler_greenbone(xml)
    a = achados[0]
    registrar("lê host, porta, nota e CVE", (a.host, a.porta, a.cvss, a.cves, a.regra) == ("10.0.0.1", "22/tcp", 9.8, ["CVE-2024-1"], "1.2.3"), str(a))
    registrar("lê solução, evidência e nome", (a.solucao, a.evidencia, a.nome_do_host) == ("Atualize", "evidencia", "srv"))
    registrar("distingue quem respondeu de quem aceitou a credencial", respondendo == ["10.0.0.1", "10.0.0.2"] and autenticados == {"10.0.0.1"})

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"rede-{SUFIXO}",)).fetchone()[0])
    senha, email = secrets.token_urlsafe(18), f"rede-{SUFIXO}@exemplo.test"
    admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Pessoa', %s, 'administrador')", (cliente, email, PasswordHasher().hash(senha)))
    senha_ssh = secrets.token_hex(16)

    try:
        pasta = tempfile.mkdtemp()
        Path(pasta, "Dockerfile").write_text('FROM ubuntu:20.04\nENV DEBIAN_FRONTEND=noninteractive\nRUN apt-get update -qq && apt-get install -y -qq openssh-server nginx-light >/dev/null && mkdir -p /run/sshd\nRUN useradd -m -s /bin/bash varredura\nCMD ["/bin/sh", "-c", "nginx; exec /usr/sbin/sshd -D -e"]\n')
        docker("build", "-q", "-t", "roar-teste-alvo-rede", pasta)
        docker("run", "-d", "--name", ALVO, "--network", REDE, "roar-teste-alvo-rede")
        docker("exec", ALVO, "sh", "-c", f"echo 'varredura:{senha_ssh}' | chpasswd")
        ip = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", ALVO).stdout.strip()
        registrar("o alvo está no ar", ip, ip)

        with TestClient(modulo.app, base_url="https://testserver") as http:
            http.post("/api/entrar", json={"email": email, "senha": senha})
            modelo = http.post("/api/vuln/modelos", json={"nome": "Rede", "ferramenta": "rede"}).json()["id"]
            alvo = http.post("/api/vuln/alvos", json={"nome": "Servidor", "hosts": [ip], "modelo_id": modelo, "a_cada_dias": 0, "credencial_tipo": "ssh", "credencial_usuario": "varredura", "credencial_senha": senha_ssh})
            registrar("cria o alvo com credencial", alvo.status_code == 201, alvo.text[:120])
            alvo = alvo.json()["id"]

            print("\n== Com credencial", flush=True)
            http.post("/api/vuln/varreduras", json={"alvo_id": alvo})
            v.processar_cliente(banco, cliente)
            u = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            registrar("termina bem", u["estado"] == "concluida", str(u))
            registrar("a credencial entrou de verdade", u["autenticada"] is True, str(u["autenticada"]))
            achados = []
            while True:
                pagina = http.get("/api/vuln/achados", params={"deslocamento": len(achados)}).json()
                achados += pagina["achados"]
                if not pagina["tem_mais"]:
                    break
            print(f"   {len(achados)} achados abertos", flush=True)
            registrar("acha falhas", len(achados) >= 10, str(len(achados)))
            registrar("o ativo certo", {a["host"] for a in achados} == {ip})
            registrar("o relatório filtra achado pouco confiável, e o informativo", all(a["severidade"] != "informativa" or a["cvss"] == 0 for a in achados))
            detalhes = [http.get(f"/api/vuln/achados/{a['id']}").json() for a in achados]
            do_pacote = [d["id"] for d in detalhes if f"Vulnerable package:   {PACOTE}" in (d["evidencia"] or "")]
            registrar(f"acha falha em {PACOTE}, com o pacote na evidência", do_pacote, str(len(do_pacote)))
            registrar("traz como corrigir", any(d["solucao"] for d in detalhes))
            registrar("a senha da credencial não aparece em lugar nenhum", senha_ssh not in json.dumps(detalhes, default=str))

            print("\n== O scanner não guarda nada", flush=True)
            with v._Greenbone() as g:
                nomes = [c.findtext("name") for c in g.get_credentials().findall("credential")]
                tarefas = [c.findtext("name") for c in g.get_tasks().findall("task")]
                alvos = [c.findtext("name") for c in g.get_targets().findall("target")]
            registrar("a senha do cliente saiu do scanner", not [n for n in nomes if str(n).startswith("roar-")], str(nomes))
            registrar("tarefa e alvo também", not [n for n in tarefas + alvos if str(n).startswith("roar-")], str(tarefas + alvos))

            print("\n== Corrigir de verdade", flush=True)
            r = docker("exec", ALVO, "dpkg", "--purge", "--force-depends", PACOTE)
            registrar("o pacote vulnerável saiu do alvo", r.returncode == 0, r.stderr[-120:])
            http.post(f"/api/vuln/achados/{do_pacote[0]}/estado", json={"estado": "correcao_informada", "motivo": f"Removi o {PACOTE} do servidor."})
            r = http.post(f"/api/vuln/achados/{do_pacote[0]}/confirmar")
            registrar("pede a varredura de confirmação", r.status_code == 201, r.text[:120])
            v.processar_cliente(banco, cliente)
            u = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            registrar("termina bem", u["estado"] == "concluida" and u["autenticada"] is True, str(u))
            confirmado = http.get(f"/api/vuln/achados/{do_pacote[0]}").json()
            registrar("a falha informada virou corrigida", confirmado["estado"] == "corrigido", confirmado["estado"])
            registrar("as outras falhas do pacote também", all(http.get(f"/api/vuln/achados/{i}").json()["estado"] == "corrigido" for i in do_pacote))
            registrar("o resto continua aberto", http.get("/api/vuln/achados").json()["achados"])

            print("\n== Senha errada", flush=True)
            antes = http.get("/api/vuln/indicadores").json()["abertos"]
            ruim = http.post("/api/vuln/alvos", json={"nome": "Senha errada", "hosts": [ip], "modelo_id": modelo, "a_cada_dias": 0, "credencial_tipo": "ssh", "credencial_usuario": "varredura", "credencial_senha": "senha-errada-de-proposito"}).json()["id"]
            http.post("/api/vuln/varreduras", json={"alvo_id": ruim})
            v.processar_cliente(banco, cliente)
            u = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            registrar("a tela mostra que a credencial não entrou", u["estado"] == "concluida" and u["autenticada"] is False, str(u))
            registrar("sem entrar, nada do que exigia credencial foi fechado", u["corrigidos"] == 0, str(u["corrigidos"]))
            registrar("os abertos continuam", http.get("/api/vuln/indicadores").json()["abertos"]["alta"] >= antes["alta"], str(antes))

            print("\n== Fora do ar", flush=True)
            docker("stop", "-t", "2", ALVO)
            alvo_fora = http.post("/api/vuln/alvos", json={"nome": "Fora", "hosts": ["172.31.255.254"], "modelo_id": modelo, "a_cada_dias": 0}).json()["id"]
            http.post("/api/vuln/varreduras", json={"alvo_id": alvo_fora})
            v.processar_cliente(banco, cliente)
            u = http.get("/api/vuln/varreduras").json()["varreduras"][0]
            registrar("sem resposta, falha com aviso, e nada fecha", u["estado"] == "falhou" and "respondeu" in (u["mensagem"] or ""), str(u))
    finally:
        docker("rm", "-f", ALVO)
        for tabela in ("vuln_historico", "vuln_achados", "vuln_ativos", "vuln_varreduras", "vuln_alvos", "vuln_modelos"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM segredos WHERE cliente_id = %s", (cliente,))
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
