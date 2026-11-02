#!/usr/bin/env python3
"""Fontes de dados com gerenciadores reais: syslog de verdade e o comando de instalação de agente.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_fontes.py

Apaga no final tudo o que criou.
"""

import secrets
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1")]

from roar_api import app as modulo_app  # noqa: E402
from roar_ingestao import fontes, provisao  # noqa: E402
from testar_ingestao import SUFIXO, URL, Ambiente, agente_ativo, esperar_gerenciador  # noqa: E402

app = modulo_app.app
RESULTADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def sh(*args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=400)
    return (r.stdout + r.stderr).strip()


def criar_usuario(amb, g):
    senha, email = secrets.token_urlsafe(18), f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
    amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, 'administrador')",
                      (g["cliente"], email, PasswordHasher().hash(senha)))
    return {"email": email, "senha": senha}


def remetente(nome):
    """Um equipamento na mesma rede do gerenciador, com endereço próprio."""
    conteiner = f"roar-teste-{nome}-{SUFIXO}"
    sh("docker", "run", "-d", "--name", conteiner, "--network", provisao.REDE, "python:3.12-alpine", "sleep", "3600")
    return conteiner, sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", conteiner)


def enviar(conteiner, host, marca, protocolo="tcp", porta=514):
    carimbo = datetime.now().strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
    mensagem = f"{carimbo} fw-matriz firewall[1]: conexao recusada {marca}\n"
    tipo = "socket.SOCK_STREAM" if protocolo == "tcp" else "socket.SOCK_DGRAM"
    programa = (f"import socket,time\ns=socket.socket(socket.AF_INET,{tipo})\ns.settimeout(5)\n"
                f"s.connect(({host!r},{porta}))\nfor _ in range(3):\n  s.send({mensagem!r}.encode());time.sleep(0.3)\ntime.sleep(1)\ns.close()\nprint('enviado')")
    return sh("docker", "exec", conteiner, "python", "-c", programa)


def chegou(amb, g, marca, limite=60):
    consulta = {"query": {"simple_query_string": {"query": marca, "fields": ["full_log"]}}}
    fim = time.time() + limite
    indice = provisao.indice_bruto_do(g["id"])
    while time.time() < fim:
        amb.indexer.sessao.post(f"{URL}/{indice}*/_refresh", timeout=30)
        r = amb.indexer.sessao.post(f"{URL}/{indice}*/_count", json=consulta, timeout=30)
        if r.ok and r.json().get("count"):
            return r.json()["count"]
        time.sleep(4)
    return 0


def esperar_no_ar(g):
    time.sleep(20)
    return esperar_gerenciador(g, 240)


def main():
    testar_validacao()
    amb = Ambiente()
    try:
        a, b = amb.gerenciador("fontes-a"), amb.gerenciador("fontes-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        ua, ub = criar_usuario(amb, a), criar_usuario(amb, b)
        banco = amb.banco
        fw, ip_fw = remetente("fw")
        amb.conteineres.append(fw)
        intruso, _ = remetente("intruso")
        amb.conteineres.append(intruso)
        registrar("equipamentos de teste com endereço", ip_fw, ip_fw)

        with TestClient(app, base_url="https://testserver") as http:
            registrar("fontes exigem sessão", http.get("/api/fontes").status_code == 401)
            http.post("/api/entrar", json=ua)

            print("\n== Syslog desligado", flush=True)
            marca0 = f"marca{uuid.uuid4().hex}"
            registrar("sem fonte, a porta não recebe", "enviado" not in enviar(fw, a["host"], marca0), "conexão recusada")

            print("\n== Syslog ligado pela tela", flush=True)
            r = http.post("/api/fontes", json={"nome": "Firewall", "protocolo": "tcp", "origens": [ip_fw]})
            registrar("fonte criada", r.status_code == 201, r.text[:120])
            fonte = r.json()["id"]
            registrar("fonte começa pendente", http.get("/api/fontes").json()["fontes"][0]["estado"] == "pendente")
            registrar("criação fica na auditoria", amb.um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'criar_fonte'", a["cliente"]) == 1)
            fontes.ciclo(banco)
            registrar("gerenciador volta depois de aplicar", esperar_no_ar(a))
            visto = http.get("/api/fontes").json()
            registrar("fonte fica ativa", visto["fontes"][0]["estado"] == "ativa", str(visto["fontes"][0])[:200])
            registrar("tela informa a porta do cliente", visto["porta_syslog"] == a["porta_eventos"] + 3, str(visto["porta_syslog"]))
            registrar("antes do primeiro dado, a tela diz que nada chegou", visto["fontes"][0]["saude"] == "nunca_recebeu", str(visto["fontes"][0]["saude"]))
            reinicios = sh("docker", "inspect", "-f", "{{.State.StartedAt}}", f"roar-ger-{a['id']}-gerenciador-1")
            fontes.ciclo(banco)
            registrar("sem mudança não reinicia", sh("docker", "inspect", "-f", "{{.State.StartedAt}}", f"roar-ger-{a['id']}-gerenciador-1") == reinicios)

            marca = f"marca{uuid.uuid4().hex}"
            registrar("equipamento permitido envia", "enviado" in enviar(fw, a["host"], marca), a["host"])
            registrar("log chega ao índice do cliente", chegou(amb, a, marca) >= 1)
            registrar("log não chega ao índice do outro cliente", amb.indexer.sessao.post(
                f"{URL}/{provisao.indice_bruto_do(b['id'])}*/_count",
                json={"query": {"simple_query_string": {"query": marca, "fields": ["full_log"]}}}, timeout=30).json().get("count", 0) == 0)
            achados = http.get("/api/logs", params={"busca": marca}).json()["logs"]
            registrar("log aparece nos logs brutos da tela", achados and marca in achados[0]["bruto"]["full_log"])
            registrar("a origem é o endereço do equipamento", achados and achados[0]["bruto"].get("location") == ip_fw, str(achados[0]["bruto"].get("location") if achados else None))
            saude = http.get("/api/fontes").json()["fontes"][0]
            registrar("tela mostra que está recebendo", saude["saude"] == "recebendo" and saude["ultimo_dado"], str((saude["saude"], saude["ultimo_dado"])))

            marca2 = f"marca{uuid.uuid4().hex}"
            enviar(intruso, a["host"], marca2)
            registrar("endereço fora da lista é ignorado", chegou(amb, a, marca2, limite=25) == 0)

            print("\n== Porta publicada", flush=True)
            publicada = visto["porta_syslog"]
            try:
                with socket.create_connection(("127.0.0.1", publicada), timeout=5):
                    aberta = True
            except OSError:
                aberta = False
            registrar("a porta do cliente está publicada no servidor", aberta, str(publicada))

            print("\n== Entradas ruins", flush=True)
            for nome, corpo in (("XML no endereço", {"nome": "x", "origens": ["1.1.1.1</allowed-ips><remote>"]}),
                                ("texto qualquer", {"nome": "x", "origens": ["firewall"]}),
                                ("internet inteira", {"nome": "x", "origens": ["0.0.0.0/0"]}),
                                ("rede larga demais", {"nome": "x", "origens": ["10.0.0.0/7"]}),
                                ("sem origem", {"nome": "x", "origens": []}),
                                ("protocolo estranho", {"nome": "x", "protocolo": "tcp</protocol>", "origens": ["1.1.1.1"]}),
                                ("IPv6", {"nome": "x", "origens": ["2001:db8::1"]})):
                registrar(f"recusado: {nome}", http.post("/api/fontes", json=corpo).status_code == 422)

            print("\n== Configuração que o gerenciador recusa", flush=True)
            antes = sh("docker", "exec", f"roar-ger-{a['id']}-gerenciador-1", "md5sum", "/var/ossec/etc/ossec.conf")
            ok, _ = provisao.aplicar_configuracao(a["id"], "<ossec_config><remote><connection>errada</connection></remote></ossec_config>")
            registrar("gerenciador reprova", not ok)
            registrar("configuração anterior volta", sh("docker", "exec", f"roar-ger-{a['id']}-gerenciador-1", "md5sum", "/var/ossec/etc/ossec.conf") == antes)
            registrar("a API do gerenciador continua no ar", esperar_gerenciador(a, 60))
            marca3 = f"marca{uuid.uuid4().hex}"
            enviar(fw, a["host"], marca3)
            registrar("a coleta continua depois da recusa", chegou(amb, a, marca3) >= 1)

            print("\n== Isolamento", flush=True)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ub)
            registrar("outro cliente não vê a fonte", http.get("/api/fontes").json()["fontes"] == [])
            registrar("outro cliente não desativa", http.post(f"/api/fontes/{fonte}/desativar").status_code == 404)
            registrar("outro cliente não acha o log", http.get("/api/logs", params={"busca": marca}).json()["logs"] == [])
            comando_b = http.get("/api/fontes/instalacao").json()["sistemas"][0]["comando"]
            registrar("cada cliente vê a própria senha", b["senha_inscricao"] in comando_b and a["senha_inscricao"] not in comando_b)
            http.post("/api/sair")
            http.cookies.clear()

            print("\n== Instalar agente pelo comando da tela", flush=True)
            http.post("/api/entrar", json=ua)
            sistemas = http.get("/api/fontes/instalacao").json()["sistemas"]
            registrar("ver o comando fica na auditoria", amb.um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'ver_instalacao_de_agente'", a["cliente"]) == 1)
            deb = next(s for s in sistemas if s["provado"])["comando"]
            nome = f"roar-teste-deb-{SUFIXO}"
            amb.conteineres.append(nome)
            sh("docker", "run", "-d", "--name", nome, "--hostname", nome, "--network", provisao.REDE, "ubuntu:24.04", "sleep", "3600")
            sh("docker", "exec", nome, "sh", "-c", "apt-get update -qq && apt-get install -y -qq curl sudo systemd lsb-release ca-certificates")
            # Dentro da rede dos contêineres o gerenciador atende nas portas internas, e não há systemd rodando.
            comando = (deb.replace("ENDERECO_DESTE_SERVIDOR", a["host"])
                       .replace(f"WAZUH_MANAGER_PORT='{a['porta_eventos']}'", "WAZUH_MANAGER_PORT='1514'")
                       .replace(f"WAZUH_REGISTRATION_PORT='{a['porta_inscricao']}'", "WAZUH_REGISTRATION_PORT='1515'")
                       .replace("sudo systemctl enable --now wazuh-agent", "/var/ossec/bin/wazuh-control start"))
            saida = sh("docker", "exec", nome, "sh", "-c", comando)
            agente = agente_ativo(a, nome, 180)
            registrar("o comando instala e o agente se inscreve", agente, str(agente) if agente else saida[-300:])
    finally:
        clientes = [g["cliente"] for g in amb.gerenciadores]
        amb.admin.execute("DELETE FROM fontes WHERE cliente_id = ANY(%s)", (clientes,))
        amb.admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


def testar_validacao():
    print("== Configuração gerada", flush=True)
    xml = fontes.fragmento_de_configuracao([
        {"tipo": "syslog", "config": {"protocolo": "tcp", "origens": ["10.0.0.5", "10.0.1.0/24"]}},
        {"tipo": "syslog", "config": {"protocolo": "tcp", "origens": ["10.0.0.5"]}},
        {"tipo": "syslog", "config": {"protocolo": "udp", "origens": ["192.168.1.1"]}},
    ])
    registrar("uma entrada por protocolo", xml.count("<remote>") == 2)
    registrar("origem repetida entra uma vez", xml.count("10.0.0.5/32") == 1)
    registrar("sem fonte não muda nada", fontes.fragmento_de_configuracao([]) == "")


if __name__ == "__main__":
    sys.exit(main())
