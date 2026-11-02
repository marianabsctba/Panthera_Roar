#!/usr/bin/env python3
"""Conectores que já vêm no Wazuh, com gerenciador e agentes reais. Requer infra/subir.sh e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_conectores.py

Com conta real só funciona o aviso, que vai a um receptor local. Nas nuvens, prova que a configuração é aceita,
que o módulo roda e por onde a credencial passa, mas não que os dados chegam. Apaga no final tudo o que criou.
"""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import cofre, fontes, provisao  # noqa: E402
from roar_motor import acoes, blocos  # noqa: E402
from testar_ingestao import AGENTE_CONF, SUFIXO, Ambiente, agente_ativo, esperar_gerenciador  # noqa: E402

RESULTADOS = []
GUID_A, GUID_B, GUID_C = "11111111-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "99999999-8888-7777-6666-555555555555"
RECEPTOR = """
import http.server
class R(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        corpo = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        open('/tmp/recebido', 'ab').write(self.path.encode() + b' ' + corpo + b'\\n')
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
http.server.HTTPServer(('0.0.0.0', 8080), R).serve_forever()
"""


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def sh(*args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=400)
    return (r.stdout + r.stderr).strip()


def subir_agente(amb, g, pasta):
    conf, passe, log = pasta / "c.conf", pasta / "c.pass", pasta / "c.log"
    conf.write_text(AGENTE_CONF.format(host=g["host"]))
    log.touch()
    passe.write_text(g["senha_inscricao"] + "\n")
    os.chmod(pasta, 0o755)
    os.chmod(log, 0o644)
    nome = f"roar-teste-con-{SUFIXO}"
    sh("docker", "run", "-d", "--name", nome, "--hostname", nome, "--cap-add", "NET_ADMIN", "--network", provisao.REDE,
       "-e", f"WAZUH_MANAGER_SERVER={g['host']}", "-v", f"{conf}:/wazuh-config-mount/etc/ossec.conf",
       "-v", f"{passe}:/wazuh-config-mount/etc/authd.pass", "-v", f"{log}:/var/log/roar-teste.log", "wazuh/wazuh-agent:4.14.9")
    amb.conteineres.append(nome)
    sh("docker", "exec", nome, "sh", "-c", "yum install -y -q iptables shadow-utils passwd net-tools; touch /etc/hosts.deny; useradd -m vitima; echo 'vitima:SenhaDeTeste1' | chpasswd")
    return nome, log


def esperar(condicao, limite=90, passo=4):
    fim = time.time() + limite
    valor = condicao()
    while not valor and time.time() < fim:
        time.sleep(passo)
        valor = condicao()
    return valor


def testar_formato():
    print("== Regras do formato", flush=True)

    def recusado(definicao):
        try:
            blocos.validar(definicao, acoes.validar_acao)
            return False
        except (blocos.DefinicaoInvalida, acoes.AcaoRecusada):
            return True

    quando = {"tipo": "evento", "regra_id": "5712"}
    desativar = {"tipo": "acao", "acao": "desativar_conta", "parametros": {}}
    aprovar = {"tipo": "aprovacao"}
    registrar("desativar sem aprovação é recusado", recusado({"quando": quando, "blocos": [desativar]}))
    registrar("aprovação depois não vale", recusado({"quando": quando, "blocos": [desativar, aprovar]}))
    registrar("aprovação antes vale", not recusado({"quando": quando, "blocos": [aprovar, desativar]}))
    registrar("aprovação antes do se vale dentro dele", not recusado({"quando": quando, "blocos": [aprovar, {
        "tipo": "se", "condicao": {"campo": "nivel", "op": "minimo", "valor": 1}, "entao": [desativar], "senao": []}]}))
    registrar("aprovação em outro ramo não vale", recusado({"quando": quando, "blocos": [{"tipo": "paralelo", "ramos": [[aprovar], [desativar]]}]}))
    registrar("prazo inventado é recusado", recusado({"quando": quando, "blocos": [aprovar, {"tipo": "acao", "acao": "desativar_conta", "parametros": {"duracao_minutos": 7}}]}))
    registrar("forma de bloqueio inventada é recusada", recusado({"quando": quando, "se": [{"campo": "alvo_externo", "op": "igual", "valor": True}],
                                                                   "blocos": [{"tipo": "acao", "acao": "bloquear_ip", "parametros": {"metodo": "rm -rf"}}]}))
    for nome, conta in (("root", "root"), ("ROOT em maiúsculas", "ROOT"), ("Administrator", "Administrator"), ("com ponto e vírgula", "a;id"),
                        ("com espaço", "a b"), ("com caminho", "../a"), ("começa com traço", "-a"), ("vazia", ""), ("nula", None), ("com $", "$(id)")):
        try:
            acoes.conta_permitida(conta)
            registrar(f"conta recusada: {nome}", False)
        except acoes.AcaoRecusada:
            registrar(f"conta recusada: {nome}", True)
    try:
        acoes.conta_permitida("Maria", ["maria"])
        registrar("lista de protegidas não diferencia maiúsculas", False)
    except acoes.AcaoRecusada:
        registrar("lista de protegidas não diferencia maiúsculas", True)
    registrar("conta comum passa", acoes.conta_permitida("maria.silva") == "maria.silva")


def main():
    testar_formato()
    cofre.gerar()
    amb = Ambiente()
    receptor = f"roar-teste-receptor-{SUFIXO}"
    try:
        g = amb.gerenciador("con-a")
        registrar("gerenciador no ar", esperar_gerenciador(g))
        conteiner = f"roar-ger-{g['id']}-gerenciador-1"
        def no_gerenciador(comando):
            return sh("docker", "exec", conteiner, "sh", "-c", comando)
        pasta = Path(tempfile.mkdtemp(prefix="roar-con-"))
        nome, log = subir_agente(amb, g, pasta)
        agente = agente_ativo(g, nome, 180)
        registrar("agente ativo", agente, str(agente))
        registrar("as respostas com prazo chegam ao agente", esperar(lambda: all(
            f"{c}3600 " in sh("docker", "exec", nome, "sh", "-c", "cat /var/ossec/etc/shared/ar.conf") for c in ("firewall-drop", "route-null", "host-deny", "disable-account")), limite=120))
        registrar("o agente é reconhecido como Linux", acoes._plataforma(g["id"], agente) == "linux")

        print("\n== Respostas reais no ativo", flush=True)
        sh("docker", "exec", nome, "sh", "-c", "/var/ossec/bin/wazuh-control status >/dev/null")
        saida = acoes.desativar_conta(g["id"], {"usuario": "vitima", "agente_id": agente}, {"duracao_minutos": 60})
        registrar("desativar conta sai", saida["comando"] == "disable-account", str(saida))
        registrar("a conta fica travada no ativo", esperar(lambda: "LK" in sh("docker", "exec", nome, "passwd", "-S", "vitima") or "locked" in sh("docker", "exec", nome, "passwd", "-S", "vitima").lower()),
                  sh("docker", "exec", nome, "passwd", "-S", "vitima")[:80])
        for metodo, prova, comando in (("rota", "1.0.0.2", "ip route; route -n 2>/dev/null"), ("hosts", "1.0.0.3", "cat /etc/hosts.deny")):
            saida = acoes.bloquear_ip(g["id"], {"alvo": prova, "agente_id": agente}, {"metodo": metodo})
            achou = esperar(lambda: prova in sh("docker", "exec", nome, "sh", "-c", comando), limite=40)
            registrar(f"bloqueio por {metodo} chega ao ativo", achou, f"{saida['comando']}: {sh('docker', 'exec', nome, 'sh', '-c', 'tail -2 /var/ossec/logs/active-responses.log')[-160:] if not achou else ''}")
        saida = acoes.bloquear_ip(g["id"], {"alvo": "1.0.0.4", "agente_id": agente}, {})
        registrar("bloqueio padrão continua no firewall", saida["comando"] == "firewall-drop" and esperar(
            lambda: "1.0.0.4" in sh("docker", "exec", nome, "iptables", "-S", "INPUT"), limite=40))

        senha, email = secrets.token_urlsafe(18), f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
        amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash) VALUES (%s, %s, 'Analista', %s)",
                          (g["cliente"], email, PasswordHasher().hash(senha)))
        with TestClient(app, base_url="https://testserver") as http:
            http.post("/api/entrar", json={"email": email, "senha": senha})

            def conectar(tipo, campos, segredo, nome_da_fonte=None):
                return http.post("/api/fontes/nuvem", json={"nome": nome_da_fonte or tipo, "tipo": tipo, "campos": campos, "segredo": segredo})

            print("\n== Entradas ruins", flush=True)
            os.environ.pop("ROAR_DESTINO_INTERNO", None)
            conta_gcp = json.dumps({"type": "service_account", "project_id": "projeto-de-teste", "private_key_id": "x", "client_email": "a@b.c"})
            for nome_ruim, corpo in (("slack em outro endereço", ("slack", {"nivel": "10"}, "https://atacante.exemplo/h")),
                                     ("nível fora da faixa", ("slack", {"nivel": "99"}, "https://hooks.slack.com/x")),
                                     ("bucket com XML", ("aws", {"bucket": "a</name>", "chave_de_acesso": "AKIAABCDEFGHIJKLMNOP"}, "s")),
                                     ("chave da AWS com quebra", ("aws", {"bucket": "bucket-de-teste", "chave_de_acesso": "AKIAABCDEFGHIJKLMNOP"}, "s\n[outro]")),
                                     ("segredo do Azure com quebra", ("azure", {"dominio": "a.onmicrosoft.com", "aplicativo": GUID_A, "workspace": GUID_B}, "s\napplication_id = x")),
                                     ("Google sem ser conta de serviço", ("gcp", {"projeto": "projeto-teste", "assinatura": "sub"}, '{"type": "user"}')),
                                     ("Google sem JSON", ("gcp", {"projeto": "projeto-teste", "assinatura": "sub"}, "abc")),
                                     ("chave com XML", ("virustotal", {}, "abc</api_key><x>")),
                                     ("tipo desconhecido", ("shuffle", {}, "x"))):
                registrar(f"recusado: {nome_ruim}", conectar(*corpo).status_code == 422)

            print("\n== Nuvens", flush=True)
            segredo_aws, segredo_azure = f"aws-{uuid.uuid4().hex}", f"azure-{uuid.uuid4().hex}"
            for tipo, campos, segredo in (("msgraph", {"locatario": GUID_A, "aplicativo": GUID_B}, f"graph-{uuid.uuid4().hex}"),
                                          ("aws", {"bucket": "bucket-de-teste", "chave_de_acesso": "AKIAABCDEFGHIJKLMNOP"}, segredo_aws),
                                          ("azure", {"dominio": "empresa.onmicrosoft.com", "aplicativo": GUID_A, "workspace": GUID_C}, segredo_azure),
                                          ("gcp", {"projeto": "projeto-de-teste", "assinatura": "assinatura-teste"}, conta_gcp)):
                r = conectar(tipo, campos, segredo)
                registrar(f"{tipo} criado", r.status_code == 201, r.text[:120])
            registrar("segundo Google Cloud é recusado, o módulo aceita um só", conectar("gcp", {"projeto": "projeto-de-outro", "assinatura": "outra"}, conta_gcp).status_code == 409)
            fontes.ciclo(amb.banco)
            time.sleep(20)
            registrar("gerenciador volta", esperar_gerenciador(g, 240))
            vistos = http.get("/api/fontes").json()["fontes"]
            registrar("todos ficam ativos", all(f["estado"] == "ativa" for f in vistos), str([(f["tipo"], f["estado"], f["mensagem"]) for f in vistos])[:300])
            registrar("as credenciais não voltam pela tela", segredo_aws not in http.get("/api/fontes").text and segredo_azure not in http.get("/api/fontes").text)
            registrar("o arquivo do Azure existe e não é legível por todos", "-rw-r-----" in no_gerenciador("ls -l /var/ossec/etc/roar-credenciais/"))
            registrar("a credencial da AWS está no arquivo, e não na configuração",
                      segredo_aws in no_gerenciador("cat /root/.aws/credentials") and segredo_aws not in no_gerenciador("cat /var/ossec/etc/ossec.conf"))
            for marca, nome_do_modulo in (("ms-graph", "Graph"), ("aws-s3", "AWS"), ("azure-logs", "Azure"), ("gcp-pubsub", "Google Cloud")):
                saida = esperar(lambda: no_gerenciador(f"grep -E 'wazuh-modulesd:{marca}' /var/ossec/logs/ossec.log | tail -2"), limite=60)
                registrar(f"módulo {nome_do_modulo} rodando", saida, (saida or "")[:220].replace("\n", " | "))

            print("\n== Aviso de verdade, com um receptor local", flush=True)
            sh("docker", "run", "-d", "--name", receptor, "--network", provisao.REDE, "python:3.12-alpine", "python", "-c", RECEPTOR)
            amb.conteineres.append(receptor)
            os.environ["ROAR_DESTINO_INTERNO"] = "1"
            r = conectar("slack", {"nivel": "3"}, f"http://{receptor}:8080/hook-secreto")
            registrar("aviso criado", r.status_code == 201, r.text[:100])
            aviso = r.json()["id"]
            fontes.ciclo(amb.banco)
            time.sleep(20)
            esperar_gerenciador(g, 240)
            registrar("o processo de avisos está rodando", esperar(lambda: "wazuh-integratord" in no_gerenciador("/var/ossec/bin/wazuh-control status | grep integratord | grep -v 'not running'"), limite=40),
                      no_gerenciador("/var/ossec/bin/wazuh-control status | grep integratord"))
            registrar("a tela não finge saber se o aviso funciona", next(f for f in http.get("/api/fontes").json()["fontes"] if f["id"] == aviso)["saude"] is None)
            marca = f"marca{uuid.uuid4().hex}"
            with open(log, "a") as f:
                for i in range(14):
                    f.write(f"Nov  2 12:00:0{i % 10} servidor sshd[9{i}]: Failed password for invalid user {marca} from 1.0.0.9 port 4{i} ssh2\n")
            chegou = esperar(lambda: marca in sh("docker", "exec", receptor, "cat", "/tmp/recebido"), limite=120)
            registrar("o alerta real chega ao destino do aviso", chegou, sh("docker", "exec", conteiner, "sh", "-c", "tail -3 /var/ossec/logs/integrations.log")[-200:] if not chegou else "")

            print("\n== Tirar", flush=True)
            for f in http.get("/api/fontes").json()["fontes"]:
                http.post(f"/api/fontes/{f['id']}/desativar")
            fontes.ciclo(amb.banco)
            time.sleep(20)
            registrar("gerenciador volta depois de tirar tudo", esperar_gerenciador(g, 240))
            registrar("as credenciais saem do gerenciador", segredo_aws not in no_gerenciador("cat /root/.aws/credentials 2>/dev/null") and
                      not no_gerenciador("ls /var/ossec/etc/roar-credenciais/ 2>/dev/null"))
            conf = no_gerenciador("cat /var/ossec/etc/ossec.conf")
            registrar("os módulos saem da configuração", not any(x in conf for x in ("<ms-graph>", "aws-s3", "azure-logs", "<gcp-pubsub>", "<integration>")))
    finally:
        clientes = [x["cliente"] for x in amb.gerenciadores]
        for tabela in ("fontes", "segredos", "usuarios"):
            amb.admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
