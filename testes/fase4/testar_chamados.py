#!/usr/bin/env python3
"""Chamados em ferramentas de ITSM (ServiceNow, Jira Service Management e GLPI), com servidores de exemplo locais.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_chamados.py

O servidor de exemplo responde como as APIs de verdade (Table API do ServiceNow, REST v3 do Jira, API REST do GLPI com
sessão). A criação e o acompanhamento passam pela mesma chamada que vai à internet, só com o endereço trocado para o
exemplo. Apaga no final tudo o que criou.
"""

import base64
import json
import os
import secrets
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "ueba")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import chamados, cofre, rede_externa  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
SENHA_DO_SERVICENOW = "sn-" + secrets.token_urlsafe(12)
TOKEN_DO_JIRA = "jira" + secrets.token_hex(12)
APP_DO_GLPI, USUARIO_DO_GLPI = "app" + secrets.token_hex(10), "usr" + secrets.token_hex(10)
SERVICO = {"pedidos": [], "status": 200, "sn_estado": "1", "jira_status": ("Aberto", "new"), "glpi_status": 1}


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class Ferramentas(BaseHTTPRequestHandler):
    def _responder(self, corpo, status=None):
        dados = json.dumps(corpo).encode()
        self.send_response(status or SERVICO["status"])
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(dados)

    def _anotar(self, corpo=None):
        SERVICO["pedidos"].append({"metodo": self.command, "caminho": self.path, "cabecalhos": dict(self.headers), "corpo": corpo})

    def do_GET(self):
        self._anotar()
        caminho = urlsplit(self.path).path
        if caminho.startswith("/api/now/table/incident/"):
            return self._responder({"result": {"state": SERVICO["sn_estado"]}})
        if caminho.startswith("/rest/api/3/issue/"):
            nome, categoria = SERVICO["jira_status"]
            return self._responder({"fields": {"status": {"name": nome, "statusCategory": {"key": categoria}}}})
        if caminho == "/apirest.php/initSession":
            certo = self.headers.get("App-Token") == APP_DO_GLPI and self.headers.get("Authorization") == f"user_token {USUARIO_DO_GLPI}"
            return self._responder({"session_token": "sessao-glpi"} if certo else ["ERROR_GLPI_LOGIN"], None if certo else 401)
        if caminho.startswith("/apirest.php/Ticket/"):
            return self._responder({"id": 77, "status": SERVICO["glpi_status"]})
        if caminho == "/apirest.php/killSession":
            return self._responder({})
        self._responder({}, 404)

    def do_POST(self):
        corpo = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        self._anotar(corpo)
        caminho = urlsplit(self.path).path
        if caminho == "/api/now/table/incident":
            return self._responder({"result": {"sys_id": "a1b2c3", "number": "INC0010023"}}, None if SERVICO["status"] != 200 else 201)
        if caminho == "/rest/api/3/issue":
            return self._responder({"id": "10001", "key": "SOC-12"}, None if SERVICO["status"] != 200 else 201)
        if caminho == "/apirest.php/Ticket":
            return self._responder({"id": 77, "message": "Item adicionado"}, None if SERVICO["status"] != 200 else 201)
        self._responder({}, 404)

    def log_message(self, *args):
        pass


def basico(usuario, senha):
    return "Basic " + base64.b64encode(f"{usuario}:{senha}".encode()).decode()


def main():
    cofre.gerar()
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), Ferramentas)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{servidor.server_address[1]}"
    os.environ["ROAR_DESTINO_INTERNO"] = "1"

    def chamar(metodo, endereco, cabecalhos=None, **kwargs):
        # O endereço de verdade (a instância, o site, o GLPI) vira o do exemplo; o resto é a chamada da produção.
        partes = urlsplit(endereco)
        return rede_externa.chamar(metodo, base + partes.path + (f"?{partes.query}" if partes.query else ""), cabecalhos, **kwargs)

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    clientes = []

    def organizacao(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        g = f"{nome}{SUFIXO}"
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 41000 + secrets.randbelow(19000)))
        acessos = {}
        for perfil in ("administrador", "auditor"):
            senha, email = secrets.token_urlsafe(18), f"{nome}-{perfil}-{SUFIXO}@exemplo.test"
            admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, %s, %s, %s)",
                          (c, email, f"Ana {perfil}", PasswordHasher().hash(senha), perfil))
            acessos[perfil] = {"email": email, "senha": senha}
        clientes.append(c)
        return {"id": c, "g": g, "acessos": acessos}

    def processar():
        return chamados.processar(banco, a["g"], a["id"], chamar=chamar, endereco_do_roar="roar.exemplo.test")

    def chamado(caso):
        return admin.execute("SELECT estado, numero, endereco, situacao_externa, mensagem, tentativas FROM chamados WHERE caso_id = %s", (caso,)).fetchone()

    def notas(caso):
        return [n[0] for n in admin.execute("SELECT texto FROM casos_notas WHERE caso_id = %s AND automatica ORDER BY id", (caso,)).fetchall()]

    try:
        a, b = organizacao("cham"), organizacao("chamb")
        with TestClient(app, base_url="https://testserver") as http:
            http.post("/api/entrar", json=a["acessos"]["administrador"])

            print("\n== Cadastro", flush=True)
            for nome, corpo in (("instância que não é do ServiceNow", {"tipo": "servicenow", "campos": {"instancia": "empresa.exemplo.com", "usuario": "roar"}, "segredo": "x"}),
                                ("site que não é do Jira", {"tipo": "jira", "campos": {"site": "jira.exemplo.com", "email": "a@b.com", "projeto": "SOC"}, "segredo": "x"}),
                                ("projeto do Jira inválido", {"tipo": "jira", "campos": {"site": "empresa.atlassian.net", "email": "a@b.com", "projeto": "s o c"}, "segredo": "x"}),
                                ("GLPI sem https", {"tipo": "glpi", "campos": {"endereco": "http://glpi.empresa.test/apirest.php"}, "segredo": json.dumps({"app_token": APP_DO_GLPI, "usuario": USUARIO_DO_GLPI})}),
                                ("GLPI sem o token do aplicativo", {"tipo": "glpi", "campos": {"endereco": "https://glpi.empresa.test/apirest.php"}, "segredo": USUARIO_DO_GLPI}),
                                ("senha com quebra de linha", {"tipo": "servicenow", "campos": {"instancia": "empresa.service-now.com", "usuario": "roar"}, "segredo": "a\nb"})):
                registrar(f"recusado: {nome}", http.post("/api/fontes/nuvem", json={"nome": "x", **corpo}).status_code == 422)
            fontes = {}
            for tipo, campos, segredo in (("servicenow", {"instancia": "https://Empresa.service-now.com/", "usuario": "roar.integracao"}, SENHA_DO_SERVICENOW),
                                          ("jira", {"site": "empresa.atlassian.net", "email": "Soc@Empresa.com", "projeto": "soc", "tipo_de_item": "Task"}, TOKEN_DO_JIRA),
                                          ("glpi", {"endereco": "https://glpi.empresa.test/apirest.php"}, json.dumps({"app_token": APP_DO_GLPI, "usuario": USUARIO_DO_GLPI}))):
                r = http.post("/api/fontes/nuvem", json={"nome": tipo.capitalize(), "tipo": tipo, "campos": campos, "segredo": segredo})
                registrar(f"{tipo} conectado", r.status_code == 201, r.text[:120])
                fontes[tipo] = r.json()["id"]
            visto = http.get("/api/fontes").text
            registrar("nenhuma credencial volta pela tela", all(x not in visto for x in (SENHA_DO_SERVICENOW, TOKEN_DO_JIRA, APP_DO_GLPI, USUARIO_DO_GLPI)))
            config = admin.execute("SELECT config FROM fontes WHERE id = %s", (fontes["servicenow"],)).fetchone()[0]
            registrar("o endereço é guardado limpo", config["instancia"] == "empresa.service-now.com", str(config))
            admin.execute("UPDATE fontes SET estado = 'ativa' WHERE id = ANY(%s)", (list(fontes.values()),))

            print("\n== Abrir", flush=True)
            casos = {}
            for tipo, severidade in (("servicenow", "critica"), ("jira", "alta"), ("glpi", "media")):
                casos[tipo] = http.post("/api/casos", json={"titulo": f"Conta invadida ({tipo})", "severidade": severidade}).json()["id"]
            ferramentas = http.get(f"/api/casos/{casos['servicenow']}").json()["ferramentas"]
            registrar("o caso lista as ferramentas conectadas", sorted(f["tipo"] for f in ferramentas) == ["glpi", "jira", "servicenow"])
            registrar("com várias ferramentas, é preciso escolher", http.post(f"/api/casos/{casos['servicenow']}/chamado", json={}).status_code == 422)
            for tipo in casos:
                registrar(f"pedido no {tipo}", http.post(f"/api/casos/{casos[tipo]}/chamado", json={"fonte_id": fontes[tipo]}).status_code == 202)
            registrar("pedir de novo é recusado", http.post(f"/api/casos/{casos['jira']}/chamado", json={"fonte_id": fontes["jira"]}).status_code == 409)
            registrar("a tela mostra o pedido", http.get(f"/api/casos/{casos['jira']}").json()["chamado"]["estado"] == "pedido")
            SERVICO["pedidos"].clear()
            registrar("o serviço cria os três", processar() == 3)
            sn, jira, glpi = (chamado(casos[t]) for t in ("servicenow", "jira", "glpi"))
            registrar("ServiceNow: número e endereço do incidente", sn[:3] == ("aberto", "INC0010023", "https://empresa.service-now.com/nav_to.do?uri=incident.do?sys_id=a1b2c3"), str(sn))
            registrar("Jira: chave e endereço do item", jira[:3] == ("aberto", "SOC-12", "https://empresa.atlassian.net/browse/SOC-12"), str(jira))
            registrar("GLPI: número e endereço do chamado", glpi[:3] == ("aberto", "77", "https://glpi.empresa.test/front/ticket.form.php?id=77"), str(glpi))
            pedidos = {p["caminho"].split("?")[0]: p for p in SERVICO["pedidos"] if p["metodo"] == "POST"}
            incidente = pedidos["/api/now/table/incident"]
            registrar("ServiceNow: usuário e senha, crítico vira impacto e urgência 1", incidente["cabecalhos"].get("Authorization") == basico("roar.integracao", SENHA_DO_SERVICENOW)
                      and incidente["corpo"]["impact"] == 1 and incidente["corpo"]["urgency"] == 1 and incidente["corpo"]["short_description"] == "[Roar] Conta invadida (servicenow)")
            item = pedidos["/rest/api/3/issue"]
            registrar("Jira: e-mail e token, projeto, tipo e etiquetas", item["cabecalhos"].get("Authorization") == basico("soc@empresa.com", TOKEN_DO_JIRA)
                      and item["corpo"]["fields"]["project"] == {"key": "SOC"} and item["corpo"]["fields"]["issuetype"] == {"name": "Task"}
                      and "severidade-alta" in item["corpo"]["fields"]["labels"], json.dumps(item["corpo"])[:200])
            ticket = pedidos["/apirest.php/Ticket"]
            registrar("GLPI: sessão com os dois tokens, média vira urgência 3", ticket["cabecalhos"].get("Session-Token") == "sessao-glpi"
                      and ticket["cabecalhos"].get("App-Token") == APP_DO_GLPI and ticket["corpo"]["input"]["urgency"] == 3)
            registrar("GLPI: a sessão é encerrada", any(p["caminho"].endswith("/killSession") for p in SERVICO["pedidos"]))
            registrar("o chamado leva o link de volta e o número do caso", f"nº {casos['servicenow']}" in incidente["corpo"]["description"]
                      and "https://roar.exemplo.test/casos" in incidente["corpo"]["description"])
            registrar("o chamado não leva os alertas", "alerta nº" not in json.dumps([incidente["corpo"], item["corpo"], ticket["corpo"]]))
            registrar("o histórico do caso conta que o chamado abriu", "Chamado SOC-12 aberto no Jira: https://empresa.atlassian.net/browse/SOC-12" in notas(casos["jira"]),
                      str(notas(casos["jira"])))
            registrar("a tela mostra o número", http.get(f"/api/casos/{casos['servicenow']}").json()["chamado"]["numero"] == "INC0010023")

            print("\n== Acompanhar", flush=True)
            SERVICO["pedidos"].clear()
            registrar("respeita o intervalo", processar() == 0 and not SERVICO["pedidos"])
            admin.execute("UPDATE chamados SET conferido_em = now() - interval '10 minutes' WHERE cliente_id = %s", (a["id"],))
            SERVICO["sn_estado"], SERVICO["jira_status"] = "2", ("Em andamento", "indeterminate")
            processar()
            registrar("ainda aberto: guarda a situação", chamado(casos["servicenow"])[:4] == ("aberto", "INC0010023", chamado(casos["servicenow"])[2], "Em andamento")
                      and chamado(casos["jira"])[3] == "Em andamento" and chamado(casos["glpi"])[3] == "Novo")
            admin.execute("UPDATE chamados SET conferido_em = now() - interval '10 minutes' WHERE cliente_id = %s", (a["id"],))
            SERVICO["sn_estado"], SERVICO["jira_status"], SERVICO["glpi_status"] = "6", ("Concluído", "done"), 5
            processar()
            registrar("resolvido nas três ferramentas", [chamado(casos[t])[0] for t in casos] == ["resolvido"] * 3, str([chamado(casos[t])[:4] for t in casos]))
            registrar("o caso ganha a nota da resolução", notas(casos["glpi"])[-1].startswith("O chamado 77 ficou solucionado no GLPI"), notas(casos["glpi"])[-1])
            registrar("o caso não é encerrado sozinho", http.get(f"/api/casos/{casos['glpi']}").json()["caso"]["estado"] != "encerrado")
            SERVICO["pedidos"].clear()
            admin.execute("UPDATE chamados SET conferido_em = now() - interval '10 minutes' WHERE cliente_id = %s", (a["id"],))
            registrar("resolvido não é mais conferido", processar() == 0 and not SERVICO["pedidos"])

            print("\n== Problemas", flush=True)
            novo = http.post("/api/casos", json={"titulo": "Credencial errada", "severidade": "baixa"}).json()["id"]
            http.post(f"/api/casos/{novo}/chamado", json={"fonte_id": fontes["servicenow"]})
            SERVICO["status"] = 401
            processar()
            registrar("credencial recusada aparece no caso", "credencial" in (chamado(novo)[4] or "") and chamado(novo)[0] == "pedido", str(chamado(novo)))
            processar()
            processar()
            registrar("depois de três tentativas, não abriu", chamado(novo)[0] == "falhou" and chamado(novo)[5] == 3, str(chamado(novo)))
            registrar("e o caso conta o porquê", any("Não foi possível abrir o chamado no ServiceNow" in n for n in notas(novo)))
            SERVICO["status"] = 200
            registrar("tentar de novo funciona", http.post(f"/api/casos/{novo}/chamado", json={"fonte_id": fontes["servicenow"]}).status_code == 202)
            processar()
            registrar("e abre", chamado(novo)[0] == "aberto")

            print("\n== Quem pode", flush=True)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=a["acessos"]["auditor"])
            registrar("quem só lê vê o chamado", http.get(f"/api/casos/{casos['jira']}").json()["chamado"]["numero"] == "SOC-12")
            registrar("mas não pede", http.post(f"/api/casos/{novo}/chamado", json={"fonte_id": fontes["servicenow"]}).status_code == 403)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=b["acessos"]["administrador"])
            registrar("outra organização não pede no caso daqui", http.post(f"/api/casos/{novo}/chamado", json={"fonte_id": fontes["servicenow"]}).status_code == 404)
            outro = http.post("/api/casos", json={"titulo": "Caso da outra", "severidade": "baixa"}).json()["id"]
            registrar("nem com a ferramenta daqui", http.post(f"/api/casos/{outro}/chamado", json={"fonte_id": fontes["servicenow"]}).status_code == 422)
    finally:
        servidor.shutdown()
        banco.fechar()
        for tabela in ("chamados", "casos_notas", "casos_itens", "casos", "fontes", "segredos", "auditoria"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id = ANY(SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM gerenciadores WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
