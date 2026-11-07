#!/usr/bin/env python3
"""Fontes de identidade (Okta e Google Workspace), com gerenciador real e um Okta e um Google de exemplo locais.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_identidade.py

Os serviços de exemplo respondem como os de verdade (página pelo cabeçalho Link no Okta, nextPageToken e troca do JWT por
acesso no Google); a busca passa pela mesma chamada que vai à internet, só com o endereço trocado para o exemplo.
Apaga no final tudo o que criou.
"""

import base64
import json
import os
import secrets
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1"), str(RAIZ / "testes/fase4")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import cofre, fabricantes, identidade, provisao, rede_externa  # noqa: E402
from testar_api_generica import contar, criar_usuario  # noqa: E402
from testar_ingestao import Ambiente, esperar_gerenciador  # noqa: E402

RESULTADOS = []
TOKEN_DO_OKTA = "00" + secrets.token_urlsafe(30).replace("-", "a")
ACESSO_DO_GOOGLE = "ya29." + secrets.token_hex(16)
PRIVADA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CHAVE = {"type": "service_account", "client_email": "roar@exemplo.iam.gserviceaccount.com", "client_id": "123",
         "private_key": PRIVADA.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()}
SERVICO = {"okta": [], "workspace": {}, "pedidos": [], "assertivas": [], "status": 200}


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def evento_okta(uuid_, momento, tipo="user.session.start", resultado="SUCCESS", motivo=None, usuario="ana@empresa.com", ip="200.160.2.3"):
    return {"uuid": uuid_, "published": momento, "eventType": tipo, "displayMessage": "Evento de exemplo", "severity": "INFO",
            "outcome": {"result": resultado, "reason": motivo}, "actor": {"alternateId": usuario},
            "client": {"ipAddress": ip, "geographicalContext": {"country": "Brazil", "city": "Curitiba"}, "userAgent": {"rawUserAgent": "Mozilla"}},
            "target": [{"type": "User", "alternateId": usuario}]}


def atividade(qualificador, momento, nome, parametros=None, usuario="ana@empresa.com"):
    return {"id": {"time": momento, "uniqueQualifier": qualificador}, "actor": {"email": usuario}, "ipAddress": "200.160.2.3",
            "events": [{"name": nome, "type": "x", "parameters": parametros or []}]}


class Servico(BaseHTTPRequestHandler):
    def _responder(self, corpo, cabecalhos=None):
        dados = json.dumps(corpo).encode()
        self.send_response(SERVICO["status"])
        for k, v in (cabecalhos or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(dados)

    def do_GET(self):
        partes = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(partes.query).items()}
        SERVICO["pedidos"].append({"caminho": partes.path, "q": q, "autorizacao": self.headers.get("Authorization"), "host": self.headers.get("Host")})
        if partes.path == "/api/v1/logs":
            # Duas por página, só os posteriores ou iguais a since, como o Okta.
            itens = sorted((e for e in SERVICO["okta"] if e["published"] >= q["since"]), key=lambda e: e["published"])
            inicio = int(q.get("after", 0))
            pagina = itens[inicio:inicio + 2]
            cabecalhos = {}
            if inicio + 2 < len(itens):
                cabecalhos["Link"] = f'<https://empresa.okta.com/api/v1/logs?since={q["since"]}&after={inicio + 2}>; rel="next"'
            return self._responder(pagina, cabecalhos)
        aplicacao = partes.path.rsplit("/", 1)[-1]
        itens = [a for a in SERVICO["workspace"].get(aplicacao, []) if a["id"]["time"] >= q["startTime"]]
        inicio = int(q.get("pageToken", 0))
        corpo = {"items": itens[inicio:inicio + 2]}
        if inicio + 2 < len(itens):
            corpo["nextPageToken"] = str(inicio + 2)
        self._responder(corpo)

    def do_POST(self):
        tamanho = int(self.headers.get("Content-Length", 0))
        q = {k: v[0] for k, v in parse_qs(self.rfile.read(tamanho).decode()).items()}
        SERVICO["assertivas"].append(q)
        self._responder({"access_token": ACESSO_DO_GOOGLE, "expires_in": 3600, "token_type": "Bearer"})

    def log_message(self, *args):
        pass


def main():
    cofre.gerar()
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), Servico)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{servidor.server_address[1]}"
    os.environ["ROAR_DESTINO_INTERNO"] = "1"

    def chamar(metodo, endereco, cabecalhos=None, **kwargs):
        # O endereço de verdade (Okta do cliente, Google) vira o do exemplo; o resto é a chamada da produção.
        partes = urlsplit(endereco)
        return rede_externa.chamar(metodo, base + partes.path + (f"?{partes.query}" if partes.query else ""), cabecalhos, **kwargs)

    agora = datetime.now(timezone.utc)
    hora = lambda minutos: identidade._iso(agora - timedelta(minutes=minutos))  # noqa: E731

    print("\n== Okta: busca", flush=True)
    SERVICO["okta"] = [evento_okta("o1", hora(50)), evento_okta("o2", hora(40)), evento_okta("o3", hora(30), resultado="FAILURE", motivo="INVALID_CREDENTIALS"),
                       evento_okta("o4", hora(30), tipo="user.account.lock"), evento_okta("o5", hora(20)), evento_okta("velho", hora(60 * 30))]
    eventos, posicao = identidade.buscar_okta("empresa.okta.com", TOKEN_DO_OKTA, {}, chamar)
    registrar("o token vai no cabeçalho SSWS", SERVICO["pedidos"][0]["autorizacao"] == f"SSWS {TOKEN_DO_OKTA}")
    registrar("segue as páginas pelo cabeçalho Link", [e["id"] for e in eventos] == ["o1", "o2", "o3", "o4", "o5"], str([e["id"] for e in eventos]))
    registrar("na primeira busca, só o último dia", "velho" not in [e["id"] for e in eventos])
    plano = eventos[2]
    registrar("evento plano com os nomes do Roar", plano["srcuser"] == "ana@empresa.com" and plano["srcip"] == "200.160.2.3"
              and plano["resultado"] == "FAILURE" and plano["motivo"] == "INVALID_CREDENTIALS" and plano["cidade"] == "Curitiba", json.dumps(plano)[:200])
    registrar("a posição é o mais novo entregue", posicao["desde"] == hora(20) and posicao["vistos"] == ["o5"], json.dumps(posicao))
    eventos, posicao = identidade.buscar_okta("empresa.okta.com", TOKEN_DO_OKTA, posicao, chamar)
    registrar("sem novidade, nada se repete", eventos == [], str([e["id"] for e in eventos]))
    SERVICO["okta"] += [evento_okta("o6", hora(20)), evento_okta("o7", hora(10))]
    eventos, posicao = identidade.buscar_okta("empresa.okta.com", TOKEN_DO_OKTA, posicao, chamar)
    registrar("só o novo, mesmo o da mesma hora do último", [e["id"] for e in eventos] == ["o6", "o7"], str([e["id"] for e in eventos]))

    class Resposta:
        def __init__(self, link):
            self.headers = {"Link": link}
    registrar("página de outro domínio não é seguida", identidade._proxima_do_okta(Resposta('<https://ladrao.exemplo/x>; rel="next"'), "empresa.okta.com") is None)
    SERVICO["status"] = 401
    try:
        identidade.buscar_okta("empresa.okta.com", TOKEN_DO_OKTA, posicao, chamar)
        registrar("token recusado vira aviso", False)
    except identidade.FonteComProblema as erro:
        registrar("token recusado vira aviso", "credencial" in str(erro), str(erro))
    SERVICO["status"] = 429
    try:
        identidade.buscar_okta("empresa.okta.com", TOKEN_DO_OKTA, posicao, chamar)
        registrar("limite de chamadas vira aviso", False)
    except identidade.FonteComProblema as erro:
        registrar("limite de chamadas vira aviso", "esperar" in str(erro), str(erro))
    SERVICO["status"] = 200

    print("\n== Google Workspace: busca", flush=True)
    SERVICO["workspace"] = {
        "login": [atividade("l1", hora(50), "login_success"), atividade("l2", hora(40), "login_failure"), atividade("l3", hora(30), "suspicious_login")],
        "admin": [atividade("a1", hora(35), "ASSIGN_ROLE", [{"name": "ROLE_NAME", "value": "_SEED_ADMIN_ROLE"}])],
        "drive": [atividade("d1", hora(25), "change_visibility", [{"name": "visibility", "value": "public_on_the_web"}, {"name": "primary_event", "boolValue": True}])],
    }
    SERVICO["pedidos"].clear()
    eventos, posicao = identidade.buscar_workspace(CHAVE, "admin@empresa.com", {}, chamar)
    assertiva = SERVICO["assertivas"][-1]
    cabecalho, corpo, assinatura = assertiva["assertion"].split(".")
    reivindicacoes = json.loads(base64.urlsafe_b64decode(corpo + "=" * (-len(corpo) % 4)))
    try:
        PRIVADA.public_key().verify(base64.urlsafe_b64decode(assinatura + "=" * (-len(assinatura) % 4)), f"{cabecalho}.{corpo}".encode(), padding.PKCS1v15(), hashes.SHA256())
        assinada = True
    except Exception:
        assinada = False
    registrar("o pedido de acesso é um JWT assinado pela conta de serviço", assinada and assertiva["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer")
    registrar("em nome do administrador, só leitura da auditoria", reivindicacoes["sub"] == "admin@empresa.com" and reivindicacoes["iss"] == CHAVE["client_email"]
              and reivindicacoes["scope"] == identidade.ESCOPO_DO_WORKSPACE and reivindicacoes["aud"] == identidade.ENDERECO_DO_TOKEN)
    registrar("o acesso vai nos relatórios", all(p["autorizacao"] == f"Bearer {ACESSO_DO_GOOGLE}" for p in SERVICO["pedidos"]) and len(SERVICO["pedidos"]) == 4,
              str(len(SERVICO["pedidos"])))
    registrar("login, administração e Drive, com as páginas", sorted(e["id"] for e in eventos) == sorted(
        ["l1-login_success", "l2-login_failure", "l3-suspicious_login", "a1-ASSIGN_ROLE", "d1-change_visibility"]), str([e["id"] for e in eventos]))
    drive = next(e for e in eventos if e["aplicacao"] == "drive")
    registrar("os parâmetros viram campos", drive["parametros"] == {"visibility": "public_on_the_web", "primary_event": True}, json.dumps(drive["parametros"]))
    SERVICO["pedidos"].clear()
    SERVICO["workspace"]["login"].insert(0, atividade("l0", hora(45), "login_success"))  # chegou atrasado
    eventos, posicao = identidade.buscar_workspace(CHAVE, "admin@empresa.com", posicao, chamar)
    registrar("volta no tempo e pega o atrasado, sem repetir o resto", [e["id"] for e in eventos] == ["l0-login_success"], str([e["id"] for e in eventos]))
    inicio = SERVICO["pedidos"][0]["q"]["startTime"]
    registrar("a volta é de três horas antes do mais novo", inicio == identidade._iso(agora - timedelta(minutes=30) - identidade.VOLTA_DO_WORKSPACE), inicio)

    print("\n== Entradas ruins", flush=True)
    for tipo, campos, segredo, nome in (("okta", {"dominio": "empresa.exemplo.com"}, TOKEN_DO_OKTA, "domínio que não é do Okta"),
                                        ("okta", {"dominio": "10.0.0.1"}, TOKEN_DO_OKTA, "endereço no lugar do domínio"),
                                        ("okta", {"dominio": "empresa.okta.com"}, "token com espaço e\nquebra", "token estranho"),
                                        ("workspace", {"administrador": "sem-arroba"}, json.dumps(CHAVE), "administrador sem e-mail"),
                                        ("workspace", {"administrador": "admin@empresa.com"}, "nao-e-json", "credencial que não é JSON"),
                                        ("workspace", {"administrador": "admin@empresa.com"}, json.dumps({"type": "authorized_user"}), "credencial que não é conta de serviço")):
        try:
            identidade.validar(tipo, campos)
            identidade.validar_segredo(tipo, segredo)
            registrar(f"recusado: {nome}", False)
        except ValueError:
            registrar(f"recusado: {nome}", True)
    registrar("domínio com https:// e barra no fim é aceito", identidade.validar("okta", {"dominio": "https://Empresa.okta.com/"}) == {"dominio": "empresa.okta.com"})

    print("\n== Ponta a ponta: tela, cofre, gerenciador e regras", flush=True)
    amb = Ambiente()
    try:
        a, b = amb.gerenciador("id-a"), amb.gerenciador("id-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        fabricantes.aplicar(a["id"])
        esperados = [(evento_okta("r1", hora(1), resultado="FAILURE", motivo="INVALID_CREDENTIALS"), "100932"),
                     (evento_okta("r2", hora(1), tipo="user.mfa.okta_verify.deny_push", resultado="DENY"), "100933"),
                     (evento_okta("r3", hora(1), tipo="user.account.privilege.grant"), "100935")]
        for e, regra in esperados:
            saida = provisao.testar_log(a["id"], json.dumps(identidade.evento_do_okta(e)))["saida"]
            registrar(f"regra do Okta {regra}", (saida.get("rule") or {}).get("id") == regra, str((saida.get("rule") or {}).get("id")))
        for e, regra in ((atividade("r4", hora(1), "login_failure"), "100942"), (atividade("r5", hora(1), "2sv_disable"), "100944"),
                         (atividade("r6", hora(1), "change_visibility", [{"name": "visibility", "value": "people_with_link"}]), "100946")):
            plano = identidade.eventos_do_workspace(e, "drive" if "visibility" in json.dumps(e) else "login")[0]
            saida = provisao.testar_log(a["id"], json.dumps(plano))["saida"]
            registrar(f"regra do Workspace {regra}", (saida.get("rule") or {}).get("id") == regra, str((saida.get("rule") or {}).get("id")))

        ua, ub = criar_usuario(amb, a["cliente"]), criar_usuario(amb, b["cliente"])
        with TestClient(app, base_url="https://testserver") as http:
            http.post("/api/entrar", json=ua)
            r = http.post("/api/fontes/nuvem", json={"nome": "Okta", "tipo": "okta", "campos": {"dominio": "empresa.okta.com"}, "segredo": TOKEN_DO_OKTA})
            registrar("fonte do Okta criada", r.status_code == 201, r.text[:120])
            okta = r.json()["id"]
            r = http.post("/api/fontes/nuvem", json={"nome": "Workspace", "tipo": "workspace", "campos": {"administrador": "admin@empresa.com"}, "segredo": json.dumps(CHAVE)})
            registrar("fonte do Workspace criada", r.status_code == 201, r.text[:120])
            workspace = r.json()["id"]
            r = http.post("/api/fontes/nuvem", json={"nome": "x", "tipo": "okta", "campos": {"dominio": "empresa.exemplo.com"}, "segredo": TOKEN_DO_OKTA})
            registrar("a tela recusa domínio que não é do Okta", r.status_code == 422, r.text[:120])
            visto = http.get("/api/fontes").text
            registrar("a credencial não volta pela tela", TOKEN_DO_OKTA not in visto and "PRIVATE KEY" not in visto)
            amb.admin.execute("UPDATE fontes SET estado = 'ativa' WHERE id = ANY(%s)", ([okta, workspace],))

            marca = f"marca{uuid.uuid4().hex}"
            SERVICO["okta"] = [evento_okta(f"{marca}-1", hora(5)), evento_okta(f"{marca}-2", hora(4), resultado="FAILURE", motivo="INVALID_CREDENTIALS")]
            SERVICO["workspace"] = {"login": [atividade(marca, hora(3), "login_failure")]}
            entregues = identidade.coletar(amb.banco, a["id"], a["cliente"], chamar=chamar)
            registrar("entregou ao gerenciador", entregues == 3, str(entregues))
            registrar("os eventos chegam ao índice do cliente", contar(amb, a, marca, esperado=3) == 3)
            registrar("não chegam ao outro cliente", contar(amb, b, marca, limite=6) == 0)
            linha = amb.admin.execute("SELECT posicao, mensagem, ultimo_dado_em IS NOT NULL FROM fontes WHERE id = %s", (okta,)).fetchone()
            registrar("a fonte guarda de onde recomeça", linha[0] and linha[0]["vistos"] == [f"{marca}-2"] and linha[1] is None and linha[2], str(linha[:2]))

            pedidos = len(SERVICO["pedidos"])
            identidade.coletar(amb.banco, a["id"], a["cliente"], chamar=chamar)
            registrar("respeita o intervalo", len(SERVICO["pedidos"]) == pedidos)
            amb.admin.execute("UPDATE fontes SET proxima_busca = NULL WHERE id = ANY(%s)", ([okta, workspace],))
            registrar("na busca seguinte, nada se repete", identidade.coletar(amb.banco, a["id"], a["cliente"], chamar=chamar) == 0)

            SERVICO["status"] = 403
            amb.admin.execute("UPDATE fontes SET proxima_busca = NULL WHERE id = ANY(%s)", ([okta, workspace],))
            identidade.coletar(amb.banco, a["id"], a["cliente"], chamar=chamar)
            mensagens = {f["id"]: f["mensagem"] for f in http.get("/api/fontes").json()["fontes"]}
            registrar("credencial recusada aparece na tela", "credencial" in (mensagens.get(okta) or "") and "credencial" in (mensagens.get(workspace) or ""), str(mensagens))
            SERVICO["status"] = 200
            amb.admin.execute("UPDATE fontes SET proxima_busca = NULL WHERE id = ANY(%s)", ([okta, workspace],))
            identidade.coletar(amb.banco, a["id"], a["cliente"], chamar=chamar)
            mensagens = {f["id"]: f["mensagem"] for f in http.get("/api/fontes").json()["fontes"]}
            registrar("voltou ao normal, o aviso sai", mensagens.get(okta) is None and mensagens.get(workspace) is None, str(mensagens))

            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ub)
            registrar("outro cliente não vê", http.get("/api/fontes").json()["fontes"] == [])
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ua)
            registrar("desativar responde", http.post(f"/api/fontes/{okta}/desativar").status_code == 204)
            pedidos = len(SERVICO["pedidos"])
            amb.admin.execute("UPDATE fontes SET proxima_busca = NULL WHERE id = %s", (okta,))
            identidade.coletar(amb.banco, a["id"], a["cliente"], chamar=chamar)
            registrar("desativada não busca mais", not any(p["caminho"] == "/api/v1/logs" for p in SERVICO["pedidos"][pedidos:]))
    finally:
        servidor.shutdown()
        clientes = [g["cliente"] for g in amb.gerenciadores]
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
