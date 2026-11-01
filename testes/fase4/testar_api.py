#!/usr/bin/env python3
"""Fase 4, primeira parte: login e fila de alertas. Requer infra/subir.sh já executado e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_api.py

Usa o banco de verdade e apaga no final tudo o que criou.
"""

import hashlib
import json
import random
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api")]

ENV = {}
for linha in Path("/opt/panthera-roar/.env").read_text().splitlines():
    if "=" in linha and not linha.startswith("#"):
        k, v = linha.split("=", 1)
        ENV[k] = v
ADMIN = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
URL_API = f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar"

from roar_api.app import COOKIE, ESTATICO, app, falhas_de_login  # noqa: E402

XSS = '<img src=x onerror="alert(1)">'
RESULTADOS = []
CRIADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def recusado(funcao):
    try:
        funcao()
        return False
    except psycopg.Error:
        return True


def novo_cliente(nome):
    sufixo = uuid.uuid4().hex[:10]
    cliente = ADMIN.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{sufixo}",)).fetchone()[0]
    ger = f"t{sufixo}"
    ADMIN.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)",
                  (ger, cliente, random.randint(40000, 60000)))
    senha = secrets.token_urlsafe(18)
    email = f"analista-{sufixo}@exemplo.test"
    ADMIN.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash) VALUES (%s, %s, %s, %s)",
                  (cliente, email, f"Analista {nome}", PasswordHasher().hash(senha)))
    agora = datetime.now(timezone.utc)
    entidade = ADMIN.execute(
        "INSERT INTO entidades (cliente_id, tipo, chave, nome, primeira_vista, ultima_vista, risco)"
        " VALUES (%s, 'usuario', %s, %s, %s, %s, 75) RETURNING id", (cliente, f"maria{sufixo}", XSS, agora, agora)).fetchone()[0]
    ADMIN.execute("UPDATE entidades SET risco_em = %s WHERE id = %s", (agora, entidade))
    grupo = ADMIN.execute(
        "INSERT INTO grupos_alerta (cliente_id, chave, dia, gerenciador_id, agente_id, nivel, severidade, regras,"
        " primeira_em, ultima_em) VALUES (%s, 'k', %s, %s, '001', 10, 'media', '{5712}', %s, %s) RETURNING id",
        (cliente, agora.date(), ger, agora, agora)).fetchone()[0]
    evento = ADMIN.execute(
        "INSERT INTO eventos (cliente_id, grupo_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel, severidade,"
        " regra_id, regra_descricao, agente_id, agente_nome, ip_origem, usuario, bruto)"
        " VALUES (%s, %s, %s, 'wazuh', 'e1', %s, 10, 'media', '5712', %s, '001', 'servidor', '203.0.113.5', %s, %s)"
        " RETURNING id", (cliente, grupo, ger, agora, XSS, XSS, Jsonb({"segredo_do_bruto": "nao-sair"}))).fetchone()[0]
    ADMIN.execute(
        "INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id, detalhes)"
        " VALUES (%s, %s, 'primeiro_host', 'h', %s, 15, %s, %s, %s)",
        (cliente, entidade, agora.date(), agora, evento, Jsonb({"host": XSS})))
    alerta = ADMIN.execute(
        "INSERT INTO alertas_risco (cliente_id, entidade_id, severidade, risco_maximo, aberto_em)"
        " VALUES (%s, %s, 'alta', 75, %s) RETURNING id", (cliente, entidade, agora)).fetchone()[0]
    dados = {"id": cliente, "ger": ger, "email": email, "senha": senha, "alerta": alerta, "grupo": grupo}
    CRIADOS.append(dados)
    return dados


def limpar():
    ids = [c["id"] for c in CRIADOS]
    for tabela in ("sinais", "alertas_risco", "entidades", "eventos", "grupos_alerta", "gerenciadores", "usuarios"):
        ADMIN.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (ids,))
    ADMIN.execute("DELETE FROM clientes WHERE id = ANY(%s)", (ids,))


def entrar(http, cliente):
    return http.post("/api/entrar", json={"email": cliente["email"], "senha": cliente["senha"]})


def main():
    a, b = novo_cliente("a"), novo_cliente("b")
    with TestClient(app, base_url="https://testserver") as http:
        print("\n== Sem sessão", flush=True)
        for rota in ("/api/eu", "/api/fila", f"/api/riscos/{a['alerta']}", f"/api/grupos/{a['grupo']}"):
            registrar(f"{rota.split('/')[2]} exige sessão", http.get(rota).status_code == 401)
        http.cookies.set(COOKIE, "token-inventado")
        registrar("token inventado não entra", http.get("/api/eu").status_code == 401)
        http.cookies.clear()

        print("\n== Login", flush=True)
        registrar("senha errada é recusada", http.post("/api/entrar", json={"email": a["email"], "senha": "x"}).status_code == 401)
        resposta_inexistente = http.post("/api/entrar", json={"email": "ninguem@exemplo.test", "senha": "x"})
        resposta_errada = http.post("/api/entrar", json={"email": a["email"], "senha": "y"})
        registrar("não revela se o e-mail existe", resposta_inexistente.status_code == resposta_errada.status_code
                  and resposta_inexistente.text == resposta_errada.text)
        registrar("injeção no e-mail não entra", http.post(
            "/api/entrar", json={"email": "' OR 1=1 --", "senha": "x"}).status_code == 401)
        falhas_de_login.clear()

        r = entrar(http, a)
        cabecalho = r.headers.get("set-cookie", "").lower()
        registrar("login certo entra", r.status_code == 204)
        registrar("cookie protegido", all(x in cabecalho for x in ("httponly", "samesite=strict", "secure")), cabecalho[:0])
        token = http.cookies.get(COOKIE)
        registrar("banco guarda só o hash do token",
                  ADMIN.execute("SELECT count(*) FROM sessoes WHERE token_hash = %s", (token,)).fetchone()[0] == 0
                  and ADMIN.execute("SELECT count(*) FROM sessoes WHERE token_hash = %s",
                                    (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0] == 1)
        registrar("sessão identifica o cliente", http.get("/api/eu").json()["cliente"].startswith("a-"))

        print("\n== Isolamento entre clientes", flush=True)
        fila = http.get("/api/fila").json()
        registrar("fila só tem riscos do cliente", [x["id"] for x in fila["riscos"]] == [a["alerta"]])
        registrar("fila só tem alertas do cliente", [x["id"] for x in fila["grupos"]] == [a["grupo"]])
        registrar("risco de outro cliente não é encontrado", http.get(f"/api/riscos/{b['alerta']}").status_code == 404)
        registrar("alerta de outro cliente não é encontrado", http.get(f"/api/grupos/{b['grupo']}").status_code == 404)
        registrar("o próprio risco abre", http.get(f"/api/riscos/{a['alerta']}").status_code == 200)
        registrar("o próprio alerta abre", http.get(f"/api/grupos/{a['grupo']}").status_code == 200)
        registrar("cliente enviado na requisição é ignorado", [x["id"] for x in http.get(
            "/api/fila", params={"cliente": str(b["id"]), "cliente_id": str(b["id"])}).json()["riscos"]] == [a["alerta"]])

        print("\n== Panorama", flush=True)
        painel = http.get("/api/panorama", params={"dias": 7}).json()
        registrar("período tem um ponto por dia, mesmo sem dados", len(painel["por_dia"]) == 7)
        registrar("alerta de hoje entra no gráfico", sum(d["media"] for d in painel["por_dia"]) == 1, str(painel["por_dia"][-1]))
        registrar("gráfico de sinais tem os dados do cliente", painel["sinais"] == [{"tipo": "primeiro_host", "total": 1}])
        registrar("gráfico de origens sai sem máscara", painel["origens"] == [{"origem": "203.0.113.5", "total": 1}])
        registrar("gráfico de risco tem a entidade do cliente", [r["entidade"] for r in painel["riscos"]] == [XSS])
        registrar("período absurdo é contido", len(http.get("/api/panorama", params={"dias": 10**6}).json()["por_dia"]) == 90
                  and len(http.get("/api/panorama", params={"dias": -5}).json()["por_dia"]) == 1)
        registrar("panorama exige sessão", TestClient(app, base_url="https://testserver").get("/api/panorama").status_code == 401)
        fuso = ADMIN.execute("SELECT fuso FROM clientes WHERE id = %s", (a["id"],)).fetchone()[0]
        ADMIN.execute("UPDATE clientes SET fuso = 'Asia/Tokyo' WHERE id = %s", (a["id"],))
        dia_toquio = http.get("/api/panorama", params={"dias": 1}).json()["por_dia"][-1]["dia"]
        esperado = ADMIN.execute("SELECT (now() AT TIME ZONE 'Asia/Tokyo')::date::text").fetchone()[0]
        ADMIN.execute("UPDATE clientes SET fuso = %s WHERE id = %s", (fuso, a["id"]))
        registrar("dia segue o fuso do cliente", dia_toquio == esperado, dia_toquio)
        falhas_ruins = http.get("/api/panorama", params={"dias": "'; DROP TABLE eventos; --"})
        registrar("período com texto é recusado", falhas_ruins.status_code == 422)

        print("\n== Entradas e saídas", flush=True)
        registrar("id gigante não vira erro", http.get(f"/api/riscos/{2**70}").status_code == 404)
        registrar("id negativo não vira erro", http.get("/api/grupos/-1").status_code == 404)
        registrar("id com texto é recusado", http.get("/api/riscos/1%20OR%201=1").status_code == 422)
        registrar("limite absurdo é contido", http.get("/api/fila", params={"limite": 10**9}).status_code == 200)
        registrar("IP sai sem máscara de rede", http.get(f"/api/grupos/{a['grupo']}").json()["eventos"][0]["ip_origem"] == "203.0.113.5")
        agora = datetime.now(timezone.utc)
        ADMIN.execute(
            "INSERT INTO grupos_alerta (cliente_id, chave, dia, gerenciador_id, agente_id, nivel, severidade, regras,"
            " primeira_em, ultima_em) VALUES (%s, 'normal', %s, %s, '001', 3, 'baixa', '{5715}', %s, %s)",
            (a["id"], agora.date(), a["ger"], agora, agora))
        registrar("login normal não polui a fila", len(http.get("/api/fila").json()["grupos"]) == 1)
        tudo = "".join(http.get(r).text for r in ("/api/fila", f"/api/riscos/{a['alerta']}", f"/api/grupos/{a['grupo']}"))
        registrar("alerta bruto não sai pela API", "segredo_do_bruto" not in tudo)
        registrar("texto hostil sai só como dado JSON", json.loads(http.get(f"/api/riscos/{a['alerta']}").text)["alerta"]["entidade"] == XSS)
        registrar("resposta da API não fica em cache", http.get("/api/fila").headers.get("cache-control") == "no-store")
        registrar("rotas de documentação estão fechadas", http.get("/docs").status_code == 404 and http.get("/openapi.json").status_code == 404)

        print("\n== Tela", flush=True)
        inicio = http.get("/")
        politica = inicio.headers.get("content-security-policy", "")
        registrar("tela abre", inicio.status_code == 200 and "Panthera" in inicio.text)
        registrar("política de conteúdo bloqueia script de fora", "default-src 'self'" in politica and "unsafe" not in politica)
        registrar("tela não pode ser embutida", "frame-ancestors 'none'" in politica)
        js = (ESTATICO / "roar.js").read_text(encoding="utf-8")
        registrar("tela nunca monta HTML com dado", not any(x in js.replace("nunca com innerHTML", "") for x in
                  ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(")))
        html = (ESTATICO / "index.html").read_text(encoding="utf-8")
        registrar("nenhum script embutido na página", "<script>" not in html and " onclick=" not in html)
        # O namespace do SVG parece um endereço, mas nada é baixado dele.
        sem_namespace = (html + js).replace("http://www.w3.org/2000/svg", "")
        registrar("nenhum recurso externo", "http://" not in sem_namespace and "https://" not in sem_namespace)
        texto = html + js
        registrar("tela não cita ferramentas", not any(x in texto.lower() for x in ("wazuh", "shuffle", "temporal", "opensearch", "be safe")))

        print("\n== Requisição de outro site", flush=True)
        r = http.post("/api/sair", headers={"Origin": "https://atacante.example"})
        registrar("outro site não encerra a sessão", r.status_code == 403 and http.get("/api/eu").status_code == 200)

        print("\n== Fim da sessão", flush=True)
        antigo = http.cookies.get(COOKIE)
        registrar("sair responde", http.post("/api/sair").status_code == 204)
        http.cookies.set(COOKIE, antigo)
        registrar("token antigo não vale depois de sair", http.get("/api/eu").status_code == 401)
        http.cookies.clear()

        entrar(http, b)
        ADMIN.execute("UPDATE sessoes SET expira_em = now() - interval '1 minute' WHERE token_hash = %s",
                      (hashlib.sha256(http.cookies.get(COOKIE).encode()).hexdigest(),))
        registrar("sessão expirada não vale", http.get("/api/eu").status_code == 401)
        http.cookies.clear()
        entrar(http, b)
        ADMIN.execute("UPDATE usuarios SET ativo = false WHERE cliente_id = %s", (b["id"],))
        registrar("usuário desativado perde o acesso na hora", http.get("/api/eu").status_code == 401)
        registrar("usuário desativado não entra", entrar(http, b).status_code == 401)
        ADMIN.execute("UPDATE usuarios SET ativo = true WHERE cliente_id = %s", (b["id"],))
        http.cookies.clear()
        falhas_de_login.clear()

        print("\n== Tentativas em série", flush=True)
        codigos = [http.post("/api/entrar", json={"email": a["email"], "senha": f"t{i}"}).status_code for i in range(6)]
        registrar("bloqueia depois de 5 tentativas", codigos == [401] * 5 + [429], str(codigos))
        registrar("nem a senha certa entra durante o bloqueio", entrar(http, a).status_code == 429)
        falhas_de_login.clear()

    print("\n== Papel da API no banco", flush=True)
    with psycopg.connect(URL_API, autocommit=True) as api:
        registrar("não lê usuários nem hashes", recusado(lambda: api.execute("SELECT senha_hash FROM usuarios")))
        registrar("não lê sessões", recusado(lambda: api.execute("SELECT * FROM sessoes")))
        registrar("não altera usuários", recusado(lambda: api.execute("UPDATE usuarios SET ativo = true")))
        registrar("não troca o próprio cliente pelo cadastro", recusado(lambda: api.execute("UPDATE clientes SET nome = 'x'")))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    try:
        codigo = main()
    finally:
        limpar()
    sys.exit(codigo)
