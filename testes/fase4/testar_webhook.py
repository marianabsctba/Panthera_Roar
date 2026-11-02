#!/usr/bin/env python3
"""Webhook de entrada com gerenciador real: do envio HTTP até os logs brutos do cliente certo.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_webhook.py

Apaga no final tudo o que criou.
"""

import json
import secrets
import sys
import time
import uuid
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1")]

from roar_api import app as modulo  # noqa: E402
from roar_ingestao import fontes, provisao  # noqa: E402
from testar_ingestao import URL, Ambiente, esperar_gerenciador  # noqa: E402

app = modulo.app
RESULTADOS = []
ROTA = "/api/entrada/webhook"


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def criar_usuario(amb, cliente):
    senha, email = secrets.token_urlsafe(18), f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
    amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash) VALUES (%s, %s, 'Analista', %s)",
                      (cliente, email, PasswordHasher().hash(senha)))
    return {"email": email, "senha": senha}


def chegou(amb, g, marca, limite=60):
    consulta = {"query": {"simple_query_string": {"query": marca}}}
    fim, indice = time.time() + limite, provisao.indice_bruto_do(g["id"])
    while time.time() < fim:
        amb.indexer.sessao.post(f"{URL}/{indice}*/_refresh", timeout=30)
        r = amb.indexer.sessao.post(f"{URL}/{indice}*/_search", json=consulta, timeout=30)
        if r.ok and r.json()["hits"]["hits"]:
            return r.json()["hits"]["hits"][0]["_source"]
        time.sleep(4)
    return None


def main():
    amb = Ambiente()
    try:
        a, b = amb.gerenciador("webhook-a"), amb.gerenciador("webhook-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        ua, ub = criar_usuario(amb, a["cliente"]), criar_usuario(amb, b["cliente"])
        with TestClient(app, base_url="https://testserver") as http:
            registrar("criar exige sessão", http.post("/api/fontes/webhook", json={"nome": "x"}).status_code == 401)
            http.post("/api/entrar", json=ub)
            token_b = http.post("/api/fontes/webhook", json={"nome": "de B"}).json()["token"]
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ua)
            r = http.post("/api/fontes/webhook", json={"nome": "Sistema de RH"}).json()
            token, fonte = r["token"], r["id"]
            http.post("/api/sair")
            http.cookies.clear()
            cabecalho = {"Authorization": f"Bearer {token}"}

            print("\n== Token", flush=True)
            guardado = amb.admin.execute("SELECT token_hash, config::text FROM fontes WHERE id = %s", (fonte,)).fetchone()
            registrar("o banco guarda só o hash", token not in guardado[0] and token not in guardado[1])
            registrar("sem token é recusado", http.post(ROTA, json={"a": 1}).status_code == 401)
            registrar("token errado é recusado", http.post(ROTA, json={"a": 1}, headers={"Authorization": "Bearer " + "x" * 43}).status_code == 401)
            registrar("sem o prefixo é recusado", http.post(ROTA, json={"a": 1}, headers={"Authorization": token}).status_code == 401)
            registrar("nada entrou na fila", amb.um("SELECT count(*) FROM entrada_webhook WHERE fonte_id = %s", fonte) == 0)

            print("\n== Corpo", flush=True)
            for nome, conteudo, esperado in (("não é JSON", b"nao-json", 422), ("texto solto", b'"a"', 422), ("número", b"1", 422),
                                             ("lista vazia", b"[]", 422), ("lista com texto", b'["a"]', 422),
                                             ("lista grande", json.dumps([{"a": 1}] * 101).encode(), 422),
                                             ("evento grande", json.dumps({"a": "x" * 61000}).encode(), 413),
                                             ("envio grande", b'{"a":"' + b"x" * 1_000_001 + b'"}', 413),
                                             ("aninhado demais", b"[" * 200000, 422)):
                recebido = http.post(ROTA, content=conteudo, headers=cabecalho).status_code
                registrar(f"recusado: {nome}", recebido == esperado, str(recebido))

            print("\n== Do envio aos logs", flush=True)
            marca, marca_b = f"marca{uuid.uuid4().hex}", f"marca{uuid.uuid4().hex}"
            # Conteúdo hostil: tenta se passar por outro agente, gerenciador e cliente.
            hostil = {"mensagem": marca, "agent": {"id": "999", "name": "falso"}, "manager": {"name": f"gerenciador-{b['id']}"},
                      "cliente_id": str(b["cliente"]), "rule": {"id": "1", "level": 16}, "texto": "linha\nnova <xml> ' \""}
            r = http.post(ROTA, json=hostil, headers=cabecalho)
            registrar("envio aceito", r.status_code == 202, r.text[:100])
            registrar("lista também é aceita", http.post(ROTA, json=[{"m": 1}, {"m": 2}], headers=cabecalho).json()["recebidos"] == 2)
            http.post(ROTA, json={"mensagem": marca_b}, headers={"Authorization": f"Bearer {token_b}"})
            fila = amb.admin.execute("SELECT cliente_id, gerenciador_id FROM entrada_webhook WHERE corpo LIKE %s", (f"%{marca}%",)).fetchone()
            registrar("o cliente vem do token, não do conteúdo", str(fila[0]) == str(a["cliente"]) and fila[1] == a["id"])
            fontes.ciclo(amb.banco)
            registrar("a fila esvazia depois de entregar", amb.um("SELECT count(*) FROM entrada_webhook WHERE fonte_id = %s", fonte) == 0)
            doc = chegou(amb, a, marca)
            registrar("o evento chega ao índice do cliente", doc, str(doc)[:300])
            registrar("não chega ao índice do outro cliente", chegou(amb, b, marca, limite=8) is None)
            registrar("o evento do outro cliente fica no dele", chegou(amb, b, marca_b) and chegou(amb, a, marca_b, limite=8) is None)
            registrar("o agente do conteúdo não vale", doc and doc.get("agent", {}).get("id") != "999" or "data" in (doc or {}), str((doc or {}).get("agent")))

            http.post("/api/entrar", json=ua)
            vistos = http.get("/api/fontes").json()["fontes"]
            registrar("a tela mostra que está recebendo", vistos[0]["saude"] == "recebendo", str(vistos[0]["saude"]))
            registrar("a tela não traz o token", token not in http.get("/api/fontes").text)
            registrar("o log aparece nos logs brutos", http.get("/api/logs", params={"busca": marca}).json()["total"] >= 1)
            registrar("criação fica na auditoria", amb.um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'criar_fonte'", a["cliente"]) == 1)

            print("\n== Banco", flush=True)
            url_api = f"postgresql://roar_api:{amb.env['ROAR_API_SENHA']}@127.0.0.1:5433/roar"
            with psycopg.connect(url_api) as con:
                con.execute("SELECT set_config('roar.cliente', %s, true)", (str(a["cliente"]),))
                try:
                    con.execute("SELECT * FROM entrada_webhook")
                    registrar("API não lê a fila", False)
                except psycopg.errors.InsufficientPrivilege:
                    registrar("API não lê a fila", True)

            print("\n== Fila cheia", flush=True)
            limite = modulo.LIMITE_DA_FILA_DO_WEBHOOK
            modulo.LIMITE_DA_FILA_DO_WEBHOOK = 3
            http.post(ROTA, json=[{"m": 1}, {"m": 2}, {"m": 3}], headers=cabecalho)
            registrar("fila cheia pede para esperar, sem perder o que tem", http.post(ROTA, json={"m": 4}, headers=cabecalho).status_code == 429
                      and amb.um("SELECT count(*) FROM entrada_webhook WHERE fonte_id = %s", fonte) == 3)
            modulo.LIMITE_DA_FILA_DO_WEBHOOK = limite

            print("\n== Desativar", flush=True)
            registrar("desativar responde", http.post(f"/api/fontes/{fonte}/desativar").status_code == 204)
            registrar("token de fonte desativada para de valer", http.post(ROTA, json={"a": 1}, headers=cabecalho).status_code == 401)
    finally:
        clientes = [g["cliente"] for g in amb.gerenciadores]
        for tabela in ("entrada_webhook", "fontes", "usuarios"):
            amb.admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
