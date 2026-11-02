#!/usr/bin/env python3
"""Busca periódica em API, com gerenciador real e um sistema de exemplo local.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_api_generica.py

Apaga no final tudo o que criou.
"""

import json
import os
import secrets
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import cofre, fontes, provisao  # noqa: E402
from testar_ingestao import URL, Ambiente, esperar_gerenciador  # noqa: E402

RESULTADOS = []
SISTEMA = {"status": 200, "corpo": b"{}", "recebidos": []}


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class Sistema(BaseHTTPRequestHandler):
    def do_GET(self):
        SISTEMA["recebidos"].append(dict(self.headers))
        self.send_response(SISTEMA["status"])
        self.end_headers()
        self.wfile.write(SISTEMA["corpo"])

    def log_message(self, *args):
        pass


def criar_usuario(amb, cliente):
    senha, email = secrets.token_urlsafe(18), f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
    amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, 'administrador')",
                      (cliente, email, PasswordHasher().hash(senha)))
    return {"email": email, "senha": senha}


def contar(amb, g, marca, limite=40, esperado=1):
    consulta = {"query": {"simple_query_string": {"query": marca}}}
    fim, indice, total = time.time() + limite, provisao.indice_bruto_do(g["id"]), 0
    while time.time() < fim:
        amb.indexer.sessao.post(f"{URL}/{indice}*/_refresh", timeout=30)
        r = amb.indexer.sessao.post(f"{URL}/{indice}*/_count", json=consulta, timeout=30)
        total = r.json().get("count", 0) if r.ok else 0
        if total >= esperado:
            return total
        time.sleep(4)
    return total


def main():
    cofre.gerar()
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), Sistema)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{servidor.server_address[1]}"
    amb = Ambiente()
    try:
        a, b = amb.gerenciador("api-a"), amb.gerenciador("api-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        ua, ub = criar_usuario(amb, a["cliente"]), criar_usuario(amb, b["cliente"])
        with TestClient(app, base_url="https://testserver") as http:
            registrar("criar exige sessão", http.post("/api/fontes/api", json={}).status_code == 401)
            http.post("/api/entrar", json=ua)

            print("\n== Entradas ruins", flush=True)
            os.environ.pop("ROAR_DESTINO_INTERNO", None)
            for nome, corpo in (("rede interna", {"endereco": "https://10.0.0.1/x"}), ("metadados de nuvem", {"endereco": "https://169.254.169.254/"}),
                                ("sem https", {"endereco": "http://exemplo.com/"}), ("sem endereço", {"endereco": ""}),
                                ("caminho estranho", {"endereco": "https://documentation.wazuh.com/", "caminho": "a[0]"}),
                                ("cabeçalho Host", {"endereco": "https://documentation.wazuh.com/", "cabecalho": "Host"}),
                                ("cabeçalho com quebra de linha", {"endereco": "https://documentation.wazuh.com/", "cabecalho": "X\r\nY"}),
                                ("intervalo curto demais", {"endereco": "https://documentation.wazuh.com/", "intervalo_minutos": 1})):
                registrar(f"recusado: {nome}", http.post("/api/fontes/api", json={"nome": "x", **corpo}).status_code == 422)

            print("\n== Busca", flush=True)
            os.environ["ROAR_DESTINO_INTERNO"] = "1"
            credencial = f"credencial-{uuid.uuid4().hex}"
            r = http.post("/api/fontes/api", json={"nome": "Sistema de exemplo", "endereco": base + "/eventos", "caminho": "data.itens",
                                                   "cabecalho": "X-Chave", "segredo": credencial, "intervalo_minutos": 5})
            registrar("fonte criada", r.status_code == 201, r.text[:120])
            fonte = r.json()["id"]
            registrar("a credencial não volta pela tela", credencial not in http.get("/api/fontes").text)
            config = amb.admin.execute("SELECT config FROM fontes WHERE id = %s", (fonte,)).fetchone()[0]
            registrar("a fonte guarda só o nome da credencial", credencial not in json.dumps(config))

            def buscar_agora():
                amb.admin.execute("UPDATE fontes SET proxima_busca = NULL WHERE id = %s", (fonte,))
                fontes.buscar_apis(amb.banco, a["id"], a["cliente"])

            marca1, marca2, marca3 = (f"marca{uuid.uuid4().hex}" for _ in range(3))
            SISTEMA["corpo"] = json.dumps({"data": {"itens": [{"m": marca1}, {"m": marca2}, "texto solto", 7]}}).encode()
            buscar_agora()
            registrar("a credencial vai no cabeçalho pedido", SISTEMA["recebidos"][-1].get("X-Chave") == credencial)
            registrar("os itens chegam ao índice do cliente", contar(amb, a, marca1) == 1 and contar(amb, a, marca2) == 1)
            registrar("não chegam ao outro cliente", contar(amb, b, marca1, limite=6) == 0)
            registrar("a tela mostra que está recebendo", http.get("/api/fontes").json()["fontes"][0]["saude"] == "recebendo")

            pedidos = len(SISTEMA["recebidos"])
            fontes.buscar_apis(amb.banco, a["id"], a["cliente"])
            registrar("respeita o intervalo", len(SISTEMA["recebidos"]) == pedidos)
            buscar_agora()
            time.sleep(8)
            registrar("o que já foi entregue não repete", contar(amb, a, marca1, limite=5, esperado=2) == 1)

            SISTEMA["corpo"] = json.dumps({"data": {"itens": [{"m": marca2}, {"m": marca3}]}}).encode()
            buscar_agora()
            registrar("só o novo entra", contar(amb, a, marca3) == 1 and contar(amb, a, marca2, limite=5, esperado=2) == 1)

            print("\n== Problemas aparecem na tela", flush=True)

            def mensagem():
                return http.get("/api/fontes").json()["fontes"][0]["mensagem"]

            SISTEMA["corpo"] = b"nao-e-json"
            buscar_agora()
            registrar("resposta que não é JSON", mensagem() == "A resposta não é JSON.", str(mensagem()))
            SISTEMA["corpo"] = b'{"outra": []}'
            buscar_agora()
            registrar("caminho que não existe", "não existe" in (mensagem() or ""), str(mensagem()))
            SISTEMA["status"] = 500
            buscar_agora()
            registrar("sistema com erro", mensagem() == "O sistema respondeu 500.", str(mensagem()))
            SISTEMA["status"], SISTEMA["corpo"] = 302, b""
            buscar_agora()
            registrar("redirecionamento não é seguido", mensagem() == "O sistema respondeu 302.", str(mensagem()))
            SISTEMA["status"], SISTEMA["corpo"] = 200, b"[" * 200000
            buscar_agora()
            registrar("JSON aninhado demais não derruba", mensagem() == "A resposta não é JSON.", str(mensagem()))
            SISTEMA["corpo"] = json.dumps({"data": {"itens": []}}).encode()
            buscar_agora()
            registrar("voltou ao normal, o aviso sai", mensagem() is None, str(mensagem()))

            print("\n== Mudança de DNS depois de criada", flush=True)
            os.environ.pop("ROAR_DESTINO_INTERNO", None)
            pedidos = len(SISTEMA["recebidos"])
            buscar_agora()
            registrar("endereço que virou interno é recusado na busca", len(SISTEMA["recebidos"]) == pedidos and "interna" in (mensagem() or ""), str(mensagem()))
            os.environ["ROAR_DESTINO_INTERNO"] = "1"

            print("\n== Isolamento", flush=True)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ub)
            registrar("outro cliente não vê", http.get("/api/fontes").json()["fontes"] == [])
            registrar("outro cliente não desativa", http.post(f"/api/fontes/{fonte}/desativar").status_code == 404)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ua)

            print("\n== Desativar", flush=True)
            pedidos = len(SISTEMA["recebidos"])
            registrar("desativar responde", http.post(f"/api/fontes/{fonte}/desativar").status_code == 204)
            registrar("a credencial é apagada", amb.um("SELECT count(*) FROM segredos WHERE nome = %s", config["segredo"]) == 0)
            buscar_agora()
            registrar("desativada não busca mais", len(SISTEMA["recebidos"]) == pedidos)
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
