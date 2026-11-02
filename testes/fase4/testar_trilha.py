#!/usr/bin/env python3
"""Trilha de auditoria e aviso de tentativa recusada, com banco real.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_trilha.py
"""

import csv
import io
import secrets
import sys
import uuid
from pathlib import Path

import psycopg
import pyotp
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api import app as modulo  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    clientes, gerenciadores = [], []

    def criar_cliente(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        clientes.append(c)
        return c

    def criar_usuario(cliente, perfil):
        senha, email = secrets.token_urlsafe(18), f"{perfil}-{uuid.uuid4().hex[:8]}@exemplo.test"
        i = admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                          (cliente, email, f"Pessoa {perfil}", PasswordHasher().hash(senha), perfil)).fetchone()[0]
        return {"email": email, "senha": senha, "id": str(i)}

    def linhas(cliente, acao):
        return admin.execute("SELECT usuario_id, alvo, origem FROM auditoria WHERE cliente_id = %s AND acao = %s", (cliente, acao)).fetchall()

    try:
        a, b = criar_cliente("trilha-a"), criar_cliente("trilha-b")
        ana, ivo, auditora, de_b = criar_usuario(a, "administrador"), criar_usuario(a, "analista_n1"), criar_usuario(a, "auditor"), criar_usuario(b, "administrador")

        with TestClient(modulo.app, base_url="https://testserver") as http:
            print("== Acessos", flush=True)
            r = http.post("/api/entrar", json={"email": ivo["email"], "senha": "errada"})
            registrar("senha errada continua dando a mesma resposta", r.status_code == 401 and r.json()["detail"] == "E-mail ou senha incorretos.")
            registrar("a recusa fica na trilha do cliente", len(linhas(a, "login_recusado")) == 1 and linhas(a, "login_recusado")[0][1] == ivo["email"])
            registrar("a origem fica registrada", linhas(a, "login_recusado")[0][2] is not None)
            r = http.post("/api/entrar", json={"email": f"ninguem-{SUFIXO}@exemplo.test", "senha": "errada"})
            registrar("e-mail desconhecido responde igual", r.status_code == 401 and r.json()["detail"] == "E-mail ou senha incorretos.")
            registrar("e-mail desconhecido não entra na trilha de ninguém", not admin.execute("SELECT count(*) FROM auditoria WHERE alvo LIKE %s", (f"ninguem-{SUFIXO}%",)).fetchone()[0])

            http.post("/api/entrar", json={"email": ana["email"], "senha": ana["senha"]})
            registrar("logon fica na trilha", len(linhas(a, "logon")) == 1 and str(linhas(a, "logon")[0][0]) == ana["id"])

            print("\n== Aviso em tempo real", flush=True)
            avisos = http.get("/api/notificacoes").json()["avisos"]
            registrar("o administrador vê o aviso na hora", len(avisos) == 1 and avisos[0]["tipo"] == "login_recusado" and avisos[0]["alvo"] == ivo["email"], str(avisos)[:160])
            modulo.falhas_de_login.clear()
            for _ in range(3):
                TestClient(modulo.app, base_url="https://testserver").post("/api/entrar", json={"email": ivo["email"], "senha": "errada"})
            avisos = http.get("/api/notificacoes").json()["avisos"]
            registrar("tentativas repetidas somam em um aviso", len(avisos) == 1 and avisos[0]["contagem"] == 4, str(avisos)[:160])
            registrar("cada uma continua na trilha", len(linhas(a, "login_recusado")) == 4)
            modulo.falhas_de_login.clear()
            outra = TestClient(modulo.app, base_url="https://testserver")
            for _ in range(modulo.TENTATIVAS + 3):
                outra.post("/api/entrar", json={"email": auditora["email"], "senha": "errada"})
            registrar("depois do bloqueio não cresce mais", len(linhas(a, "login_recusado")) == 4 + modulo.TENTATIVAS, str(len(linhas(a, "login_recusado"))))
            modulo.falhas_de_login.clear()

            print("\n== Quem vê", flush=True)
            ivo_http = TestClient(modulo.app, base_url="https://testserver")
            ivo_http.post("/api/entrar", json={"email": ivo["email"], "senha": ivo["senha"]})
            for metodo, rota in (("GET", "/api/auditoria"), ("GET", "/api/auditoria/exportar"), ("GET", "/api/notificacoes"), ("POST", "/api/notificacoes/lidas")):
                registrar(f"analista não acessa {rota}", ivo_http.request(metodo, rota).status_code == 403)
            auditora_http = TestClient(modulo.app, base_url="https://testserver")
            auditora_http.post("/api/entrar", json={"email": auditora["email"], "senha": auditora["senha"]})
            registrar("auditoria lê a trilha", auditora_http.get("/api/auditoria").status_code == 200)
            b_http = TestClient(modulo.app, base_url="https://testserver")
            b_http.post("/api/entrar", json={"email": de_b["email"], "senha": de_b["senha"]})
            trilha_b = b_http.get("/api/auditoria").json()["linhas"]
            registrar("outro cliente não vê a trilha", all(ivo["email"] not in l["alvo"] for l in trilha_b) and {l["acao"] for l in trilha_b} == {"logon"}, str(trilha_b)[:160])
            registrar("outro cliente não vê os avisos", b_http.get("/api/notificacoes").json()["avisos"] == [])

            print("\n== Marcar como lido", flush=True)
            registrar("marca os avisos", http.post("/api/notificacoes/lidas").status_code == 204)
            registrar("somem da lista", http.get("/api/notificacoes").json()["avisos"] == [])
            registrar("guarda quem leu", str(admin.execute("SELECT lida_por FROM notificacoes WHERE cliente_id = %s LIMIT 1", (a,)).fetchone()[0]) == ana["id"])
            registrar("marcar não apaga da trilha", len(linhas(a, "login_recusado")) >= 4)
            TestClient(modulo.app, base_url="https://testserver").post("/api/entrar", json={"email": ivo["email"], "senha": "errada"})
            registrar("nova tentativa abre outro aviso", len(http.get("/api/notificacoes").json()["avisos"]) == 1)
            modulo.falhas_de_login.clear()

            print("\n== Segundo fator", flush=True)
            inicio = http.post("/api/mfa/iniciar", json={"senha": ana["senha"]}).json()
            http.post("/api/mfa/confirmar", json={"codigo": pyotp.TOTP(inicio["segredo"]).now()})
            mfa_http = TestClient(modulo.app, base_url="https://testserver")
            mfa_http.post("/api/entrar", json={"email": ana["email"], "senha": ana["senha"]})
            mfa_http.post("/api/mfa/verificar", json={"codigo": "000000"})
            registrar("código errado fica na trilha", len(linhas(a, "mfa_recusado")) == 1)
            registrar("código errado também avisa", any(x["tipo"] == "mfa_recusado" for x in http.get("/api/notificacoes").json()["avisos"]))
            logons_da_ana = [l for l in linhas(a, "logon") if str(l[0]) == ana["id"]]
            registrar("senha certa sem o código ainda não é logon", len(logons_da_ana) == 1, str(len(logons_da_ana)))
            modulo.falhas_de_login.clear()

            print("\n== Logoff", flush=True)
            antes = len(linhas(a, "logoff"))
            ivo_http.post("/api/sair")
            registrar("logoff fica na trilha", len(linhas(a, "logoff")) == antes + 1)
            ivo_http.post("/api/sair")
            registrar("sair sem sessão não registra nada", len(linhas(a, "logoff")) == antes + 1)

            print("\n== Acessos concedidos e ativos", flush=True)
            r = http.post("/api/usuarios", json={"nome": "Nova", "email": f"nova-{SUFIXO}@exemplo.test", "perfil": "analista_n1"})
            registrar("concessão de acesso fica na trilha", len(linhas(a, "criar_usuario")) == 1, str(r.status_code))
            registrar("mudança de perfil fica na trilha", http.put(f"/api/usuarios/{ivo['id']}", json={"perfil": "analista_n2", "ativo": True}).status_code == 204 and len(linhas(a, "alterar_usuario")) >= 1)
            g = uuid.uuid4().hex[:12]
            admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, a, 51000 + secrets.randbelow(8000)))
            gerenciadores.append(g)
            admin.execute("INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, estado) VALUES (%s, %s, '007', 'srv-novo', 'active')", (a, g))
            registrar("inclusão de ativo fica na trilha, sem pessoa", linhas(a, "incluir_ativo") == [(None, "srv-novo (007)", None)], str(linhas(a, "incluir_ativo")))
            admin.execute("DELETE FROM ativos WHERE gerenciador_id = %s", (g,))
            registrar("exclusão de ativo fica na trilha", len(linhas(a, "excluir_ativo")) == 1)

            print("\n== Origem", flush=True)
            sem_origem = admin.execute("SELECT acao, count(*) FROM auditoria WHERE cliente_id = %s AND usuario_id IS NOT NULL AND origem IS NULL GROUP BY 1", (a,)).fetchall()
            registrar("toda ação de uma pessoa tem origem", not sem_origem, str(sem_origem))
            registrar("a mudança de perfil tem origem", all(l[2] for l in linhas(a, "alterar_usuario")), str(linhas(a, "alterar_usuario")))
            registrar("ação de sistema continua sem origem", linhas(a, "excluir_ativo")[0][2] is None)
            registrar("a API não forja a origem por outra sessão", admin.execute("SELECT current_setting('roar.origem', true)").fetchone()[0] in (None, ""))

            print("\n== Consulta", flush=True)
            d = auditora_http.get("/api/auditoria", params={"acao": "logon"}).json()
            registrar("filtra por ação", d["linhas"] and {l["acao"] for l in d["linhas"]} == {"logon"})
            registrar("traz o nome de quem fez", any(l["pessoa"] == "Pessoa administrador" for l in d["linhas"]), str(d["linhas"])[:160])
            registrar("ação de sistema aparece sem pessoa", any(l["pessoa"] is None for l in auditora_http.get("/api/auditoria", params={"acao": "incluir_ativo"}).json()["linhas"]))
            registrar("lista as ações para o filtro", {"logon", "login_recusado", "incluir_ativo"} <= set(auditora_http.get("/api/auditoria").json()["acoes"]))
            registrar("filtro por pessoa", all(l["alvo"] == ivo["email"] for l in auditora_http.get("/api/auditoria", params={"acao": "login_recusado", "pessoa": ivo["id"]}).json()["linhas"]))
            registrar("pessoa inválida é recusada", auditora_http.get("/api/auditoria", params={"pessoa": "x' OR 1=1"}).status_code == 422)
            for i in range(modulo.TAMANHO_DA_TRILHA + 5):
                admin.execute("INSERT INTO auditoria (cliente_id, acao, alvo) VALUES (%s, 'paginar', %s)", (a, str(i)))
            p1 = auditora_http.get("/api/auditoria", params={"acao": "paginar"}).json()
            p2 = auditora_http.get("/api/auditoria", params={"acao": "paginar", "antes_de": p1["proximo"]}).json()
            registrar("pagina sem repetir nem pular", len(p1["linhas"]) == modulo.TAMANHO_DA_TRILHA and len(p2["linhas"]) == 5 and not {l["id"] for l in p1["linhas"]} & {l["id"] for l in p2["linhas"]} and p2["proximo"] is None)

            print("\n== Exportar", flush=True)
            admin.execute("INSERT INTO auditoria (cliente_id, acao, alvo) VALUES (%s, 'formula', '=HYPERLINK(\"http://mal\")')", (a,))
            r = auditora_http.get("/api/auditoria/exportar", params={"dias": 30})
            registrar("sai em CSV", r.status_code == 200 and r.headers["content-type"].startswith("text/csv"))
            tabela = list(csv.reader(io.StringIO(r.text)))
            registrar("tem cabeçalho e linhas", tabela[0][:2] == ["quando", "acao"] and len(tabela) > 10)
            registrar("fórmula de planilha é neutralizada", not any(c.startswith("=") for l in tabela for c in l) and any(c.startswith("'=") for l in tabela for c in l))
            registrar("exportar fica na trilha", len(linhas(a, "exportar_auditoria")) == 1)

        print("\n== Banco", flush=True)
        with psycopg.connect(f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar") as con:
            con.execute("SELECT set_config('roar.cliente', %s, false)", (a,))
            for sql, nome in (("UPDATE auditoria SET alvo = 'x'", "alterar a trilha"), ("DELETE FROM auditoria", "apagar a trilha"), ("DELETE FROM notificacoes", "apagar avisos")):
                try:
                    con.execute(sql)
                    registrar(f"a API não consegue {nome}", False)
                except psycopg.errors.InsufficientPrivilege:
                    registrar(f"a API não consegue {nome}", True)
                con.rollback()
                con.execute("SELECT set_config('roar.cliente', %s, false)", (a,))
    finally:
        admin.execute("DELETE FROM notificacoes WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM ativos WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM auditoria WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM gerenciadores WHERE id = ANY(%s)", (gerenciadores,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))
        admin.close()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
