#!/usr/bin/env python3
"""Perfis: cada rota contra cada perfil, de verdade, com banco real. Não precisa de gerenciador.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_perfis.py

A tabela abaixo é independente do código: uma rota nova sem permissão declarada aqui faz o teste falhar.
"""

import re
import secrets
import sys
import uuid
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api import permissoes  # noqa: E402
from roar_api.app import app  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
SEM_PERMISSAO = {("POST", "/api/entrar"), ("POST", "/api/sair"), ("GET", "/api/eu"), ("POST", "/api/minha-senha"), ("POST", "/api/entrada/webhook")}
# O que se espera de cada perfil, escrito à mão de propósito.
ESPERADO = {
    "administrador": {"ver", "ver_bruto", "gerir_regras", "gerir_fontes", "instalar_agente", "gerir_playbooks", "aprovar", "gerir_usuarios"},
    "engenharia": {"ver", "ver_bruto", "gerir_regras", "gerir_fontes", "instalar_agente", "gerir_playbooks"},
    "analista_n2": {"ver", "ver_bruto", "aprovar"},
    "analista_n1": {"ver", "ver_bruto"},
    "auditor": {"ver"},
}
ROTAS = {
    ("GET", "/api/fila"): "ver", ("GET", "/api/panorama"): "ver", ("GET", "/api/eventos"): "ver", ("GET", "/api/eventos/{identificador}/bruto"): "ver_bruto",
    ("GET", "/api/logs"): "ver_bruto", ("GET", "/api/ativos"): "ver", ("GET", "/api/mitre/matriz"): "ver", ("GET", "/api/mitre/tecnicas/{tecnica}"): "ver",
    ("GET", "/api/fim"): "ver", ("GET", "/api/fim/ativos/{agente}/arquivos"): "ver", ("POST", "/api/fim/caminhos"): "gerir_fontes",
    ("POST", "/api/fim/caminhos/{identificador}/desativar"): "gerir_fontes", ("POST", "/api/fim/varreduras"): "gerir_fontes",
    ("GET", "/api/normas"): "ver", ("GET", "/api/arquivos"): "ver", ("GET", "/api/regras"): "ver", ("POST", "/api/regras/converter"): "gerir_regras",
    ("GET", "/api/regras/proprias"): "ver", ("POST", "/api/regras/proprias"): "gerir_regras", ("PUT", "/api/regras/proprias/{identificador}"): "gerir_regras",
    ("POST", "/api/regras/proprias/{identificador}/desativar"): "gerir_regras", ("POST", "/api/regras/importar"): "gerir_regras", ("GET", "/api/regras/exportar"): "ver",
    ("GET", "/api/regras/biblioteca"): "ver", ("POST", "/api/regras/biblioteca/{identificador}/ativar"): "gerir_regras", ("GET", "/api/regras/arquivos/{arquivo}"): "ver",
    ("GET", "/api/regras/{regra_id}"): "ver", ("PUT", "/api/regras/{regra_id}/versao"): "gerir_regras", ("POST", "/api/regras/{regra_id}/desligar"): "gerir_regras",
    ("POST", "/api/regras/{regra_id}/restaurar"): "gerir_regras", ("GET", "/api/fontes"): "ver", ("POST", "/api/fontes"): "gerir_fontes", ("POST", "/api/fontes/nuvem"): "gerir_fontes",
    ("POST", "/api/fontes/api"): "gerir_fontes", ("POST", "/api/fontes/webhook"): "gerir_fontes", ("POST", "/api/fontes/{identificador}/desativar"): "gerir_fontes",
    ("GET", "/api/fontes/instalacao"): "instalar_agente", ("GET", "/api/automacao"): "ver", ("POST", "/api/automacao/playbooks"): "gerir_playbooks",
    ("PUT", "/api/automacao/playbooks/{identificador}"): "gerir_playbooks", ("POST", "/api/automacao/playbooks/{identificador}/{acao}"): "gerir_playbooks",
    ("POST", "/api/automacao/para-codigo"): "ver", ("POST", "/api/automacao/de-codigo"): "ver", ("POST", "/api/automacao/simular"): "gerir_playbooks",
    ("POST", "/api/automacao/aprovacoes/{identificador}/aprovar"): "aprovar", ("POST", "/api/automacao/aprovacoes/{identificador}/recusar"): "aprovar",
    ("GET", "/api/riscos/{identificador}"): "ver", ("GET", "/api/grupos/{identificador}"): "ver", ("GET", "/api/usuarios"): "gerir_usuarios", ("POST", "/api/usuarios"): "gerir_usuarios",
    ("PUT", "/api/usuarios/{identificador}"): "gerir_usuarios", ("POST", "/api/usuarios/{identificador}/nova-senha"): "gerir_usuarios",
}
VALORES = {"identificador": "999999", "agente": "999", "tecnica": "T1110", "arquivo": "inexistente.xml", "regra_id": "999999", "acao": "ativar"}


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def permissao_da_rota(rota):
    for dependencia in rota.dependant.dependencies:
        if hasattr(dependencia.call, "permissao"):
            return dependencia.call.permissao
    return None


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    clientes, usuarios = [], {}

    def criar_cliente(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        clientes.append(c)
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)",
                      (f"{nome.replace('-', '')}{SUFIXO}", c, 50000 + secrets.randbelow(10000)))
        return c

    def criar_usuario(cliente, perfil, trocar=False):
        senha, email = secrets.token_urlsafe(18), f"{perfil}-{uuid.uuid4().hex[:8]}@exemplo.test"
        i = admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil, trocar_senha) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                          (cliente, email, perfil, PasswordHasher().hash(senha), perfil, trocar)).fetchone()[0]
        return {"email": email, "senha": senha, "id": str(i)}

    try:
        a, b = criar_cliente("perfis-a"), criar_cliente("perfis-b")
        for perfil in ESPERADO:
            usuarios[perfil] = criar_usuario(a, perfil)
        outro_admin = criar_usuario(b, "administrador")

        print("== Declaração", flush=True)
        registrar("os perfis são os esperados", {p: set(v) for p, v in permissoes.PERFIS.items()} == ESPERADO)
        rotas = [(m, r.path, r) for r in app.routes if isinstance(r, APIRoute) for m in r.methods if r.path.startswith("/api/")]
        sem_tabela = [(m, p) for m, p, r in rotas if (m, p) not in ROTAS and (m, p) not in SEM_PERMISSAO]
        registrar("toda rota está na tabela do teste", not sem_tabela, str(sem_tabela))
        errados = [(m, p, permissao_da_rota(r), ROTAS[(m, p)]) for m, p, r in rotas if (m, p) in ROTAS and permissao_da_rota(r) != ROTAS[(m, p)]]
        registrar("toda rota exige a permissão esperada", not errados, str(errados))
        soltas = [(m, p) for m, p, r in rotas if (m, p) in SEM_PERMISSAO and permissao_da_rota(r)]
        registrar("as rotas abertas são só as previstas", not soltas, str(soltas))

        print("\n== Cada rota contra cada perfil", flush=True)
        with TestClient(app, base_url="https://testserver") as http:
            registrar("sem sessão, tudo responde 401", all(
                http.request(m, re.sub(r"{(\w+)}", lambda x: VALORES[x.group(1)], p), json={}).status_code == 401 for m, p in ROTAS))
            for perfil, permitidas in ESPERADO.items():
                http.post("/api/entrar", json={"email": usuarios[perfil]["email"], "senha": usuarios[perfil]["senha"]})
                errado = []
                for (metodo, caminho), permissao in ROTAS.items():
                    # Corpo vazio e ids inexistentes: passa da permissão e para na validação, sem mudar nada.
                    endereco = re.sub(r"{(\w+)}", lambda x: VALORES[x.group(1)], caminho).replace("/usuarios/999999", f"/usuarios/{uuid.uuid4()}")
                    r = http.request(metodo, endereco, json={})
                    negado = r.status_code == 403
                    if negado != (permissao not in permitidas):
                        errado.append((metodo, caminho, r.status_code))
                registrar(f"{perfil}: faz só o que pode", not errado, str(errado)[:300])
                eu = http.get("/api/eu").json()
                registrar(f"{perfil}: a tela recebe as permissões certas", set(eu["permissoes"]) == permitidas)
                http.post("/api/sair")
                http.cookies.clear()

            print("\n== Gestão de usuários", flush=True)
            http.post("/api/entrar", json={"email": usuarios["administrador"]["email"], "senha": usuarios["administrador"]["senha"]})
            lista = http.get("/api/usuarios").text
            registrar("a lista não traz senha nem hash", "senha" not in lista and "argon2" not in lista)
            registrar("a lista só traz o próprio cliente", outro_admin["email"] not in lista and usuarios["auditor"]["email"] in lista)
            registrar("perfil inventado é recusado", http.post("/api/usuarios", json={"email": "x@exemplo.test", "nome": "x", "perfil": "dono"}).status_code == 422)
            registrar("e-mail inválido é recusado", http.post("/api/usuarios", json={"email": "nao", "nome": "x", "perfil": "auditor"}).status_code == 422)
            registrar("e-mail já usado em outro cliente não revela de quem é", http.post("/api/usuarios", json={"email": outro_admin["email"], "nome": "x", "perfil": "auditor"}).json().get("detail") == "Não foi possível usar este e-mail.")
            email_novo = f"novo-{uuid.uuid4().hex[:8]}@exemplo.test"
            criado = http.post("/api/usuarios", json={"email": email_novo, "nome": "Nova", "perfil": "analista_n1"}).json()
            registrar("criar devolve senha temporária uma vez", criado.get("senha_temporaria") and criado["senha_temporaria"] not in http.get("/api/usuarios").text)
            registrar("o banco não guarda a senha em texto", criado["senha_temporaria"] not in admin.execute("SELECT senha_hash FROM usuarios WHERE id = %s", (criado["id"],)).fetchone()[0])
            registrar("criação fica na auditoria", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'criar_usuario'", (a,)).fetchone()[0] == 1)

            print("\n== Outro cliente", flush=True)
            registrar("não altera usuário de outro cliente", http.put(f"/api/usuarios/{outro_admin['id']}", json={"perfil": "auditor", "ativo": False}).status_code == 404)
            registrar("não troca a senha de usuário de outro cliente", http.post(f"/api/usuarios/{outro_admin['id']}/nova-senha").status_code == 404)
            registrar("o usuário do outro cliente continua igual", admin.execute("SELECT perfil, ativo FROM usuarios WHERE id = %s", (outro_admin["id"],)).fetchone() == ("administrador", True))

            print("\n== Último administrador", flush=True)
            eu_admin = usuarios["administrador"]["id"]
            registrar("não rebaixa a última pessoa administradora", http.put(f"/api/usuarios/{eu_admin}", json={"perfil": "auditor", "ativo": True}).status_code == 409)
            registrar("não desativa a última pessoa administradora", http.put(f"/api/usuarios/{eu_admin}", json={"perfil": "administrador", "ativo": False}).status_code == 409)
            http.post("/api/sair")
            http.cookies.clear()

            print("\n== Senha temporária", flush=True)
            http.post("/api/entrar", json={"email": email_novo, "senha": criado["senha_temporaria"]})
            registrar("entra e a tela sabe que precisa trocar", http.get("/api/eu").json()["trocar_senha"] is True)
            registrar("com senha temporária não vê nada", http.get("/api/fila").status_code == 403)
            registrar("senha curta é recusada", http.post("/api/minha-senha", json={"atual": criado["senha_temporaria"], "nova": "curta"}).status_code == 422)
            registrar("senha atual errada é recusada", http.post("/api/minha-senha", json={"atual": "errada", "nova": "x" * 16}).status_code == 403)
            registrar("repetir a mesma senha é recusado", http.post("/api/minha-senha", json={"atual": criado["senha_temporaria"], "nova": criado["senha_temporaria"]}).status_code == 422)
            nova = secrets.token_urlsafe(18)
            registrar("trocar responde", http.post("/api/minha-senha", json={"atual": criado["senha_temporaria"], "nova": nova}).status_code == 204)
            registrar("depois de trocar, vê os dados", http.get("/api/fila").status_code == 200)
            http.post("/api/sair")
            http.cookies.clear()
            registrar("a senha temporária não entra mais", http.post("/api/entrar", json={"email": email_novo, "senha": criado["senha_temporaria"]}).status_code == 401)
            registrar("a nova entra", http.post("/api/entrar", json={"email": email_novo, "senha": nova}).status_code == 204)

            print("\n== Mudança vale na hora", flush=True)
            sessao_dela = http.cookies.get("roar_sessao")
            with TestClient(app, base_url="https://testserver") as chefe:
                chefe.post("/api/entrar", json={"email": usuarios["administrador"]["email"], "senha": usuarios["administrador"]["senha"]})
                registrar("a sessão dela funciona", http.get("/api/logs").status_code == 200)
                registrar("administrador rebaixa", chefe.put(f"/api/usuarios/{criado['id']}", json={"perfil": "auditor", "ativo": True}).status_code == 204)
                registrar("a sessão antiga cai na hora", http.get("/api/fila").status_code == 401, str(bool(sessao_dela)))
                http.cookies.clear()
                http.post("/api/entrar", json={"email": email_novo, "senha": nova})
                registrar("entrando de novo, vale o perfil novo", http.get("/api/logs").status_code == 403 and http.get("/api/fila").status_code == 200)
                registrar("administrador desativa", chefe.put(f"/api/usuarios/{criado['id']}", json={"perfil": "auditor", "ativo": False}).status_code == 204)
                registrar("desativada cai na hora", http.get("/api/fila").status_code == 401)
                http.cookies.clear()
                registrar("desativada não entra", http.post("/api/entrar", json={"email": email_novo, "senha": nova}).status_code == 401)
                chefe.put(f"/api/usuarios/{criado['id']}", json={"perfil": "administrador", "ativo": True})
                registrar("com outra pessoa administradora, dá para rebaixar a primeira", chefe.put(f"/api/usuarios/{eu_admin}", json={"perfil": "auditor", "ativo": True}).status_code == 204)
                registrar("rebaixar sem passar por administração não eleva ninguém", chefe.get("/api/usuarios").status_code == 401)

            print("\n== Banco", flush=True)
            url_api = f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar"
            with psycopg.connect(url_api) as con:
                try:
                    con.execute("SELECT * FROM usuarios")
                    registrar("a API segue sem ler a tabela de usuários", False)
                except psycopg.errors.InsufficientPrivilege:
                    registrar("a API segue sem ler a tabela de usuários", True)
            with psycopg.connect(url_api) as con:
                registrar("sem cliente definido, a lista vem vazia", con.execute("SELECT count(*) FROM roar_listar_usuarios()").fetchone()[0] == 0)
    finally:
        for tabela in ("auditoria", "regras"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM gerenciadores WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))
        admin.close()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
