#!/usr/bin/env python3
"""Organizações pela tela, com gerenciador real: criar, entrar com a senha temporária, isolamento e remoção.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_organizacoes.py

Apaga no final tudo o que criou.
"""

import secrets
import sys
import uuid
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import organizacoes, provisao  # noqa: E402

RESULTADOS = []
SUFIXO = uuid.uuid4().hex[:8]
ENV = provisao.ler_env(provisao.DESTINO / ".env")
ADMIN = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def conta(cliente, plataforma=False):
    senha, email = secrets.token_urlsafe(18), f"org-{uuid.uuid4().hex[:8]}@exemplo.test"
    ADMIN.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil, plataforma) VALUES (%s, %s, 'Pessoa', %s, 'administrador', %s)",
                  (cliente, email, PasswordHasher().hash(senha), plataforma))
    return {"email": email, "senha": senha}


def entrar(credenciais):
    http = TestClient(app, base_url="https://testserver")
    http.post("/api/entrar", json=credenciais)
    return http


def um(sql, *valores):
    linha = ADMIN.execute(sql, valores).fetchone()
    return linha[0] if linha else None


def main():
    nome_base, nome_novo = f"Base {SUFIXO}", f"Nova {SUFIXO}"
    base = um("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", nome_base)
    novo = None
    try:
        with TestClient(app, base_url="https://testserver") as anonimo:
            print("== Quem pode", flush=True)
            registrar("lista exige sessão", anonimo.get("/api/organizacoes").status_code == 401)
            credenciais_do_dono = conta(base, plataforma=True)
            comum, dono = entrar(conta(base)), entrar(credenciais_do_dono)
            registrar("administrador comum não é da plataforma", comum.get("/api/eu").json()["plataforma"] is False)
            registrar("quem administra a instalação é", dono.get("/api/eu").json()["plataforma"] is True)
            registrar("administrador comum não lista", comum.get("/api/organizacoes").status_code == 403)
            registrar("administrador comum não cria", comum.post("/api/organizacoes", json={"nome": "x", "email": "x@exemplo.test"}).status_code == 403)
            registrar("administrador comum não remove", comum.post(f"/api/organizacoes/{base}/remover", json={"confirmacao": nome_base}).status_code == 403)

            print("== Pedido", flush=True)
            registrar("nome vazio é recusado", dono.post("/api/organizacoes", json={"nome": "  ", "email": "a@exemplo.test"}).status_code == 422)
            registrar("e-mail estranho é recusado", dono.post("/api/organizacoes", json={"nome": "a", "email": "não é e-mail"}).status_code == 422)
            registrar("nome em uso é recusado", dono.post("/api/organizacoes", json={"nome": nome_base.upper(), "email": f"b-{SUFIXO}@exemplo.test"}).status_code == 409)
            email = f"Chefe-{SUFIXO}@Exemplo.test"
            r = dono.post("/api/organizacoes", json={"nome": nome_novo, "email": email})
            registrar("pedido aceito", r.status_code == 201, str(r.status_code))
            temporaria = r.json()["senha_temporaria"]
            guardado = um("SELECT senha_hash FROM organizacoes_pedidos WHERE nome = %s", nome_novo)
            registrar("a senha não fica em claro", guardado and temporaria not in guardado and guardado.startswith("$argon2"))
            registrar("pedido repetido é recusado", dono.post("/api/organizacoes", json={"nome": nome_novo, "email": f"c-{SUFIXO}@exemplo.test"}).status_code == 409)
            registrar("e-mail em pedido é recusado", dono.post("/api/organizacoes", json={"nome": f"Outra {SUFIXO}", "email": email}).status_code == 409)
            registrar("o pedido aparece", any(p["nome"] == nome_novo and p["estado"] == "pendente" for p in dono.get("/api/organizacoes").json()["pedidos"]))
            registrar("a lista não mostra o hash", "argon2" not in dono.get("/api/organizacoes").text)
            registrar("o pedido fica na auditoria", um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'pedir_organizacao' AND alvo = %s", base, nome_novo) == 1)

            print("== Execução", flush=True)
            while organizacoes.processar_um(ENV):
                pass
            novo = um("SELECT id FROM clientes WHERE nome = %s", nome_novo)
            estado = ADMIN.execute("SELECT estado, senha_hash, mensagem FROM organizacoes_pedidos WHERE nome = %s", (nome_novo,)).fetchone()
            registrar("organização criada", novo and estado[0] == "pronto", str(estado[0]) + " " + str(estado[2]))
            registrar("a senha some do pedido", estado[1] is None)
            registrar("nasce com gerenciador próprio", um("SELECT count(*) FROM gerenciadores WHERE cliente_id = %s", novo) == 1)

            print("== Primeiro acesso e isolamento", flush=True)
            registrar("senha errada não entra", anonimo.post("/api/entrar", json={"email": email, "senha": "errada-errada"}).status_code == 401)
            nova = entrar({"email": email, "senha": temporaria})
            registrar("entra com a senha temporária", nova.get("/api/eu").json().get("trocar_senha") is True)
            registrar("sem trocar, não vê dados", nova.get("/api/ativos").status_code == 403)
            definitiva = secrets.token_urlsafe(18)
            registrar("troca a senha", nova.post("/api/minha-senha", json={"atual": temporaria, "nova": definitiva}).status_code == 204)
            nova = entrar({"email": email, "senha": definitiva})
            eu = nova.get("/api/eu").json()
            registrar("entra na organização certa, sem poder de plataforma", eu["cliente"] == nome_novo and eu["plataforma"] is False)
            registrar("é administradora da própria", "gerir_usuarios" in eu["permissoes"])
            registrar("não vê gente de outra organização", all(u["email"] == email.lower() for u in nova.get("/api/usuarios").json()["usuarios"]))
            registrar("administrador da nova não lista organizações", nova.get("/api/organizacoes").status_code == 403)
            linha = next(o for o in dono.get("/api/organizacoes").json()["organizacoes"] if o["id"] == str(novo))
            registrar("a lista traz a nova, removível", linha["removivel"] is True and linha["usuarios"] == 1)

            print("== Trocar de organização", flush=True)
            gerenciador_novo = um("SELECT id FROM gerenciadores WHERE cliente_id = %s", novo)
            ADMIN.execute("INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, estado) VALUES (%s, %s, '001', 'so-da-nova', 'active')", (novo, gerenciador_novo))
            nomes_de = lambda h: [a["nome"] for a in h.get("/api/ativos").json()["ativos"]]  # noqa: E731
            registrar("antes de entrar não vê nada da outra", "so-da-nova" not in nomes_de(dono))
            registrar("administrador comum não entra", comum.post(f"/api/organizacoes/{novo}/entrar").status_code == 403)
            registrar("administrador da outra não entra", nova.post(f"/api/organizacoes/{base}/entrar").status_code == 403)
            registrar("sem sessão não entra", anonimo.post(f"/api/organizacoes/{novo}/entrar").status_code == 401)
            registrar("organização inexistente é recusada", dono.post(f"/api/organizacoes/{uuid.uuid4()}/entrar").status_code == 404)
            outra_sessao = entrar(credenciais_do_dono)
            registrar("entrar responde", dono.post(f"/api/organizacoes/{novo}/entrar").json().get("cliente") == nome_novo)
            eu = dono.get("/api/eu").json()
            registrar("a sessão diz onde está", eu["cliente"] == nome_novo and eu["em_outra_organizacao"] is True and eu["cliente_proprio"] == nome_base)
            registrar("vê os dados de lá", nomes_de(dono) == ["so-da-nova"])
            registrar("vê as pessoas de lá", [u["email"] for u in dono.get("/api/usuarios").json()["usuarios"]] == [email.lower()])
            registrar("a outra sessão da mesma pessoa não muda", outra_sessao.get("/api/eu").json()["cliente"] == nome_base and "so-da-nova" not in nomes_de(outra_sessao))
            registrar("quem é de lá não é afetado", nova.get("/api/eu").json()["cliente"] == nome_novo)
            registrar("a entrada fica na auditoria de lá", um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'entrar_na_organizacao'", novo) == 1)
            registrar("a entrada fica na auditoria de cá", um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'entrar_em_outra_organizacao' AND alvo = %s", base, nome_novo) == 1)
            registrar("entrar de novo não repete o registro", dono.post(f"/api/organizacoes/{novo}/entrar").status_code == 200 and um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'entrar_na_organizacao'", novo) == 1)
            linha = next(l for l in nova.get("/api/auditoria").json()["linhas"] if l["acao"] == "entrar_na_organizacao")
            registrar("a organização vê o nome de quem entrou", "administração da instalação" in (linha["pessoa"] or ""), str(linha["pessoa"]))
            dono.post("/api/usuarios", json={"email": f"feito-la-{SUFIXO}@exemplo.test", "nome": "Feita lá", "perfil": "analista_n1"})
            registrar("o que faz lá nasce lá", um("SELECT cliente_id FROM usuarios WHERE email = %s", f"feito-la-{SUFIXO}@exemplo.test") == novo)
            registrar("e fica na auditoria de lá", um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'criar_usuario'", novo) == 1)
            registrar("lá dentro continua sem remover a própria", dono.post(f"/api/organizacoes/{base}/remover", json={"confirmacao": nome_base}).status_code == 409)
            registrar("a saída responde", dono.post("/api/organizacoes/voltar").json().get("cliente") == nome_base)
            eu = dono.get("/api/eu").json()
            registrar("voltou para a própria", eu["cliente"] == nome_base and eu["em_outra_organizacao"] is False and "so-da-nova" not in nomes_de(dono))
            registrar("a saída fica na auditoria de lá", um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'sair_da_organizacao'", novo) == 1)
            dono.post(f"/api/organizacoes/{novo}/entrar")
            ADMIN.execute("UPDATE usuarios SET plataforma = false WHERE email = %s", (credenciais_do_dono["email"],))
            registrar("perdeu o poder, volta na hora", dono.get("/api/eu").json()["cliente"] == nome_base and "so-da-nova" not in nomes_de(dono))
            registrar("e não entra mais", dono.post(f"/api/organizacoes/{novo}/entrar").status_code == 403)
            ADMIN.execute("UPDATE usuarios SET plataforma = true WHERE email = %s", (credenciais_do_dono["email"],))
            dono.post("/api/organizacoes/voltar")

            print("== Remoção", flush=True)
            propria = next(o for o in dono.get("/api/organizacoes").json()["organizacoes"] if o["id"] == str(base))
            registrar("a própria não é removível", propria["removivel"] is False)
            registrar("a própria é recusada", dono.post(f"/api/organizacoes/{base}/remover", json={"confirmacao": nome_base}).status_code == 409)
            registrar("nome errado é recusado", dono.post(f"/api/organizacoes/{novo}/remover", json={"confirmacao": "outro"}).status_code == 409)
            registrar("organização inexistente é recusada", dono.post(f"/api/organizacoes/{uuid.uuid4()}/remover", json={"confirmacao": "x"}).status_code == 409)
            registrar("identificador estranho não passa", dono.post("/api/organizacoes/1%20or%201/remover", json={"confirmacao": "x"}).status_code in (404, 422))
            gerenciador = um("SELECT id FROM gerenciadores WHERE cliente_id = %s", novo)
            registrar("nada mudou com as recusas", um("SELECT count(*) FROM organizacoes_pedidos WHERE acao = 'remover' AND nome = %s", nome_base) == 0)
            registrar("remoção aceita", dono.post(f"/api/organizacoes/{novo}/remover", json={"confirmacao": nome_novo}).status_code == 202)
            registrar("remoção fica na auditoria", um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'remover_organizacao' AND alvo = %s", base, nome_novo) == 1)
            while organizacoes.processar_um(ENV):
                pass
            estado = ADMIN.execute("SELECT estado, mensagem FROM organizacoes_pedidos WHERE acao = 'remover' AND nome = %s", (nome_novo,)).fetchone()
            registrar("pedido concluído", estado[0] == "pronto", str(estado))
            registrar("a organização sumiu", um("SELECT count(*) FROM clientes WHERE id = %s", novo) == 0)
            registrar("o gerenciador sumiu", not (provisao.DESTINO / "gerenciadores" / gerenciador).exists())
            registrar("a sessão morreu", nova.get("/api/eu").status_code == 401)
            registrar("quem estava dentro dela volta para a própria", outra_sessao.post(f"/api/organizacoes/{novo}/entrar").status_code == 404 and outra_sessao.get("/api/eu").json()["cliente"] == nome_base)
            registrar("a conta não entra mais", anonimo.post("/api/entrar", json={"email": email, "senha": definitiva}).status_code == 401)
            registrar("a outra organização continua", um("SELECT count(*) FROM clientes WHERE id = %s", base) == 1)
            novo = None

            print("== Falha", flush=True)
            original = provisao.criar
            provisao.criar = lambda nome: (_ for _ in ()).throw(RuntimeError("segredo-interno"))
            try:
                nome_falho = f"Falha {SUFIXO}"
                dono.post("/api/organizacoes", json={"nome": nome_falho, "email": f"falha-{SUFIXO}@exemplo.test"})
                while organizacoes.processar_um(ENV):
                    pass
            finally:
                provisao.criar = original
            pedido = next(p for p in dono.get("/api/organizacoes").json()["pedidos"] if p["nome"] == nome_falho)
            registrar("falha aparece sem detalhe interno", pedido["estado"] == "falhou" and "segredo-interno" not in (pedido["mensagem"] or ""))
            registrar("falha apaga a senha do pedido", um("SELECT senha_hash FROM organizacoes_pedidos WHERE nome = %s", nome_falho) is None)

            print("== Falha no meio", flush=True)
            copia = provisao.shutil.copy
            nome_meio = f"Meio {SUFIXO}"

            def quebrada(*_):
                raise FileNotFoundError("modelo sumiu")

            provisao.shutil.copy = quebrada
            try:
                dono.post("/api/organizacoes", json={"nome": nome_meio, "email": f"meio-{SUFIXO}@exemplo.test"})
                while organizacoes.processar_um(ENV):
                    pass
            finally:
                provisao.shutil.copy = copia
            registrar("falhou de verdade no meio", um("SELECT estado FROM organizacoes_pedidos WHERE nome = %s", nome_meio) == "falhou")
            registrar("não fica organização pela metade", um("SELECT count(*) FROM clientes WHERE nome = %s", nome_meio) == 0)
            registrar("o nome fica livre para tentar de novo", dono.post("/api/organizacoes", json={"nome": nome_meio, "email": f"meio2-{SUFIXO}@exemplo.test"}).status_code == 201)
            ADMIN.execute("DELETE FROM organizacoes_pedidos WHERE nome = %s AND estado = 'pendente'", (nome_meio,))
            registrar("a instalação leva o modelo do gerenciador", (provisao.DESTINO / "app/infra/wazuh/gerenciador/docker-compose.yml").is_file())
    finally:
        for g in ADMIN.execute("SELECT id FROM gerenciadores WHERE cliente_id = %s", (novo,)).fetchall() if novo else []:
            provisao.remover(g[0])
        ADMIN.execute("DELETE FROM organizacoes_pedidos WHERE nome LIKE %s", (f"% {SUFIXO}",))
        ADMIN.execute("DELETE FROM auditoria WHERE cliente_id = %s", (base,))
        ADMIN.execute("DELETE FROM usuarios WHERE cliente_id = %s", (base,))
        ADMIN.execute("DELETE FROM clientes WHERE id = %s", (base,))

    falhas = [n for n, p in RESULTADOS if not p]
    print(f"\n{len(RESULTADOS) - len(falhas)}/{len(RESULTADOS)} passaram")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main()
