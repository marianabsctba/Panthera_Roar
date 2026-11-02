#!/usr/bin/env python3
"""Segundo fator com banco real e códigos de verdade, gerados como um aplicativo autenticador gera.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_mfa.py
"""

import secrets
import sys
import time
import uuid
from pathlib import Path

import psycopg
import pyotp
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api import app as modulo  # noqa: E402
from roar_api import mfa  # noqa: E402

app = modulo.app
RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def codigo(segredo, deslocamento=0):
    return pyotp.TOTP(segredo).at(time.time() + deslocamento * mfa.PASSO)


def main():
    print("== Peças", flush=True)
    chave = "chave-de-teste"
    u1, u2 = uuid.uuid4(), uuid.uuid4()
    selado = mfa.selar(chave, u1, "SEGREDO")
    registrar("o segredo não aparece cifrado", b"SEGREDO" not in selado)
    registrar("abre para a mesma pessoa", mfa.abrir(chave, u1, selado) == "SEGREDO")
    for nome, funcao in (("outra pessoa", lambda: mfa.abrir(chave, u2, selado)), ("outra chave", lambda: mfa.abrir("outra", u1, selado)),
                         ("valor adulterado", lambda: mfa.abrir(chave, u1, selado[:-1] + bytes([selado[-1] ^ 1])))):
        try:
            funcao()
            registrar(f"não abre: {nome}", False)
        except mfa.SegredoInvalido:
            registrar(f"não abre: {nome}", True)
    s = pyotp.random_base32()
    agora = int(time.time())
    registrar("código de agora vale", mfa.passo_do_codigo(s, pyotp.TOTP(s).at(agora), agora) == agora // 30)
    registrar("código com espaço vale", mfa.passo_do_codigo(s, pyotp.TOTP(s).at(agora)[:3] + " " + pyotp.TOTP(s).at(agora)[3:], agora) is not None)
    registrar("código de 2 minutos atrás não vale", mfa.passo_do_codigo(s, pyotp.TOTP(s).at(agora - 120), agora) is None)
    for ruim in ("", "abc", "12345", "1234567", "١٢٣٤٥٦", "123 45"):
        registrar(f"formato recusado: {ruim!r}", mfa.passo_do_codigo(s, ruim, agora) is None)
    registrar("o QR sai em SVG, sem nada de fora", mfa.qr_em_svg(mfa.endereco(s, "Maria")).startswith("<svg") and "<script" not in mfa.qr_em_svg(mfa.endereco(s, "Maria")))

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    clientes = []

    def criar_cliente(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        clientes.append(c)
        return c

    def criar_usuario(cliente, perfil="administrador"):
        senha, email = secrets.token_urlsafe(18), f"{perfil}-{uuid.uuid4().hex[:8]}@exemplo.test"
        i = admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                          (cliente, email, f"Pessoa {perfil}", PasswordHasher().hash(senha), perfil)).fetchone()[0]
        return {"email": email, "senha": senha, "id": str(i)}

    try:
        a, b = criar_cliente("mfa-a"), criar_cliente("mfa-b")
        ana, bia, de_b = criar_usuario(a), criar_usuario(a, "analista_n1"), criar_usuario(b)
        def entrar(http, u):
            http.cookies.clear()
            return http.post("/api/entrar", json={"email": u["email"], "senha": u["senha"]})

        with TestClient(app, base_url="https://testserver") as http:
            print("\n== Ligar", flush=True)
            registrar("exige sessão", http.post("/api/mfa/iniciar", json={"senha": "x"}).status_code == 401)
            r = entrar(http, ana)
            registrar("sem autenticador, a senha basta", r.status_code == 204 and http.get("/api/fila").status_code == 200)
            registrar("exigir sem ter ligado é recusado", http.put("/api/organizacao/mfa", json={"obrigatorio": True}).status_code == 409)
            registrar("iniciar com senha errada é recusado", http.post("/api/mfa/iniciar", json={"senha": "errada"}).status_code == 403)
            inicio = http.post("/api/mfa/iniciar", json={"senha": ana["senha"]}).json()
            segredo = inicio["segredo"]
            registrar("entrega segredo e QR", segredo and inicio["qr"].startswith("<svg"))
            guardado = bytes(admin.execute("SELECT mfa_selado FROM usuarios WHERE id = %s", (ana["id"],)).fetchone()[0])
            registrar("no banco o segredo está cifrado", segredo.encode() not in guardado)
            registrar("antes de confirmar, ainda não está ligado", http.get("/api/eu").json()["mfa_ativo"] is False)
            registrar("código errado não liga", http.post("/api/mfa/confirmar", json={"codigo": "000000"}).status_code == 422)
            codigo_de_ligar = codigo(segredo)
            r = http.post("/api/mfa/confirmar", json={"codigo": codigo_de_ligar})
            recuperacao = r.json().get("codigos_de_recuperacao", [])
            registrar("código certo liga e entrega os de recuperação", r.status_code == 200 and len(recuperacao) == 10, str(r.status_code))
            registrar("os de recuperação ficam só em hash", not admin.execute("SELECT count(*) FROM mfa_recuperacao WHERE codigo_hash = ANY(%s)", (recuperacao,)).fetchone()[0]
                      and admin.execute("SELECT count(*) FROM mfa_recuperacao WHERE usuario_id = %s", (ana["id"],)).fetchone()[0] == 10)
            registrar("ligar de novo é recusado", http.post("/api/mfa/iniciar", json={"senha": ana["senha"]}).status_code == 409)
            registrar("fica na auditoria", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'ligar_mfa'", (a,)).fetchone()[0] == 1)

            print("\n== Entrar", flush=True)
            r = entrar(http, ana)
            registrar("depois da senha, pede o código", r.status_code == 200 and r.json() == {"mfa": True})
            eu = http.get("/api/eu").json()
            registrar("a tela sabe que falta o código", eu["mfa_pendente"] is True)
            for metodo, rota in (("GET", "/api/fila"), ("GET", "/api/logs"), ("GET", "/api/usuarios"), ("GET", "/api/relatorios"), ("GET", "/api/fontes/instalacao")):
                registrar(f"sem o código não vê {rota}", http.request(metodo, rota).status_code == 403)
            registrar("sem o código não troca a senha", http.post("/api/minha-senha", json={"atual": ana["senha"], "nova": "x" * 16}).status_code == 403)
            registrar("sem o código não mexe no autenticador", http.post("/api/mfa/desligar", json={"senha": ana["senha"], "codigo": "1"}).status_code == 403)
            registrar("código errado é recusado", http.post("/api/mfa/verificar", json={"codigo": "000000"}).status_code == 422)
            registrar("o código usado ao ligar não vale de novo", http.post("/api/mfa/verificar", json={"codigo": codigo_de_ligar}).status_code == 422)
            achado = codigo(segredo, 1)
            r = http.post("/api/mfa/verificar", json={"codigo": achado})
            registrar("código certo libera", r.status_code == 204 and http.get("/api/fila").status_code == 200, str(r.status_code))
            registrar("a sessão deixa de estar pendente", http.get("/api/eu").json()["mfa_pendente"] is False)
            registrar("fica na auditoria", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'entrar_com_mfa'", (a,)).fetchone()[0] >= 1)

            print("\n== Reutilizar código", flush=True)
            entrar(http, ana)
            registrar("o mesmo código não entra duas vezes", http.post("/api/mfa/verificar", json={"codigo": achado}).status_code == 422)
            registrar("código usado continua sem dar acesso", http.get("/api/fila").status_code == 403)

            print("\n== Recuperação", flush=True)
            codigo_r = recuperacao[0]
            registrar("código de recuperação entra", http.post("/api/mfa/verificar", json={"codigo": codigo_r.upper()}).status_code == 204)
            registrar("o uso fica marcado na auditoria", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'entrar_com_codigo_de_recuperacao'", (a,)).fetchone()[0] == 1)
            entrar(http, ana)
            registrar("o mesmo código de recuperação não vale duas vezes", http.post("/api/mfa/verificar", json={"codigo": codigo_r}).status_code == 422)

            print("\n== Tentativas demais", flush=True)
            modulo.falhas_de_login.clear()
            for _ in range(5):
                http.post("/api/mfa/verificar", json={"codigo": "000000"})
            r = http.post("/api/mfa/verificar", json={"codigo": recuperacao[1]})
            registrar("depois de 5 erros, nem o certo entra", r.status_code == 429, str(r.status_code))
            registrar("a sessão pendente cai", http.get("/api/eu").status_code == 401)
            modulo.falhas_de_login.clear()

            print("\n== Outras pessoas", flush=True)
            entrar(http, ana)
            http.post("/api/mfa/verificar", json={"codigo": recuperacao[1]})
            registrar("não remove de outro cliente", http.post(f"/api/usuarios/{de_b['id']}/mfa/remover").status_code == 404)
            registrar("não remove da própria conta sem provar nada", http.post(f"/api/usuarios/{ana['id']}/mfa/remover").status_code == 409)
            registrar("a tela sabe quantos códigos restam", http.get("/api/eu").json()["mfa_codigos_restantes"] == 8)
            lista = http.get("/api/usuarios").json()["usuarios"]
            registrar("a lista mostra quem usa, sem o segredo", any(u["id"] == ana["id"] and u["mfa_ativo"] for u in lista) and "selado" not in str(lista))

            print("\n== Tornar obrigatório", flush=True)
            registrar("com o seu ligado, dá para exigir", http.put("/api/organizacao/mfa", json={"obrigatorio": True}).status_code == 204)
            # Sem "with": o ciclo de vida é um só, e fechar um segundo cliente fecharia o banco do primeiro.
            bia_http = TestClient(app, base_url="https://testserver")
            entrar(bia_http, bia)
            registrar("quem não tem não vê nada", bia_http.get("/api/fila").status_code == 403)
            registrar("a tela sabe que é obrigatório", bia_http.get("/api/eu").json()["mfa_obrigatorio"] is True)
            inicio_bia = bia_http.post("/api/mfa/iniciar", json={"senha": bia["senha"]}).json()
            registrar("consegue configurar", bia_http.post("/api/mfa/confirmar", json={"codigo": codigo(inicio_bia["segredo"])}).status_code == 200)
            registrar("depois de configurar, vê os dados", bia_http.get("/api/fila").status_code == 200)
            registrar("não desliga enquanto for obrigatório", bia_http.post("/api/mfa/desligar", json={"senha": bia["senha"], "codigo": codigo(inicio_bia["segredo"], 1)}).status_code == 409)
            registrar("outro cliente não foi afetado", entrar(http, de_b).status_code == 204 and http.get("/api/fila").status_code == 200)
            http.cookies.clear()

            print("\n== Perdeu o celular", flush=True)
            entrar(http, ana)
            http.post("/api/mfa/verificar", json={"codigo": recuperacao[2]})
            http.put("/api/organizacao/mfa", json={"obrigatorio": False})
            registrar("administrador remove", http.post(f"/api/usuarios/{bia['id']}/mfa/remover").status_code == 204)
            registrar("as sessões da pessoa caem", bia_http.get("/api/fila").status_code == 401)
            bia_http.cookies.clear()
            registrar("a pessoa volta a entrar com a senha", bia_http.post("/api/entrar", json={"email": bia["email"], "senha": bia["senha"]}).status_code == 204)
            registrar("a remoção fica na auditoria", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'remover_mfa_de_usuario'", (a,)).fetchone()[0] == 1)
            registrar("analista não remove de ninguém", bia_http.post(f"/api/usuarios/{ana['id']}/mfa/remover").status_code == 403)

            print("\n== Desligar", flush=True)
            registrar("sem o código, não desliga", http.post("/api/mfa/desligar", json={"senha": ana["senha"], "codigo": "000000"}).status_code == 403)
            registrar("sem a senha, não desliga", http.post("/api/mfa/desligar", json={"senha": "errada", "codigo": codigo(segredo, 1)}).status_code == 403)
            print("   esperando o próximo código, como o aplicativo faria", flush=True)
            time.sleep(mfa.PASSO + 2)
            registrar("gerar códigos novos exige o código", http.post("/api/mfa/novos-codigos", json={"senha": ana["senha"], "codigo": "000000"}).status_code == 403)
            r = http.post("/api/mfa/novos-codigos", json={"senha": ana["senha"], "codigo": codigo(segredo, 1)})
            novos = r.json().get("codigos_de_recuperacao", [])
            registrar("gera dez códigos novos", r.status_code == 200 and len(novos) == 10, str(r.status_code))
            antigo = recuperacao[5]
            http.cookies.clear()
            entrar(http, ana)
            registrar("os antigos deixam de valer", http.post("/api/mfa/verificar", json={"codigo": antigo}).status_code == 422)
            registrar("os novos valem", http.post("/api/mfa/verificar", json={"codigo": novos[0]}).status_code == 204)
            time.sleep(mfa.PASSO + 2)
            r = http.post("/api/mfa/desligar", json={"senha": ana["senha"], "codigo": codigo(segredo, 1)})
            registrar("com senha e código, desliga", r.status_code == 204, str(r.status_code))
            registrar("os códigos de recuperação somem", admin.execute("SELECT count(*) FROM mfa_recuperacao WHERE usuario_id = %s", (ana["id"],)).fetchone()[0] == 0)
            registrar("a senha volta a bastar", entrar(http, ana).status_code == 204 and http.get("/api/fila").status_code == 200)

        print("\n== Banco", flush=True)
        with psycopg.connect(f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar") as con:
            try:
                con.execute("SELECT * FROM mfa_recuperacao")
                registrar("a API não lê os códigos de recuperação", False)
            except psycopg.errors.InsufficientPrivilege:
                registrar("a API não lê os códigos de recuperação", True)
    finally:
        admin.execute("DELETE FROM auditoria WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))
        admin.close()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
