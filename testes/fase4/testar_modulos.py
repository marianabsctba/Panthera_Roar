#!/usr/bin/env python3
"""Perfis de instalação: módulo fora do perfil não responde, e o resto continua funcionando.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_modulos.py
"""

import os
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

from roar_api import app as modulo  # noqa: E402
from roar_api import modulos  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    print("== Regras", flush=True)
    so_vuln, so_siem = {"vulnerabilidades"}, {"siem"}
    registrar("o login existe em todos", all(modulos.rota_liberada("/api/entrar", m) for m in (so_vuln, so_siem)))
    registrar("o segundo fator também", all(modulos.rota_liberada("/api/mfa/verificar", m) for m in (so_vuln, so_siem)))
    registrar("só vulnerabilidades não tem logs", not modulos.rota_liberada("/api/logs", so_vuln))
    registrar("só vulnerabilidades tem achados", modulos.rota_liberada("/api/vuln/achados", so_vuln))
    registrar("só SIEM não tem achados", not modulos.rota_liberada("/api/vuln/achados", so_siem))
    registrar("só SIEM tem logs", modulos.rota_liberada("/api/logs", so_siem))
    registrar("prefixo não engana: /api/usuariosx não é /api/usuarios", not modulos.rota_liberada("/api/usuariosx", so_vuln))
    registrar("prefixo não engana: /api/cvesx não é /api/cves", not modulos.rota_liberada("/api/cvesx", so_vuln))
    registrar("rota nova, sem classificar, não abre em só vulnerabilidades", not modulos.rota_liberada("/api/qualquer-coisa-nova", so_vuln))
    registrar("a página abre em todos", modulos.rota_liberada("/", so_vuln) and modulos.rota_liberada("/estatico/roar.js", so_vuln))
    rotas = [r.path for r in modulo.app.routes if isinstance(r, APIRoute) and r.path.startswith("/api/")]
    livres = sorted(r for r in rotas if modulos.rota_liberada(r.replace("{identificador}", "1"), so_vuln))
    print(f"   {len(rotas)} rotas, {len(livres)} em só vulnerabilidades", flush=True)
    registrar("nenhuma rota de log, regra ou automação em só vulnerabilidades", not [r for r in livres if any(p in r for p in ("/logs", "/regras", "/automacao", "/eventos", "/fontes", "/integridade"))], str(livres)[:300])

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"modulos-{SUFIXO}",)).fetchone()[0])
    senha, email = secrets.token_urlsafe(18), f"modulos-{SUFIXO}@exemplo.test"
    admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Pessoa', %s, 'administrador')", (cliente, email, PasswordHasher().hash(senha)))
    original = modulo.MODULOS
    try:
        with TestClient(modulo.app, base_url="https://testserver") as http:
            print("\n== Só vulnerabilidades", flush=True)
            modulo.MODULOS = so_vuln
            registrar("entra", http.post("/api/entrar", json={"email": email, "senha": senha}).status_code == 204)
            registrar("a tela sabe o que está instalado", http.get("/api/eu").json()["modulos"] == ["vulnerabilidades"])
            registrar("vê os achados", http.get("/api/vuln/achados").status_code == 200)
            registrar("vê a base de CVEs", http.get("/api/cves").status_code == 200)
            registrar("gere usuários", http.get("/api/usuarios").status_code == 200)
            registrar("vê a trilha", http.get("/api/auditoria").status_code == 200)
            for rota in ("/api/fila", "/api/logs", "/api/regras", "/api/volume", "/api/integridade", "/api/fontes", "/api/automacao/playbooks"):
                registrar(f"{rota} não existe", http.get(rota).status_code == 404)
            registrar("funciona sem indexador e sem gerenciador", http.post("/api/vuln/modelos", json={"nome": "Web", "ferramenta": "web"}).status_code == 201)

            print("\n== Só SIEM", flush=True)
            modulo.MODULOS = so_siem
            registrar("a tela sabe", http.get("/api/eu").json()["modulos"] == ["siem"])
            registrar("não tem achados", http.get("/api/vuln/achados").status_code == 404)
            registrar("tem a fila", http.get("/api/fila").status_code == 200)

            print("\n== Completo", flush=True)
            modulo.MODULOS = modulos.PERFIS["completo"]
            registrar("tem os dois", http.get("/api/fila").status_code == 200 and http.get("/api/vuln/achados").status_code == 200)
            registrar("perfil desconhecido cai no completo", modulos.PERFIS.get("xpto", modulos.PERFIS["completo"]) == modulos.PERFIS["completo"])

        print("\n== Tela", flush=True)
        html = (modulo.ESTATICO / "index.html").read_text(encoding="utf-8")
        import re
        botoes = re.findall(r'<button type="button" data-vista="([a-z]+)"([^>]*)>', html)
        sem_marca = [v for v, resto in botoes if "data-modulo" not in resto and v not in ("usuarios", "auditoria", "ajuda")]
        registrar("toda aba de módulo diz a que módulo pertence", not sem_marca, str(sem_marca))
    finally:
        modulo.MODULOS = original
        for tabela in ("vuln_modelos",):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM auditoria WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = %s)", (cliente,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))
        admin.close()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
