#!/usr/bin/env python3
"""Medição de volume com o indexador real e eventos de quantidade conhecida.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_volume.py
"""

import json
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api import app as modulo  # noqa: E402
from roar_ingestao import provisao  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
URL = "https://127.0.0.1:9200"


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    indexer = provisao.indexer_admin(ENV)
    sessao = indexer.sessao if hasattr(indexer, "sessao") else indexer
    clientes, gerenciadores = [], []

    def criar(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        g = uuid.uuid4().hex[:12]
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 52000 + secrets.randbelow(8000)))
        clientes.append(c)
        gerenciadores.append(g)
        senha, email = secrets.token_urlsafe(18), f"volume-{uuid.uuid4().hex[:8]}@exemplo.test"
        admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Pessoa', %s, 'auditor')", (c, email, PasswordHasher().hash(senha)))
        return c, g, email, senha

    def gravar(g, indice, eventos):
        linhas = []
        for momento, ativo, tamanho in eventos:
            linhas.append(json.dumps({"index": {"_index": f"wazuh-{indice}-4.x-{g}-teste"}}))
            linhas.append(json.dumps({"timestamp": momento.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "full_log": "x" * tamanho, "agent": {"name": ativo}, "decoder": {"name": "sshd"}}))
        r = sessao.post(f"{URL}/_bulk?refresh=true", data="\n".join(linhas) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=60)
        r.raise_for_status()
        assert not r.json()["errors"], str(r.json())[:300]

    try:
        ca, ga, email_a, senha_a = criar("volume-a")
        cb, gb, email_b, senha_b = criar("volume-b")
        agora = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        # 600 no minuto cheio, há duas horas: 10 eventos por segundo. Mais 60 espalhados nos últimos minutos.
        cheio = agora - timedelta(hours=2)
        eventos = [(cheio + timedelta(seconds=i % 60), "srv-a", 100) for i in range(600)]
        eventos += [(agora - timedelta(minutes=2, seconds=i), "srv-b", 100) for i in range(60)]
        gravar(ga, "archives", eventos)
        gravar(ga, "alerts", [(agora - timedelta(minutes=2), "srv-a", 100)] * 5)
        gravar(gb, "archives", [(agora - timedelta(minutes=2), "srv-de-b", 100)] * 7)

        with TestClient(modulo.app, base_url="https://testserver") as _:
            http = TestClient(modulo.app, base_url="https://testserver")
            http.post("/api/entrar", json={"email": email_a, "senha": senha_a})
            r = http.get("/api/volume", params={"dias": 1})
            registrar("responde", r.status_code == 200, r.text[:200])
            d = r.json()
            logs = d["logs"]
            registrar("conta os eventos", logs["total"] == 660, str(logs["total"]))
            registrar("o pico é o minuto mais cheio", logs["eps_pico"] == 10, str(logs["eps_pico"]))
            registrar("diz quando foi o pico", (logs["pico_em"] or "").startswith(cheio.strftime("%Y-%m-%dT%H:%M")), str(logs["pico_em"]))
            registrar("EPS agora vem dos últimos minutos", logs["eps_agora"] == 0.2, str(logs["eps_agora"]))
            registrar("EPS médio é a conta certa", abs(logs["eps_medio"] - 660 / 86400) < 0.001, str(logs["eps_medio"]))
            registrar("tamanho médio pelo log original", logs["bytes_por_evento"] == 100, str(logs["bytes_por_evento"]))
            registrar("tamanho por dia soma os eventos", sum(x["bytes_estimados"] for x in logs["por_dia"]) == 66000, str(logs["por_dia"])[:160])
            registrar("mostra quem manda mais", logs["ativos"][0] == {"nome": "srv-a", "eventos": 600}, str(logs["ativos"]))
            registrar("mostra o tipo de log", logs["origens"][0]["nome"] == "sshd")
            registrar("alertas à parte", d["alertas"]["total"] == 5)
            registrar("mostra o espaço ocupado", d["ocupado_bytes"] and d["ocupado_bytes"] > 0, str(d["ocupado_bytes"]))
            registrar("logs e alertas somam o total", d["ocupado"]["logs"] + d["ocupado"]["alertas"] == d["ocupado_bytes"], str(d["ocupado"])[:160])
            registrar("o disco vem por dia", sum(x["logs"] + x["alertas"] for x in d["ocupado"]["por_dia"]) == d["ocupado_bytes"] and d["ocupado"]["retencao_dias"] > 0)
            registrar("período inválido não quebra", http.get("/api/volume", params={"dias": 99999}).json()["dias"] == 90 and http.get("/api/volume", params={"dias": -1}).json()["dias"] == 1)

            print("\n== Clientes", flush=True)
            outra = TestClient(modulo.app, base_url="https://testserver")
            outra.post("/api/entrar", json={"email": email_b, "senha": senha_b})
            b = outra.get("/api/volume", params={"dias": 1}).json()["logs"]
            registrar("cada cliente vê só o dele", b["total"] == 7 and b["ativos"] == [{"nome": "srv-de-b", "eventos": 7}], str(b["total"]))
            registrar("sem sessão não vê", TestClient(modulo.app, base_url="https://testserver").get("/api/volume").status_code == 401)

            print("\n== Sem dados", flush=True)
            cc, gc, email_c, senha_c = criar("volume-c")
            vazio = TestClient(modulo.app, base_url="https://testserver")
            vazio.post("/api/entrar", json={"email": email_c, "senha": senha_c})
            v = vazio.get("/api/volume").json()
            registrar("cliente sem evento vê zero, sem erro", v["logs"]["total"] == 0 and v["logs"]["eps_pico"] == 0 and v["logs"]["pico_em"] is None, str(v["logs"])[:160])
            registrar("o espaço ocupado é zero", not v["ocupado_bytes"], str(v["ocupado_bytes"]))
    finally:
        for g in gerenciadores:
            sessao.delete(f"{URL}/wazuh-archives-4.x-{g}-*", timeout=30)
            sessao.delete(f"{URL}/wazuh-alerts-4.x-{g}-*", timeout=30)
        admin.execute("DELETE FROM auditoria WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
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
