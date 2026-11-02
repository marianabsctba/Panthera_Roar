#!/usr/bin/env python3
"""Inteligência com a plataforma de verdade: indicador criado nela, evento batendo, playbook pedindo aprovação.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_misp_real.py

Precisa da plataforma instalada (infra/misp.sh). Apaga no final tudo o que criou, inclusive o evento nela.
"""

import json
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import requests
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "ingestao")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import inteligencia  # noqa: E402
from roar_ingestao.ciclo import conexoes  # noqa: E402
from roar_motor import disparo  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
IP_MAU = f"45.33.{secrets.randbelow(250)}.{secrets.randbelow(250) + 1}"
BASE = ENV["ROAR_MISP_ENDERECO"]
CAB = {"Authorization": ENV["MISP_CHAVE"], "Accept": "application/json", "Content-Type": "application/json"}
REGISTRAR = {"tipo": "acao", "acao": "registrar", "parametros": {}}
EXTERNO = {"campo": "alvo_externo", "op": "igual", "valor": True}


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    _, banco, _ = conexoes()
    evento_misp, clientes = None, []

    def cliente(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        g = f"{nome}{SUFIXO}"
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 41000 + secrets.randbelow(19000)))
        senha, email = secrets.token_urlsafe(18), f"{nome}-{SUFIXO}@exemplo.test"
        u = admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, 'administrador') RETURNING id",
                          (c, email, PasswordHasher().hash(senha))).fetchone()[0]
        clientes.append(c)
        return {"id": c, "g": g, "u": u, "acesso": {"email": email, "senha": senha}}

    def evento(c, ip):
        return admin.execute(
            """INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao, gerenciador_id, agente_id, ip_origem, bruto)
               VALUES (%s, 'teste', %s, %s, 10, 'alta', '5712', 'Evento de teste', %s, '001', %s, %s) RETURNING id""",
            (c["id"], uuid.uuid4().hex, datetime.now(timezone.utc), c["g"], ip, Jsonb({"data": {"srcip": ip}}))).fetchone()[0]

    try:
        print("== A plataforma", flush=True)
        versao = requests.get(f"{BASE}/servers/getVersion", headers=CAB, timeout=30)
        registrar("responde com a chave da instalação", versao.status_code == 200, versao.text[:80])
        registrar("recusa sem a chave", requests.get(f"{BASE}/servers/getVersion", headers={"Accept": "application/json"}, timeout=30).status_code in (401, 403))
        login = requests.post(f"{BASE}/users/login", json={"email": "admin@admin.test", "password": "admin"}, headers={"Accept": "application/json"}, timeout=30, allow_redirects=False)
        registrar("a senha padrão do projeto não entra", "Set-Cookie" not in login.headers or login.status_code != 200 or "authenticated" not in login.text, str(login.status_code))

        print("\n== Indicador criado nela", flush=True)
        criado = requests.post(f"{BASE}/events", headers=CAB, json={"Event": {
            "info": f"Prova do Roar {SUFIXO}", "distribution": 0, "threat_level_id": 1, "analysis": 2, "published": True,
            "Attribute": [{"type": "ip-src", "category": "Network activity", "value": IP_MAU, "to_ids": True, "comment": "Servidor de comando de teste"},
                          {"type": "ip-src", "category": "Network activity", "value": "45.79.0.77", "to_ids": False, "comment": "Só informativo"}]}}, timeout=60)
        registrar("evento criado", criado.status_code == 200, criado.text[:100])
        evento_misp = criado.json()["Event"]["id"]
        requests.post(f"{BASE}/events/publish/{evento_misp}", headers=CAB, timeout=60)

        print("\n== Toda organização recebe a fonte", flush=True)
        a, b = cliente("mispa"), cliente("mispb")
        registrar("nasce sozinha", inteligencia.garantir_fonte_local(banco, a["id"]) and inteligencia.garantir_fonte_local(banco, b["id"]))
        registrar("não duplica", not inteligencia.garantir_fonte_local(banco, a["id"]))
        fonte = next(f for f in inteligencia.fontes_vencidas(banco, a["id"]) if f["interna"])
        registrar("o banco não guarda endereço nem chave", fonte["endereco"] == "interno" and fonte["segredo"] is None, str(fonte))
        resultado = inteligencia.sincronizar_fonte(banco, a["id"], fonte)
        registrar("sincroniza de verdade", resultado["erro"] is None and resultado["novos"] >= 1, str(resultado))
        registrar("trouxe o indicador", admin.execute("SELECT count(*) FROM intel_indicadores WHERE cliente_id = %s AND valor = %s", (a["id"], IP_MAU)).fetchone()[0] == 1)
        registrar("ignora o que não é para detecção", admin.execute("SELECT count(*) FROM intel_indicadores WHERE cliente_id = %s AND valor = '45.79.0.77'", (a["id"],)).fetchone()[0] == 0)

        print("\n== Evento que bate, playbook que pede aprovação", flush=True)
        playbook = admin.execute(
            "INSERT INTO playbooks (cliente_id, nome, definicao, intervalo_minutos, criado_por) VALUES (%s, %s, %s, 0, %s) RETURNING id",
            (a["id"], "Pelo indicador", json.dumps({"quando": {"tipo": "indicador"}, "se": [EXTERNO], "blocos": [{"tipo": "aprovacao"}, REGISTRAR]}), a["u"])).fetchone()[0]
        with psycopg.connect(disparo.url_do_banco(), row_factory=dict_row) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (a["id"],))
            disparo.avaliar(con, a["id"])
        ev = evento(a, IP_MAU)
        de_b = evento(b, IP_MAU)
        inteligencia.ciclo(banco, a["id"])
        registrar("o cruzamento acha", admin.execute("SELECT count(*) FROM intel_ocorrencias WHERE cliente_id = %s AND evento_id = %s", (a["id"], ev)).fetchone()[0] == 1)
        registrar("outro cliente não é afetado", admin.execute("SELECT count(*) FROM intel_ocorrencias WHERE evento_id = %s", (de_b,)).fetchone()[0] == 0)
        with psycopg.connect(disparo.url_do_banco(), row_factory=dict_row) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (a["id"],))
            criadas = disparo.avaliar(con, a["id"])
        execucao = admin.execute("SELECT origem_tipo, origem_id, alvo, definicao FROM execucoes WHERE playbook_id = %s", (playbook,)).fetchone()
        registrar("o playbook dispara", criadas == 1 and execucao and execucao[0] == "indicador" and execucao[1] == ev and execucao[2] == IP_MAU, str(execucao)[:120])
        registrar("e começa pedindo aprovação", execucao and execucao[3]["blocos"][0]["tipo"] == "aprovacao")

        print("\n== Pela tela", flush=True)
        with TestClient(app, base_url="https://testserver") as http:
            http.post("/api/entrar", json=a["acesso"])
            visao = http.get("/api/inteligencia").json()
            f = next(x for x in visao["fontes"] if x["interna"])
            registrar("a fonte aparece como incluída", f["ativa"] and f["indicadores"] >= 1, str(f)[:160])
            texto = json.dumps(visao)
            registrar("a tela não vê a chave nem o endereço", ENV["MISP_CHAVE"] not in texto and BASE not in texto)
            registrar("a ocorrência aparece", any(o["valor"] == IP_MAU for o in visao["ocorrencias"]), str(visao["ocorrencias"][:1])[:160])
            registrar("dá para desligar", http.delete(f"/api/inteligencia/fontes/{f['id']}").status_code == 204)
            registrar("desligada não some", any(x["id"] == f["id"] and not x["ativa"] for x in http.get("/api/inteligencia").json()["fontes"]))
            inteligencia.garantir_fonte_local(banco, a["id"])
            registrar("o ciclo não religa sozinho", not any(x["interna"] for x in inteligencia.fontes_vencidas(banco, a["id"])))
            registrar("não sincroniza desligada", http.post(f"/api/inteligencia/fontes/{f['id']}/sincronizar").status_code == 404)
            registrar("dá para ligar de novo", http.post(f"/api/inteligencia/fontes/{f['id']}/ligar").status_code == 204)
            registrar("fica na auditoria", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'ligar_fonte_de_inteligencia'", (a["id"],)).fetchone()[0] == 1)
            registrar("outra fonte não usa este caminho", http.post("/api/inteligencia/fontes/999999999/ligar").status_code == 404)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=b["acesso"])
            registrar("outra organização não liga a fonte alheia", http.post(f"/api/inteligencia/fontes/{f['id']}/ligar").status_code == 404)

        print("\n== Plataforma fora do ar", flush=True)
        original = inteligencia.plataforma_local
        inteligencia.plataforma_local = lambda: ("http://127.0.0.1:9", "x")
        fonte_b = next(x for x in inteligencia.fontes_vencidas(banco, b["id"]) if x["interna"])
        try:
            r = inteligencia.sincronizar_fonte(banco, b["id"], fonte_b)
        finally:
            inteligencia.plataforma_local = original
        registrar("avisa em vez de quebrar", r["erro"] and "não respondeu" in r["erro"], str(r))
    finally:
        if evento_misp:
            requests.delete(f"{BASE}/events/delete/{evento_misp}", headers=CAB, timeout=60)
        for tabela in ("aprovacoes", "execucoes", "playbooks", "soar_cursor", "intel_ocorrencias", "intel_indicadores", "intel_fontes", "intel_cursor", "eventos", "auditoria"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id = ANY(SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM gerenciadores WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
