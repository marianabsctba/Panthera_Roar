#!/usr/bin/env python3
"""Playbook disparado por indicador de ameaça, com o banco real e o papel do motor.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_gatilho_indicador.py

Apaga no final tudo o que criou.
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
from psycopg.rows import dict_row

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "ingestao")]

from roar_api.app import app  # noqa: E402
from roar_motor import blocos, disparo  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
REGISTRAR = {"tipo": "acao", "acao": "registrar", "parametros": {}}
DEFINICAO = {"quando": {"tipo": "indicador"}, "se": [], "blocos": [REGISTRAR]}


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def testar_formato():
    print("== Formato", flush=True)
    registrar("o gatilho é aceito", blocos.validar(DEFINICAO))
    try:
        blocos.validar({**DEFINICAO, "quando": {"tipo": "indicador", "x": 1}})
        registrar("opção inventada é recusada", False)
    except blocos.DefinicaoInvalida:
        registrar("opção inventada é recusada", True)
    try:
        blocos.validar({**DEFINICAO, "blocos": [{"tipo": "acao", "acao": "bloquear_ip", "parametros": {}}]})
        registrar("bloquear ainda exige endereço externo", False)
    except blocos.DefinicaoInvalida:
        registrar("bloquear ainda exige endereço externo", True)
    base = {"id": 1, "origem_tipo": "indicador"}
    registrar("não dispara playbook de regra", not blocos.atende({"quando": {"tipo": "evento", "regra_id": "1"}, "blocos": []}, base))
    registrar("dispara o de indicador", blocos.atende(DEFINICAO, base))


class Cenario:
    def __init__(self, admin):
        self.admin, self.clientes = admin, []

    def cliente(self, nome):
        cliente = str(self.admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        gerenciador = f"{nome}{SUFIXO}"
        self.admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (gerenciador, cliente, 40000 + secrets.randbelow(20000)))
        senha, email = secrets.token_urlsafe(18), f"{nome}-{SUFIXO}@exemplo.test"
        usuario = self.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, 'administrador') RETURNING id",
                                     (cliente, email, PasswordHasher().hash(senha))).fetchone()[0]
        fonte = self.admin.execute("INSERT INTO intel_fontes (cliente_id, nome, tipo, endereco, criado_por) VALUES (%s, 'Teste', 'taxii', 'https://exemplo.test', %s) RETURNING id", (cliente, usuario)).fetchone()[0]
        c = {"id": cliente, "gerenciador": gerenciador, "usuario": usuario, "fonte": fonte, "acesso": {"email": email, "senha": senha}}
        self.clientes.append(c)
        return c

    def evento(self, c, ip="1.0.0.9", quando=None):
        return self.admin.execute(
            """INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao, gerenciador_id, agente_id, ip_origem, bruto)
               VALUES (%s, 'teste', %s, %s, 5, 'media', '100', 'Evento de teste', %s, '001', %s, '{"segredo": "bruto"}') RETURNING id""",
            (c["id"], uuid.uuid4().hex, quando or datetime.now(timezone.utc), c["gerenciador"], ip)).fetchone()[0]

    def achado(self, c, evento, valor="1.0.0.9", no_passado=False):
        indicador = self.admin.execute(
            """INSERT INTO intel_indicadores (cliente_id, fonte_id, tipo, valor) VALUES (%s, %s, 'ip', %s)
               ON CONFLICT (fonte_id, tipo, valor) DO UPDATE SET ultima_vez = now() RETURNING id""", (c["id"], c["fonte"], valor)).fetchone()[0]
        self.admin.execute("INSERT INTO intel_ocorrencias (indicador_id, evento_id, cliente_id, ocorrido_em, no_passado) VALUES (%s, %s, %s, now(), %s)", (indicador, evento, c["id"], no_passado))

    def playbook(self, c, definicao=DEFINICAO):
        return self.admin.execute("INSERT INTO playbooks (cliente_id, nome, definicao, intervalo_minutos, criado_por) VALUES (%s, %s, %s, 0, %s) RETURNING id",
                                  (c["id"], uuid.uuid4().hex, json.dumps(definicao), c["usuario"])).fetchone()[0]

    def execucoes(self, playbook):
        return self.admin.execute("SELECT origem_tipo, origem_id, alvo, titulo FROM execucoes WHERE playbook_id = %s ORDER BY id", (playbook,)).fetchall()

    def limpar(self):
        ids = [c["id"] for c in self.clientes]
        self.admin.execute("DELETE FROM intel_ocorrencias WHERE cliente_id = ANY(%s)", (ids,))
        for tabela in ("intel_indicadores", "intel_fontes", "aprovacoes", "execucoes", "playbooks", "soar_cursor", "eventos", "auditoria"):
            self.admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (ids,))
        self.admin.execute("DELETE FROM sessoes WHERE usuario_id = ANY(SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (ids,))
        self.admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (ids,))
        self.admin.execute("DELETE FROM gerenciadores WHERE cliente_id = ANY(%s)", (ids,))
        self.admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (ids,))


def avaliar(url, c):
    with psycopg.connect(url, row_factory=dict_row) as con:
        con.execute("SELECT set_config('roar.cliente', %s, true)", (c["id"],))
        return disparo.avaliar(con, c["id"])


def main():
    testar_formato()
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    cen = Cenario(admin)
    url = disparo.url_do_banco()
    try:
        a, b = cen.cliente("gia"), cen.cliente("gib")
        print("\n== O histórico não vira rajada", flush=True)
        antigo = cen.evento(a)
        cen.achado(a, antigo, "1.0.0.8")
        pb = cen.playbook(a)
        avaliar(url, a)
        registrar("achado de antes do playbook não dispara", cen.execucoes(pb) == [], str(cen.execucoes(pb)))

        print("\n== Um evento comum não dispara, o achado sim", flush=True)
        evento = cen.evento(a)
        avaliar(url, a)
        registrar("evento sem indicador não dispara", cen.execucoes(pb) == [])
        cen.achado(a, evento)
        registrar("o achado que chega depois do evento dispara", avaliar(url, a) == 1)
        x = cen.execucoes(pb)
        registrar("a execução aponta para o evento", x and x[0][0] == "indicador" and x[0][1] == evento and x[0][2] == "1.0.0.9", str(x))
        registrar("o título diz qual indicador", x and x[0][3] == "Indicador de ameaça: 1.0.0.9", str(x and x[0][3]))
        registrar("o próximo ciclo não repete", avaliar(url, a) == 0)
        cen.achado(a, evento, "outro.exemplo.test")
        registrar("dois indicadores no mesmo evento: uma resposta só", avaliar(url, a) == 0 and len(cen.execucoes(pb)) == 1)

        print("\n== Condições", flush=True)
        interno = cen.playbook(a, {**DEFINICAO, "se": [{"campo": "alvo_externo", "op": "igual", "valor": True}]})
        privado = cen.evento(a, "10.0.0.7")
        cen.achado(a, privado, "10.0.0.7")
        avaliar(url, a)
        registrar("a condição do playbook vale", cen.execucoes(interno) == [], str(cen.execucoes(interno)))
        registrar("o playbook sem condição dispara", any(e[1] == privado for e in cen.execucoes(pb)))

        print("\n== Achado no passado", flush=True)
        velho = cen.evento(a, "1.0.0.5", datetime.now(timezone.utc) - timedelta(days=90))
        cen.achado(a, velho, "1.0.0.5", no_passado=True)
        avaliar(url, a)
        registrar("não dispara resposta", not any(e[1] == velho for e in cen.execucoes(pb)))
        cursor = admin.execute("SELECT ultima_ocorrencia FROM soar_cursor WHERE cliente_id = %s", (a["id"],)).fetchone()[0]
        maximo = admin.execute("SELECT max(id) FROM intel_ocorrencias WHERE cliente_id = %s", (a["id"],)).fetchone()[0]
        registrar("mas o cursor anda", cursor == maximo, f"{cursor} {maximo}")

        print("\n== Permissões do motor", flush=True)
        with psycopg.connect(url) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (a["id"],))
            registrar("lê os achados da própria organização", con.execute("SELECT count(*) FROM intel_ocorrencias").fetchone()[0] >= 3)
            for sql, nome in (("SELECT descricao FROM intel_indicadores", "a descrição do indicador"), ("SELECT segredo FROM intel_fontes", "a credencial da fonte"), ("SELECT bruto FROM eventos", "o log bruto")):
                try:
                    with con.transaction():
                        con.execute(sql)
                    registrar(f"não lê {nome}", False)
                except psycopg.errors.InsufficientPrivilege:
                    registrar(f"não lê {nome}", True)
        with psycopg.connect(url) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (b["id"],))
            registrar("não vê os achados de outra organização", con.execute("SELECT count(*) FROM intel_ocorrencias").fetchone()[0] == 0)
        pb_b = cen.playbook(b)
        avaliar(url, b)
        registrar("o playbook de outra organização não dispara", cen.execucoes(pb_b) == [])

        print("\n== Simular pela tela", flush=True)
        with TestClient(app, base_url="https://testserver") as http:
            http.post("/api/entrar", json=a["acesso"])
            r = http.post("/api/automacao/simular", json={"definicao": DEFINICAO, "intervalo_minutos": 0})
            registrar("simula o gatilho", r.status_code == 200 and r.json()["disparos"] >= 2, r.text[:200])
            r = http.post("/api/automacao/simular", json={"definicao": {**DEFINICAO, "se": [{"campo": "pais", "op": "e", "valor": "Atlantis"}]}, "intervalo_minutos": 0})
            registrar("a simulação respeita as condições", r.status_code == 200 and r.json()["disparos"] == 0, r.text[:120])
            r = http.post("/api/automacao/playbooks", json={"nome": f"Pelo indicador {SUFIXO}", "intervalo_minutos": 60, "definicao": DEFINICAO})
            registrar("a API salva o playbook", r.status_code in (200, 201), r.text[:160])
    finally:
        cen.limpar()
        admin.close()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
