#!/usr/bin/env python3
"""Investigação do alerta, com dois casos montados: uma conta invadida por força bruta e um falso positivo.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_investigacao.py

A organização de teste ganha um banco próprio no armazém, com logs e fluxos de rede do atacante, para as perguntas do
armazém rodarem de verdade. Apaga no final tudo o que criou.
"""

import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "ingestao"), str(RAIZ / "ueba")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import armazem  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
ATACANTE = "45.33.12.7"
AGORA = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    armazem_admin = armazem.admin(ENV)
    clientes, bancos = [], []

    def cliente(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        g = f"{nome}{SUFIXO}"
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 41000 + secrets.randbelow(19000)))
        acessos = {}
        for perfil in ("administrador", "analista_n1"):
            senha, email = secrets.token_urlsafe(18), f"{nome}-{perfil}-{SUFIXO}@exemplo.test"
            admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, %s)",
                          (c, email, PasswordHasher().hash(senha), perfil))
            acessos[perfil] = {"email": email, "senha": senha}
        clientes.append(c)
        return {"id": c, "g": g, "acessos": acessos}

    def evento(c, quando, regra, descricao, nivel, grupos, agente="001", agente_nome="srv-web", ip=None, usuario=None):
        severidade = "critica" if nivel >= 12 else "alta" if nivel >= 10 else "media" if nivel >= 7 else "baixa"
        return admin.execute(
            """INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao, regra_grupos,
                                    gerenciador_id, agente_id, agente_nome, ip_origem, usuario, bruto)
               VALUES (%s, 'teste', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (c["id"], uuid.uuid4().hex, quando, nivel, severidade, regra, descricao, grupos, c["g"], agente, agente_nome, ip, usuario,
             Jsonb({"rule": {"id": regra}}))).fetchone()[0]

    def entidade(c, chave, risco, ips):
        e = admin.execute("""INSERT INTO entidades (cliente_id, tipo, chave, nome, primeira_vista, ultima_vista, risco, risco_em)
                             VALUES (%s, 'usuario', %s, %s, %s, %s, %s, %s) RETURNING id""",
                          (c["id"], chave, chave, AGORA - timedelta(days=90), AGORA, risco, AGORA)).fetchone()[0]
        for ip, desde, vezes in ips:
            admin.execute("INSERT INTO vistos (cliente_id, entidade_id, dimensao, valor, primeira_vez, contagem) VALUES (%s, %s, 'ip', %s, %s, %s)",
                          (c["id"], e, ip, desde, vezes))
        return e

    try:
        a, b = cliente("inva"), cliente("invb")
        # Conta invadida: força bruta contra duas contas em dois servidores, um login que dá certo e, em seguida, root.
        joao = entidade(a, "joao", 75, [("10.0.0.5", AGORA - timedelta(days=30), 140)])
        falhas = [evento(a, AGORA - timedelta(minutes=30 - i), "5710", "Login recusado", 5, ["authentication_failed"], ip=ATACANTE, usuario="joao") for i in range(8)]
        falhas += [evento(a, AGORA - timedelta(minutes=20), "5710", "Login recusado", 5, ["authentication_failed"], agente="002", agente_nome="srv-banco", ip=ATACANTE, usuario="maria")]
        alerta = evento(a, AGORA, "5712", "Força bruta de SSH", 10, ["authentication_failures"], ip=ATACANTE, usuario="joao")
        entrou = evento(a, AGORA + timedelta(minutes=5), "5715", "Login com sucesso", 3, ["authentication_success"], ip=ATACANTE, usuario="joao")
        root = evento(a, AGORA + timedelta(minutes=10), "5402", "Virou root com sudo", 12, ["sudo"], usuario="joao")
        admin.execute("""INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id, detalhes)
                         VALUES (%s, %s, 'sucesso_apos_falhas', %s, %s, 75, %s, %s, '{}')""", (a["id"], joao, ATACANTE, AGORA.date(), AGORA + timedelta(minutes=5), entrou))
        admin.execute("""INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, criticidade) VALUES (%s, %s, '001', 'srv-web', 'critica')""", (a["id"], a["g"]))
        # Falso positivo: alguém errou a senha uma vez, da máquina de sempre.
        entidade(a, "ana", 0, [("10.0.0.9", AGORA - timedelta(days=60), 300)])
        engano = evento(a, AGORA, "5710", "Login recusado", 5, ["authentication_failed"], agente="003", agente_nome="estacao-ana", ip="10.0.0.9", usuario="ana")
        alheio = evento(b, AGORA, "5710", "Login recusado", 5, ["authentication_failed"], ip=ATACANTE, usuario="joao")

        # O armazém da organização: logs do atacante e os fluxos dele com três máquinas, com 80 MB saindo para ele.
        banco = armazem.criar_organizacao(armazem_admin, a["id"], 30, 30)
        bancos.append(banco)
        admin.execute("UPDATE clientes SET ler_do_armazem = true WHERE id = %s", (a["id"],))
        momento = (AGORA - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
        armazem_admin.executar(f"""INSERT INTO {banco}.logs (id, ocorrido_em, gerenciador, agente_id, decoder, regra_id, ip_origem, full_log)
                                   SELECT generateUUIDv4(), toDateTime64('{momento}', 3, 'UTC'), '{a["g"]}', '001', 'sshd', '5710', '{ATACANTE}', 'log' FROM numbers(37)""")
        for interno, porta, saindo in (("10.0.0.20", 22, 1_000_000), ("10.0.0.21", 22, 2_000_000), ("10.0.0.22", 443, 80 * 1024 * 1024)):
            armazem_admin.executar(f"""INSERT INTO {banco}.fluxos (ocorrido_em, exportador, origem, destino, porta_origem, porta_destino, protocolo, bytes, pacotes)
                                       VALUES (toDateTime64('{momento}', 3, 'UTC'), '10.0.0.1', '{ATACANTE}', '{interno}', 50000, {porta}, 'tcp', 4000, 40),
                                              (toDateTime64('{momento}', 3, 'UTC'), '10.0.0.1', '{interno}', '{ATACANTE}', {porta}, 50000, 'tcp', {saindo}, 900)""")

        with TestClient(app, base_url="https://testserver") as http:
            registrar("exige sessão", http.get(f"/api/eventos/{alerta}/investigacao").status_code == 401)
            http.post("/api/entrar", json=a["acessos"]["administrador"])
            r = http.get(f"/api/eventos/{alerta}/investigacao")
            registrar("responde", r.status_code == 200, r.text[:200])
            d = r.json()
            p = {x["id"]: x for x in d["perguntas"]}
            print("  " + "\n  ".join(f"[{x['tom']}] {x['pergunta']} {x['resposta']}" for x in d["perguntas"]), flush=True)

            print("\n== Conta invadida", flush=True)
            registrar("o endereço atacou mais de um ativo e mais de uma conta: pesa contra",
                      p["origem"]["tom"] == "agrava" and "10 outros alertas" in p["origem"]["resposta"] and "2 ativos" in p["origem"]["resposta"], p["origem"]["resposta"])
            registrar("vê o login que deu certo depois das falhas", p["entrou"]["tom"] == "agrava" and "joao" in p["entrou"]["resposta"]
                      and [c["id"] for c in p["entrou"]["eventos"]] == [entrou], str(p["entrou"]))
            registrar("a conta virou root depois: pesa contra e é citado", p["conta"]["tom"] == "agrava" and root in [c["id"] for c in p["conta"]["eventos"]], str(p["conta"])[:300])
            registrar("o endereço é novo para a conta", p["endereco_conhecido"]["tom"] == "agrava", p["endereco_conhecido"]["resposta"])
            registrar("o risco da pessoa é alto e cita o sinal", p["risco"]["tom"] == "agrava" and "75" in p["risco"]["resposta"]
                      and entrou in [c["id"] for c in p["risco"]["eventos"]], str(p["risco"]))
            registrar("o ativo é crítico e teve alerta grave", p["ativo"]["tom"] == "agrava" and root in [c["id"] for c in p["ativo"]["eventos"]], p["ativo"]["resposta"])
            registrar("o armazém conta os logs do endereço", d["armazem"] is True and "37 logs" in p["logs"]["resposta"] and "sshd" in p["logs"]["resposta"], p["logs"]["resposta"])
            registrar("os fluxos mostram três máquinas e a saída grande", p["fluxos"]["tom"] == "agrava" and "3 máquinas" in p["fluxos"]["resposta"]
                      and "82,9 MB" in p["fluxos"]["resposta"] and "porta 22" in p["fluxos"]["resposta"], p["fluxos"]["resposta"])
            registrar("o que pesa contra vem primeiro", [x["tom"] for x in d["perguntas"]] == sorted((x["tom"] for x in d["perguntas"]), key=["agrava", "atenua", "informa"].index))
            citados = {c["id"] for x in d["perguntas"] for c in x["eventos"]}
            validos = {r[0] for r in admin.execute("SELECT id FROM eventos WHERE cliente_id = %s", (a["id"],)).fetchall()}
            registrar("todo alerta citado existe e é da organização", citados and citados <= validos, str(citados - validos))
            registrar("cita no máximo cinco por resposta", all(len(x["eventos"]) <= 5 for x in d["perguntas"]))
            registrar("cada resposta diz como foi achada", all(x["como"] for x in d["perguntas"]))

            print("\n== Falso positivo", flush=True)
            e = http.get(f"/api/eventos/{engano}/investigacao").json()
            q = {x["id"]: x for x in e["perguntas"]}
            print("  " + "\n  ".join(f"[{x['tom']}] {x['pergunta']} {x['resposta']}" for x in e["perguntas"]), flush=True)
            registrar("nada pesa contra", not any(x["tom"] == "agrava" for x in e["perguntas"]), str([(x["id"], x["tom"]) for x in e["perguntas"]]))
            registrar("o endereço é o de sempre da conta", q["endereco_conhecido"]["tom"] == "atenua" and "desde" in q["endereco_conhecido"]["resposta"], q["endereco_conhecido"]["resposta"])
            registrar("ninguém entrou depois", q["entrou"]["tom"] == "atenua")
            registrar("sem fluxos com o endereço, a pergunta alivia", q["fluxos"]["tom"] == "atenua", q["fluxos"]["resposta"])

            print("\n== Sem armazém e alerta do gerenciador", flush=True)
            admin.execute("UPDATE clientes SET ler_do_armazem = false WHERE id = %s", (a["id"],))
            s = http.get(f"/api/eventos/{alerta}/investigacao").json()
            registrar("sem armazém, as perguntas do banco continuam", s["armazem"] is None and {"origem", "entrou", "conta", "risco", "ativo"} <= {x["id"] for x in s["perguntas"]}
                      and not {"logs", "fluxos"} & {x["id"] for x in s["perguntas"]})
            do_gerenciador = evento(a, AGORA, "1002", "Problema", 2, [], agente="000", agente_nome="gerenciador")
            registrar("alerta sem origem nem conta, do gerenciador, não inventa pergunta", http.get(f"/api/eventos/{do_gerenciador}/investigacao").json()["perguntas"] == [])
            registrar("alerta que não existe", http.get("/api/eventos/999999999999/investigacao").status_code == 404)

            print("\n== Máscara e isolamento", flush=True)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=a["acessos"]["analista_n1"])
            m = http.get(f"/api/eventos/{alerta}/investigacao")
            registrar("quem vê mascarado recebe a investigação", m.status_code == 200 and m.json()["perguntas"], m.text[:120])
            registrar("sem o nome da conta nem o endereço", "joao" not in m.text and ATACANTE not in m.text, m.text[:300])
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=b["acessos"]["administrador"])
            registrar("outra organização não vê", http.get(f"/api/eventos/{alerta}/investigacao").status_code == 404)
            o = http.get(f"/api/eventos/{alheio}/investigacao").json()
            registrar("e o mesmo endereço lá não traz nada daqui", o["perguntas"] and not any(c["id"] in validos for x in o["perguntas"] for c in x["eventos"])
                      and "Nenhum outro alerta" in {x["id"]: x for x in o["perguntas"]}["origem"]["resposta"])
    finally:
        for banco in bancos:
            armazem_admin.executar(f"DROP DATABASE IF EXISTS {banco}")
        # O motor de risco roda junto e pode ter guardado o que viu destes alertas.
        for tabela in ("sinais", "vistos", "alertas_risco", "notificacoes", "pares", "eventos", "auditoria", "ativos"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM horas WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM entidades WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM ueba_cursor WHERE cliente_id = ANY(%s)", (clientes,))
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
