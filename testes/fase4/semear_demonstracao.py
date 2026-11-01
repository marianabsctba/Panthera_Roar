#!/usr/bin/env python3
"""Cria um cliente de demonstração com dados de exemplo, passando pelo UEBA de verdade.

    /opt/panthera-roar/venv/bin/python testes/fase4/semear_demonstracao.py

O acesso gerado fica em /opt/panthera-roar/demonstracao.txt, só para root.
"""

import os
import random
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg
from argon2 import PasswordHasher
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ueba")]

from roar_ueba.motor import Motor, Parametros  # noqa: E402

ENV = {}
for linha in Path("/opt/panthera-roar/.env").read_text().splitlines():
    if "=" in linha and not linha.startswith("#"):
        k, v = linha.split("=", 1)
        ENV[k] = v
ADMIN = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
FUSO = ZoneInfo("America/Sao_Paulo")
NOME = "Demonstração"
SUCESSO, FALHA, SUDO = ["authentication_success"], ["authentication_failed"], ["sudo"]
PESSOAS = ["maria.silva", "joao.souza", "ana.lima", "pedro.alves", "carla.dias", "rafael.nunes", "beatriz.rocha", "lucas.melo"]
SERVIDORES = {"001": "srv-financeiro", "002": "srv-rh", "003": "srv-arquivos", "004": "srv-dominio"}


def main():
    r = random.Random(7)
    antigo = ADMIN.execute("SELECT id FROM clientes WHERE nome = %s", (NOME,)).fetchone()
    if antigo:
        for tabela in ("sinais", "alertas_risco", "falhas_por_hora", "horas", "vistos", "entidades", "ueba_cursor",
                       "eventos", "grupos_alerta", "gerenciadores", "usuarios"):
            ADMIN.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", antigo)
        ADMIN.execute("DELETE FROM clientes WHERE id = %s", antigo)

    cliente = ADMIN.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (NOME,)).fetchone()[0]
    ger = "demonstracao"
    ADMIN.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, 65000)", (ger, cliente))
    senha = secrets.token_urlsafe(16)
    email = "demonstracao@exemplo.test"
    ADMIN.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash) VALUES (%s, %s, 'Analista', %s)",
                  (cliente, email, PasswordHasher().hash(senha)))

    n = [0]

    def ev(quando, usuario, grupos, agente, ip, regra, descricao, nivel=3, bruto=None):
        n[0] += 1
        severidade = "critica" if nivel >= 15 else "alta" if nivel >= 12 else "media" if nivel >= 7 else "baixa"
        grupo = ADMIN.execute(
            """INSERT INTO grupos_alerta AS g (cliente_id, chave, dia, gerenciador_id, agente_id, ip_origem, nivel,
                 severidade, regras, primeira_em, ultima_em)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cliente_id, chave) DO UPDATE SET total = g.total + 1,
                 nivel = GREATEST(g.nivel, EXCLUDED.nivel),
                 severidade = CASE WHEN EXCLUDED.nivel > g.nivel THEN EXCLUDED.severidade ELSE g.severidade END,
                 regras = ARRAY(SELECT DISTINCT unnest(g.regras || EXCLUDED.regras)),
                 ultima_em = GREATEST(g.ultima_em, EXCLUDED.ultima_em) RETURNING id""",
            (cliente, f"{agente}|{ip}|{quando.date()}", quando.date(), ger, agente, ip, nivel, severidade, [regra],
             quando, quando)).fetchone()[0]
        ADMIN.execute(
            """INSERT INTO eventos (cliente_id, grupo_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel, severidade,
                 regra_id, regra_descricao, regra_grupos, agente_id, agente_nome, ip_origem, usuario, bruto)
               VALUES (%s, %s, %s, 'wazuh', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (cliente, grupo, ger, f"d{n[0]}", quando, nivel, severidade, regra, descricao, grupos, agente,
             SERVIDORES[agente], ip, usuario, Jsonb(bruto or {})))

    agora = datetime.now(timezone.utc)
    hoje = agora.astimezone(FUSO).replace(hour=0, minute=0, second=0, microsecond=0)
    for d in range(30, 0, -1):
        dia = hoje - timedelta(days=d)
        if dia.weekday() >= 5:
            continue
        for i, p in enumerate(PESSOAS):
            agente = list(SERVIDORES)[i % 3]
            for h in (9, 11, 14, 17):
                ev(dia.replace(hour=h, minute=r.randint(0, 59)).astimezone(timezone.utc), p, SUCESSO, agente,
                   f"10.10.{i}.20", "5715", "sshd: authentication success.")

    # Ruído de todo dia: alertas comuns, que o Wazuh detecta sem envolver identidade.
    externos = [f"198.51.100.{i}" for i in (11, 23, 42, 58)] + ["203.0.113.9", "203.0.113.31"]
    comuns = [
        ("550", "Integrity checksum changed.", 7),
        ("510", "Host-based anomaly detection event (rootcheck).", 7),
        ("31151", "Multiple web server 400 error codes from same source ip.", 10),
        ("5551", "PAM: Multiple failed logins in a small period of time.", 10),
        ("40111", "Multiple authentication failures.", 12),
    ]
    for d in range(30, -1, -1):
        dia = hoje - timedelta(days=d)
        for _ in range(r.randint(3, 12) if dia.weekday() < 5 else r.randint(0, 4)):
            regra, descricao, nivel = r.choices(comuns, weights=(8, 4, 3, 2, 1))[0]
            quando = dia.replace(hour=r.randint(0, 23), minute=r.randint(0, 59)).astimezone(timezone.utc)
            if quando < agora:
                ev(quando, None, ["syscheck"], r.choice(list(SERVIDORES)), r.choice(externos), regra, descricao, nivel=nivel)
    # Um dia ruim, para o gráfico mostrar o que chama atenção.
    pico = (hoje - timedelta(days=6)).replace(hour=14).astimezone(timezone.utc)
    for i in range(35):
        ev(pico + timedelta(minutes=i), None, ["attack"], "004", "203.0.113.31", "40111", "Multiple authentication failures.", nivel=12)
    for i in range(3):
        ev(pico + timedelta(minutes=40 + i), None, ["attack"], "004", "203.0.113.31", "100002", "Possible ransomware activity.", nivel=15)

    # Credencial roubada: ativo e endereço novos, de madrugada, com privilégio.
    q = (hoje.replace(hour=3, minute=12) if agora.astimezone(FUSO).hour > 3 else hoje - timedelta(hours=21)).astimezone(timezone.utc)
    ev(q, "maria.silva", SUCESSO, "004", "203.0.113.45", "5715", "sshd: authentication success.")
    ev(q + timedelta(minutes=2), "maria.silva", SUDO, "004", "203.0.113.45", "5402", "Successful sudo to ROOT executed.",
       nivel=3, bruto={"data": {"dstuser": "root"}})
    # Força bruta que funcionou.
    t = q + timedelta(minutes=40)
    for i in range(14):
        ev(t + timedelta(seconds=i * 6), "joao.souza", FALHA, "001", "198.51.100.77", "5760",
           "sshd: authentication failed.", nivel=5)
    ev(t + timedelta(seconds=120), "joao.souza", SUCESSO, "001", "198.51.100.77", "5715", "sshd: authentication success.")
    # Nome hostil, para ver a tela tratando como texto.
    for i in range(30):
        ev(t + timedelta(minutes=5, seconds=i), '<img src=x onerror="alert(1)">', FALHA, "003", "198.51.100.200", "5710",
           "sshd: Attempt to login using a non-existent user", nivel=5)
    ev(t + timedelta(minutes=9), "ana.lima", SUCESSO, "003", "10.10.2.20", "5715", "sshd: authentication success.")

    motor = Motor(f"postgresql://roar_ueba:{ENV['ROAR_UEBA_SENHA']}@127.0.0.1:5433/roar", Parametros(atraso_segundos=0))
    while motor.processar_cliente(cliente, "America/Sao_Paulo") == motor.p.lote:
        pass
    motor.fechar()

    arquivo = Path("/opt/panthera-roar/demonstracao.txt")
    arquivo.write_text(f"{email}\n{senha}\n")
    os.chmod(arquivo, 0o600)
    total = ADMIN.execute("SELECT count(*) FROM alertas_risco WHERE cliente_id = %s", (cliente,)).fetchone()[0]
    print(f"Demonstração criada: {n[0]} eventos, {total} alertas de risco. Acesso em {arquivo}.")


if __name__ == "__main__":
    main()
