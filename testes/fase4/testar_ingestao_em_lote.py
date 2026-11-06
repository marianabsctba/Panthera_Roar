#!/usr/bin/env python3
"""Etapa 3 do armazém de eventos (docs/clickhouse.md): alertas gravados em lote, o Postgres só com os dias recentes e a
ingestão lendo do armazém. Banco e armazém reais; os alertas são sintéticos, de uma organização temporária.

    sudo bash testes/rodar.sh testes/fase4/testar_ingestao_em_lote.py
"""

import json
import random
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_ingestao import armazem, ciclo, provisao  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402
from roar_ingestao.ciclo import ler_env  # noqa: E402

RESULTADOS = []
ENV = ler_env(provisao.DESTINO / ".env")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def alerta(i, quando=None, agente="001", nivel=None, sem_regra=False):
    quando = quando or datetime.now(timezone.utc) - timedelta(minutes=i % 50)
    a = {"timestamp": quando.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000", "id": f"{int(quando.timestamp())}.{i}",
         "agent": {"id": agente, "name": f"srv-{agente}"}, "full_log": f"teste lote {i}",
         "rule": {"id": str(5700 + i % 7), "level": nivel if nivel is not None else (3, 5, 7, 10, 12)[i % 5], "description": f"regra {i % 7}",
                  "groups": ["sshd", "authentication_failed"], "mitre": {"id": ["T1110"]}},
         "data": {"srcip": f"198.51.100.{i % 9 + 1}" if i % 4 else "x", "srcuser": f"user{i % 6}"}}
    if sem_regra:
        del a["rule"]
    return a


def lote_de_teste(n, semente=7):
    random.seed(semente)
    docs = []
    for i in range(n):
        if i % 97 == 0:
            docs.append((f"inv-{i}", alerta(i, sem_regra=True)))
        elif i % 89 == 0:
            docs.append((f"ger-{i}", alerta(i, agente="000")))
        else:
            docs.append((f"os-{i}", alerta(i, agente=random.choice(["001", "002", "003"]))))
    return docs + docs[:20]  # os primeiros de novo: repetidos


def grupos_de(admin, cliente):
    return sorted((g[0], g[1], g[2], tuple(g[3]), g[4], g[5], g[6], str(g[7])) for g in admin.execute(
        """SELECT total, nivel, severidade, regras, primeira_em, ultima_em, agente_id, ip_origem FROM grupos_alerta WHERE cliente_id = %s""", (cliente,)).fetchall())


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    url = f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar"
    banco = Armazenamento(url)
    clientes, gerenciadores = [], []

    def organizacao(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{uuid.uuid4().hex[:6]}",)).fetchone()[0])
        g = f"lote{uuid.uuid4().hex[:8]}"
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 64000 + len(gerenciadores) * 4))
        clientes.append(c)
        gerenciadores.append(g)
        return c, g

    adm = armazem.admin(ENV)
    try:
        print("== Tabela dividida por dia", flush=True)
        tipo = admin.execute("SELECT relkind FROM pg_class WHERE relname = 'eventos'").fetchone()[0]
        dias = {r[0] for r in admin.execute("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'eventos'::regclass").fetchall()}
        hoje = datetime.now(timezone.utc).date()
        registrar("eventos é dividida por dia, com os próximos dias prontos", tipo == "p" and all(f"eventos_{(hoje + timedelta(days=d)):%Y%m%d}" in dias for d in range(3))
                  and "eventos_fora_dos_dias" in dias, f"{tipo} {sorted(dias)[-4:]}")
        try:
            banco.manter_dias(3)
            registrar("guardar menos de 7 dias é recusado", False)
        except psycopg.Error:
            banco.con.rollback()
            registrar("guardar menos de 7 dias é recusado", True)

        print("\n== Lote igual ao de um por um", flush=True)
        c1, g1 = organizacao("lote-antigo")
        c2, g2 = organizacao("lote-novo")
        docs = lote_de_teste(600)
        antigo = Counter()
        for i in range(0, len(docs), 100):
            antigo.update(banco.gravar_lote(docs[i:i + 100], g1, c1))
        novo = Counter()
        for i in range(0, len(docs), 100):
            novo.update(banco.gravar_em_lote(docs[i:i + 100], g2, c2))
        registrar("as mesmas contagens (novos, repetidos, inválidos, quarentena)", antigo == novo, f"{dict(antigo)} | {dict(novo)}")
        registrar("os mesmos grupos da fila, com total, nível, severidade, regras e horários", grupos_de(admin, c1) == grupos_de(admin, c2) and grupos_de(admin, c1),
                  f"{len(grupos_de(admin, c1))} e {len(grupos_de(admin, c2))}")
        sem_grupo = admin.execute("SELECT count(*) FROM eventos WHERE cliente_id = %s AND grupo_id IS NULL", (c2,)).fetchone()[0]
        registrar("todo evento novo ganha o seu grupo", sem_grupo == 0, str(sem_grupo))
        q1 = admin.execute("SELECT origem_id, motivo FROM quarentena WHERE gerenciador_id = %s ORDER BY 1", (g1,)).fetchall()
        q2 = admin.execute("SELECT origem_id, motivo FROM quarentena WHERE gerenciador_id = %s ORDER BY 1", (g2,)).fetchall()
        registrar("a mesma quarentena", q1 == q2 and q1, str(len(q1)))
        registrar("repetir o lote inteiro não grava nada de novo", banco.gravar_em_lote(docs, g2, c2)["novos"] == 0)

        print("\n== Vazão", flush=True)
        c3, g3 = organizacao("vazao")
        grandes = [(f"v-{i}", alerta(i, agente=f"{i % 40:03d}" if i % 40 else "041")) for i in range(20000)]
        inicio = time.monotonic()
        for i in range(0, len(grandes), 5000):
            banco.gravar_em_lote(grandes[i:i + 5000], g3, c3)
        em_lote = len(grandes) / (time.monotonic() - inicio)
        c4, g4 = organizacao("vazao-antiga")
        inicio = time.monotonic()
        banco.gravar_lote(grandes[:2000], g4, c4)
        um_por_um = 2000 / (time.monotonic() - inicio)
        mil = lambda n: f"{n:,.0f}".replace(",", ".")  # noqa: E731
        registrar(f"em lote grava {mil(em_lote)} alertas por segundo; um por um, {mil(um_por_um)}", em_lote > 5 * um_por_um and em_lote > 3000)

        print("\n== Só os dias recentes", flush=True)
        c5, g5 = organizacao("dias")
        velho, recente = alerta(1, quando=datetime.now(timezone.utc) - timedelta(days=200)), alerta(2)
        banco.gravar_em_lote([("velho", velho), ("recente", recente)], g5, c5)
        admin.execute("CREATE TABLE IF NOT EXISTS eventos_20200101 PARTITION OF eventos FOR VALUES FROM ('2020-01-01') TO ('2020-01-02')")
        banco.manter_dias(90)
        restam = {r[0] for r in admin.execute("SELECT origem_id FROM eventos WHERE cliente_id = %s", (c5,)).fetchall()}
        registrar("o alerta de 200 dias sai, o de hoje fica", restam == {"recente"}, str(restam))
        registrar("o dia vencido sai inteiro", admin.execute("SELECT to_regclass('eventos_20200101')").fetchone()[0] is None)

        print("\n== Ingestão lendo do armazém", flush=True)
        c6, g6 = organizacao("armazem")
        nome_do_banco = armazem.criar_organizacao(adm, c6, 90, 30)
        agora = datetime.now(timezone.utc)
        linhas = []
        for i in range(120):
            a = alerta(i, quando=agora - timedelta(minutes=30) + timedelta(seconds=i), agente="007")
            linhas.append({"id": str(uuid.uuid4()), "ocorrido_em": a["timestamp"][:23].replace("T", " "), "recebido_em": (agora - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                           "gerenciador": g6, "agente_id": "007", "regra_id": a["rule"]["id"], "nivel": a["rule"]["level"], "full_log": a["full_log"], "dados": json.dumps(a)})
        corpo = "\n".join(json.dumps(l) for l in linhas)
        adm.executar(f"INSERT INTO {nome_do_banco}.alertas SETTINGS date_time_input_format = 'best_effort' FORMAT JSONEachRow {corpo}")
        # Os 30 primeiros já tinham vindo pelo indexer, com outro id: a troca não pode repeti-los.
        banco.gravar_lote([(f"os-{i}", json.loads(linhas[i]["dados"])) for i in range(30)], g6, c6)
        banco.gravar_checkpoint(g6, datetime.fromisoformat(json.loads(linhas[29]["dados"])["timestamp"].replace("+0000", "+00:00")))
        leitor = armazem.leitor(ENV)
        ciclo.LOTE_DO_ARMAZEM = 50
        total = ciclo.rodar_gerenciador_do_armazem(leitor, banco, g6, c6)
        por_wazuh = admin.execute("SELECT bruto->>'id', count(*) FROM eventos WHERE cliente_id = %s GROUP BY 1 HAVING count(*) > 1", (c6,)).fetchall()
        no_postgres = admin.execute("SELECT count(*) FROM eventos WHERE cliente_id = %s", (c6,)).fetchone()[0]
        registrar("lê do armazém em lotes, sem repetir o que o indexer já entregou", total["lidos"] == 120 and no_postgres == 120 and not por_wazuh,
                  f"{dict(total)}, {no_postgres} no Postgres, repetidos {por_wazuh[:3]}")
        ultimo = leitor.linhas(f"SELECT toString(id) AS i FROM {nome_do_banco}.alertas ORDER BY recebido_em DESC, id DESC LIMIT 1")[0]["i"]
        registrar("a posição fica guardada no último lido", banco.ler_posicao(f"armazem:{g6}") and json.loads(banco.ler_posicao(f"armazem:{g6}")[1])[1] == ultimo)
        de_novo = ciclo.rodar_gerenciador_do_armazem(leitor, banco, g6, c6)
        registrar("a volta seguinte não relê nada", de_novo["lidos"] == 0, str(dict(de_novo)))
        recente = dict(linhas[0], id=str(uuid.uuid4()), recebido_em=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
        adm.executar(f"INSERT INTO {nome_do_banco}.alertas SETTINGS date_time_input_format = 'best_effort' FORMAT JSONEachRow {json.dumps(recente)}")
        registrar("o que acabou de chegar espera a folga, para não pular gravação em andamento",
                  ciclo.rodar_gerenciador_do_armazem(leitor, banco, g6, c6)["lidos"] == 0)
        grupos = admin.execute("SELECT sum(total) FROM grupos_alerta WHERE cliente_id = %s", (c6,)).fetchone()[0]
        registrar("e a fila soma cada alerta uma vez", grupos == 120, str(grupos))
    finally:
        for c in clientes:
            try:
                armazem.remover_organizacao(adm, c)
            except Exception:
                pass
            admin.execute("DELETE FROM eventos WHERE cliente_id = %s", (c,))
            admin.execute("DELETE FROM grupos_alerta WHERE cliente_id = %s", (c,))
        for g in gerenciadores:
            admin.execute("DELETE FROM quarentena WHERE gerenciador_id = %s", (g,))
            admin.execute("DELETE FROM checkpoints WHERE fonte IN (%s, %s)", (g, f"armazem:{g}"))
            admin.execute("DELETE FROM gerenciadores WHERE id = %s", (g,))
        for c in clientes:
            admin.execute("DELETE FROM clientes WHERE id = %s", (c,))
        admin.execute("DROP TABLE IF EXISTS eventos_20200101")
        banco.fechar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
