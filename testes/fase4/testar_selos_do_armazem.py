#!/usr/bin/env python3
"""Etapa 4 do armazém de eventos (docs/clickhouse.md): selos sobre o armazém, perícia com os eventos de lá e a cópia
fria por dia. Banco e armazém reais; os eventos são sintéticos, de uma organização temporária.

    sudo bash testes/rodar.sh testes/fase4/testar_selos_do_armazem.py
"""

import json
import shutil
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_api import evidencia  # noqa: E402
from roar_ingestao import armazem, copia_do_armazem, provisao, selo  # noqa: E402
from roar_ingestao import verificador_de_evidencia as verificador  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402
from roar_ingestao.ciclo import ler_env  # noqa: E402

RESULTADOS = []
ENV = ler_env(provisao.DESTINO / ".env")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def linha(gerenciador, quando, i, recebido=None):
    evento = {"timestamp": quando.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000", "agent": {"id": "001", "name": "srv-01"},
              "full_log": f"evento selado {i}", "rule": {"id": "5710", "level": 5}, "id": f"{int(quando.timestamp())}.{i}"}
    return {"id": str(uuid.uuid4()), "ocorrido_em": quando.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "gerenciador": gerenciador, "agente_id": "001",
            "full_log": evento["full_log"], "dados": json.dumps(evento), "recebido_em": (recebido or quando).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}


def inserir(adm, banco, tabela, linhas):
    corpo = "\n".join(json.dumps(l) for l in linhas)
    adm.executar(f"INSERT INTO {banco}.{tabela} SETTINGS date_time_input_format = 'best_effort' FORMAT JSONEachRow {corpo}")


def limpar(admin):
    """Os selos só recebem acréscimo: o gatilho sai só durante a limpeza do que este teste criou (e do que uma rodada
    interrompida deixou)."""
    clientes = [r[0] for r in admin.execute("SELECT id FROM clientes WHERE nome LIKE 'selos-%%'").fetchall()]
    gerenciadores = [r[0] for r in admin.execute("SELECT id FROM gerenciadores WHERE cliente_id = ANY(%s)", (clientes,)).fetchall()]
    tabelas = ("selo_ancoras", "selo_verificacoes", "selo_folhas", "selos")
    for tabela in tabelas:
        admin.execute(f"ALTER TABLE {tabela} DISABLE TRIGGER so_acrescenta")
    try:
        for tabela in tabelas:
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
    finally:
        for tabela in tabelas:
            admin.execute(f"ALTER TABLE {tabela} ENABLE TRIGGER so_acrescenta")
    admin.execute("DELETE FROM gerenciadores WHERE id = ANY(%s)", (gerenciadores,))
    admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))


def main():
    print("== Cabeçalho do selo", flush=True)
    base = {"gerenciador": "g", "cliente": "c", "n": 1, "fonte": "logs", "inicio": "a", "fim": "b", "total": 0, "tardio": False, "raiz": "r",
            "anterior": "0" * 64, "chave": "k", "selado_em": "s"}
    registrar("selo do indexador não ganha campo novo: o hash dos antigos não muda", "origem" not in selo.cabecalho_do_selo({**base, "origem": "indexador"})
              and selo.hash_do_selo(base) == selo.hash_do_selo({**base, "origem": "indexador"}))
    registrar("selo do armazém leva a origem assinada", selo.cabecalho_do_selo({**base, "origem": "armazem"})["origem"] == "armazem"
              and selo.hash_do_selo({**base, "origem": "armazem"}) != selo.hash_do_selo(base))
    registrar("o verificar.py do pacote calcula igual nos dois casos", all(
        verificador.hash_do_selo({**selo.cabecalho_do_selo(s), "versao": selo.VERSAO}) == selo.hash_do_selo(s) for s in (base, {**base, "origem": "armazem"})))

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    adm, leitor = armazem.admin(ENV), armazem.leitor(ENV)
    limpar(admin)
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"selos-{uuid.uuid4().hex[:6]}",)).fetchone()[0])
    gerenciador = f"selo{uuid.uuid4().hex[:8]}"
    admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, 64300)", (gerenciador, cliente))
    nome_do_banco = armazem.criar_organizacao(adm, cliente, 180, 180)
    chave, publica = selo.carregar_chave()
    raiz_das_copias = copia_do_armazem.pasta(ENV)
    try:
        print("\n== Selar sobre o armazém", flush=True)
        agora = datetime.now(timezone.utc)
        inicio = selo._piso(agora - timedelta(hours=2))
        linhas = [linha(gerenciador, inicio + timedelta(minutes=2 * i), i) for i in range(30)]
        inserir(adm, nome_do_banco, "logs", linhas)
        fonte = selo.FonteDoArmazem(leitor, cliente)
        registrar("a fonte acha o primeiro evento e as janelas", fonte.primeiro("logs", gerenciador) == inicio.replace(microsecond=0)
                  and sum(n for _, n in fonte.janelas("logs", gerenciador, inicio, agora)) == 30)
        selados = selo.selar_novas_janelas(fonte, banco, chave, publica, gerenciador, cliente, "logs", agora=agora)
        selos = admin.execute("SELECT origem, total FROM selos WHERE gerenciador_id = %s ORDER BY n", (gerenciador,)).fetchall()
        registrar("as janelas viram selos marcados como do armazém", selados >= 4 and {o for o, _ in selos} == {"armazem"} and sum(t for _, t in selos) == 30, str(selos))
        estado, achados, eventos = selo.verificar(None, banco, publica, gerenciador, cliente, armazem=leitor)
        registrar("a conferência no armazém dá íntegra", estado == "integra" and eventos == 30, f"{estado} {achados[:2]} {eventos}")
        estado, achados, _ = selo.verificar(None, banco, publica, gerenciador, cliente, armazem=None)
        registrar("sem o armazém, a conferência não finge que conferiu", estado == "violada" and achados[0]["tipo"] == "armazem_indisponivel")

        print("\n== Perícia com os eventos do armazém", flush=True)
        ids = [l["id"] for l in linhas[:5]]
        con = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True, row_factory=dict_row)
        pacotes = evidencia.montar_pacotes(con, None, None, [gerenciador], "logs", ids, publica, armazem=leitor, banco=nome_do_banco)
        problemas, _ = verificador.conferir(pacotes[0][1])
        registrar("o pacote sai com a prova de cada evento, e o verificar.py confere", len(pacotes[0][1]["eventos"]) == 5 and not problemas
                  and pacotes[0][1]["selos"][0].get("origem") == "armazem", str(problemas[:2]))
        try:
            evidencia.montar_pacotes(con, None, None, ["outro"], "logs", ids, publica, armazem=leitor, banco=nome_do_banco)
            registrar("evento de gerenciador que não é da organização não entra", False)
        except evidencia.EvidenciaRecusada:
            registrar("evento de gerenciador que não é da organização não entra", True)

        print("\n== Mexer no armazém aparece", flush=True)
        adm.executar(f"ALTER TABLE {nome_do_banco}.logs UPDATE dados = replaceOne(dados, 'evento selado 3', 'evento trocado 3') WHERE id = toUUID({{i:String}}) SETTINGS mutations_sync = 1",
                     {"i": linhas[3]["id"]})
        adm.executar(f"ALTER TABLE {nome_do_banco}.logs DELETE WHERE id = toUUID({{i:String}}) SETTINGS mutations_sync = 1", {"i": linhas[7]["id"]})
        inserir(adm, nome_do_banco, "logs", [linha(gerenciador, inicio + timedelta(minutes=1), 99)])
        estado, achados, _ = selo.verificar(None, banco, publica, gerenciador, cliente, armazem=leitor)
        tipos = {(a["tipo"], a.get("evento")) for a in achados}
        registrar("evento alterado, apagado e incluído depois são apontados um por um", estado == "violada" and ("evento_alterado", linhas[3]["id"]) in tipos
                  and ("evento_apagado", linhas[7]["id"]) in tipos and any(t == "evento_sem_selo" for t, _ in tipos), str(sorted(tipos))[:300])
        try:
            evidencia.montar_pacotes(con, None, None, [gerenciador], "logs", [linhas[3]["id"]], publica, armazem=leitor, banco=nome_do_banco)
            registrar("o pacote recusa o evento alterado depois do selo", False)
        except evidencia.EvidenciaRecusada as erro:
            registrar("o pacote recusa o evento alterado depois do selo", "alterado" in str(erro), str(erro))

        print("\n== Cópia fria por dia", flush=True)
        dia_antigo = agora - timedelta(days=5)
        inserir(adm, nome_do_banco, "logs", [linha(gerenciador, dia_antigo, 500)])
        inserir(adm, nome_do_banco, "alertas", [linha(gerenciador, dia_antigo, 501)])
        feitos = copia_do_armazem.copiar(adm, raiz_das_copias)
        dias = copia_do_armazem.dias_copiados(raiz_das_copias, cliente)
        registrar("o dia fechado vira uma cópia própria, e o de hoje espera", feitos >= 1 and f"{dia_antigo:%Y%m%d}" in dias and f"{agora:%Y%m%d}" not in dias, str(dias))
        registrar("copiar de novo não refaz o que já tem cópia", copia_do_armazem.copiar(adm, raiz_das_copias) == 0
                  or f"{dia_antigo:%Y%m%d}" in copia_do_armazem.dias_copiados(raiz_das_copias, cliente))
        apagadas = copia_do_armazem.vencer(raiz_das_copias, 3)
        registrar("a cópia vence no prazo", apagadas >= 1 and f"{dia_antigo:%Y%m%d}" not in copia_do_armazem.dias_copiados(raiz_das_copias, cliente))
    finally:
        armazem.remover_organizacao(adm, cliente)
        shutil.rmtree(raiz_das_copias / armazem.banco_do(cliente), ignore_errors=True)
        limpar(admin)
        banco.fechar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
