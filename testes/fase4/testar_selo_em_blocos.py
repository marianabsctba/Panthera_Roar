#!/usr/bin/env python3
"""Selo em blocos (ingestao/roar_ingestao/selo_em_blocos.py): a versão dos selos para janelas grandes do armazém. As folhas
saem do próprio armazém, a árvore é feita sobre os blocos, a conferência aponta o bloco que mudou, o pacote de perícia
prova um evento com as folhas do bloco dele, e o verificar.py confere sozinho. No fim, uma janela de um milhão de
eventos, para medir.

    sudo bash testes/rodar.sh testes/fase4/testar_selo_em_blocos.py
"""

import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "testes/fase4")]

from roar_api import evidencia  # noqa: E402
from roar_ingestao import armazem, provisao, selo, selo_em_blocos  # noqa: E402
from roar_ingestao import verificador_de_evidencia as verificador  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402
from roar_ingestao.ciclo import ler_env  # noqa: E402
from testar_selos_do_armazem import inserir, limpar, linha  # noqa: E402

RESULTADOS = []
ENV = ler_env(provisao.DESTINO / ".env")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def selos_de(admin, gerenciador):
    return [dict(zip(("n", "versao", "total", "blocos", "folhas_superiores", "tardio", "recebido_de"), l)) for l in admin.execute(
        "SELECT n, versao, total, blocos, folhas_superiores, tardio, recebido_de FROM selos WHERE gerenciador_id = %s ORDER BY n", (gerenciador,)).fetchall()]


def main():
    print("== Contas", flush=True)
    folhas = [bytes([i]) * 32 for i in (3, 1, 2)]
    registrar("o resumo do bloco não depende da ordem das folhas", selo_em_blocos.resumo_do_bloco(folhas) == selo_em_blocos.resumo_do_bloco(sorted(folhas)))
    registrar("blocos em potência de dois, com até mil folhas cada, em média", (selo_em_blocos.quantos_blocos(0), selo_em_blocos.quantos_blocos(1024),
              selo_em_blocos.quantos_blocos(1025), selo_em_blocos.quantos_blocos(45_000_000)) == (1, 1, 2, 65536))
    base = {"gerenciador": "g", "cliente": "c", "n": 1, "fonte": "logs", "inicio": "a", "fim": "b", "total": 0, "tardio": False, "raiz": "r",
            "anterior": "0" * 64, "chave": "k", "selado_em": "s", "origem": "armazem"}
    em_blocos = {**base, "versao": 2, "blocos": 16, "folhas_superiores": 9, "recebido_de": None, "recebido_ate": "t"}
    registrar("o cabeçalho da versão 2 leva os blocos e a faixa de chegada; o da versão 1 não muda", "blocos" in selo.cabecalho_do_selo(em_blocos)
              and "blocos" not in selo.cabecalho_do_selo(base) and selo.hash_do_selo(base) == selo.hash_do_selo({**base, "versao": 1}))
    registrar("o verificar.py calcula o mesmo hash do selo em blocos", verificador.hash_do_selo({**selo.cabecalho_do_selo(em_blocos)}) == selo.hash_do_selo(em_blocos))

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    adm, leitor = armazem.admin(ENV), armazem.leitor(ENV)
    limpar(admin)
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"selos-blocos-{uuid.uuid4().hex[:6]}",)).fetchone()[0])
    gerenciador = f"blc{uuid.uuid4().hex[:8]}"
    admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, 64300)", (gerenciador, cliente))
    nome_do_banco = armazem.criar_organizacao(adm, cliente, 180, 180)
    chave, publica = selo.carregar_chave()
    fonte = selo.FonteDoArmazem(leitor, cliente)
    limites = selo_em_blocos.LIMITE_POR_EVENTO, selo_em_blocos.FOLHAS_POR_BLOCO
    try:
        # Limites pequenos: vários blocos com poucos eventos.
        selo_em_blocos.LIMITE_POR_EVENTO, selo_em_blocos.FOLHAS_POR_BLOCO = 20, 8
        print("\n== Selar em blocos", flush=True)
        agora = datetime.now(timezone.utc)
        inicio = selo._piso(agora - timedelta(hours=2))
        linhas = [linha(gerenciador, inicio + timedelta(seconds=7 * i), i) for i in range(100)]
        inserir(adm, nome_do_banco, "logs", linhas)
        selo.selar_novas_janelas(fonte, banco, chave, publica, gerenciador, cliente, "logs", agora=agora)
        selos = selos_de(admin, gerenciador)
        primeiro = selos[0]
        registrar("a janela grande vira um selo em blocos", primeiro["versao"] == 2 and primeiro["total"] == 100 and primeiro["blocos"] == 16
                  and 1 <= primeiro["folhas_superiores"] <= 16, str(primeiro))
        registrar("o Postgres guarda só os blocos, não uma folha por evento", len(selo_em_blocos.desempacotar_blocos(admin.execute(
            "SELECT folhas FROM selo_folhas WHERE gerenciador_id = %s AND n = %s", (gerenciador, primeiro["n"])).fetchone()[0])) == primeiro["folhas_superiores"])
        estado, achados, eventos = selo.verificar(None, banco, publica, gerenciador, cliente, armazem=leitor)
        registrar("a conferência no armazém dá íntegra", estado == "integra" and eventos == 100, f"{estado} {achados[:2]} {eventos}")

        print("\n== Perícia", flush=True)
        con = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True, row_factory=dict_row)
        ids = [l["id"] for l in linhas[:4]]
        pacote = evidencia.montar_pacotes(con, None, None, [gerenciador], "logs", ids, publica, armazem=leitor, banco=nome_do_banco)[0][1]
        problemas, _ = verificador.conferir(pacote)
        registrar("o pacote prova cada evento com as folhas do bloco, e o verificar.py confere", not problemas and all(e["versao"] == 2 for e in pacote["eventos"])
                  and all(len(e["folhas_do_bloco"]) <= 30 for e in pacote["eventos"]), str(problemas[:2]))
        trocado = {**pacote, "eventos": [{**pacote["eventos"][0], "bruto": pacote["eventos"][0]["bruto"].replace("evento selado", "evento trocado")}]}
        registrar("mexer no log do pacote aparece no verificar.py", verificador.conferir(trocado)[0])
        outro = {**pacote, "eventos": [{**pacote["eventos"][0], "documento": {"full_log": "outro"}}]}
        registrar("o laudo não pode mostrar um log diferente do provado", verificador.conferir(outro)[0])

        print("\n== Tardio", flush=True)
        atrasado = linha(gerenciador, inicio + timedelta(minutes=3), 777, recebido=datetime.now(timezone.utc) + timedelta(seconds=1))
        time.sleep(7)
        inserir(adm, nome_do_banco, "logs", [atrasado])
        selados = selo.selar_tardios(fonte, banco, chave, publica, gerenciador, cliente, "logs", agora=datetime.now(timezone.utc) + timedelta(seconds=10))
        tardio = selos_de(admin, gerenciador)[-1]
        registrar("o que chegou depois do corte vira um selo tardio em blocos, com a faixa de chegada", selados == 1 and tardio["tardio"] and tardio["versao"] == 2
                  and tardio["total"] == 1 and tardio["recebido_de"] is not None, str(tardio))
        estado, achados, eventos = selo.verificar(None, banco, publica, gerenciador, cliente, armazem=leitor)
        registrar("com o tardio, continua íntegra", estado == "integra" and eventos == 101, f"{estado} {achados[:2]} {eventos}")

        print("\n== Mexer no armazém aparece", flush=True)
        alvo, apagado = linhas[10], linhas[20]
        adm.executar(f"ALTER TABLE {nome_do_banco}.logs UPDATE dados = replaceOne(dados, 'evento selado', 'evento trocado') WHERE id = toUUID({{i:String}}) SETTINGS mutations_sync = 1",
                     {"i": alvo["id"]})
        adm.executar(f"ALTER TABLE {nome_do_banco}.logs DELETE WHERE id = toUUID({{i:String}}) SETTINGS mutations_sync = 1", {"i": apagado["id"]})
        estado, achados, _ = selo.verificar(None, banco, publica, gerenciador, cliente, armazem=leitor)
        alterados = [a for a in achados if a["tipo"] == "bloco_alterado"]
        registrar("o evento alterado e o apagado aparecem no bloco de cada um", estado == "violada" and 1 <= len(alterados) <= 2
                  and any(a["eventos_hoje"] == a["eventos_selados"] - 1 for a in alterados), str(alterados))
        try:
            evidencia.montar_pacotes(con, None, None, [gerenciador], "logs", [alvo["id"]], publica, armazem=leitor, banco=nome_do_banco)
            registrar("o pacote recusa o evento do bloco alterado", False)
        except evidencia.EvidenciaRecusada as erro:
            registrar("o pacote recusa o evento do bloco alterado", "não confere" in str(erro), str(erro))
        segredo = bytes(admin.execute("SELECT segredo FROM selo_folhas WHERE gerenciador_id = %s AND n = %s", (gerenciador, primeiro["n"])).fetchone()[0])
        n_blocos = primeiro["blocos"]
        mexidos = {selo_em_blocos.bloco_do_sal(selo_em_blocos.sal(segredo, i), n_blocos) for i in (alvo["id"], apagado["id"])}
        intacto = next(l["id"] for l in linhas if selo_em_blocos.bloco_do_sal(selo_em_blocos.sal(segredo, l["id"]), n_blocos) not in mexidos)
        pacote = evidencia.montar_pacotes(con, None, None, [gerenciador], "logs", [intacto], publica, armazem=leitor, banco=nome_do_banco)[0][1]
        registrar("o evento de outro bloco continua com prova", not verificador.conferir(pacote)[0])
    finally:
        selo_em_blocos.LIMITE_POR_EVENTO, selo_em_blocos.FOLHAS_POR_BLOCO = limites
        armazem.remover_organizacao(adm, cliente)
        limpar(admin)

    print("\n== Volume: uma janela de um milhão de eventos", flush=True)
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"selos-volume-{uuid.uuid4().hex[:6]}",)).fetchone()[0])
    gerenciador = f"vol{uuid.uuid4().hex[:8]}"
    admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, 64300)", (gerenciador, cliente))
    nome_do_banco = armazem.criar_organizacao(adm, cliente, 180, 180)
    fonte = selo.FonteDoArmazem(leitor, cliente)
    try:
        agora = datetime.now(timezone.utc)
        inicio = selo._piso(agora - timedelta(hours=2))
        # Um log de uns 600 bytes, como um alerta comum, espalhado pelos 15 minutos.
        adm.executar(f"""INSERT INTO {nome_do_banco}.logs (id, ocorrido_em, recebido_em, gerenciador, agente_id, full_log, dados)
                         SELECT generateUUIDv4(number), toDateTime64({{a:String}}, 3, 'UTC') + toIntervalMillisecond(number % 900000), toDateTime64({{a:String}}, 3, 'UTC'),
                                {{g:String}}, '001', concat('log de volume ', toString(number)),
                                concat('{{"timestamp":"x","agent":{{"id":"001"}},"full_log":"log de volume ', toString(number), '","pad":"', repeat('x', 500), '"}}')
                         FROM numbers(1000000)""", {"a": inicio.strftime("%Y-%m-%d %H:%M:%S"), "g": gerenciador})
        comeco = time.monotonic()
        selo.selar_novas_janelas(fonte, banco, chave, publica, gerenciador, cliente, "logs", agora=agora, limite=1)
        selar = time.monotonic() - comeco
        grande = selos_de(admin, gerenciador)[0]
        registrar("um milhão de eventos vira um selo em blocos", grande["versao"] == 2 and grande["total"] == 1_000_000, str(grande))
        comeco = time.monotonic()
        estado, achados, eventos = selo.verificar(None, banco, publica, gerenciador, cliente, armazem=leitor)
        conferir = time.monotonic() - comeco
        registrar("e confere íntegra", estado == "integra" and eventos == 1_000_000, f"{estado} {achados[:1]}")
        print(f"   tempo: selar {selar:.1f} s, conferir {conferir:.1f} s ({grande['folhas_superiores']} blocos)", flush=True)
        registrar("selar e conferir levam menos de um minuto cada", selar < 60 and conferir < 60, f"{selar:.1f} s e {conferir:.1f} s")
    finally:
        armazem.remover_organizacao(adm, cliente)
        limpar(admin)
        banco.fechar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
