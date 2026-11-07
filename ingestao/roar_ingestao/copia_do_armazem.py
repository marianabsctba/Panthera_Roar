"""Cópia fria do armazém de eventos (docs/clickhouse.md, etapa 4): cada dia de cada organização vira uma cópia à parte.

Igual à do indexador, em que cada índice é um dia: a partição do dia (logs e alertas) vai para o disco de cópias, depois
que o dia fecha, e a cópia vence sozinha em ROAR_ARQUIVO_DIAS. Uma organização nunca entra na cópia de outra, porque
cada cópia é de um banco só. Roda no serviço de organizações, como root, que vê a pasta das cópias.

Trazer de volta: o dia volta para <tabela>_recuperados, à parte da tabela de sempre (a retenção dela apagaria o dia
antigo na hora), e as telas leem as duas juntas por <tabela>_leitura. Quem apaga o dia de volta é o pedido, quando vence.
Como a pasta das cópias é só do root, os dias guardados de cada organização ficam registrados no banco
(copias_do_armazem), para a tela mostrar o que dá para trazer.
"""

import logging
import re
import shutil
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import armazem as armazem_de_eventos

log = logging.getLogger("roar.copia_do_armazem")
# O dia só é copiado depois de fechar e de passar a folga dos atrasados.
DIAS_DE_FOLGA = 2
COPIAS_POR_VOLTA = 30
NOME_DO_DIA = re.compile(r"\d{8}")
NOME_DO_BANCO = re.compile(r"roar_c_[0-9a-f]{32}")
TABELAS_DO_TIPO = {"alertas": ("alertas",), "logs": ("logs",), "ambos": ("alertas", "logs")}


def pasta(env):
    return Path(env.get("ARMAZEM_COPIAS") or "/opt/panthera-roar/armazem-copias")


def dias_para_copiar(adm, banco, ja_copiados, hoje):
    """As partições de dias já fechados que ainda não têm cópia."""
    limite = (hoje - timedelta(days=DIAS_DE_FOLGA)).strftime("%Y%m%d")
    linhas = adm.linhas("""SELECT DISTINCT partition AS p FROM system.parts
                           WHERE database = {b:String} AND active AND table IN ('logs', 'alertas') AND partition <= {l:String} ORDER BY p""",
                        {"b": banco, "l": limite})
    return [l["p"] for l in linhas if NOME_DO_DIA.fullmatch(l["p"]) and l["p"] not in ja_copiados]


def copiar(adm, raiz, hoje=None):
    """Copia os dias que faltam, de todas as organizações. Devolve quantos copiou."""
    hoje = hoje or datetime.now(timezone.utc).date()
    feitos = 0
    for linha in adm.linhas("SELECT name FROM system.databases WHERE startsWith(name, 'roar_c_') ORDER BY name"):
        banco = linha["name"]
        if not re.fullmatch(r"roar_c_[0-9a-f]{32}", banco):
            continue
        ja = {p.name for p in (raiz / banco).glob("*") if p.is_dir()}
        for dia in dias_para_copiar(adm, banco, ja, hoje):
            if feitos >= COPIAS_POR_VOLTA:
                return feitos
            adm.executar(f"BACKUP TABLE {banco}.logs PARTITION {dia}, TABLE {banco}.alertas PARTITION {dia} TO Disk('copias', '{banco}/{dia}')")
            feitos += 1
            log.info("cópia de %s do dia %s", banco, dia)
    return feitos


def vencer(raiz, dias, hoje=None):
    """Apaga as cópias com mais de `dias`. Devolve quantas apagou."""
    hoje = hoje or datetime.now(timezone.utc).date()
    apagadas = 0
    for copia in raiz.glob("roar_c_*/*"):
        if copia.is_dir() and NOME_DO_DIA.fullmatch(copia.name):
            dia = date(int(copia.name[:4]), int(copia.name[4:6]), int(copia.name[6:]))
            if (hoje - dia).days > dias:
                shutil.rmtree(copia)
                apagadas += 1
    return apagadas


def dias_copiados(raiz, cliente_id):
    """Os dias guardados de uma organização, para a tela."""
    banco = raiz / armazem_de_eventos.banco_do(cliente_id)
    return sorted(p.name for p in banco.glob("*") if p.is_dir() and NOME_DO_DIA.fullmatch(p.name))


def registrar(banco_admin, raiz):
    """Põe no banco os dias guardados de cada organização, e tira os que venceram. A tela lê dali."""
    guardados = {}
    for copia in raiz.glob("roar_c_*/*"):
        if copia.is_dir() and NOME_DO_BANCO.fullmatch(copia.parent.name) and NOME_DO_DIA.fullmatch(copia.name):
            cliente = str(uuid.UUID(copia.parent.name[len("roar_c_"):]))
            guardados.setdefault(cliente, set()).add(date(int(copia.name[:4]), int(copia.name[4:6]), int(copia.name[6:])))
    existentes = {str(c) for (c,) in banco_admin.execute("SELECT id FROM clientes").fetchall()}
    for cliente, dias in guardados.items():
        if cliente not in existentes:
            continue  # Organização removida: a cópia vence sozinha.
        banco_admin.execute("DELETE FROM copias_do_armazem WHERE cliente_id = %s AND NOT dia = ANY(%s)", (cliente, sorted(dias)))
        banco_admin.execute("INSERT INTO copias_do_armazem (cliente_id, dia) SELECT %s, unnest(%s::date[]) ON CONFLICT DO NOTHING", (cliente, sorted(dias)))
    banco_admin.execute("DELETE FROM copias_do_armazem WHERE NOT cliente_id = ANY(%s::uuid[])", (list(guardados),))


def presentes(armazem, banco):
    """{(tabela, dia AAAAMMDD)} que já estão no armazém, na tabela de sempre ou de volta da cópia."""
    linhas = armazem.linhas("""SELECT DISTINCT table, partition FROM system.parts WHERE database = {b:String} AND active
                               AND table IN ('logs', 'alertas', 'logs_recuperados', 'alertas_recuperados')""", {"b": banco})
    return {(l["table"].removesuffix("_recuperados"), l["partition"]) for l in linhas}


def recuperar(adm, raiz, cliente_id, de, ate, tipo):
    """Traz de volta os dias do período que estão na cópia e não no armazém. Devolve o que voltou, como "logs:AAAAMMDD"."""
    banco = armazem_de_eventos.banco_do(cliente_id)
    ja = presentes(adm, banco)
    voltaram = []
    for i in range((ate - de).days + 1):
        dia = (de + timedelta(days=i)).strftime("%Y%m%d")
        if not (raiz / banco / dia).is_dir():
            continue
        for tabela in TABELAS_DO_TIPO[tipo]:
            if (tabela, dia) in ja:
                continue
            # A tabela de recuperados não tem a retenção da original: a definição é diferente de propósito.
            adm.executar(f"""RESTORE TABLE {banco}.{tabela} AS {banco}.{tabela}_recuperados PARTITION {dia} FROM Disk('copias', '{banco}/{dia}')
                             SETTINGS allow_non_empty_tables = true, allow_different_table_def = true""")
            voltaram.append(f"{tabela}:{dia}")
    # A cópia de um dia sem alerta não tem partição de alertas: só conta o que de fato voltou.
    agora = presentes(adm, banco)
    return [v for v in voltaram if tuple(v.split(":")) in agora]


def devolver(adm, cliente_id, itens):
    """Apaga os dias que voltaram. Só o que tem a forma de um dia de logs ou alertas, e só nas tabelas de recuperados."""
    banco = armazem_de_eventos.banco_do(cliente_id)
    for item in itens:
        tabela, _, dia = item.partition(":")
        if tabela in ("logs", "alertas") and NOME_DO_DIA.fullmatch(dia):
            adm.executar(f"ALTER TABLE {banco}.{tabela}_recuperados DROP PARTITION {dia}")


def processar(env):
    if not env.get("ARMAZEM_SENHA"):
        return False
    raiz = pasta(env)
    if not raiz.is_dir():
        return False
    adm = armazem_de_eventos.admin(env)
    feitos = copiar(adm, raiz)
    vencer(raiz, int(env.get("ROAR_ARQUIVO_DIAS") or 365))
    from . import provisao

    with provisao.banco_admin(env) as b:
        registrar(b, raiz)
    return feitos > 0
