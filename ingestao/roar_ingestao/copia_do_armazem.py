"""Cópia fria do armazém de eventos (docs/clickhouse.md, etapa 4): cada dia de cada organização vira uma cópia à parte.

Igual à do indexador, em que cada índice é um dia: a partição do dia (logs e alertas) vai para o disco de cópias, depois
que o dia fecha, e a cópia vence sozinha em ROAR_ARQUIVO_DIAS. Uma organização nunca entra na cópia de outra, porque
cada cópia é de um banco só. Roda no serviço de organizações, como root, que vê a pasta das cópias.
"""

import logging
import re
import shutil
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import armazem as armazem_de_eventos

log = logging.getLogger("roar.copia_do_armazem")
# O dia só é copiado depois de fechar e de passar a folga dos atrasados.
DIAS_DE_FOLGA = 2
COPIAS_POR_VOLTA = 30
NOME_DO_DIA = re.compile(r"\d{8}")


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


def processar(env):
    if not env.get("ARMAZEM_SENHA"):
        return False
    raiz = pasta(env)
    if not raiz.is_dir():
        return False
    adm = armazem_de_eventos.admin(env)
    feitos = copiar(adm, raiz)
    vencer(raiz, int(env.get("ROAR_ARQUIVO_DIAS") or 365))
    return feitos > 0
