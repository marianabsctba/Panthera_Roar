"""Vigia dos coletores (docs/clickhouse.md, etapa 5): reinicia o coletor que parou de entregar.

Visto no servidor de teste: depois de um reinício do armazém, o envio do Vector pode ficar parado sem registrar erro, com
os eventos guardados no buffer em disco. Nada se perde, mas nada chega ao armazém até o coletor reiniciar. O vigia não
depende da causa: se o gerenciador escreveu no arquivo de logs há mais de LIMITE e o armazém não recebeu nada dele desde
então, reinicia o coletor, que entrega o que estava no buffer. Roda no serviço de organizações, como root, que vê os
volumes do Docker.
"""

import logging
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import armazem as armazem_de_eventos
from . import provisao

log = logging.getLogger("roar.vigia_do_coletor")
LIMITE = timedelta(minutes=5)
# Armazém fora do ar não volta com reinício do coletor: espera antes de tentar de novo.
ENTRE_REINICIOS = timedelta(minutes=15)
# Só olha as horas recentes: a consulta usa a divisão por dia e não lê a tabela inteira.
JANELA = timedelta(hours=2)
_reiniciados = {}


def parado(escrito_em, entregue_em, agora):
    """O gerenciador escreveu há mais de LIMITE e o armazém não recebeu nada dele depois disso."""
    if escrito_em is None or agora - escrito_em < LIMITE:
        return False
    return entregue_em is None or entregue_em < escrito_em


def _escrito_em(gerenciador_id):
    """Última escrita do gerenciador no arquivo que o coletor lê (todos os eventos passam por ele)."""
    r = subprocess.run(["docker", "volume", "inspect", f"roar-ger-{gerenciador_id}_logs", "--format", "{{.Mountpoint}}"],
                       capture_output=True, text=True)
    if r.returncode:
        return None
    arquivo = Path(r.stdout.strip()) / "archives" / "archives.json"
    return datetime.fromtimestamp(arquivo.stat().st_mtime, timezone.utc) if arquivo.is_file() else None


def _entregue_em(adm, banco, gerenciador_id, agora):
    linha = adm.linhas(f"""SELECT toUnixTimestamp64Milli(max(recebido_em)) AS m, count() AS n FROM {banco}.logs
                           WHERE gerenciador = {{g:String}} AND ocorrido_em >= {{d:DateTime64(3)}}""",
                       {"g": gerenciador_id, "d": (agora - JANELA).strftime("%Y-%m-%d %H:%M:%S")})[0]
    return datetime.fromtimestamp(int(linha["m"]) / 1000, timezone.utc) if int(linha["n"]) else None


def _reiniciar(gerenciador_id):
    pasta = provisao.DESTINO / "gerenciadores" / gerenciador_id
    provisao._compose(pasta, gerenciador_id, "restart", "coletor")


def conferir(adm, gerenciadores, agora=None, escrito_em=_escrito_em, reiniciar=_reiniciar):
    """gerenciadores: [(id, cliente)]. Devolve os ids reiniciados."""
    agora = agora or datetime.now(timezone.utc)
    com_armazem = {l["name"] for l in adm.linhas("SELECT name FROM system.databases WHERE startsWith(name, 'roar_c_')")}
    feitos = []
    for gerenciador_id, cliente in gerenciadores:
        banco = armazem_de_eventos.banco_do(cliente)
        if banco not in com_armazem or agora - _reiniciados.get(gerenciador_id, datetime.min.replace(tzinfo=timezone.utc)) < ENTRE_REINICIOS:
            continue
        escrito = escrito_em(gerenciador_id)
        entregue = _entregue_em(adm, banco, gerenciador_id, agora) if escrito else None
        if not parado(escrito, entregue, agora):
            continue
        log.warning("coletor do gerenciador %s parado: escrito %s, entregue %s; reiniciando", gerenciador_id, escrito, entregue)
        try:
            reiniciar(gerenciador_id)
        except subprocess.CalledProcessError as erro:
            log.error("não reiniciou o coletor do gerenciador %s: %s", gerenciador_id, (erro.stderr or "")[-300:])
        _reiniciados[gerenciador_id] = agora
        feitos.append(gerenciador_id)
    return feitos


def processar(env):
    if not env.get("ARMAZEM_SENHA"):
        return []
    with provisao.banco_admin(env) as b:
        gerenciadores = b.execute("SELECT id, cliente_id FROM gerenciadores ORDER BY id").fetchall()
    return conferir(armazem_de_eventos.admin(env), [(g, str(c)) for g, c in gerenciadores])
