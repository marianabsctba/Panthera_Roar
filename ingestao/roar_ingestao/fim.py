"""Integridade de arquivos. Quem varre e compara é o módulo do agente; aqui só configuramos e trazemos o resultado."""

import hashlib
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

import requests

from . import provisao

log = logging.getLogger("roar.fim")
PASTA_GERENCIADORES = Path("/opt/panthera-roar/gerenciadores")
SISTEMAS = {"linux": "Linux", "windows": "Windows"}
MODOS = {"agendado": "", "tempo_real": ' realtime="yes"', "quem_alterou": ' whodata="yes"'}
CAMINHO_LINUX = re.compile(r"/[^\x00-\x1f<>&\"']{0,399}")
CAMINHO_WINDOWS = re.compile(r"[A-Za-z]:\\[^\x00-\x1f<>&\"'*?|]{0,396}")
# Monitorar a raiz inteira faz o agente varrer o disco todo a cada ciclo.
RAIZES = {"/", "/proc", "/sys", "/dev"}
ARQUIVOS_POR_ATIVO = 5000
SEGUNDOS_ENTRE_ATUALIZACOES = 300


class CaminhoInvalido(Exception):
    """A mensagem aparece na tela, então precisa explicar o que corrigir."""


def validar_caminho(caminho, sistema, modo):
    caminho = str(caminho).strip()
    if sistema not in SISTEMAS:
        raise CaminhoInvalido("O sistema precisa ser Linux ou Windows.")
    if modo not in MODOS:
        raise CaminhoInvalido("Modo de monitoramento desconhecido.")
    padrao = CAMINHO_LINUX if sistema == "linux" else CAMINHO_WINDOWS
    if not padrao.fullmatch(caminho):
        raise CaminhoInvalido("Use um caminho completo, como /etc/ssh ou C:\\Windows\\System32, sem aspas nem curingas.")
    if ".." in caminho.replace("\\", "/").split("/"):
        raise CaminhoInvalido("O caminho não pode ter '..'.")
    normalizado = caminho.rstrip("/\\") or "/"
    if normalizado in RAIZES or re.fullmatch(r"[A-Za-z]:", normalizado):
        raise CaminhoInvalido("Monitorar a raiz do disco sobrecarrega o ativo: escolha uma pasta.")
    return normalizado


def conteudo_do_agent_conf(caminhos):
    """Um bloco por sistema: o agente só aplica o que tem o seu nome."""
    blocos = []
    for sistema, rotulo in SISTEMAS.items():
        desse = [c for c in caminhos if c["sistema"] == sistema]
        if desse:
            linhas = "".join(f'    <directories check_all="yes" report_changes="no"{MODOS[c["modo"]]}>{escape(c["caminho"])}</directories>\n' for c in desse)
            blocos.append(f'<agent_config os="{rotulo}">\n  <syscheck>\n{linhas}  </syscheck>\n</agent_config>\n')
    return "".join(blocos) or "<agent_config>\n</agent_config>\n"


def _com_cliente(banco, cliente, sql, *args):
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        cursor = banco.con.execute(sql, args)
        return cursor.fetchall() if cursor.description else None


def aplicar_caminhos(banco, gerenciador_id, cliente):
    linhas = _com_cliente(banco, cliente, "SELECT id, caminho, sistema, modo, estado FROM fim_caminhos WHERE gerenciador_id = %s AND estado IN ('pendente', 'ativo', 'desativado') ORDER BY id", gerenciador_id)
    em_uso = [{"caminho": l[1], "sistema": l[2], "modo": l[3]} for l in linhas if l[4] != "desativado"]
    pendentes = [l[0] for l in linhas if l[4] == "pendente"]
    conteudo = conteudo_do_agent_conf(em_uso)
    resumo = hashlib.sha256(conteudo.encode()).hexdigest()
    marca = PASTA_GERENCIADORES / gerenciador_id / "fim.aplicado"
    anterior = marca.read_text() if marca.exists() else hashlib.sha256(conteudo_do_agent_conf([]).encode()).hexdigest()
    if resumo == anterior and not pendentes:
        return 0
    ok, detalhe = (True, {}) if resumo == anterior else provisao.aplicar_agent_conf(gerenciador_id, conteudo)
    if ok:
        marca.write_text(resumo)
    else:
        log.error("gerenciador %s recusou a configuração de FIM: %s", gerenciador_id, str(detalhe)[:300])
    for pendente in pendentes:
        _com_cliente(banco, cliente, "UPDATE fim_caminhos SET estado = %s, mensagem = %s WHERE id = %s",
                     "ativo" if ok else "recusado", None if ok else "O gerenciador recusou esta configuração. Nada mudou.", pendente)
    return len(pendentes)


def enviar_varreduras(banco, gerenciador_id, cliente):
    for pedido, agente in _com_cliente(banco, cliente, "SELECT id, agente_id FROM fim_varreduras WHERE gerenciador_id = %s AND estado = 'pendente' ORDER BY id LIMIT 50", gerenciador_id):
        try:
            resposta = provisao._api_do_gerenciador(gerenciador_id, "PUT", "/syscheck", params={"agents_list": agente})
            enviada = resposta.get("data", {}).get("total_affected_items", 0) > 0
        except requests.RequestException:
            enviada = False
        _com_cliente(banco, cliente, "UPDATE fim_varreduras SET estado = %s WHERE id = %s", "enviada" if enviada else "falhou", pedido)


def _data(texto):
    if not texto:
        return None
    try:
        return datetime.fromisoformat(str(texto).replace("Z", "+00:00"))
    except ValueError:
        return None


def _epoca(valor):
    try:
        return datetime.fromtimestamp(int(valor), timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return _data(valor)


def atualizar_base(banco, gerenciador_id, cliente, ultima=None):
    """A base inteira fica no gerenciador: aqui guardamos uma cópia para a tela não depender dele estar no ar."""
    ultima = ultima if ultima is not None else _ULTIMAS
    if time.monotonic() - ultima.get(gerenciador_id, -SEGUNDOS_ENTRE_ATUALIZACOES) < SEGUNDOS_ENTRE_ATUALIZACOES:
        return 0
    ultima[gerenciador_id] = time.monotonic()
    total = 0
    agentes = _com_cliente(banco, cliente, "SELECT agente_id FROM ativos WHERE gerenciador_id = %s AND agente_id <> '000' AND estado = 'active'", gerenciador_id)
    for (agente,) in agentes:
        try:
            dados = provisao._api_do_gerenciador(gerenciador_id, "GET", f"/syscheck/{agente}", params={"limit": ARQUIVOS_POR_ATIVO, "type": "file"})
            varredura = provisao._api_do_gerenciador(gerenciador_id, "GET", f"/syscheck/{agente}/last_scan")
        except requests.RequestException as erro:
            log.warning("base de arquivos do agente %s: %s", agente, type(erro).__name__)
            continue
        itens = dados.get("data", {}).get("affected_items", [])
        momento = (varredura.get("data", {}).get("affected_items") or [{}])[0]
        with banco.con.transaction():
            banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            banco.con.execute("DELETE FROM fim_base WHERE gerenciador_id = %s AND agente_id = %s", (gerenciador_id, agente))
            for item in itens:
                banco.con.execute(
                    """INSERT INTO fim_base (cliente_id, gerenciador_id, agente_id, caminho, tipo, tamanho, modificado_em, sha256, dono, permissao)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
                    (cliente, gerenciador_id, agente, str(item.get("file", ""))[:2000].replace("\x00", ""), item.get("type"), item.get("size"), _epoca(item.get("mtime")),
                     item.get("sha256"), item.get("uname"), item.get("perm")))
            banco.con.execute("UPDATE ativos SET fim_inicio = %s, fim_fim = %s WHERE gerenciador_id = %s AND agente_id = %s",
                              (_data(momento.get("start")), _data(momento.get("end")), gerenciador_id, agente))
        total += len(itens)
    return total


_ULTIMAS = {}
