"""Selo em blocos (versão 2), para janelas grandes do armazém de eventos (docs/clickhouse.md, "Selo em volume alto").

O selo da versão 1 lê cada evento no Python e guarda uma folha por evento no Postgres: em 50 mil eventos por segundo, são
45 milhões de folhas por janela de 15 minutos. Aqui a folha é calculada no próprio armazém, sobre o log exatamente como
foi gravado (os bytes, sem reescrever o JSON), com sal por evento derivado de um segredo da janela. Os eventos se espalham
em blocos de umas mil folhas por um sorteio fixo (os primeiros bytes do sal), o armazém resume cada bloco (as folhas em
ordem, num hash só), e a árvore de Merkle é feita só sobre os blocos. O Postgres guarda o selo e o resumo de cada bloco.

A prova de um evento leva as folhas do bloco dele e o caminho do bloco até a raiz, e o verificar.py do pacote confere
sozinho. A conferência aponta o bloco que mudou (quantos eventos tinha e quantos tem), não o evento: é o preço de não
guardar uma folha por evento.

Cada selo diz que eventos cobre pela hora de chegada ao armazém (recebido_em): o que chegar depois do corte entra num
selo tardio. Incluir um evento com hora de chegada antiga muda o bloco dele, e aparece.
"""

import gzip
import hashlib
import json
import math
from datetime import datetime, timedelta, timezone

from . import armazem as armazem_de_eventos

VERSAO = 2
FOLHAS_POR_BLOCO = 1024
# Até aqui, a janela fica na versão 1, que aponta evento por evento (uns 110 por segundo, em média, na janela).
LIMITE_POR_EVENTO = 100_000


# ------------------------------------------------------------------ as contas (as mesmas do verificar.py)

def sal(segredo, identificador):
    return hashlib.sha256(segredo + identificador.encode()).digest()


def folha(sal_da_folha, identificador, bruto):
    return hashlib.sha256(b"\x02" + sal_da_folha + identificador.encode() + b"\n" + bruto).digest()


def bloco_do_sal(sal_da_folha, blocos):
    return int.from_bytes(sal_da_folha[:8], "big") % blocos


def resumo_do_bloco(folhas):
    return hashlib.sha256(b"\x03" + b"".join(sorted(folhas))).digest()


def folha_superior(bloco, total, resumo):
    return hashlib.sha256(b"\x04" + bloco.to_bytes(8, "big") + total.to_bytes(8, "big") + resumo).digest()


def quantos_blocos(total):
    """Potência de dois que deixa cada bloco com até FOLHAS_POR_BLOCO folhas, em média."""
    return 1 << max(0, math.ceil(math.log2(max(1, math.ceil(total / FOLHAS_POR_BLOCO)))))


def empacotar_blocos(blocos):
    """[(bloco, total, resumo)] para guardar no lugar das folhas (selo_folhas.folhas)."""
    return gzip.compress("".join(f"{b}\t{t}\t{r.hex()}\n" for b, t, r in blocos).encode(), compresslevel=6, mtime=0)


def desempacotar_blocos(dados):
    blocos = []
    for linha in gzip.decompress(bytes(dados)).decode().splitlines():
        b, t, r = linha.split("\t")
        blocos.append((int(b), int(t), bytes.fromhex(r)))
    return blocos


def folhas_superiores(blocos):
    return [folha_superior(b, t, r) for b, t, r in sorted(blocos)]


# ------------------------------------------------------------------ no armazém

# O log como foi gravado; o grande demais ficou só com o começo e o resumo do original.
BRUTO = "if(notEmpty(dados), dados, concat(full_log, '\\n', resumo_do_original))"
SAL = "SHA256(concat(unhex({segredo:String}), toString(id)))"


def _filtro(selo):
    """Os eventos do selo: a janela pela hora do evento, e a faixa de chegada ao armazém."""
    filtro = """gerenciador = {g:String} AND ocorrido_em >= parseDateTime64BestEffort({a:String}, 3) AND ocorrido_em < parseDateTime64BestEffort({b:String}, 3)
                AND recebido_em <= parseDateTime64BestEffort({ate:String}, 3)"""
    if selo.get("recebido_de"):
        filtro += " AND recebido_em > parseDateTime64BestEffort({de:String}, 3)"
    return filtro


def _parametros(selo, segredo):
    p = {"g": selo["gerenciador"], "a": selo["inicio"], "b": selo["fim"], "ate": selo["recebido_ate"], "segredo": segredo.hex()}
    if selo.get("recebido_de"):
        p["de"] = selo["recebido_de"]
    return p


def calcular_blocos(leitor, banco, fonte, selo, segredo):
    """[(bloco, total, resumo)] dos blocos com evento, calculados no armazém. Nada de evento desce para cá."""
    linhas = leitor.linhas(f"""
        SELECT bloco, count() AS total, hex(SHA256(concat(char(3), arrayStringConcat(arraySort(groupArray(folha)))))) AS resumo
        FROM (SELECT {SAL} AS s, reinterpretAsUInt64(reverse(substring(s, 1, 8))) % {{blocos:UInt64}} AS bloco,
                     toString(SHA256(concat(char(2), s, toString(id), '\\n', {BRUTO}))) AS folha
              FROM {banco}.{fonte} WHERE {_filtro(selo)})
        GROUP BY bloco ORDER BY bloco""", {**_parametros(selo, segredo), "blocos": selo["blocos"]})
    return [(int(l["bloco"]), int(l["total"]), bytes.fromhex(l["resumo"])) for l in linhas]


def contar(leitor, banco, fonte, selo):
    return int(leitor.linhas(f"SELECT count() AS n FROM {banco}.{fonte} WHERE {_filtro(selo)}", _parametros(selo, b""))[0]["n"])


# ------------------------------------------------------------------ conferir e provar

def conferir(leitor, cliente, selo, segredo, guardados):
    """Compara os blocos de hoje com os guardados no selo. Devolve (achados, eventos conferidos)."""
    from .selo import raiz_de_merkle

    banco = armazem_de_eventos.banco_do(cliente)
    achados = []
    if raiz_de_merkle(folhas_superiores(guardados)).hex() != selo["raiz"] or len(guardados) != selo["folhas_superiores"] \
            or sum(t for _, t, _ in guardados) != selo["total"]:
        achados.append({"tipo": "folhas_alteradas", "n": selo["n"]})
    hoje = {b: (t, r) for b, t, r in calcular_blocos(leitor, banco, selo["fonte"], selo, segredo)}
    selados = {b: (t, r) for b, t, r in guardados}
    for bloco in sorted(set(hoje) | set(selados)):
        antes, agora = selados.get(bloco), hoje.get(bloco)
        if antes != agora:
            achados.append({"tipo": "bloco_alterado", "n": selo["n"], "bloco": bloco,
                            "eventos_selados": antes[0] if antes else 0, "eventos_hoje": agora[0] if agora else 0})
    return achados, sum(t for _, t, _ in guardados)


def provar(leitor, banco, selo, segredo, guardados, identificador):
    """A prova de um evento do selo, ou None se o evento não é deste selo. Recusa (ValueError) o evento cujo bloco mudou.
    O banco é o da organização da sessão (quem chama), nunca o do pedido."""
    from .selo import caminho_de_merkle

    p = {**_parametros(selo, segredo), "blocos": selo["blocos"], "i": identificador}
    # Pela tabela de leitura: o evento pode estar num dia trazido de volta da cópia fria.
    proprio = leitor.linhas(f"""SELECT hex({SAL}) AS s, {BRUTO} AS bruto FROM {banco}.{selo['fonte']}_leitura
                                WHERE {_filtro(selo)} AND id = toUUID({{i:String}}) LIMIT 1""", p)
    if not proprio:
        return None
    sal_da_folha = bytes.fromhex(proprio[0]["s"])
    bloco = bloco_do_sal(sal_da_folha, selo["blocos"])
    folhas = sorted(bytes.fromhex(l["f"]) for l in leitor.linhas(f"""
        SELECT hex(SHA256(concat(char(2), {SAL}, toString(id), '\\n', {BRUTO}))) AS f FROM {banco}.{selo['fonte']}_leitura
        WHERE {_filtro(selo)} AND reinterpretAsUInt64(reverse(substring({SAL}, 1, 8))) % {{blocos:UInt64}} = {{bloco:UInt64}}""", {**p, "bloco": bloco}))
    blocos = sorted(guardados)
    posicao = next((k for k, (b, _, _) in enumerate(blocos) if b == bloco), None)
    if posicao is None or (blocos[posicao][1], blocos[posicao][2]) != (len(folhas), resumo_do_bloco(folhas)) \
            or folha(sal_da_folha, identificador, proprio[0]["bruto"].encode()) not in folhas:
        raise ValueError(f"O bloco do evento {identificador} não confere com o selo: algo mudou nele depois da selagem.")
    return {"id": identificador, "versao": VERSAO, "selo": selo["n"], "bruto": proprio[0]["bruto"], "documento": documento_do_bruto(proprio[0]["bruto"]), "sal": sal_da_folha.hex(), "bloco": bloco,
            "folhas_do_bloco": [f.hex() for f in folhas], "indice": posicao, "caminho": caminho_de_merkle(folhas_superiores(blocos), posicao)}


def documento_do_bruto(bruto):
    """Para ler no laudo: o JSON do log; o grande demais ficou só com o começo e o resumo do original."""
    try:
        documento = json.loads(bruto)
        if isinstance(documento, dict):
            return documento
    except ValueError:
        pass
    return {"full_log": bruto}


def corte(agora=None):
    """A hora de chegada até onde o selo cobre: alguns segundos atrás, para não pegar gravação em andamento."""
    agora = agora or datetime.now(timezone.utc)
    return (agora - timedelta(seconds=5)).astimezone(timezone.utc).replace(microsecond=0).isoformat(timespec="seconds")
