"""Selos de integridade dos eventos.

    python -m roar_ingestao.selo [--uma-vez] [--verificar]

A cada janela, os eventos viram uma árvore de Merkle (RFC 9162) com sal por folha, e a raiz entra numa
cadeia assinada. Os selos ficam no banco e os eventos no indexador: mexer em um sem o outro aparece.

O que isto prova: o evento não mudou desde a selagem, e a selagem não foi reescrita. O que não prova:
que o conteúdo do log é verdadeiro. Um log forjado antes de chegar aqui é selado como qualquer outro.
"""

import argparse
import gzip
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from . import rede_externa

log = logging.getLogger("roar.selo")

FONTES = {"alertas": "wazuh-alerts-4.x-", "logs": "wazuh-archives-4.x-"}
JANELA = timedelta(minutes=15)
# O indexador recebe com atraso: selar antes disso mandaria evento bom para a lista dos tardios.
MARGEM = timedelta(minutes=10)
# Evento que chega até aqui depois de selada a janela entra num selo marcado como tardio.
HORIZONTE_DOS_TARDIOS = timedelta(hours=24)
JANELAS_POR_CICLO = 96
TAMANHO_DA_PAGINA = 1000
PASTA_DA_CHAVE = Path(os.getenv("ROAR_SELO_PASTA", "/opt/panthera-roar/selo"))
GENESE = "0" * 64
VERSAO = 1
SEGUNDOS_ENTRE_COMPLETAS = 7 * 86400
SEGUNDOS_ENTRE_RECENTES = 6 * 3600


# ------------------------------------------------------------------ o que qualquer um pode conferir

def canonico(valor):
    return json.dumps(valor, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def resumo(dados):
    return hashlib.sha256(dados).digest()


def sal_da_folha(segredo, identificador):
    return hmac.new(segredo, identificador.encode(), hashlib.sha256).digest()


def hash_da_folha(sal, identificador, documento):
    return resumo(b"\x00" + sal + identificador.encode() + b"\n" + canonico(documento))


def _no(esquerda, direita):
    return resumo(b"\x01" + esquerda + direita)


def raiz_de_merkle(folhas):
    if not folhas:
        return resumo(b"")
    nivel = list(folhas)
    while len(nivel) > 1:
        # Subir aos pares e deixar a sobra para o nível seguinte dá a mesma árvore da RFC 9162.
        nivel = [_no(nivel[i], nivel[i + 1]) if i + 1 < len(nivel) else nivel[i] for i in range(0, len(nivel), 2)]
    return nivel[0]


def caminho_de_merkle(folhas, indice):
    """Os irmãos da folha, de baixo para cima: bastam para refazer a raiz sem ver os outros eventos."""
    caminho, nivel, i = [], list(folhas), indice
    while len(nivel) > 1:
        irmao = i ^ 1
        if irmao < len(nivel):
            caminho.append(nivel[irmao].hex())
        nivel = [_no(nivel[j], nivel[j + 1]) if j + 1 < len(nivel) else nivel[j] for j in range(0, len(nivel), 2)]
        i //= 2
    return caminho


def raiz_pelo_caminho(folha, indice, total, caminho):
    """RFC 9162, 2.1.3.2. None se o caminho não fecha exatamente com o total de folhas."""
    if not 0 <= indice < total:
        return None
    fn, sn, atual = indice, total - 1, folha
    for irmao in caminho:
        if sn == 0:
            return None
        irmao = bytes.fromhex(irmao)
        if fn & 1 or fn == sn:
            atual = _no(irmao, atual)
            if not fn & 1:
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            atual = _no(atual, irmao)
        fn >>= 1
        sn >>= 1
    return atual if sn == 0 else None


def cabecalho_do_selo(selo):
    return {
        "versao": VERSAO, "gerenciador": selo["gerenciador"], "cliente": str(selo["cliente"]), "n": selo["n"], "fonte": selo["fonte"],
        "inicio": selo["inicio"], "fim": selo["fim"], "total": selo["total"], "tardio": selo["tardio"],
        "raiz": selo["raiz"], "anterior": selo["anterior"], "chave": selo["chave"], "selado_em": selo["selado_em"],
    }


def hash_do_selo(selo):
    return hashlib.sha256(canonico(cabecalho_do_selo(selo))).hexdigest()


def assinatura_confere(publica, selo):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(publica)).verify(bytes.fromhex(selo["assinatura"]), bytes.fromhex(selo["hash"]))
        return True
    except (InvalidSignature, ValueError):
        return False


# ------------------------------------------------------------------ chave

def impressao_da_chave(publica):
    return hashlib.sha256(bytes.fromhex(publica)).hexdigest()


def carregar_chave(pasta=None):
    """Fora do banco, de propósito: quem tem só o banco não consegue selar. Cria na primeira vez."""
    pasta = Path(pasta or PASTA_DA_CHAVE)
    privada, publica = pasta / "privada", pasta / "publica"
    if not privada.exists():
        pasta.mkdir(parents=True, exist_ok=True, mode=0o700)
        nova = Ed25519PrivateKey.generate()
        descritor = os.open(privada, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descritor, "wb") as f:
            f.write(nova.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        publica.write_text(nova.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    return Ed25519PrivateKey.from_private_bytes(privada.read_bytes()), publica.read_text().strip()


def ler_chave_publica(pasta=None):
    return (Path(pasta or PASTA_DA_CHAVE) / "publica").read_text().strip()


# ------------------------------------------------------------------ folhas guardadas

def empacotar_folhas(pares):
    return gzip.compress("".join(f"{i}\t{h.hex()}\n" for i, h in pares).encode(), compresslevel=6, mtime=0)


def desempacotar_folhas(dados):
    pares = []
    for linha in gzip.decompress(bytes(dados)).decode().splitlines():
        identificador, h = linha.rsplit("\t", 1)
        pares.append((identificador, bytes.fromhex(h)))
    return pares


def folhas_em_ordem(segredo, documentos):
    """Ordem pelo identificador: a árvore não depende da ordem em que o indexador devolveu."""
    return [(i, hash_da_folha(sal_da_folha(segredo, i), i, d)) for i, d in sorted(documentos, key=lambda x: x[0])]


# ------------------------------------------------------------------ indexador

def _iso(momento):
    return momento.astimezone(timezone.utc).isoformat(timespec="seconds")


def _piso(momento):
    momento = momento.astimezone(timezone.utc)
    return momento.replace(minute=momento.minute - momento.minute % 15, second=0, microsecond=0)


def _padrao(fonte, gerenciador):
    return f"{FONTES[fonte]}{gerenciador}-*"


def _procurar(indexer, fonte, gerenciador, corpo):
    r = indexer.sessao.post(f"{indexer.url}/{_padrao(fonte, gerenciador)}/_search?allow_no_indices=true&ignore_unavailable=true", json=corpo, timeout=120)
    r.raise_for_status()
    return r.json()


def _faixa(inicio, fim):
    return {"range": {"timestamp": {"gte": _iso(inicio), "lt": _iso(fim)}}}


def documentos_da_janela(indexer, fonte, gerenciador, inicio, fim):
    corpo = {"size": TAMANHO_DA_PAGINA, "sort": [{"_id": "asc"}], "query": _faixa(inicio, fim)}
    documentos = []
    while True:
        achados = _procurar(indexer, fonte, gerenciador, corpo)["hits"]["hits"]
        documentos.extend((d["_id"], d["_source"]) for d in achados)
        if len(achados) < TAMANHO_DA_PAGINA:
            return documentos
        corpo["search_after"] = achados[-1]["sort"]


def _primeiro_evento(indexer, fonte, gerenciador, depois_de=None):
    corpo = {"size": 0, "aggs": {"menor": {"min": {"field": "timestamp"}}}}
    if depois_de:
        corpo["query"] = {"range": {"timestamp": {"gte": _iso(depois_de)}}}
    valor = _procurar(indexer, fonte, gerenciador, corpo).get("aggregations", {}).get("menor", {}).get("value")
    return datetime.fromtimestamp(valor / 1000, timezone.utc) if valor is not None else None


# ------------------------------------------------------------------ selar

def _com_cliente(banco, cliente):
    banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))


def _ponta_da_cadeia(banco, gerenciador):
    linha = banco.con.execute("SELECT n, hash FROM selos WHERE gerenciador_id = %s ORDER BY n DESC LIMIT 1", (gerenciador,)).fetchone()
    return (linha[0], linha[1]) if linha else (0, GENESE)


def gravar_selo(banco, chave, publica, gerenciador, cliente, fonte, inicio, fim, documentos, tardio=False):
    segredo = secrets.token_bytes(32)
    pares = folhas_em_ordem(segredo, documentos)
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        n, anterior = _ponta_da_cadeia(banco, gerenciador)
        selo = {
            "gerenciador": gerenciador, "cliente": str(cliente), "n": n + 1, "fonte": fonte, "inicio": _iso(inicio), "fim": _iso(fim), "total": len(pares), "tardio": tardio,
            "raiz": raiz_de_merkle([h for _, h in pares]).hex(), "anterior": anterior, "chave": impressao_da_chave(publica), "selado_em": _iso(datetime.now(timezone.utc)),
        }
        selo["hash"] = hash_do_selo(selo)
        selo["assinatura"] = chave.sign(bytes.fromhex(selo["hash"])).hex()
        banco.con.execute(
            "INSERT INTO selos (gerenciador_id, n, cliente_id, fonte, inicio, fim, total, tardio, raiz, anterior, hash, assinatura, chave, selado_em) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (gerenciador, selo["n"], cliente, fonte, selo["inicio"], selo["fim"], selo["total"], tardio, selo["raiz"], anterior, selo["hash"], selo["assinatura"], selo["chave"], selo["selado_em"]))
        banco.con.execute("INSERT INTO selo_folhas (gerenciador_id, n, cliente_id, segredo, folhas) VALUES (%s, %s, %s, %s, %s)",
                          (gerenciador, selo["n"], cliente, segredo, empacotar_folhas(pares)))
    return selo


def selar_novas_janelas(indexer, banco, chave, publica, gerenciador, cliente, fonte, agora=None, limite=JANELAS_POR_CICLO):
    """Janela vazia também é selada: é isso que mostra um buraco apagado depois."""
    agora = agora or datetime.now(timezone.utc)
    teto = _piso(agora - MARGEM)
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        ultimo = banco.con.execute("SELECT max(fim) FROM selos WHERE gerenciador_id = %s AND fonte = %s", (gerenciador, fonte)).fetchone()[0]
    inicio = ultimo
    if inicio is None:
        primeiro = _primeiro_evento(indexer, fonte, gerenciador)
        if primeiro is None:
            return 0
        inicio = _piso(primeiro)
    selados = 0
    while inicio < teto and selados < limite:
        fim = inicio + JANELA
        documentos = documentos_da_janela(indexer, fonte, gerenciador, inicio, fim)
        if not documentos:
            # Um trecho longo sem nada vira um selo só, para a cadeia não crescer à toa.
            proximo = _primeiro_evento(indexer, fonte, gerenciador, fim)
            fim = min(_piso(proximo), teto) if proximo else teto
            fim = max(fim, inicio + JANELA)
        gravar_selo(banco, chave, publica, gerenciador, cliente, fonte, inicio, fim, documentos)
        selados += 1
        inicio = fim
    return selados


def _selos_das_janelas(banco, gerenciador, fonte, inicio, fim):
    return banco.con.execute("SELECT s.n, s.inicio, s.fim, s.total, f.folhas FROM selos s JOIN selo_folhas f USING (gerenciador_id, n) "
                             "WHERE s.gerenciador_id = %s AND s.fonte = %s AND s.fim > %s AND s.inicio < %s ORDER BY s.n",
                             (gerenciador, fonte, inicio, fim)).fetchall()


def selar_tardios(indexer, banco, chave, publica, gerenciador, cliente, fonte, agora=None):
    """Quem chegou depois da selagem entra marcado: ajuda a explicar atraso, e não esconde uma inclusão posterior."""
    agora = agora or datetime.now(timezone.utc)
    corpo = {"size": 0, "query": {"range": {"timestamp": {"gte": _iso(agora - HORIZONTE_DOS_TARDIOS), "lt": _iso(_piso(agora - MARGEM))}}},
             "aggs": {"janelas": {"date_histogram": {"field": "timestamp", "fixed_interval": "15m", "min_doc_count": 1}}}}
    baldes = _procurar(indexer, fonte, gerenciador, corpo).get("aggregations", {}).get("janelas", {}).get("buckets", [])
    selados = 0
    for balde in baldes:
        inicio = datetime.fromtimestamp(balde["key"] / 1000, timezone.utc)
        fim = inicio + JANELA
        with banco.con.transaction():
            _com_cliente(banco, cliente)
            selos = _selos_das_janelas(banco, gerenciador, fonte, inicio, fim)
        if not selos:
            continue
        conhecidos = {i for s in selos for i, _ in desempacotar_folhas(s[4])}
        if balde["doc_count"] <= len(conhecidos):
            continue
        novos = [(i, d) for i, d in documentos_da_janela(indexer, fonte, gerenciador, inicio, fim) if i not in conhecidos]
        if novos:
            gravar_selo(banco, chave, publica, gerenciador, cliente, fonte, inicio, fim, novos, tardio=True)
            selados += 1
    return selados


# ------------------------------------------------------------------ verificar

def _selo_da_linha(linha):
    return {
        "gerenciador": linha[0], "n": linha[1], "cliente": str(linha[2]), "fonte": linha[3], "inicio": _iso(linha[4]), "fim": _iso(linha[5]), "total": linha[6], "tardio": linha[7],
        "raiz": linha[8], "anterior": linha[9], "hash": linha[10], "assinatura": linha[11], "chave": linha[12], "selado_em": _iso(linha[13]),
    }


COLUNAS = "gerenciador_id, n, cliente_id, fonte, inicio, fim, total, tardio, raiz, anterior, hash, assinatura, chave, selado_em"


def conferir_cadeia(selos, publica):
    """Olha só os selos, sem o indexador. Devolve os achados."""
    achados = []
    impressao = impressao_da_chave(publica)
    anterior, numero = GENESE, 0
    for selo in selos:
        if selo["n"] != numero + 1:
            achados.append({"tipo": "selo_faltando", "n": numero + 1})
        if selo["anterior"] != anterior:
            achados.append({"tipo": "cadeia_quebrada", "n": selo["n"]})
        if hash_do_selo(selo) != selo["hash"]:
            achados.append({"tipo": "selo_alterado", "n": selo["n"]})
        elif selo["chave"] != impressao:
            achados.append({"tipo": "chave_desconhecida", "n": selo["n"]})
        elif not assinatura_confere(publica, selo):
            achados.append({"tipo": "assinatura_invalida", "n": selo["n"]})
        anterior, numero = selo["hash"], selo["n"]
    return achados


def _grupos_que_se_tocam(selos):
    """Um selo tardio ocupa a janela do original. Quem se sobrepõe é conferido junto, para um não acusar o evento do outro."""
    grupos = []
    for selo in sorted(selos, key=lambda s: (s["fonte"], s["inicio"], s["n"])):
        if grupos and grupos[-1][0]["fonte"] == selo["fonte"] and selo["inicio"] < max(s["fim"] for s in grupos[-1]):
            grupos[-1].append(selo)
        else:
            grupos.append([selo])
    return grupos


def conferir_grupo(indexer, gerenciador, grupo, guardados):
    """Compara o que está hoje no indexador com o que foi selado, e aponta evento por evento."""
    inicio = min(datetime.fromisoformat(s["inicio"]) for s in grupo)
    fim = max(datetime.fromisoformat(s["fim"]) for s in grupo)
    atuais = dict(documentos_da_janela(indexer, grupo[0]["fonte"], gerenciador, inicio, fim))
    achados, conhecidos = [], set()
    for selo in grupo:
        if selo["n"] not in guardados:
            achados.append({"tipo": "folhas_faltando", "n": selo["n"]})
            continue
        segredo, pares = guardados[selo["n"]]
        if raiz_de_merkle([h for _, h in pares]).hex() != selo["raiz"] or len(pares) != selo["total"]:
            achados.append({"tipo": "folhas_alteradas", "n": selo["n"]})
        for identificador, guardado in pares:
            conhecidos.add(identificador)
            if identificador not in atuais:
                achados.append({"tipo": "evento_apagado", "n": selo["n"], "evento": identificador})
            elif hash_da_folha(sal_da_folha(segredo, identificador), identificador, atuais[identificador]) != guardado:
                achados.append({"tipo": "evento_alterado", "n": selo["n"], "evento": identificador})
    achados.extend({"tipo": "evento_sem_selo", "n": grupo[0]["n"], "evento": i} for i in atuais.keys() - conhecidos)
    return achados, len(conhecidos)


def verificar(indexer, banco, publica, gerenciador, cliente, retencao_dias=90, somente_recentes=None, agora=None):
    """Sem somente_recentes confere tudo. A retenção apaga evento antigo de propósito: ali só a cadeia vale."""
    agora = agora or datetime.now(timezone.utc)
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        selos = [_selo_da_linha(l) for l in banco.con.execute(f"SELECT {COLUNAS} FROM selos WHERE gerenciador_id = %s ORDER BY n", (gerenciador,)).fetchall()]
    achados = conferir_cadeia(selos, publica)
    desde = agora - timedelta(days=retencao_dias - 1)
    if somente_recentes:
        desde = max(desde, agora - somente_recentes)
    eventos = 0
    for grupo in _grupos_que_se_tocam([s for s in selos if datetime.fromisoformat(s["fim"]) > desde]):
        # Um grupo por vez: guardar as folhas de três meses juntas não cabe na memória.
        with banco.con.transaction():
            _com_cliente(banco, cliente)
            guardados = {l[0]: (bytes(l[1]), desempacotar_folhas(l[2])) for l in banco.con.execute(
                "SELECT n, segredo, folhas FROM selo_folhas WHERE gerenciador_id = %s AND n = ANY(%s)", (gerenciador, [s["n"] for s in grupo])).fetchall()}
        novos, quantos = conferir_grupo(indexer, gerenciador, grupo, guardados)
        achados.extend(novos)
        eventos += quantos
    estado = "violada" if achados else "integra"
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        banco.con.execute("INSERT INTO selo_verificacoes (cliente_id, gerenciador_id, completa, selos_conferidos, eventos_conferidos, estado, achados) "
                          "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                          (cliente, gerenciador, somente_recentes is None, len(selos), eventos, estado, json.dumps(achados[:500])))
    return estado, achados, eventos


# ------------------------------------------------------------------ âncora pública

MAGICA_OTS = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
CALENDARIOS = ("https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org")
MAIOR_RECIBO = 10_000
HORAS_ENTRE_ANCORAS = 24


def arquivo_ots(hash_hex, recibo):
    """O formato aberto dos carimbos: qualquer pessoa confere com a ferramenta pública, sem depender do Roar."""
    return MAGICA_OTS + b"\x01\x08" + bytes.fromhex(hash_hex) + bytes(recibo)


def ancorar(banco, gerenciador, cliente, enviar, agora=None):
    """Registra a ponta da cadeia fora do nosso controle: depois disso, nem quem tem a chave reescreve o passado sem aparecer.

    Só o resumo sai daqui. Falha de rede não atrapalha a selagem: tenta de novo no próximo ciclo.
    """
    agora = agora or datetime.now(timezone.utc)
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        n, hash_atual = _ponta_da_cadeia(banco, gerenciador)
        ultima = banco.con.execute("SELECT max(criada_em) FROM selo_ancoras WHERE gerenciador_id = %s", (gerenciador,)).fetchone()[0]
    if not n or (ultima and agora - ultima < timedelta(hours=HORAS_ENTRE_ANCORAS)):
        return 0
    feitas = 0
    for calendario in CALENDARIOS:
        try:
            recibo = enviar(calendario, bytes.fromhex(hash_atual))
        except Exception as erro:
            log.warning("âncora em %s falhou: %s", calendario, type(erro).__name__)
            continue
        with banco.con.transaction():
            _com_cliente(banco, cliente)
            banco.con.execute("INSERT INTO selo_ancoras (gerenciador_id, n, cliente_id, hash, calendario, recibo) VALUES (%s, %s, %s, %s, %s, %s)",
                              (gerenciador, n, cliente, hash_atual, calendario, recibo))
        feitas += 1
    return feitas


def enviar_ao_calendario(calendario, resumo_da_ponta):
    resposta, corpo = rede_externa.chamar("POST", f"{calendario}/digest", cabecalhos={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "panthera-roar"},
                                          limite_de_bytes=MAIOR_RECIBO, data=resumo_da_ponta)
    if resposta.status_code != 200 or not corpo:
        raise ValueError("recibo fora do esperado")
    return corpo


# ------------------------------------------------------------------ serviço

def rodar_ciclo(indexer, banco, chave, publica, com_ancora=False):
    total = 0
    for gerenciador, cliente in banco.gerenciadores():
        for fonte in FONTES:
            try:
                total += selar_novas_janelas(indexer, banco, chave, publica, gerenciador, cliente, fonte)
                total += selar_tardios(indexer, banco, chave, publica, gerenciador, cliente, fonte)
            except Exception:
                # Fica sem selar e tenta de novo: uma janela nunca é pulada, porque o ponto de partida vem do banco.
                log.exception("selagem de %s de %s falhou", fonte, gerenciador)
        if com_ancora:
            ancorar(banco, gerenciador, cliente, enviar_ao_calendario)
    return total


def verificar_todos(indexer, banco, publica, retencao_dias, somente_recentes=None):
    for gerenciador, cliente in banco.gerenciadores():
        try:
            estado, achados, eventos = verificar(indexer, banco, publica, gerenciador, cliente, retencao_dias, somente_recentes)
            log.log(logging.ERROR if achados else logging.INFO, "verificação de %s: %s, %d eventos, %d achados", gerenciador, estado, eventos, len(achados))
        except Exception:
            log.exception("verificação de %s falhou", gerenciador)


def main():
    from .ciclo import conexoes

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--uma-vez", action="store_true")
    args.add_argument("--verificar", action="store_true")
    a = args.parse_args()
    indexer, banco, env = conexoes()
    chave, publica = carregar_chave()
    retencao = int(env.get("RETENCAO_DIAS", 90))
    # Só o resumo da cadeia sai daqui, mas quem roda sem internet ou prefere não sair desliga.
    com_ancora = env.get("ROAR_SELO_ANCORA", "1") == "1"
    if a.verificar:
        verificar_todos(indexer, banco, publica, retencao)
        return
    if a.uma_vez:
        print(rodar_ciclo(indexer, banco, chave, publica, com_ancora))
        return
    proxima_recente = proxima_completa = 0.0
    while True:
        rodar_ciclo(indexer, banco, chave, publica, com_ancora)
        # Conferir tudo relê todos os eventos: pesa, então é semanal. O último dia é conferido com folga mais vezes.
        if time.monotonic() >= proxima_completa:
            verificar_todos(indexer, banco, publica, retencao)
            proxima_completa = time.monotonic() + SEGUNDOS_ENTRE_COMPLETAS
            proxima_recente = time.monotonic() + SEGUNDOS_ENTRE_RECENTES
        elif time.monotonic() >= proxima_recente:
            verificar_todos(indexer, banco, publica, retencao, somente_recentes=timedelta(hours=24))
            proxima_recente = time.monotonic() + SEGUNDOS_ENTRE_RECENTES
        time.sleep(60)


if __name__ == "__main__":
    main()
