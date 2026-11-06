"""Pacote de evidência: os eventos escolhidos, a prova de cada um e nada sobre os vizinhos.

Os irmãos no caminho de Merkle têm sal, então não dá para adivinhar o conteúdo de um evento que não foi
entregue. É a divulgação seletiva: entrega o que importa ao caso, sem expor o resto do log.
"""

import bisect
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from roar_ingestao import armazem as armazem_de_eventos
from roar_ingestao import selo as selagem
from roar_ingestao import verificador_de_evidencia as verificador

MODELOS = Path(__file__).parent / "modelos"
LIMITE_DE_EVENTOS = 200
# Um período inteiro para perícia: acima disso, o pedido tem de ser refinado.
LIMITE_DO_PERIODO = 10000
# Até aqui o laudo traz cada evento por extenso; acima, só a lista, e o conteúdo fica no arquivo de dados.
EVENTOS_POR_EXTENSO = 200
LOTE_DE_BUSCA = 1000
# Id de evento do armazém de eventos (docs/clickhouse.md); o do indexador tem outro formato.
ID_DO_ARMAZEM = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class EvidenciaRecusada(Exception):
    """A mensagem aparece na tela."""


def _momento(documento):
    texto = str(documento.get("timestamp", ""))
    # O indexador escreve +0000, e o fromisoformat antigo não aceita.
    return datetime.fromisoformat(texto[:-2] + ":" + texto[-2:] if texto[-5] in "+-" and ":" not in texto[-5:] else texto)


class _Janelas:
    """As folhas de cada selo, lidas uma vez só: num período, milhares de eventos caem nos mesmos selos."""

    def __init__(self, con, gerenciador, fonte, de, ate):
        self.con = con
        linhas = con.execute("SELECT n, inicio, fim FROM selos WHERE gerenciador_id = %s AND fonte = %s AND inicio <= %s AND fim > %s ORDER BY fim, n",
                             (gerenciador, fonte, ate, de)).fetchall()
        self.gerenciador, self.janelas = gerenciador, [(l["fim"], l["inicio"], l["n"]) for l in linhas]
        self.fins = [j[0] for j in self.janelas]
        self.folhas = {}

    def que_cobrem(self, momento):
        # Janelas tardias podem se sobrepor às normais: todas as que cobrem o momento são candidatas.
        return [n for fim, inicio, n in self.janelas[bisect.bisect_right(self.fins, momento):] if inicio <= momento]

    def da_janela(self, n):
        if n not in self.folhas:
            linha = self.con.execute("SELECT segredo, folhas FROM selo_folhas WHERE gerenciador_id = %s AND n = %s", (self.gerenciador, n)).fetchone()
            pares = selagem.desempacotar_folhas(linha["folhas"])
            self.folhas[n] = (bytes(linha["segredo"]), pares, {i: k for k, (i, _) in enumerate(pares)})
        return self.folhas[n]


def montar_prova(identificador, documento, selo, segredo, pares, posicoes=None):
    if posicoes is None:
        posicoes = {i: k for k, (i, _) in enumerate(pares)}
    indice = posicoes.get(identificador)
    if indice is None:
        return None
    sal = selagem.sal_da_folha(segredo, identificador)
    if selagem.hash_da_folha(sal, identificador, documento) != pares[indice][1]:
        raise EvidenciaRecusada(f"O evento {identificador} não confere com o selo: foi alterado depois da selagem. Veja a verificação em Integridade.")
    return {"id": identificador, "documento": documento, "selo": selo, "indice": indice, "sal": sal.hex(), "caminho": selagem.caminho_de_merkle([h for _, h in pares], indice)}


def _buscar_documentos(indexer, url, gerenciadores, fonte, ids, armazem=None, banco=None):
    """{id: (gerenciador, documento, momento)}. Cada evento vem de onde foi selado: id do armazém, do armazém (o log como o
    gerenciador gravou); os outros, do indexador."""
    achados = {}
    do_armazem = [i for i in ids if armazem is not None and ID_DO_ARMAZEM.fullmatch(i)]
    for inicio in range(0, len(do_armazem), LOTE_DE_BUSCA):
        lote = do_armazem[inicio:inicio + LOTE_DE_BUSCA]
        for linha in armazem.linhas(f"""SELECT toString(id) AS i, gerenciador, dados, full_log, resumo_do_original, toUnixTimestamp64Milli(ocorrido_em) AS ms
                                        FROM {banco}.{fonte} WHERE id IN (SELECT toUUID(arrayJoin(splitByChar(',', {{ids:String}}))))""", {"ids": ",".join(lote)}):
            # O banco é o da organização da sessão; o gerenciador ainda tem de ser um dos dela.
            if linha["gerenciador"] in gerenciadores:
                achados[linha["i"]] = (linha["gerenciador"], armazem_de_eventos.documento_original(linha),
                                       datetime.fromtimestamp(int(linha["ms"]) / 1000, timezone.utc))
    restantes = [i for i in ids if i not in achados and not (armazem is not None and ID_DO_ARMAZEM.fullmatch(i))]
    achados.update(_buscar_no_indexador(indexer, url, gerenciadores, fonte, restantes))
    return achados


def _buscar_no_indexador(indexer, url, gerenciadores, fonte, ids):
    indices = ",".join(f"{selagem.FONTES[fonte]}{g}-*" for g in gerenciadores)
    achados = {}
    for inicio in range(0, len(ids), LOTE_DE_BUSCA):
        lote = ids[inicio:inicio + LOTE_DE_BUSCA]
        r = indexer.post(f"{url}/{indices}/_search?allow_no_indices=true&ignore_unavailable=true",
                         json={"size": len(lote), "query": {"ids": {"values": lote}}}, timeout=60)
        r.raise_for_status()
        for h in r.json()["hits"]["hits"]:
            gerenciador = next(g for g in gerenciadores if f"-{g}-" in h["_index"])
            achados[h["_id"]] = (gerenciador, h["_source"], _momento(h["_source"]))
    return achados


def montar_pacotes(con, indexer, url, gerenciadores, fonte, ids, publica, armazem=None, banco=None):
    """Um pacote por gerenciador, porque cada um tem a própria cadeia. Roda sob o RLS da sessão: selo e folhas de outro cliente nem aparecem aqui."""
    achados = _buscar_documentos(indexer, url, gerenciadores, fonte, ids, armazem, banco)
    faltando = [i for i in ids if i not in achados]
    if faltando:
        raise EvidenciaRecusada(f"Evento não encontrado: {faltando[0]}.")
    por_gerenciador = {}
    for identificador in ids:
        por_gerenciador.setdefault(achados[identificador][0], []).append(identificador)
    return [_montar_um(con, gerenciador, fonte, lista, achados, publica) for gerenciador, lista in por_gerenciador.items()]


def montar_pacote(con, indexer, url, gerenciadores, fonte, ids, publica, armazem=None, banco=None):
    pacotes = montar_pacotes(con, indexer, url, gerenciadores, fonte, ids, publica, armazem, banco)
    if len(pacotes) > 1:
        raise EvidenciaRecusada("Gere um pacote por gerenciador.")
    return pacotes[0][1], pacotes[0][2]


def _montar_um(con, gerenciador, fonte, ids, achados, publica):
    momentos = {i: achados[i][2] for i in ids}
    janelas = _Janelas(con, gerenciador, fonte, min(momentos.values()), max(momentos.values()))
    eventos = []
    for identificador in ids:
        documento = achados[identificador][1]
        prova = None
        for n in janelas.que_cobrem(momentos[identificador]):
            segredo, pares, posicoes = janelas.da_janela(n)
            prova = montar_prova(identificador, documento, n, segredo, pares, posicoes)
            if prova:
                break
        if not prova:
            raise EvidenciaRecusada(f"O evento {identificador} ainda não foi selado. Os eventos são selados em até 30 minutos.")
        eventos.append(prova)
    numeros = [e["selo"] for e in eventos]
    # Até a primeira âncora depois do último evento, ou até a ponta: é o trecho que mostra que nada foi reescrito.
    ancora = con.execute("SELECT min(n) AS n FROM selo_ancoras WHERE gerenciador_id = %s AND n >= %s", (gerenciador, max(numeros))).fetchone()["n"]
    teto = ancora if ancora is not None else con.execute("SELECT max(n) AS n FROM selos WHERE gerenciador_id = %s", (gerenciador,)).fetchone()["n"]
    linhas = con.execute(f"SELECT {selagem.COLUNAS} FROM selos WHERE gerenciador_id = %s AND n BETWEEN %s AND %s ORDER BY n", (gerenciador, min(numeros), teto))
    selos = []
    for linha in linhas.fetchall():
        selo = selagem._selo_da_linha(tuple(linha[c.strip()] for c in selagem.COLUNAS.split(",")))
        selos.append({**selagem.cabecalho_do_selo(selo), "hash": selo["hash"], "assinatura": selo["assinatura"]})
    ancoras = con.execute("SELECT n, hash, calendario, recibo FROM selo_ancoras WHERE gerenciador_id = %s AND n = %s ORDER BY calendario", (gerenciador, teto)).fetchall()
    return gerenciador, {
        "formato": "panthera-roar-evidencia-1", "chave_publica": publica, "fonte": fonte, "eventos": eventos, "selos": selos,
        "ancoras": [{"n": a["n"], "hash": a["hash"], "calendario": a["calendario"], "arquivo": f"ancoras/selo-{a['n']}-{i}.ots"} for i, a in enumerate(ancoras)],
    }, ancoras


def _laudo(pacote, sessao, agora, descricao=None):
    ambiente = Environment(loader=FileSystemLoader(MODELOS), autoescape=select_autoescape(["html"]))
    selos = {s["n"]: s for s in pacote["selos"]}
    por_extenso = len(pacote["eventos"]) <= EVENTOS_POR_EXTENSO
    return ambiente.get_template("evidencia.html").render(
        cliente=sessao["cliente_nome"], autor=sessao["nome"], agora=agora.strftime("%d/%m/%Y %H:%M UTC"), pacote=pacote, selos=selos,
        impressao=selagem.impressao_da_chave(pacote["chave_publica"]), descricao=descricao, por_extenso=por_extenso,
        documentos=[(e, json.dumps(e["documento"], ensure_ascii=False, indent=2, sort_keys=True) if por_extenso else "") for e in pacote["eventos"]])


LEIA = """Pacote de evidência do Panthera Roar

evidencia.json   os eventos, a prova de cada um e os selos
laudo.pdf        o mesmo conteúdo para leitura, com a explicação do método
verificar.py     confere o pacote em qualquer computador, sem o Roar: python verificar.py evidencia.json
ancoras/         carimbos públicos da cadeia, no formato aberto OpenTimestamps, quando houver

O resultado positivo diz que estes eventos são os mesmos que foram selados, e que os selos não foram
reescritos. Não diz que o conteúdo do log é verdadeiro. O material apoia a cadeia de custódia, mas não
substitui perícia. Este pacote contém dados pessoais: compartilhe só com quem precisa.
"""


def gerar_zip(pacote, ancoras, sessao, gerar_pdf, agora=None):
    return gerar_zip_de_varios([(None, pacote, ancoras)], sessao, gerar_pdf, agora)


def gerar_zip_de_varios(pacotes, sessao, gerar_pdf, agora=None, descricao=None):
    """Com mais de um gerenciador, cada cadeia vai numa pasta, e cada pasta se confere sozinha."""
    agora = agora or datetime.now(timezone.utc)
    saida = io.BytesIO()
    with zipfile.ZipFile(saida, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("verificar.py", Path(verificador.__file__).read_text(encoding="utf-8"))
        z.writestr("LEIA-ME.txt", LEIA if len(pacotes) == 1 else LEIA + LEIA_DE_VARIOS)
        for numero, (_, pacote, ancoras) in enumerate(pacotes, 1):
            # Quem recebe vai conferir com este programa. Se não passasse aqui, o erro seria nosso, e não deve sair.
            problemas, _ = verificador.conferir(pacote)
            if problemas:
                raise EvidenciaRecusada(f"O pacote não passou na própria conferência: {problemas[0]}")
            pasta = "" if len(pacotes) == 1 else f"cadeia-{numero}/"
            z.writestr(f"{pasta}evidencia.json", json.dumps(pacote, ensure_ascii=False, indent=2))
            z.writestr(f"{pasta}laudo.pdf", gerar_pdf(_laudo(pacote, sessao, agora, descricao)))
            for dados, linha in zip(pacote["ancoras"], ancoras):
                z.writestr(f"{pasta}{dados['arquivo']}", selagem.arquivo_ots(linha["hash"], linha["recibo"]))
    return saida.getvalue()


LEIA_DE_VARIOS = """
Os eventos vieram de mais de um gerenciador, e cada um tem a própria cadeia de selos. Cada pasta cadeia-N
se confere sozinha: python verificar.py cadeia-1/evidencia.json
"""
