"""Pacote de evidência: os eventos escolhidos, a prova de cada um e nada sobre os vizinhos.

Os irmãos no caminho de Merkle têm sal, então não dá para adivinhar o conteúdo de um evento que não foi
entregue. É a divulgação seletiva: entrega o que importa ao caso, sem expor o resto do log.
"""

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from roar_ingestao import selo as selagem
from roar_ingestao import verificador_de_evidencia as verificador

MODELOS = Path(__file__).parent / "modelos"
LIMITE_DE_EVENTOS = 200


class EvidenciaRecusada(Exception):
    """A mensagem aparece na tela."""


def _momento(documento):
    texto = str(documento.get("timestamp", ""))
    # O indexador escreve +0000, e o fromisoformat antigo não aceita.
    return datetime.fromisoformat(texto[:-2] + ":" + texto[-2:] if texto[-5] in "+-" and ":" not in texto[-5:] else texto)


def montar_prova(identificador, documento, selo, segredo, pares):
    ordem = [i for i, _ in pares]
    try:
        indice = ordem.index(identificador)
    except ValueError:
        return None
    sal = selagem.sal_da_folha(segredo, identificador)
    if selagem.hash_da_folha(sal, identificador, documento) != pares[indice][1]:
        raise EvidenciaRecusada(f"O evento {identificador} não confere com o selo: foi alterado depois da selagem. Veja a verificação em Integridade.")
    return {"id": identificador, "documento": documento, "selo": selo, "indice": indice, "sal": sal.hex(), "caminho": selagem.caminho_de_merkle([h for _, h in pares], indice)}


def montar_pacote(con, indexer, url, gerenciadores, fonte, ids, publica):
    """Roda sob o RLS da sessão: selo e folhas de outro cliente nem aparecem aqui."""
    indices = ",".join(f"{selagem.FONTES[fonte]}{g}-*" for g in gerenciadores)
    r = indexer.post(f"{url}/{indices}/_search?allow_no_indices=true&ignore_unavailable=true",
                     json={"size": len(ids), "query": {"ids": {"values": ids}}}, timeout=30)
    r.raise_for_status()
    achados = {h["_id"]: h for h in r.json()["hits"]["hits"]}
    faltando = [i for i in ids if i not in achados]
    if faltando:
        raise EvidenciaRecusada(f"Evento não encontrado: {faltando[0]}.")
    eventos, por_gerenciador = [], {}
    for identificador in ids:
        documento = achados[identificador]["_source"]
        gerenciador = next(g for g in gerenciadores if f"-{g}-" in achados[identificador]["_index"])
        momento = _momento(documento)
        linhas = con.execute("SELECT s.n, f.segredo, f.folhas FROM selos s JOIN selo_folhas f USING (gerenciador_id, n) "
                             "WHERE s.gerenciador_id = %s AND s.fonte = %s AND s.inicio <= %s AND s.fim > %s ORDER BY s.n",
                             (gerenciador, fonte, momento, momento)).fetchall()
        prova = None
        for linha in linhas:
            prova = montar_prova(identificador, documento, linha["n"], bytes(linha["segredo"]), selagem.desempacotar_folhas(linha["folhas"]))
            if prova:
                break
        if not prova:
            raise EvidenciaRecusada(f"O evento {identificador} ainda não foi selado. Os eventos são selados em até 30 minutos.")
        eventos.append(prova)
        por_gerenciador.setdefault(gerenciador, []).append(prova["selo"])
    if len(por_gerenciador) > 1:
        raise EvidenciaRecusada("Gere um pacote por gerenciador.")
    gerenciador, numeros = next(iter(por_gerenciador.items()))
    # Até a primeira âncora depois do último evento, ou até a ponta: é o trecho que mostra que nada foi reescrito.
    ancora = con.execute("SELECT min(n) AS n FROM selo_ancoras WHERE gerenciador_id = %s AND n >= %s", (gerenciador, max(numeros))).fetchone()["n"]
    teto = ancora if ancora is not None else con.execute("SELECT max(n) AS n FROM selos WHERE gerenciador_id = %s", (gerenciador,)).fetchone()["n"]
    linhas = con.execute(f"SELECT {selagem.COLUNAS} FROM selos WHERE gerenciador_id = %s AND n BETWEEN %s AND %s ORDER BY n", (gerenciador, min(numeros), teto))
    selos = []
    for linha in linhas.fetchall():
        selo = selagem._selo_da_linha(tuple(linha[c.strip()] for c in selagem.COLUNAS.split(",")))
        selos.append({**selagem.cabecalho_do_selo(selo), "hash": selo["hash"], "assinatura": selo["assinatura"]})
    ancoras = con.execute("SELECT n, hash, calendario, recibo FROM selo_ancoras WHERE gerenciador_id = %s AND n = %s ORDER BY calendario", (gerenciador, teto)).fetchall()
    return {
        "formato": "panthera-roar-evidencia-1", "chave_publica": publica, "fonte": fonte, "eventos": eventos, "selos": selos,
        "ancoras": [{"n": a["n"], "hash": a["hash"], "calendario": a["calendario"], "arquivo": f"ancoras/selo-{a['n']}-{i}.ots"} for i, a in enumerate(ancoras)],
    }, ancoras


def _laudo(pacote, sessao, agora):
    ambiente = Environment(loader=FileSystemLoader(MODELOS), autoescape=select_autoescape(["html"]))
    selos = {s["n"]: s for s in pacote["selos"]}
    return ambiente.get_template("evidencia.html").render(
        cliente=sessao["cliente_nome"], autor=sessao["nome"], agora=agora.strftime("%d/%m/%Y %H:%M UTC"), pacote=pacote, selos=selos,
        impressao=selagem.impressao_da_chave(pacote["chave_publica"]),
        documentos=[(e, json.dumps(e["documento"], ensure_ascii=False, indent=2, sort_keys=True)) for e in pacote["eventos"]])


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
    # Quem recebe vai conferir com este programa. Se não passasse aqui, o erro seria nosso, e não deve sair.
    problemas, _ = verificador.conferir(pacote)
    if problemas:
        raise EvidenciaRecusada(f"O pacote não passou na própria conferência: {problemas[0]}")
    agora = agora or datetime.now(timezone.utc)
    saida = io.BytesIO()
    with zipfile.ZipFile(saida, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("evidencia.json", json.dumps(pacote, ensure_ascii=False, indent=2))
        z.writestr("verificar.py", Path(verificador.__file__).read_text(encoding="utf-8"))
        z.writestr("LEIA-ME.txt", LEIA)
        z.writestr("laudo.pdf", gerar_pdf(_laudo(pacote, sessao, agora)))
        for dados, linha in zip(pacote["ancoras"], ancoras):
            z.writestr(dados["arquivo"], selagem.arquivo_ots(linha["hash"], linha["recibo"]))
    return saida.getvalue()
