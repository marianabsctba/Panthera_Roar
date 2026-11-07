"""Leituras do armazém de eventos (ClickHouse) no mesmo formato das leituras do indexador: a tela não sabe de onde veio.

O banco consultado é sempre o da organização da sessão (armazem.banco_do), e o filtro sai do tradutor da linguagem de
consulta (consulta_sql), com os valores como parâmetros. Desenho em docs/clickhouse.md.
"""

import json
import re
from datetime import datetime, timezone

from roar_api import consulta as linguagem
from roar_api.consulta_sql import Tradutor, escapar_like

# Para a linha do tempo: o menor intervalo, em minutos, que cabe no número de barras pedido.
INTERVALOS = (1, 5, 10, 15, 30, 60, 180, 360, 720, 1440, 10080)
LIMITE_DO_TOTAL = 100000


def intervalo(minutos, barras):
    return next((i for i in INTERVALOS if minutos / i <= barras), INTERVALOS[-1])


def _iso(segundos):
    return datetime.fromtimestamp(int(segundos), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def documento(linha):
    """O log como o indexador mostrava: o JSON do Wazuh, com a localização e a operadora que o coletor achou."""
    try:
        doc = json.loads(linha["dados"]) if linha.get("dados") else {}
    except ValueError:
        doc = {}
    if not isinstance(doc, dict) or not doc:
        # Log grande demais fica só com o começo e o resumo do original.
        doc = {"timestamp": linha.get("quando"), "full_log": linha.get("full_log", ""), "resumo_do_original": linha.get("resumo_do_original", "")}
    if linha.get("pais"):
        doc["GeoLocation"] = {"country_name": linha["pais"], "city_name": linha.get("cidade") or None, "region_name": linha.get("regiao") or None}
    if linha.get("operadora"):
        doc["Operadora"] = {"organization_name": linha["operadora"], "asn": linha.get("asn") or None}
    return doc


COLUNAS_DO_DOCUMENTO = "dados, full_log, resumo_do_original, pais, cidade, regiao, operadora, asn, toString(ocorrido_em) AS quando"
# A tela de logs e o pacote de perícia leem a tabela de sempre e os dias trazidos da cópia fria (logs_leitura). O dia que
# voltou entra em qualquer período: foi pedido justamente para ser consultado, e costuma ser mais antigo que o período.
DENTRO_DO_PERIODO = "ocorrido_em >= now64(3) - INTERVAL {dias} DAY OR _table = 'logs_recuperados'"


def logs(armazem, banco, pedido, condicoes, exclusoes, dias, depois_de, tamanho, campos_de_log, primeira_pagina):
    """A mesma resposta de /api/logs. `depois_de` é o cursor [milissegundos, id] da página anterior."""
    t = Tradutor()
    filtro = t.onde({"bool": {"filter": [*condicoes, pedido.filtro], "must_not": exclusoes}})
    onde = f"({DENTRO_DO_PERIODO.format(dias=int(dias))}) AND ({filtro})"
    tabela = f"{banco}.logs_leitura"
    total = int(armazem.linhas(f"SELECT count() AS n FROM (SELECT 1 FROM {tabela} WHERE {onde} LIMIT {LIMITE_DO_TOTAL + 1})", t.parametros)[0]["n"])
    contagem, linhas, linha_do_tempo, campos = None, [], [], {}
    if pedido.contar:
        if pedido.contar_por:
            grupo = t.agrupar(pedido.contar_por)
            limite = min(pedido.limite or 20, linguagem.LIMITE_DE_GRUPOS)
            agrupados = armazem.linhas(f"""SELECT {grupo} AS valor, count() AS total FROM {tabela} WHERE {onde} AND notEmpty(toString(valor))
                                           GROUP BY valor ORDER BY total DESC LIMIT {limite}""", t.parametros)
            contagem = {"campo": pedido.contar_por, "linhas": [{"valor": l["valor"], "total": int(l["total"])} for l in agrupados]}
        else:
            contagem = {"campo": None, "linhas": []}
    else:
        pagina = onde
        if depois_de:
            pagina += f" AND (ocorrido_em, id) < (fromUnixTimestamp64Milli({t.p(int(depois_de[0]), 'Int64')}), toUUID({t.p(str(depois_de[1]))}))"
        ordem = ""
        if pedido.ordem:
            expressao, _ = t.campo(pedido.ordem[0])
            ordem = f"{expressao} {'DESC' if pedido.ordem[1] == 'desc' else 'ASC'}, "
        linhas = armazem.linhas(f"""SELECT toUnixTimestamp64Milli(ocorrido_em) AS ms, toString(id) AS id_texto, {COLUNAS_DO_DOCUMENTO}
                                    FROM {tabela} WHERE {pagina} ORDER BY {ordem}ocorrido_em DESC, id DESC LIMIT {int(tamanho)}""", t.parametros)
        if primeira_pagina:
            passo = intervalo(int(dias) * 1440, 48)
            linha_do_tempo = [{"quando": _iso(l["b"]), "total": int(l["total"])} for l in armazem.linhas(
                f"""SELECT toUnixTimestamp(toStartOfInterval(ocorrido_em, INTERVAL {passo} MINUTE)) AS b, count() AS total
                    FROM {tabela} WHERE {onde} GROUP BY b ORDER BY b""", t.parametros)]
            for nome in campos_de_log:
                expressao = t.agrupar(nome)
                campos[nome] = [{"valor": l["valor"], "total": int(l["total"])} for l in armazem.linhas(
                    f"""SELECT {expressao} AS valor, count() AS total FROM {tabela} WHERE {onde} AND notEmpty(toString(valor))
                        GROUP BY valor ORDER BY total DESC LIMIT 8""", t.parametros)]
    return {
        "logs": [{"id": l["id_texto"], "bruto": documento(l)} for l in linhas],
        "cursor": [int(linhas[-1]["ms"]), linhas[-1]["id_texto"]] if linhas else None,
        "contagem": contagem, "total": min(total, LIMITE_DO_TOTAL), "total_exato": total <= LIMITE_DO_TOTAL,
        "linha_do_tempo": linha_do_tempo, "campos": campos,
    }


def _pegar(doc, caminho):
    for parte in caminho.split("."):
        if not isinstance(doc, dict):
            return None
        doc = doc.get(parte)
    return doc


def bloco(armazem, banco, pedido, tipo, minutos, usado, tamanho, buscas):
    """O resultado de um bloco de painel (ou de uma busca agendada) no formato de buscas.ler. `usado` é o campo (ou as
    colunas da tabela) que buscas.montar escolheu: as duas leituras usam a mesma escolha."""
    t = Tradutor()
    filtro = t.onde(pedido.filtro)
    tabela = f"{banco}.logs"
    janela = f"ocorrido_em >= now64(3) - INTERVAL {int(minutos)} MINUTE"
    if tipo == "numero":
        l = armazem.linhas(f"""SELECT countIf({janela}) AS atual, count() AS total FROM {tabela}
                               WHERE ocorrido_em >= now64(3) - INTERVAL {2 * int(minutos)} MINUTE AND ({filtro})""", t.parametros)[0]
        return {"total": int(l["atual"]), "anterior": int(l["total"]) - int(l["atual"])}
    onde = f"{janela} AND ({filtro})"
    total = int(armazem.linhas(f"SELECT count() AS n FROM {tabela} WHERE {onde}", t.parametros)[0]["n"])
    if tipo == "serie":
        passo = intervalo(int(minutos), buscas.BARRAS_NA_SERIE)
        balde = f"toUnixTimestamp(toStartOfInterval(ocorrido_em, INTERVAL {passo} MINUTE))"
        pontos = {int(l["b"]): {"quando": _iso(l["b"]), "total": int(l["total"])} for l in armazem.linhas(
            f"SELECT {balde} AS b, count() AS total FROM {tabela} WHERE {onde} GROUP BY b ORDER BY b", t.parametros)}
        if usado:
            for p in pontos.values():
                p["por"] = {}
            grupo = t.agrupar(usado)
            for l in armazem.linhas(f"""SELECT {balde} AS b, toString({grupo}) AS valor, count() AS total FROM {tabela}
                                        WHERE {onde} AND notEmpty(valor) GROUP BY b, valor ORDER BY b, total DESC
                                        LIMIT {buscas.LINHAS_NA_SERIE} BY b""", t.parametros):
                pontos[int(l["b"])]["por"][l["valor"]] = int(l["total"])
        return {"total": total, "pontos": [pontos[b] for b in sorted(pontos)], "campo": usado}
    if tipo in buscas.POR_CAMPO or tipo == "mapa":
        grupo, chave = t.agrupar(usado), buscas.chave_curta(usado)
        limite = 60 if tipo == "mapa" else int(tamanho)
        agrupados = armazem.linhas(f"""SELECT toString({grupo}) AS valor, count() AS total FROM {tabela} WHERE {onde} AND notEmpty(valor)
                                       GROUP BY valor ORDER BY total DESC LIMIT {limite}""", t.parametros)
        com_campo = int(armazem.linhas(f"SELECT count() AS n FROM {tabela} WHERE {onde} AND notEmpty(toString({grupo}))", t.parametros)[0]["n"])
        linhas = [{chave: l["valor"], "total": int(l["total"])} for l in agrupados]
        # Outros são os valores que existem e ficaram de fora, como no índice antigo: log sem o campo não entra.
        return {"total": total, "campo": usado, "chave": chave, "linhas": linhas, "outros": max(0, com_campo - sum(l["total"] for l in linhas))}
    colunas, chaves = usado, buscas.chaves_da_tabela(usado)
    linhas = armazem.linhas(f"""SELECT {COLUNAS_DO_DOCUMENTO} FROM {tabela} WHERE {onde}
                                ORDER BY ocorrido_em DESC LIMIT {min(pedido.limite or int(tamanho), buscas.MAXIMO_DE_LINHAS)}""", t.parametros)
    return {"total": total, "colunas": [{"campo": c, "chave": k} for c, k in zip(colunas, chaves)],
            "linhas": [{k: _pegar(documento(l), c) for c, k in zip(colunas, chaves)} for l in linhas]}


def ids_para_pericia(armazem, banco, pedido, condicoes, exclusoes, dias, selados_ate, limite):
    """(ids, total) dos logs da busca no período. Os ids só dos já selados no armazém (até `selados_ate` de cada
    gerenciador), em ordem; o total conta todos, para o pacote dizer quantos ficaram de fora."""
    t = Tradutor()
    filtro = t.onde({"bool": {"filter": [*condicoes, pedido.filtro], "must_not": exclusoes}})
    onde = f"({DENTRO_DO_PERIODO.format(dias=int(dias))}) AND ({filtro})"
    total = int(armazem.linhas(f"SELECT count() AS n FROM {banco}.logs_leitura WHERE {onde}", t.parametros)[0]["n"])
    if not selados_ate:
        return [], total
    cobertos = " OR ".join(f"(gerenciador = {t.p(g)} AND ocorrido_em < parseDateTime64BestEffort({t.p(ate.isoformat())}, 3))" for g, ate in selados_ate.items())
    ids = [l["i"] for l in armazem.linhas(f"""SELECT toString(id) AS i FROM {banco}.logs_leitura WHERE {onde} AND ({cobertos})
                                              ORDER BY ocorrido_em, id LIMIT {int(limite) + 1}""", t.parametros)]
    return ids, total


def contar_indicadores(armazem, banco, indicadores, dias, teto=10000):
    """{(tipo, valor): vezes} de cada indicador nos logs, numa leitura só. Conta o indicador inteiro, como o índice antigo:
    10.0.0.1 não conta dentro de 10.0.0.15, e evil.com não conta dentro de sub.evil.com. O LIKE usa o índice de n-gramas e
    separa os candidatos; a expressão regular confere a borda."""
    if not indicadores:
        return {}
    t = Tradutor()
    contas = []
    for i, (_, valor) in enumerate(indicadores):
        texto = str(valor).lower()
        borda = "(?i)(?:^|[^0-9a-z.])" + re.escape(texto) + "(?:$|[^0-9a-z.])"
        contas.append(f"countIf(lower(full_log) LIKE {t.p('%' + escapar_like(texto) + '%')} AND match(full_log, {t.p(borda)})) AS c{i}")
    linha = armazem.linhas(f"SELECT {', '.join(contas)} FROM {banco}.logs WHERE ocorrido_em >= now64(3) - INTERVAL {int(dias)} DAY", t.parametros)[0]
    return {chave: min(int(linha[f"c{i}"]), teto) for i, chave in enumerate(indicadores)}


def origens(armazem, banco, gerenciador_id, dias):
    """[(origem, último em milissegundos)] do gerenciador: a saúde das fontes, como a agregação por location do índice antigo."""
    t = Tradutor()
    return [(l["local"], float(l["ultimo"])) for l in armazem.linhas(
        f"""SELECT local, toUnixTimestamp64Milli(max(ocorrido_em)) AS ultimo FROM {banco}.logs
            WHERE gerenciador = {t.p(gerenciador_id)} AND ocorrido_em >= now64(3) - INTERVAL {int(dias)} DAY AND notEmpty(local)
            GROUP BY local ORDER BY ultimo DESC LIMIT 500""", t.parametros)]


def volume(armazem, banco, tabela, dias, horas_de_eps=72, amostra=500):
    """O mesmo resumo de volume do índice antigo: eventos por segundo (médio, pico por minuto, agora), por dia, por ativo e
    por tipo. As contas por minuto ficam no armazém: só sobem as horas."""
    t = f"{banco}.{tabela}"
    janela = f"ocorrido_em >= now64(3) - INTERVAL {int(dias)} DAY"
    resumo = armazem.linhas(f"""SELECT count() AS total, countIf(ocorrido_em >= now64(3) - INTERVAL 6 MINUTE AND ocorrido_em < now64(3) - INTERVAL 1 MINUTE) AS agora
                                FROM {t} WHERE {janela}""")[0]
    total = int(resumo["total"])
    por_minuto = f"SELECT toStartOfMinute(ocorrido_em) AS minuto, count() AS n FROM {t} WHERE {janela} GROUP BY minuto"
    pico = armazem.linhas(f"SELECT toUnixTimestamp(minuto) AS m, n FROM ({por_minuto}) ORDER BY n DESC, minuto LIMIT 1")
    horas = armazem.linhas(f"""SELECT toUnixTimestamp(toStartOfHour(minuto)) AS hora, sum(n) AS eventos, max(n) AS maior_minuto
                               FROM ({por_minuto}) GROUP BY hora ORDER BY hora DESC LIMIT {int(horas_de_eps)}""")
    medio = armazem.linhas(f"SELECT avg(length(full_log)) AS b FROM (SELECT full_log FROM {t} WHERE {janela} ORDER BY ocorrido_em DESC LIMIT {int(amostra)})")[0]["b"]
    tamanho_medio = float(medio) if medio not in (None, "nan") else 0.0
    dias_ = armazem.linhas(f"""SELECT toDate(ocorrido_em) AS dia, count() AS eventos FROM {t} WHERE {janela}
                               GROUP BY dia ORDER BY dia WITH FILL STEP 1""") if total else []
    ativos = armazem.linhas(f"SELECT agente_nome AS nome, count() AS eventos FROM {t} WHERE {janela} AND notEmpty(agente_nome) GROUP BY nome ORDER BY eventos DESC LIMIT 15")
    tipos = armazem.linhas(f"SELECT decoder AS nome, count() AS eventos FROM {t} WHERE {janela} AND notEmpty(decoder) GROUP BY nome ORDER BY eventos DESC LIMIT 15")
    return {
        "total": total,
        "eps_por_hora": [{"hora": _iso(h["hora"])[:13], "medio": round(int(h["eventos"]) / 3600, 3), "pico": round(int(h["maior_minuto"]) / 60, 2)} for h in reversed(horas)],
        "eps_agora": round(int(resumo["agora"]) / 300, 2),
        "eps_medio": round(total / (int(dias) * 86400), 3),
        "eps_pico": round(int(pico[0]["n"]) / 60, 2) if pico and total else 0,
        "pico_em": _iso(pico[0]["m"]) if pico and total else None,
        "bytes_por_evento": round(tamanho_medio),
        "por_dia": [{"dia": d["dia"], "eventos": int(d["eventos"]), "bytes_estimados": round(int(d["eventos"]) * tamanho_medio)} for d in dias_],
        "ativos": [{"nome": a["nome"], "eventos": int(a["eventos"])} for a in ativos],
        "origens": [{"nome": o["nome"], "eventos": int(o["eventos"])} for o in tipos],
    }


def ocupado(armazem, banco):
    """Disco ocupado pelos logs e pelos alertas, por dia (cada partição é um dia), já comprimido."""
    total, dias = {"logs": 0, "alertas": 0}, {}
    for l in armazem.linhas("""SELECT table, partition, sum(bytes_on_disk) AS bytes FROM system.parts
                               WHERE database = {b:String} AND active AND table IN ('logs', 'alertas') GROUP BY table, partition""", {"b": banco}):
        tipo, tamanho, dia = l["table"], int(l["bytes"]), l["partition"]
        total[tipo] += tamanho
        chave = f"{dia[:4]}-{dia[4:6]}-{dia[6:8]}"
        dias.setdefault(chave, {"logs": 0, "alertas": 0})[tipo] += tamanho
    return {**total, "por_dia": [{"dia": d, **v} for d, v in sorted(dias.items())]}


def fluxos(armazem, banco, horas, ip=None):
    """Os fluxos de rede das últimas horas: totais, a série por hora, quem mais manda e recebe, as portas e os países de
    destino, e os mais recentes. Com ip, só os fluxos em que ele aparece, de um lado ou do outro."""
    t = Tradutor()
    onde = f"ocorrido_em >= now64(3) - INTERVAL {int(horas)} HOUR"
    if ip:
        onde += f" AND (origem = {t.p(ip)} OR destino = {t.p(ip)})"
    tabela = f"{banco}.fluxos"
    total = armazem.linhas(f"SELECT count() AS fluxos, sum(bytes) AS bytes, sum(pacotes) AS pacotes, uniqExact(exportador) AS exportadores FROM {tabela} WHERE {onde}",
                           t.parametros)[0]

    def maiores(campo, limite=10):
        return [{"valor": l["valor"], "bytes": int(l["bytes"]), "fluxos": int(l["fluxos"])} for l in armazem.linhas(
            f"""SELECT {campo} AS valor, sum(bytes) AS bytes, count() AS fluxos FROM {tabela} WHERE {onde} AND notEmpty(toString(valor))
                GROUP BY valor ORDER BY bytes DESC LIMIT {limite}""", t.parametros)]

    horas_ = [{"hora": _iso(l["h"])[:13], "bytes": int(l["bytes"]), "fluxos": int(l["fluxos"])} for l in armazem.linhas(
        f"""SELECT toUnixTimestamp(toStartOfHour(ocorrido_em)) AS h, sum(bytes) AS bytes, count() AS fluxos FROM {tabela} WHERE {onde}
            GROUP BY h ORDER BY h""", t.parametros)]
    recentes = armazem.linhas(f"""SELECT toString(ocorrido_em) AS quando, exportador, origem, destino, porta_origem, porta_destino, protocolo, bytes, pacotes, pais, operadora
                                  FROM {tabela} WHERE {onde} ORDER BY ocorrido_em DESC LIMIT 100""", t.parametros)
    return {
        "total": {"fluxos": int(total["fluxos"]), "bytes": int(total["bytes"] or 0), "pacotes": int(total["pacotes"] or 0), "exportadores": int(total["exportadores"])},
        "horas": horas_, "origens": maiores("origem"), "destinos": maiores("destino"), "portas": maiores("porta_destino"), "paises": maiores("pais"),
        "recentes": [{**r, "porta_origem": int(r["porta_origem"]), "porta_destino": int(r["porta_destino"]), "bytes": int(r["bytes"]), "pacotes": int(r["pacotes"])} for r in recentes],
    }
