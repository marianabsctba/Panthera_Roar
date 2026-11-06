"""Buscas que viram indicador, linha do tempo, rosca, barras, lista, mapa ou tabela: os blocos dos painéis e as buscas agendadas.

A console e o serviço de buscas agendadas (ingestao/roar_ingestao/buscas.py) usam as mesmas funções, então um bloco do
painel e o alerta de uma busca contam do mesmo jeito. O texto passa pela linguagem de consulta: nunca chega cru ao índice.
"""

import sys

from roar_api import consulta as linguagem

TIPOS = {"numero": "Indicador", "serie": "Linha do tempo", "rosca": "Rosca", "barras": "Barras", "top": "Lista dos mais frequentes",
         "mapa": "Mapa de países", "tabela": "Tabela"}
# Os que agrupam por um campo. O mapa agrupa sempre pelo país.
POR_CAMPO = {"rosca", "barras", "top"}
CAMPO_DO_MAPA = "GeoLocation.country_name"
# Janelas que a tela oferece, em minutos. A busca agendada usa a mesma lista.
JANELAS = {15: "15 minutos", 60: "1 hora", 240: "4 horas", 1440: "24 horas", 10080: "7 dias", 43200: "30 dias"}
MAXIMO_DE_LINHAS = 50
BARRAS_NA_SERIE = 40
LINHAS_NA_SERIE = 6
COLUNAS_PADRAO = ["timestamp", "agent.name", "rule.description", "data.srcip", "data.srcuser"]


class BuscaInvalida(ValueError):
    pass


def indices(gerenciadores):
    return ",".join(f"wazuh-archives-4.x-{g}-*" for g in gerenciadores)


def chave_curta(campo):
    """A última parte do campo: é por ela que a máscara reconhece usuário e endereço na resposta."""
    return campo.rsplit(".", 1)[-1]


def _campo(nome):
    try:
        return linguagem.campo(nome)
    except linguagem.ConsultaInvalida as erro:
        raise BuscaInvalida(str(erro)) from None


def montar(texto, tipo, minutos, campo=None, tamanho=10):
    """O corpo da busca no índice. Devolve (corpo, campo usado), ou BuscaInvalida com o motivo."""
    if tipo not in TIPOS:
        raise BuscaInvalida("Tipo de bloco desconhecido.")
    if minutos not in JANELAS:
        raise BuscaInvalida("Janela de tempo desconhecida.")
    try:
        pedido = linguagem.analisar((texto or "").strip())
    except linguagem.ConsultaInvalida as erro:
        raise BuscaInvalida(str(erro)) from None
    tamanho = max(1, min(int(tamanho or 10), MAXIMO_DE_LINHAS))
    janela = {"range": {"timestamp": {"gte": f"now-{minutos}m"}}}
    corpo = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [janela, pedido.filtro]}}}
    usado = None
    if tipo == "numero":
        # Busca a janela anterior junto: o indicador mostra quanto mudou, e o total da janela atual sai do filtro.
        corpo["query"]["bool"]["filter"][0] = {"range": {"timestamp": {"gte": f"now-{2 * minutos}m"}}}
        corpo["aggs"] = {"atual": {"filter": janela}}
    elif tipo == "serie":
        corpo["aggs"] = {"serie": {"auto_date_histogram": {"field": "timestamp", "buckets": BARRAS_NA_SERIE}}}
        if campo:
            usado = _campo(campo)
            corpo["aggs"]["serie"]["aggs"] = {"por": {"terms": {"field": usado, "size": LINHAS_NA_SERIE}}}
    elif tipo in POR_CAMPO or tipo == "mapa":
        usado = CAMPO_DO_MAPA if tipo == "mapa" else _campo(campo or pedido.contar_por or "")
        if not usado:
            raise BuscaInvalida("Diga o campo para contar, como usuario ou origem.")
        corpo["aggs"] = {"top": {"terms": {"field": usado, "size": 60 if tipo == "mapa" else tamanho}}}
    elif tipo == "tabela":
        corpo["size"] = min(pedido.limite or tamanho, MAXIMO_DE_LINHAS)
        corpo["sort"] = [{"timestamp": "desc"}]
        usado = pedido.colunas or COLUNAS_PADRAO
        corpo["_source"] = usado
    return corpo, usado


def chaves_da_tabela(colunas):
    """A chave curta de cada coluna, sem repetir: ativo e tipo terminam os dois em name."""
    curtas = [chave_curta(c) for c in colunas]
    return [c.replace(".", "_") if curtas.count(curta) > 1 else curta for c, curta in zip(colunas, curtas)]


def _pegar(documento, caminho):
    for parte in caminho.split("."):
        if not isinstance(documento, dict):
            return None
        documento = documento.get(parte)
    return documento


def ler(resposta, tipo, campo=None):
    """O resultado do índice no formato que a tela desenha. Linhas trazem o valor na chave curta do campo, para a máscara."""
    total = resposta["hits"]["total"]["value"]
    aggs = resposta.get("aggregations", {})
    if tipo == "numero":
        atual = aggs.get("atual", {}).get("doc_count", total)
        return {"total": atual, "anterior": total - atual}
    if tipo == "serie":
        pontos = []
        for b in aggs.get("serie", {}).get("buckets", []):
            ponto = {"quando": b["key_as_string"], "total": b["doc_count"]}
            if campo:
                ponto["por"] = {str(p["key"]): p["doc_count"] for p in b.get("por", {}).get("buckets", [])}
            pontos.append(ponto)
        return {"total": total, "pontos": pontos, "campo": campo}
    if tipo in POR_CAMPO or tipo == "mapa":
        chave = chave_curta(campo)
        top = aggs.get("top", {})
        linhas = [{chave: b["key"], "total": b["doc_count"]} for b in top.get("buckets", [])]
        # Outros são os valores que existem e ficaram de fora; log sem o campo, como alerta sem país, não entra.
        return {"total": total, "campo": campo, "chave": chave, "linhas": linhas, "outros": top.get("sum_other_doc_count", 0)}
    colunas, chaves = campo, chaves_da_tabela(campo)
    return {"total": total, "colunas": [{"campo": c, "chave": k} for c, k in zip(colunas, chaves)],
            "linhas": [{k: _pegar(h["_source"], c) for c, k in zip(colunas, chaves)} for h in resposta["hits"]["hits"]]}


def executar(post, url, gerenciadores, texto, tipo, minutos, campo=None, tamanho=10, armazem=None, banco=None):
    """post: o post da sessão do índice. Sem gerenciador, devolve vazio sem perguntar nada ao índice. Com `armazem` e o
    `banco` da organização, lê do armazém de eventos, com a mesma montagem e o mesmo formato de resposta."""
    corpo, usado = montar(texto, tipo, minutos, campo, tamanho)
    if not gerenciadores:
        return ler({"hits": {"total": {"value": 0}, "hits": []}}, tipo, usado)
    if armazem is not None:
        from roar_api import leitor_armazem
        from roar_ingestao.armazem import ArmazemRecusou
        try:
            return leitor_armazem.bloco(armazem, banco, linguagem.analisar((texto or "").strip()), tipo, minutos, usado,
                                        max(1, min(int(tamanho or 10), MAXIMO_DE_LINHAS)), sys.modules[__name__])
        except linguagem.ConsultaInvalida as erro:
            raise BuscaInvalida(str(erro)) from None
        except ArmazemRecusou:
            raise BuscaInvalida("Este campo não aceita essa operação. Tente outro campo.") from None
    resposta = post(f"{url}/{indices(gerenciadores)}/_search?allow_no_indices=true&ignore_unavailable=true", json=corpo, timeout=30)
    if resposta.status_code == 400:
        raise BuscaInvalida("Este campo não aceita essa operação. Tente outro campo.")
    resposta.raise_for_status()
    return ler(resposta.json(), tipo, usado)


# ------------------------------------------------------------------ modelos

def _b(titulo, tipo, texto="", minutos=10080, campo=None, tamanho=10, largura=6):
    return {"titulo": titulo, "tipo": tipo, "texto": texto, "minutos": minutos, "campo": campo, "tamanho": tamanho, "largura": largura}


def _indicador(titulo, texto="", minutos=10080):
    return _b(titulo, "numero", texto, minutos=minutos, largura=3)


# Painéis prontos, no desenho de um centro de operações: indicadores no alto, gráficos no meio, a lista no fim.
# Quem cria um painel começa por um deles e muda o que quiser. Largura em colunas de uma grade de 12.
MODELOS = {
    "soc": {"nome": "Centro de operações", "descricao": "O dia do analista: volume, alertas por nível, quem mais dispara e de onde vem.", "blocos": [
        _indicador("Logs"),
        _indicador("Alertas de nível 7 ou mais", "nivel>=7"),
        _indicador("Alertas altos, nível 10 ou mais", "nivel>=10"),
        _indicador("Falhas de login", "grupo=authentication_failed"),
        _b("Alertas por nível, últimos 7 dias", "serie", "nivel>=3", campo="nivel", largura=8),
        _b("Alertas por ativo", "rosca", "nivel>=3", campo="ativo", tamanho=6, largura=4),
        _b("Regras que mais disparam", "barras", "nivel>=3", campo="descricao", tamanho=8),
        _b("De onde vêm os alertas", "mapa", "nivel>=3"),
        _b("Últimos alertas de nível 7 ou mais", "tabela", "nivel>=7 | campos quando, ativo, descricao, nivel, origem", largura=12),
    ]},
    "identidade": {"nome": "Identidade e acessos", "descricao": "Falhas e sucessos de login, quem mais erra a senha e de onde vêm as tentativas.", "blocos": [
        _indicador("Falhas de login", "grupo=authentication_failed"),
        _indicador("Logins com sucesso", "grupo=authentication_success"),
        _indicador("Usuário inexistente", "grupo=invalid_login"),
        _indicador("Eventos de segurança do Windows", "grupo=windows_security"),
        _b("Falhas de login por usuário, últimos 7 dias", "serie", "grupo=authentication_failed", campo="usuario", largura=8),
        _b("Falhas por usuário", "rosca", "grupo=authentication_failed", campo="usuario", tamanho=6, largura=4),
        _b("Origens com mais falhas", "barras", "grupo=authentication_failed", campo="origem", tamanho=8),
        _b("Falhas de login por país", "mapa", "grupo=authentication_failed"),
        _b("Últimas falhas de login", "tabela", "grupo=authentication_failed | campos quando, ativo, usuario, origem, pais", largura=12),
    ]},
    "ameacas": {"nome": "Ameaças e origens", "descricao": "O mapa das origens, os países e endereços que mais aparecem e as técnicas de ataque.", "blocos": [
        _b("De onde vêm os alertas", "mapa", "nivel>=5", largura=8),
        _b("Alertas por país", "rosca", "nivel>=5", campo="pais", tamanho=6, largura=4),
        _b("Endereços que mais aparecem", "barras", "nivel>=5", campo="origem", tamanho=8),
        _b("Técnicas de ataque", "barras", "nivel>=3", campo="rule.mitre.technique", tamanho=8),
        _b("Alertas por país, últimos 7 dias", "serie", "nivel>=5", campo="pais", largura=12),
        _b("Últimos alertas com origem", "tabela", "nivel>=5 E origem=* | campos quando, ativo, descricao, origem, pais", largura=12),
    ]},
    "fontes": {"nome": "Saúde das fontes", "descricao": "Quanto cada ativo e cada fonte manda: um servidor que parou aparece na hora.", "blocos": [
        _indicador("Logs na última hora", minutos=60),
        _indicador("Logs em 24 horas", minutos=1440),
        _indicador("Logs de Windows", "tipo=windows_eventchannel"),
        _indicador("Logs por syslog", "grupo=syslog"),
        _b("Logs por ativo, últimos 7 dias", "serie", campo="ativo", largura=12),
        _b("Logs por tipo", "rosca", campo="tipo", tamanho=6, largura=4),
        _b("Logs por fonte", "barras", campo="fonte", tamanho=8, largura=8),
        _b("Logs mais recentes", "tabela", "| campos quando, ativo, tipo, fonte", largura=12),
    ]},
    "integridade": {"nome": "Integridade e conformidade", "descricao": "Arquivos criados, alterados e apagados, e as checagens de configuração que reprovaram.", "blocos": [
        _indicador("Mudanças em arquivos", "grupo=syscheck"),
        _indicador("Arquivos criados", "grupo=syscheck_entry_added"),
        _indicador("Arquivos apagados", "grupo=syscheck_entry_deleted"),
        _indicador("Checagens reprovadas", "grupo=sca E data.sca.check.result=failed"),
        _b("Mudanças por tipo", "rosca", "grupo=syscheck", campo="syscheck.event", tamanho=6, largura=4),
        _b("Ativos com mais mudanças", "barras", "grupo=syscheck", campo="ativo", tamanho=8, largura=8),
        _b("Checagens que mais reprovam", "barras", "grupo=sca E data.sca.check.result=failed", campo="data.sca.check.title", tamanho=8, largura=12),
        _b("Últimos arquivos mudados", "tabela", "grupo=syscheck | campos quando, ativo, syscheck.path, syscheck.event", largura=12),
    ]},
}
