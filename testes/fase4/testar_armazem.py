#!/usr/bin/env python3
"""Armazém de eventos (ClickHouse): isolamento entre organizações, o coletor de ponta a ponta e nada perdido com o
armazém fora do ar. Com o ClickHouse e um gerenciador Wazuh reais.

    sudo bash testes/rodar.sh testes/fase4/testar_armazem.py
"""

import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_api import buscas, consulta, consulta_sql, leitor_armazem  # noqa: E402
from roar_ingestao import armazem, conferir_armazem, provisao  # noqa: E402
from roar_ingestao.ciclo import ler_env  # noqa: E402

RESULTADOS = []
ENV = ler_env(provisao.DESTINO / ".env")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def recusado(funcao):
    try:
        funcao()
        return False
    except armazem.ArmazemRecusou:
        return True


def testar_regras():
    print("== Nomes e retenção", flush=True)
    registrar("o banco sai do id da organização", armazem.banco_do("2fc1fd7b-f4e9-4aa0-9ab7-a2ab9f8e4393") == "roar_c_2fc1fd7bf4e94aa09ab7a2ab9f8e4393")
    for nome, ruim in (("organização com texto livre", "x; DROP DATABASE system"), ("gerenciador com aspas", "abc'def")):
        try:
            (armazem.banco_do if "organização" in nome else armazem.usuario_do)(ruim)
            registrar(f"recusa {nome}", False)
        except ValueError:
            registrar(f"recusa {nome}", True)
    registrar("os dias quentes vão para o disco frio antes de apagar", armazem.ttl(180, 30) ==
              "toDateTime(ocorrido_em) + INTERVAL 30 DAY TO VOLUME 'frio', toDateTime(ocorrido_em) + INTERVAL 180 DAY DELETE")
    registrar("retenção menor que os dias quentes não move nada", armazem.ttl(7, 30) == "toDateTime(ocorrido_em) + INTERVAL 7 DAY DELETE")


def traduzir(texto):
    t = consulta_sql.Tradutor()
    return t.onde(consulta.analisar(texto).filtro), t.parametros


def testar_tradutor():
    print("\n== Tradutor da linguagem de consulta", flush=True)
    onde, p = traduzir('ativo=srv-rh E "falha de login"')
    registrar("campo conhecido vira coluna e o texto vira parâmetro", onde == "(agente_nome = {p0:String}) AND (lower(full_log) LIKE {p1:String})"
              and p == {"p0": "srv-rh", "p1": "%falha de login%"}, f"{onde} {p}")
    onde, p = traduzir("usuario=admin' OR 1=1 --")
    registrar("aspas e SQL no valor ficam só no parâmetro", "admin" not in onde and "1=1" not in onde and p["p0"] == "admin'", f"{onde} {p}")
    onde, p = traduzir("data.win.eventdata.targetUserName=maria")
    registrar("campo fora das colunas lê o caminho no log original, por parâmetro", "JSONExtractRaw(dados, {p0:String}, {p1:String}, {p2:String}, {p3:String})" in onde
              and p["p3"] == "targetUserName", onde)
    onde, _ = traduzir("grupo=sshd E NAO nivel>=10")
    registrar("lista usa has e o número compara como número", onde == "(has(regra_grupos, {p0:String})) AND (NOT (nivel >= toFloat64OrNull({p1:String})))", onde)
    onde, p = traduzir("origem=10.* OU origem=*")
    registrar("curinga vira ILIKE, e campo=* vira o campo existe", "ip_origem ILIKE {p0:String}" in onde and "notEmpty(ip_origem)" in onde and p["p0"] == "10.%", f"{onde} {p}")
    onde, p = traduzir('"100%_certo"')
    registrar("% e _ do texto não viram curinga", p["p0"] == "%100\\%\\_certo%", str(p))
    onde, _ = traduzir("quando>=now-2h")
    registrar("faixa de tempo relativa", onde == "ocorrido_em >= now64(3) - INTERVAL 2 HOUR", onde)


def testar_isolamento(adm):
    print("\n== Isolamento entre organizações", flush=True)
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    ger_a, ger_b = f"teste{uuid.uuid4().hex[:7]}", f"teste{uuid.uuid4().hex[:7]}"
    senha_a, senha_b = provisao.senha_forte(), provisao.senha_forte()
    try:
        banco_a = armazem.criar_organizacao(adm, a, 90, 30)
        banco_b = armazem.criar_organizacao(adm, b, 90, 30)
        armazem.criar_gravador(adm, ger_a, a, senha_a)
        armazem.criar_gravador(adm, ger_b, b, senha_b)
        gravador = armazem.Armazem(armazem.usuario_do(ger_a), senha_a, adm.url)
        leitor = armazem.Armazem(armazem.LEITOR, ENV["ARMAZEM_LEITOR_SENHA"], adm.url)
        linha = "{\"id\":\"00000000-0000-0000-0000-0000000000aa\",\"ocorrido_em\":\"2026-11-06 12:00:00.000\",\"full_log\":\"teste\"}"
        registrar("o coletor grava no banco da própria organização", not recusado(lambda: gravador.executar(f"INSERT INTO {banco_a}.logs FORMAT JSONEachRow {linha}")))
        registrar("e não grava no de outra", recusado(lambda: gravador.executar(f"INSERT INTO {banco_b}.logs FORMAT JSONEachRow {linha}")))
        registrar("o coletor não lê nada", recusado(lambda: gravador.executar(f"SELECT count() FROM {banco_a}.logs")))
        registrar("nem apaga", recusado(lambda: gravador.executar(f"DROP TABLE {banco_a}.logs")))
        registrar("o leitor lê", leitor.linhas(f"SELECT count() AS n FROM {banco_a}.logs")[0]["n"] in (1, "1"))
        registrar("mas não grava", recusado(lambda: leitor.executar(f"INSERT INTO {banco_a}.logs FORMAT JSONEachRow {linha}")))
        registrar("nem muda configuração para fugir do limite", recusado(lambda: leitor.executar("SELECT 1 SETTINGS readonly = 0")))
        registrar("sem senha não entra", recusado(lambda: armazem.Armazem("default", "", adm.url).executar("SELECT 1")))
        criada = adm.linhas(f"SELECT create_table_query AS q FROM system.tables WHERE database = {{b:String}} AND name = 'logs'", {"b": banco_a})[0]["q"]
        registrar("a tabela nasce com a retenção da organização", "toIntervalDay(30)" in criada and "TO VOLUME" not in criada and "storage_policy = 'roar'" in criada, criada[-300:])
        armazem.aplicar_retencao(adm, a, 365, 365)
        criada = adm.linhas(f"SELECT create_table_query AS q FROM system.tables WHERE database = {{b:String}} AND name = 'logs'", {"b": banco_a})[0]["q"]
        registrar("mudar a retenção troca a regra da tabela", "toIntervalDay(365)" in criada and "toIntervalDay(30) TO VOLUME 'frio'" in criada, criada[-300:])
        armazem.remover_gravador(adm, ger_a)
        registrar("gerenciador removido perde o acesso", recusado(lambda: gravador.executar(f"INSERT INTO {banco_a}.logs FORMAT JSONEachRow {linha}")))
        armazem.remover_organizacao(adm, a)
        registrar("organização removida leva o banco junto", not adm.linhas("SELECT name FROM system.databases WHERE name = {b:String}", {"b": banco_a}))
    finally:
        for g in (ger_a, ger_b):
            armazem.remover_gravador(adm, g)
        for c in (a, b):
            armazem.remover_organizacao(adm, c)


def esperar(condicao, segundos=120):
    fim = time.time() + segundos
    while time.time() < fim:
        if condicao():
            return True
        time.sleep(3)
    return False


def testar_leituras_da_parte_2(indexer, leitor, gerenciador_id, banco, marca):
    print("\n== Caça, saúde das fontes e volume", flush=True)
    indicadores = [("ip", "8.8.8.8"), ("ip", "200.160.2.3"), ("ip", "203.0.113.1"), ("ip", "203.0.113.15"), ("dominio", f"{marca}-a"), ("hash", "nao-existe-" + marca)]
    do_armazem = leitor_armazem.contar_indicadores(leitor, banco, indicadores, 1)
    linhas = []
    for _, valor in indicadores:
        linhas += [json.dumps({"index": f"{provisao.indice_bruto_do(gerenciador_id)}*", "ignore_unavailable": True}),
                   json.dumps({"size": 0, "track_total_hits": 10000, "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-1d"}}},
                                                                                                 {"match_phrase": {"full_log": valor}}]}}})]
    respostas = indexer.sessao.post(f"{indexer.url}/_msearch", data="\n".join(linhas) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=60).json()["responses"]
    do_indexador = {chave: r["hits"]["total"]["value"] for chave, r in zip(indicadores, respostas)}
    registrar("a caça conta igual nos dois, com o indicador inteiro (203.0.113.1 não conta dentro de 203.0.113.15)", do_armazem == do_indexador
              and do_armazem[("dominio", f"{marca}-a")] >= 50 and do_armazem[("hash", "nao-existe-" + marca)] == 0, f"{do_armazem} | {do_indexador}")
    inicio = int(leitor.linhas(f"SELECT toUnixTimestamp64Milli(min(ocorrido_em)) AS m FROM {banco}.logs WHERE gerenciador = {{g:String}}", {"g": gerenciador_id})[0]["m"])
    corpo = {"size": 0, "query": {"range": {"timestamp": {"gte": "now-7d"}}},
             "aggs": {"origens": {"terms": {"field": "location", "size": 500}, "aggs": {"ultimo": {"max": {"field": "timestamp"}}}}}}
    # O gerenciador continua gravando enquanto o teste roda, e cada lado recebe em seu tempo: espera os dois baterem.
    for _ in range(7):
        de_ca = {local: ultimo for local, ultimo in leitor_armazem.origens(leitor, banco, gerenciador_id, 7)}
        baldes = indexer.sessao.post(f"{indexer.url}/{provisao.indice_bruto_do(gerenciador_id)}*/_search", json=corpo, timeout=60).json()["aggregations"]["origens"]["buckets"]
        de_la = {b["key"]: b["ultimo"]["value"] for b in baldes if b["ultimo"]["value"] >= inicio}
        if {k: v for k, v in de_ca.items() if v >= inicio} == de_la:
            break
        time.sleep(5)
    registrar("a saúde das fontes vê as mesmas origens, com a mesma última hora", de_ca and {k: v for k, v in de_ca.items() if v >= inicio} == de_la, f"{de_ca} | {de_la}")
    v = leitor_armazem.volume(leitor, banco, "logs", 1)
    registrar("o volume soma certo", v["total"] > 0 and sum(d["eventos"] for d in v["por_dia"]) == v["total"]
              and v["eps_por_hora"] and v["eps_pico"] >= v["eps_medio"] and v["bytes_por_evento"] > 0, str(v)[:300])
    registrar("e o pico aponta um minuto de verdade", v["pico_em"] and v["pico_em"].endswith(":00.000Z") and v["ativos"] and v["origens"], str(v["pico_em"]))
    ocupado = leitor_armazem.ocupado(leitor, banco)
    registrar("o disco ocupado vem por dia e por tipo", ocupado["logs"] > 0 and sum(d["logs"] for d in ocupado["por_dia"]) == ocupado["logs"], str(ocupado)[:200])


def testar_paridade(indexer, gerenciador_id, banco, marca):
    """As mesmas buscas, no indexador e no armazém, sobre os mesmos eventos, dão o mesmo resultado."""
    print("\n== Indexador e armazém respondem igual", flush=True)
    leitor = armazem.leitor(ENV)
    frase = f'"{marca}-a"'
    numeros = [frase, f"{frase} E nivel>=5", f"{frase} E nivel=5", f"{frase} E grupo=authentication_failed", f"{frase} E NAO usuario=teste1",
               f"{frase} E (usuario=teste1 OU usuario=teste2)", f"{frase} E usuario=teste*", f"{frase} E origem=*", f"{frase} E usuario~ste4",
               f"{frase} E pais=Brazil", f"{frase} E origem=203.0.113.*", f"{frase} E tipo=sshd E NAO (origem=8.8.8.8 OU origem=200.160.2.3)"]

    def nos_dois(texto, tipo, campo=None, tamanho=10):
        de_la = buscas.executar(indexer.sessao.post, indexer.url, [gerenciador_id], texto, tipo, 60, campo, tamanho)
        de_ca = buscas.executar(None, None, [gerenciador_id], texto, tipo, 60, campo, tamanho, armazem=leitor, banco=banco)
        return de_la, de_ca

    for texto in numeros:
        de_la, de_ca = nos_dois(texto, "numero")
        registrar(f"mesmo número: {texto.replace(frase, 'marca')}", de_la["total"] == de_ca["total"] and de_la["total"] > 0 if texto == frase else de_la["total"] == de_ca["total"],
                  f"indexador {de_la['total']}, armazém {de_ca['total']}")
    # Com muitos valores empatados, o índice antigo conta por aproximação: cada pedaço do índice manda só os primeiros
    # colocados dele, e um valor pode ficar de fora em algum. O armazém conta exato.
    de_la, de_ca = nos_dois(frase, "rosca", "origem", 2)
    exato = sorted((l["srcip"], l["total"]) for l in de_ca["linhas"])
    registrar("a rosca por origem conta exato no armazém, e o índice antigo nunca conta mais",
              exato == [("200.160.2.3", 5), ("8.8.8.8", 5)] and all(l["total"] <= dict(exato).get(l["srcip"], 0) for l in de_la["linhas"]),
              f"{sorted((l['srcip'], l['total']) for l in de_la['linhas'])} | {exato}")
    for tipo, campo, tamanho in (("top", "usuario", 10), ("barras", "nivel", 10), ("mapa", None, 10)):
        de_la, de_ca = nos_dois(frase, tipo, campo, tamanho)
        chave = de_la["chave"]
        la = sorted((str(l[chave]), l["total"]) for l in de_la["linhas"])
        ca = sorted((str(l[chave]), l["total"]) for l in de_ca["linhas"])
        registrar(f"mesmos valores e contagens: {tipo} por {campo or 'país'}", la == ca and de_la["outros"] == de_ca["outros"] and la, f"{la} | {ca}")
    de_la, de_ca = nos_dois(frase, "serie", "usuario")
    registrar("mesma linha do tempo, somada", sum(p["total"] for p in de_la["pontos"]) == sum(p["total"] for p in de_ca["pontos"]) == de_la["total"],
              f"{de_la['total']} e {de_ca['total']}")
    registrar("e a mesma divisão por usuário", sorted(sum((list(p.get("por", {}).items()) for p in de_la["pontos"]), []))
              == sorted(sum((list(p.get("por", {}).items()) for p in de_ca["pontos"]), [])))
    de_la, de_ca = nos_dois(f"{frase} | campos quando, ativo, usuario, origem, pais", "tabela", None, 50)
    registrar("mesma tabela", sorted(map(str, de_la["linhas"])) == sorted(map(str, de_ca["linhas"])) and len(de_ca["linhas"]) == 50,
              f"{de_la['linhas'][:1]} | {de_ca['linhas'][:1]}")
    pedido = consulta.analisar(f"{frase} | contar por usuario")
    contagem = leitor_armazem.logs(leitor, banco, pedido, [], [], 1, None, 100, [], True)["contagem"]
    registrar("a tela de logs conta por usuário", sorted((l["valor"], l["total"]) for l in contagem["linhas"]) == [(f"teste{i}", 10) for i in range(5)], str(contagem))
    pagina = leitor_armazem.logs(leitor, banco, consulta.analisar(frase), [], [], 1, None, 30, ["agent.name", "data.srcuser"], True)
    seguinte = leitor_armazem.logs(leitor, banco, consulta.analisar(frase), [], [], 1, pagina["cursor"], 30, [], False)
    ids = [l["id"] for l in pagina["logs"]] + [l["id"] for l in seguinte["logs"]]
    registrar("a tela de logs pagina sem repetir nem pular", len(ids) == 50 and len(set(ids)) == 50 and pagina["total"] == 50, f"{len(ids)} {len(set(ids))}")
    registrar("e o log volta no formato do indexador", pagina["logs"][0]["bruto"].get("agent", {}).get("name") and "full_log" in pagina["logs"][0]["bruto"]
              and pagina["campos"]["data.srcuser"] and pagina["linha_do_tempo"])
    testar_leituras_da_parte_2(indexer, leitor, gerenciador_id, banco, marca)
    filtrado = leitor_armazem.logs(leitor, banco, consulta.analisar(frase), [{"term": {"data.srcuser": "teste3"}}], [{"term": {"data.srcip": "8.8.8.8"}}], 1, None, 100, [], True)
    registrar("os filtros clicados na tela valem", filtrado["total"] == len(filtrado["logs"]) and all(l["bruto"]["data"]["srcuser"] == "teste3" and l["bruto"]["data"]["srcip"] != "8.8.8.8"
                                                                                                       for l in filtrado["logs"]) and filtrado["total"] > 0, str(filtrado["total"]))


def testar_ponta_a_ponta(adm):
    """Um gerenciador próprio, com os dois caminhos ligados (indexador e armazém), para comparar um com o outro."""
    print("\n== Do gerenciador ao armazém", flush=True)
    sys.path.insert(0, str(RAIZ / "testes/fase1"))
    from testar_ingestao import Ambiente, esperar_gerenciador
    amb = Ambiente()
    try:
        g = amb.gerenciador("armazem")
        registrar("gerenciador de teste no ar, com os dois caminhos", esperar_gerenciador(g))
        _ponta_a_ponta(adm, g["id"], g["cliente"])
    finally:
        amb.limpar()


def _ponta_a_ponta(adm, gerenciador_id, cliente_id):
    banco = armazem.banco_do(cliente_id)
    indexer = provisao.indexer_admin(ENV)
    marca = f"roar-armazem-{uuid.uuid4().hex[:10]}"

    def ip(i):
        return "8.8.8.8" if i % 10 == 0 else "200.160.2.3" if i % 10 == 1 else f"203.0.113.{i % 200 + 1}"

    def enviar(quantos, rodada):
        eventos = [f"Nov  6 12:00:00 {marca}-{rodada} sshd[{i}]: Invalid user teste{i % 5} from {ip(i)} port 22" for i in range(quantos)]
        provisao.enviar_eventos(gerenciador_id, eventos)

    def no_armazem(rodada):
        return int(adm.linhas(f"SELECT count() AS n FROM {banco}.logs WHERE full_log LIKE {{m:String}}", {"m": f"%{marca}-{rodada} %"})[0]["n"])

    def no_indexador(rodada):
        r = indexer.sessao.post(f"{indexer.url}/{provisao.indice_bruto_do(gerenciador_id)}*/_count",
                                json={"query": {"match_phrase": {"full_log": f"{marca}-{rodada}"}}}, timeout=60)
        return r.json().get("count", 0)

    enviar(50, "a")
    registrar("os logs chegam ao armazém", esperar(lambda: no_armazem("a") >= 50), str(no_armazem("a")))
    registrar("o mesmo tanto que no indexador", esperar(lambda: no_indexador("a") == no_armazem("a") == 50), f"{no_indexador('a')} e {no_armazem('a')}")
    linha = adm.linhas(f"""SELECT gerenciador, decoder, ip_origem, usuario, regra_id FROM {banco}.alertas
                           WHERE full_log LIKE {{m:String}} ORDER BY ocorrido_em LIMIT 1""", {"m": f"%{marca}-a %"})
    registrar("o alerta vem com as colunas certas", linha and linha[0]["gerenciador"] == gerenciador_id and linha[0]["decoder"] == "sshd"
              and linha[0]["ip_origem"] and linha[0]["usuario"].startswith("teste"), str(linha)[:300])
    paises = adm.linhas(f"SELECT DISTINCT pais FROM {banco}.logs WHERE full_log LIKE {{m:String}} AND pais != '' ORDER BY pais", {"m": f"%{marca}-a %"})
    registrar("o coletor acha o país do endereço público", [p["pais"] for p in paises] == ["Brazil", "United States"], str(paises))
    testar_paridade(indexer, gerenciador_id, banco, marca)

    print("\n== Armazém fora do ar", flush=True)
    subprocess.run(["docker", "stop", "roar-armazem"], check=True, capture_output=True)
    try:
        enviar(80, "b")
        time.sleep(15)
    finally:
        subprocess.run(["docker", "start", "roar-armazem"], check=True, capture_output=True)
    def no_ar():
        try:
            adm.executar("SELECT 1")
            return True
        except (armazem.ArmazemRecusou, armazem.requests.RequestException):
            return False
    esperar(no_ar, 120)
    registrar("o que chegou com o armazém parado entra quando ele volta, sem perder nada", esperar(lambda: no_armazem("b") >= 80, 180), str(no_armazem("b")))
    registrar("e sem repetir", no_armazem("b") == 80, str(no_armazem("b")))

    diferencas = conferir_armazem.comparar(indexer, adm, gerenciador_id, cliente_id, horas=2)
    registrar("a conferência hora a hora não acha buraco", not diferencas, str(diferencas)[:300])


def main():
    testar_regras()
    testar_tradutor()
    adm = armazem.admin(ENV)
    testar_isolamento(adm)
    testar_ponta_a_ponta(adm)
    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
