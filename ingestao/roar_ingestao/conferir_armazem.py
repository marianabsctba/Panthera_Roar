"""Confere, hora a hora, se o armazém recebeu o mesmo que o indexador, enquanto os dois recebem juntos (docs/clickhouse.md).

    python -m roar_ingestao.conferir_armazem [--horas 24]

O coletor descarta o lote que o armazém recusa por erro de permissão ou de tabela (4xx), sem tentar de novo. Essas
recusas só acontecem por erro de instalação, mas não podem passar quietas: é esta conferência que mostra o buraco.
Hora em andamento fica de fora, porque os dois lados ainda estão recebendo.
"""

import argparse
from datetime import datetime, timedelta, timezone

from . import armazem, provisao
from .ciclo import ler_env

CONJUNTOS = (("alertas", provisao.indice_do), ("logs", provisao.indice_bruto_do))


def no_indexador(indexer, prefixo, inicio, fim):
    """{hora: total} dos documentos do índice, por hora."""
    corpo = {"size": 0, "query": {"range": {"timestamp": {"gte": inicio.isoformat(), "lt": fim.isoformat()}}},
             "aggs": {"horas": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "time_zone": "UTC"}}}}
    r = indexer.sessao.post(f"{indexer.url}/{prefixo}*/_search", json=corpo, timeout=120)
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    # Sem índice nenhum com o prefixo, o indexador responde sem as agregações.
    baldes = r.json().get("aggregations", {}).get("horas", {}).get("buckets", [])
    return {datetime.fromtimestamp(b["key"] / 1000, timezone.utc): b["doc_count"] for b in baldes if b["doc_count"]}


def comparar(indexer, adm, gerenciador_id, cliente_id, horas=24, agora=None):
    """[(conjunto, hora, no indexador, no armazém, ids distintos)] das horas que não batem."""
    agora = agora or datetime.now(timezone.utc)
    fim = agora.replace(minute=0, second=0, microsecond=0)
    inicio = fim - timedelta(hours=horas)
    banco = armazem.banco_do(cliente_id)
    # O coletor começa no arquivo do dia: o que o Wazuh já tinha rodado para o arquivo compactado fica fora da conta.
    primeiro = adm.linhas(f"""SELECT toUnixTimestamp(toStartOfHour(min(ocorrido_em))) AS hora, count() AS total FROM {banco}.logs
                              WHERE gerenciador = {{gerenciador:String}}""", {"gerenciador": gerenciador_id})
    if primeiro and int(primeiro[0]["total"]):
        inicio = max(inicio, datetime.fromtimestamp(int(primeiro[0]["hora"]), timezone.utc))
    diferencas = []
    for conjunto, prefixo_de in CONJUNTOS:
        de_la = no_indexador(indexer, prefixo_de(gerenciador_id), inicio, fim)
        # O armazém guarda por organização: com mais de um gerenciador, a conta é do gerenciador.
        de_ca = no_armazem(adm, banco, conjunto, gerenciador_id, inicio, fim)
        for hora in sorted(set(de_la) | set(de_ca)):
            esperado, (linhas, ids) = de_la.get(hora, 0), de_ca.get(hora, (0, 0))
            if esperado != ids or linhas != ids:
                diferencas.append((conjunto, hora, esperado, linhas, ids))
    return diferencas


def no_armazem(adm, banco, tabela, gerenciador_id, inicio, fim):
    """{hora: (linhas, ids distintos)} do gerenciador: linha repetida (reenvio) aparece como diferença entre os dois."""
    linhas = adm.linhas(f"""SELECT toUnixTimestamp(toStartOfHour(ocorrido_em)) AS hora, count() AS linhas, uniqExact(id) AS ids
                            FROM {banco}.{tabela} WHERE gerenciador = {{gerenciador:String}}
                              AND ocorrido_em >= {{inicio:DateTime64(3)}} AND ocorrido_em < {{fim:DateTime64(3)}}
                            GROUP BY hora""", {"gerenciador": gerenciador_id, "inicio": inicio.strftime("%Y-%m-%d %H:%M:%S"),
                                               "fim": fim.strftime("%Y-%m-%d %H:%M:%S")})
    return {datetime.fromtimestamp(int(l["hora"]), timezone.utc): (int(l["linhas"]), int(l["ids"])) for l in linhas}


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--horas", type=int, default=24)
    a = args.parse_args()
    env = ler_env(provisao.DESTINO / ".env")
    indexer, adm = provisao.indexer_admin(env), armazem.admin(env)
    with provisao.banco_admin(env) as banco:
        gerenciadores = banco.execute("SELECT id, cliente_id FROM gerenciadores ORDER BY id").fetchall()
    tudo_certo = True
    for gerenciador_id, cliente_id in gerenciadores:
        diferencas = comparar(indexer, adm, gerenciador_id, cliente_id, a.horas)
        for conjunto, hora, esperado, linhas, ids in diferencas:
            tudo_certo = False
            print(f"{gerenciador_id} {conjunto} {hora:%Y-%m-%d %H}h: indexador {esperado}, armazém {ids} ({linhas} linhas)")
        if not diferencas:
            print(f"{gerenciador_id}: as últimas {a.horas} horas batem.")
    raise SystemExit(0 if tudo_certo else 1)


if __name__ == "__main__":
    main()
