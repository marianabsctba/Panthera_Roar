"""Prazo, idade e tempo de correção das falhas, e o que corrigir primeiro.

O prazo conta de quando a falha foi vista pela primeira vez. Falha já explorada por atacantes usa o prazo de exploradas
quando ele é menor. Informativa não tem prazo.
"""

# Os mesmos de muitos programas de gestão de vulnerabilidades. Cada organização muda os seus.
PADRAO = {"critica": 15, "alta": 30, "media": 90, "baixa": 180, "explorada": 7}
FAIXAS_DE_IDADE = ((0, 30), (31, 60), (61, 90), (91, None))
ABERTOS = "a.estado IN ('aberto', 'correcao_informada')"
SEVERIDADES_COM_PRAZO = ("critica", "alta", "media", "baixa")

# Com RLS, vuln_prazos só mostra a linha da organização da sessão; sem linha, valem os padrões.
PRAZOS = "(SELECT " + ", ".join(f"coalesce((SELECT {k} FROM vuln_prazos), {v}) AS {k}" for k, v in PADRAO.items()) + ")"
EXPLORADA = "EXISTS (SELECT 1 FROM cves c WHERE c.cve = ANY(a.cves) AND c.kev_desde IS NOT NULL)"
# Os prazos entram uma vez na consulta, com JUNTAR_PRAZOS, e não uma vez por linha.
JUNTAR_PRAZOS = f"CROSS JOIN {PRAZOS} pz"
_DIAS = f"CASE a.severidade {' '.join(f'WHEN {chr(39)}{s}{chr(39)} THEN pz.{s}' for s in SEVERIDADES_COM_PRAZO)} END"
VENCE_EM = f"""(a.primeira_vez + make_interval(days => CASE WHEN a.severidade NOT IN {SEVERIDADES_COM_PRAZO} THEN NULL
                                                         WHEN {EXPLORADA} THEN least(pz.explorada, {_DIAS}) ELSE {_DIAS} END))"""
# O pacote, quando o agente ou a varredura de contêiner acharam; senão, o próprio título: é o que a pessoa vai corrigir.
# As chaves são agente|pacote|cve e conteiner|cve|pacote|...
FONTES_COM_PACOTE = ("agente", "conteiner")
CORRECAO = "CASE a.fonte WHEN 'agente' THEN split_part(a.chave, '|', 2) WHEN 'conteiner' THEN split_part(a.chave, '|', 3) ELSE a.titulo END"


def prazos(con):
    return dict(con.execute(f"SELECT * FROM {PRAZOS} p").fetchone())


def indicadores(con, dias):
    """Precisa de con com o cliente definido e linhas como dicionário."""
    abertos = f"""SELECT a.*, {VENCE_EM} AS vence_em, {EXPLORADA} AS explorada, {CORRECAO} AS correcao
                  FROM vuln_achados a {JUNTAR_PRAZOS} WHERE {ABERTOS}"""
    situacao = con.execute(f"""SELECT count(*) FILTER (WHERE vence_em < now()) AS vencidos,
                                      count(*) FILTER (WHERE vence_em >= now() AND vence_em < now() + interval '7 days') AS vencem_em_7_dias,
                                      count(*) FILTER (WHERE vence_em IS NOT NULL) AS com_prazo
                               FROM ({abertos}) x""").fetchone()
    corrigidos = con.execute(f"""SELECT a.severidade, count(*) AS total, count(*) FILTER (WHERE a.corrigido_em <= {VENCE_EM}) AS no_prazo,
                                        extract(epoch FROM avg(a.corrigido_em - a.primeira_vez)) / 86400 AS dias_para_corrigir
                                 FROM vuln_achados a {JUNTAR_PRAZOS} WHERE a.estado = 'corrigido' AND a.corrigido_em >= now() - make_interval(days => %s)
                                 GROUP BY 1""", (dias,)).fetchall()
    faixas = ", ".join(f"count(*) FILTER (WHERE idade >= {de}{f' AND idade <= {ate}' if ate else ''}) AS \"{de}\"" for de, ate in FAIXAS_DE_IDADE)
    idade = con.execute(f"""SELECT severidade, {faixas}, count(*) AS total, max(idade) AS mais_velho
                            FROM (SELECT a.severidade, extract(day FROM now() - a.primeira_vez)::int AS idade FROM vuln_achados a WHERE {ABERTOS}) x
                            GROUP BY 1""").fetchall()
    primeiro = con.execute(f"""SELECT correcao, fonte IN {FONTES_COM_PACOTE} AS pacote, count(*) AS falhas, count(DISTINCT ativo_id) AS ativos,
                                      count(*) FILTER (WHERE explorada) AS exploradas, count(*) FILTER (WHERE vence_em < now()) AS vencidas,
                                      min(vence_em) AS vence_primeiro,
                                      (array_agg(severidade ORDER BY array_position(ARRAY['critica', 'alta', 'media', 'baixa', 'informativa'], severidade)))[1] AS pior
                               FROM ({abertos}) x GROUP BY 1, 2
                               ORDER BY count(*) FILTER (WHERE explorada) DESC, count(*) FILTER (WHERE vence_em < now()) DESC,
                                        array_position(ARRAY['critica', 'alta', 'media', 'baixa', 'informativa'],
                                                       (array_agg(severidade ORDER BY array_position(ARRAY['critica', 'alta', 'media', 'baixa', 'informativa'], severidade)))[1]),
                                        count(*) DESC, 1
                               LIMIT 20""").fetchall()
    por_severidade = {l["severidade"]: l for l in corrigidos}
    total = sum(l["total"] for l in corrigidos)
    return {
        "prazos": prazos(con), "padrao": PADRAO, "periodo": dias, **situacao,
        "no_prazo": round(100 * sum(l["no_prazo"] for l in corrigidos) / total) if total else None,
        "corrigidos": {s: {"total": l["total"], "no_prazo": l["no_prazo"],
                           "dias_para_corrigir": round(float(l["dias_para_corrigir"]), 1) if l["dias_para_corrigir"] is not None else None}
                       for s, l in por_severidade.items()},
        "faixas": [{"de": de, "ate": ate} for de, ate in FAIXAS_DE_IDADE],
        "idade": idade, "primeiro": primeiro,
    }
