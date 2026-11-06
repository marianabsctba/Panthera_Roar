"""A nota da superfície externa, de A a F: 100 pontos menos o peso de cada achado externo aberto.

Uma porta crítica aberta já derruba para C; duas, para F. Informativa não pesa. A evolução é refeita pela história dos
achados (quando apareceram e quando foram corrigidos), dia a dia, sem precisar guardar nada à parte.
"""

PESOS = {"critica": 25, "alta": 10, "media": 4, "baixa": 1}
LETRAS = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))
DIAS_DE_HISTORICO = 90
ABERTO = "a.fonte = 'externa' AND a.estado IN ('aberto', 'correcao_informada')"


def pontos(por_severidade):
    return max(0, 100 - sum(PESOS.get(s, 0) * n for s, n in por_severidade.items()))


def letra(valor):
    return next((l for minimo, l in LETRAS if valor >= minimo), "F")


def _contagem(linha):
    return {s: linha[s] for s in ("critica", "alta", "media", "baixa")}


CONTAR = ", ".join(f"count(a.id) FILTER (WHERE a.severidade = '{s}') AS {s}" for s in ("critica", "alta", "media", "baixa"))


def calcular(con):
    """{"pontos", "letra", "por_severidade", "historico": [{"dia", "pontos", "letra"}], "dominios": {id: {"pontos", "letra"}}}, ou
    None sem domínio cadastrado. Precisa de conexão que devolve dicionários, sob o RLS da organização."""
    inicio = con.execute("SELECT min(autorizado_em)::date AS dia FROM superficie_dominios").fetchone()["dia"]
    if inicio is None:
        return None
    agora = con.execute(f"SELECT {CONTAR} FROM vuln_achados a WHERE {ABERTO}").fetchone()
    por_severidade = _contagem(agora)
    historico = con.execute(f"""SELECT d::date AS dia, {CONTAR}
                                FROM generate_series(greatest(%s, current_date - {DIAS_DE_HISTORICO - 1}), current_date, interval '1 day') d
                                LEFT JOIN vuln_achados a ON a.fonte = 'externa' AND a.estado NOT IN ('aceito', 'falso_positivo')
                                     AND a.primeira_vez::date <= d::date AND (a.corrigido_em IS NULL OR a.corrigido_em::date > d::date)
                                GROUP BY 1 ORDER BY 1""", (inicio,)).fetchall()
    # A nota de cada domínio conta os achados dos nomes dele.
    dominios = con.execute(f"""SELECT h.dominio_id, {CONTAR} FROM superficie_hosts h JOIN vuln_ativos t ON t.host = h.nome
                               JOIN vuln_achados a ON a.ativo_id = t.id AND {ABERTO} GROUP BY 1""").fetchall()
    total = pontos(por_severidade)
    return {
        "pontos": total, "letra": letra(total), "por_severidade": por_severidade,
        "historico": [{"dia": h["dia"].isoformat(), "pontos": pontos(_contagem(h)), "letra": letra(pontos(_contagem(h)))} for h in historico],
        "dominios": {str(d["dominio_id"]): {"pontos": pontos(_contagem(d)), "letra": letra(pontos(_contagem(d)))} for d in dominios},
    }
