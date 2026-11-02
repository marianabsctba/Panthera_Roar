"""O que pode disparar um playbook, lido sob o RLS da transação. O disparo e a simulação usam o mesmo."""


def _de_evento(e):
    return {**e, "origem_tipo": "evento", "origem_id": e["id"], "titulo": e["regra_descricao"]}


def eventos_depois_de(con, ultimo, limite):
    linhas = con.execute(
        """SELECT id, regra_id, regra_descricao, nivel, severidade, host(ip_origem) AS alvo, usuario, agente_id, gerenciador_id, ocorrido_em, pais
           FROM eventos WHERE id > %s ORDER BY id LIMIT %s""",
        (ultimo, limite),
    ).fetchall()
    return [_de_evento(e) for e in linhas]


def eventos_da_regra(con, regra_id, dias, limite):
    linhas = con.execute(
        """SELECT id, regra_id, regra_descricao, nivel, severidade, host(ip_origem) AS alvo, usuario, agente_id, gerenciador_id, ocorrido_em, pais
           FROM eventos WHERE regra_id = %s AND ocorrido_em > now() - make_interval(days => %s)
           ORDER BY ocorrido_em LIMIT %s""",
        (regra_id, dias, limite),
    ).fetchall()
    return [_de_evento(e) for e in linhas]


_DO_INDICADOR = """SELECT o.id AS ocorrencia, o.no_passado, i.tipo AS indicador_tipo, i.valor AS indicador,
                         e.id, e.regra_id, e.regra_descricao, e.nivel, e.severidade, host(e.ip_origem) AS alvo, e.usuario, e.agente_id, e.gerenciador_id, e.ocorrido_em, e.pais
                  FROM intel_ocorrencias o JOIN intel_indicadores i ON i.id = o.indicador_id JOIN eventos e ON e.id = o.evento_id"""


def _de_indicador(o):
    # O valor vem de uma fonte externa: vai só como texto, e curto.
    return {**o, "origem_tipo": "indicador", "origem_id": o["id"], "titulo": f"Indicador de ameaça: {o['indicador'][:200]}"}


def indicadores_depois_de(con, ultima, limite):
    """Devolve também os achados no passado, para o cursor andar. Quem decide o que vira resposta é o disparo."""
    linhas = con.execute(f"{_DO_INDICADOR} WHERE o.id > %s ORDER BY o.id LIMIT %s", (ultima, limite)).fetchall()
    return [_de_indicador(o) for o in linhas]


def indicadores_recentes(con, dias, limite):
    linhas = con.execute(
        f"{_DO_INDICADOR} WHERE NOT o.no_passado AND e.ocorrido_em > now() - make_interval(days => %s) ORDER BY e.ocorrido_em LIMIT %s", (dias, limite)).fetchall()
    return [_de_indicador(o) for o in linhas]


def _riscos(con, filtro, argumentos=()):
    # O alvo de um risco é o sinal mais recente da entidade que trouxe um endereço.
    linhas = con.execute(
        f"""SELECT a.id, a.severidade, a.aberto_em AS ocorrido_em, n.chave, e.nivel, host(e.ip_origem) AS alvo, e.agente_id, e.gerenciador_id,
                   CASE WHEN n.tipo = 'usuario' THEN n.chave ELSE e.usuario END AS usuario
            FROM alertas_risco a
            JOIN entidades n ON n.id = a.entidade_id
            JOIN LATERAL (
              SELECT ev.nivel, ev.ip_origem, ev.usuario, ev.agente_id, ev.gerenciador_id
              FROM sinais s JOIN eventos ev ON ev.id = s.evento_id
              WHERE s.entidade_id = a.entidade_id
              ORDER BY ev.ip_origem IS NOT NULL DESC, s.ocorrido_em DESC LIMIT 1
            ) e ON true
            WHERE {filtro} ORDER BY a.aberto_em""",
        argumentos,
    ).fetchall()
    return [{**r, "origem_tipo": "risco", "origem_id": r["id"], "titulo": f"Risco de {r['chave']}"} for r in linhas]


def riscos_abertos(con):
    return _riscos(con, "a.estado = 'aberto'")


def riscos_recentes(con, dias):
    return _riscos(con, "a.aberto_em > now() - make_interval(days => %s)", (dias,))
