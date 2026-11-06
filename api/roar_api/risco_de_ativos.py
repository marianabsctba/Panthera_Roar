"""Nota de risco de cada ativo, de 0 a 100, juntando o que o Roar sabe dele.

Cinco partes, cada uma de 0 a 100: falhas abertas (pesando mais as que já são exploradas), comportamento (o risco do UEBA),
indicadores de ameaça vistos, alertas graves e o que falta na configuração segura. Elas se somam como chances independentes, e a criticidade do ativo
decide quanto do total vale. Toda nota vem com os motivos, para a pessoa saber por onde começar.
"""

import math

DIAS = 7
NIVEL_GRAVE = 12
# Pontos por falha aberta, antes de pesar se ela é explorada.
PONTOS = {"critica": 10, "alta": 6, "media": 3, "baixa": 1}
# Quanto cada parte pode levar da nota: indicador de ameaça visto é o sinal mais forte.
# Configuração fraca abre a porta, mas sozinha não é ataque: pesa menos.
PESOS = {"falhas": 0.7, "comportamento": 0.9, "ameacas": 1.0, "alertas": 0.6, "configuracao": 0.4}
CONFIGURACAO_RUIM = 70
# Quanto do total vale em cada criticidade.
FATOR = {"baixa": 0.6, "normal": 0.8, "alta": 0.9, "critica": 1.0}
FAIXAS = ((70, "critico"), (40, "alto"), (20, "medio"), (0, "baixo"))

# Por falha: o maior peso entre as CVEs dela. Catálogo de exploradas (KEV) primeiro, depois a chance de exploração (EPSS).
_FALHAS = f"""
    WITH falhas AS (
      SELECT a.ativo_id, a.severidade,
             coalesce(max(CASE WHEN c.kev_ransomware THEN 4 WHEN c.kev_desde IS NOT NULL THEN 3
                               WHEN c.epss >= 0.5 THEN 2 WHEN c.epss >= 0.1 THEN 1.5 ELSE 1 END), 1) AS fator,
             bool_or(c.kev_desde IS NOT NULL) AS explorada
      FROM vuln_achados a LEFT JOIN LATERAL unnest(a.cves) AS u(cve) ON true LEFT JOIN cves c ON c.cve = u.cve
      WHERE a.estado IN ('aberto', 'correcao_informada') GROUP BY a.id, a.ativo_id, a.severidade)
    SELECT t.id, t.host, t.nome, t.sistema, t.peso,
           coalesce(sum(f.fator * CASE f.severidade {" ".join(f"WHEN '{s}' THEN {p}" for s, p in PONTOS.items())} ELSE 0 END), 0) AS pontos,
           count(f.ativo_id) AS abertas,
           count(*) FILTER (WHERE f.severidade IN ('critica', 'alta')) AS graves,
           count(*) FILTER (WHERE f.explorada) AS exploradas
    FROM vuln_ativos t LEFT JOIN falhas f ON f.ativo_id = t.id
    WHERE t.monitorado GROUP BY t.id"""

_DOS_AGENTES = """
    SELECT a.gerenciador_id, a.agente_id, a.criticidade, a.sca_nota, coalesce(nullif(a.ip, ''), coalesce(a.nome, a.agente_id)) AS host,
           (SELECT e.risco FROM entidades e WHERE e.tipo = 'ativo' AND e.chave = a.gerenciador_id || ':' || a.agente_id
              AND e.risco_em >= now() - make_interval(days => %(dias)s)) AS comportamento,
           (SELECT count(DISTINCT o.indicador_id) FROM intel_ocorrencias o JOIN eventos v ON v.id = o.evento_id
             WHERE o.ocorrido_em >= now() - make_interval(days => %(dias)s)
               AND v.gerenciador_id = a.gerenciador_id AND v.agente_id = a.agente_id) AS ameacas,
           (SELECT count(*) FROM eventos v WHERE v.gerenciador_id = a.gerenciador_id AND v.agente_id = a.agente_id
              AND v.nivel >= %(grave)s AND v.ocorrido_em >= now() - make_interval(days => %(dias)s)) AS alertas
    FROM ativos a WHERE a.agente_id <> '000'"""


def _saturar(valor, meia):
    """De 0 a 100: chega a metade em `meia` e nunca passa de 100, para mil falhas não valerem dez vezes cem."""
    return 100 * (1 - math.exp(-math.log(2) * valor / meia)) if valor > 0 else 0.0


def _criticidade_do_peso(peso):
    return {1: "baixa", 2: "baixa", 3: "normal", 4: "alta", 5: "critica"}.get(peso, "normal")


def nota(falhas=None, comportamento=0.0, ameacas=0, alertas=0, criticidade="normal", configuracao=None):
    """falhas: linha de _FALHAS ou None; configuracao: a nota da configuração segura, ou None sem checagem. Devolve {nota, faixa, partes, motivos}."""
    falhas = falhas or {"pontos": 0, "abertas": 0, "graves": 0, "exploradas": 0}
    partes = {
        "falhas": round(_saturar(float(falhas["pontos"]), 30)),
        "comportamento": round(min(100.0, max(0.0, float(comportamento or 0)))),
        "ameacas": round(_saturar(ameacas, 1)),
        "alertas": round(_saturar(alertas, 5)),
        "configuracao": 0 if configuracao is None else round(100 - min(100, max(0, float(configuracao)))),
    }
    sobra = 1.0
    for parte, valor in partes.items():
        sobra *= 1 - PESOS[parte] * valor / 100
    total = round(100 * (1 - sobra) * FATOR.get(criticidade, FATOR["normal"]))
    motivos = []
    if ameacas:
        motivos.append(f"{ameacas} indicador{'es' if ameacas > 1 else ''} de ameaça visto{'s' if ameacas > 1 else ''} em {DIAS} dias")
    if falhas["exploradas"]:
        motivos.append(f"{falhas['exploradas']} falha{'s' if falhas['exploradas'] > 1 else ''} que já {'são exploradas' if falhas['exploradas'] > 1 else 'é explorada'} por atacantes")
    if partes["comportamento"] >= 15:
        motivos.append(f"comportamento fora do normal (risco {partes['comportamento']})")
    if falhas["graves"]:
        motivos.append(f"{falhas['graves']} falha{'s' if falhas['graves'] > 1 else ''} crítica{'s' if falhas['graves'] > 1 else ''} ou alta{'s' if falhas['graves'] > 1 else ''} aberta{'s' if falhas['graves'] > 1 else ''}")
    elif falhas["abertas"]:
        motivos.append(f"{falhas['abertas']} falha{'s' if falhas['abertas'] > 1 else ''} aberta{'s' if falhas['abertas'] > 1 else ''}")
    if configuracao is not None and configuracao < CONFIGURACAO_RUIM:
        motivos.append(f"configuração segura em {round(configuracao)}%")
    if alertas:
        motivos.append(f"{alertas} alerta{'s' if alertas > 1 else ''} grave{'s' if alertas > 1 else ''} em {DIAS} dias")
    if criticidade in ("alta", "critica") and total:
        motivos.append(f"criticidade {'alta' if criticidade == 'alta' else 'crítica'}")
    return {"nota": total, "faixa": next(f for limite, f in FAIXAS if total >= limite), "partes": partes, "motivos": motivos}


def calcular(con):
    """Precisa de con com o cliente definido. Devolve ({(gerenciador, agente): nota}, [ativos só de varredura, com nota]).

    O ativo com agente e o mesmo endereço varrido são um só: as falhas dos dois somam na mesma nota.
    """
    por_host = {l["host"]: l for l in con.execute(_FALHAS).fetchall()}
    agentes, usados = {}, set()
    for a in con.execute(_DOS_AGENTES, {"dias": DIAS, "grave": NIVEL_GRAVE}).fetchall():
        falhas = por_host.get(a["host"])
        if falhas:
            usados.add(a["host"])
        agentes[(a["gerenciador_id"], a["agente_id"])] = nota(falhas, a["comportamento"], a["ameacas"], a["alertas"], a["criticidade"], a["sca_nota"])
    sem_agente = []
    for host, f in por_host.items():
        if host in usados:
            continue
        criticidade = _criticidade_do_peso(f["peso"])
        sem_agente.append({"id": f["id"], "host": host, "nome": f["nome"], "sistema": f["sistema"], "criticidade": criticidade,
                           "abertas": f["abertas"], **nota(f, criticidade=criticidade)})
    sem_agente.sort(key=lambda x: (-x["nota"], x["host"]))
    return agentes, sem_agente
