"""Saúde de cada fonte de dados, lida do resumo por hora do armazém (origens_por_hora, ingestao/roar_ingestao/armazem.py).

Para cada fonte: quantos eventos chegaram nas últimas 24 horas, a vazão, quanto o gerenciador entendeu (decodificou), as
horas do dia num gráfico, e se a última hora ficou muito abaixo do normal. O normal é a média da mesma hora nos dias
anteriores: firewall de escritório que fica quieto de madrugada não vira alarme falso. No syslog, a mesma conta sai para
cada equipamento da lista, que é o que diz qual deles parou. A tela (GET /api/fontes) e o aviso de fonte quieta
(ingestao/roar_ingestao/fontes_quietas.py) usam a mesma conta.
"""

import ipaddress
from datetime import datetime, timedelta, timezone

from .consulta_sql import Tradutor

HORAS = 24
DIAS_DO_NORMAL = 7
# Abaixo disso por hora, a fonte é pequena demais para dizer que caiu: um evento a menos já pareceria queda.
MINIMO_DO_NORMAL = 60
# A última hora com menos de um quinto do normal é queda.
FRACAO_DA_QUEDA = 0.2
# Os módulos de nuvem aparecem com o próprio nome no lugar da origem.
NOME_DO_MODULO = {"msgraph": "ms-graph", "aws": "Wazuh-AWS", "azure": "azure", "gcp": "Wazuh-GCloud"}


def _hora(agora):
    return agora.replace(minute=0, second=0, microsecond=0)


def ler(armazem, banco, gerenciador_id, agora=None):
    """{local: {"ultimo": ms, "horas": {hora unix: (eventos, entendidos)}, "primeira": hora unix}} dos últimos 8 dias."""
    agora = agora or datetime.now(timezone.utc)
    desde = _hora(agora) - timedelta(days=DIAS_DO_NORMAL + 1)
    t = Tradutor()
    linhas = armazem.linhas(
        f"""SELECT local, toUnixTimestamp(hora) AS h, sum(eventos) AS e, sum(entendidos) AS d, toUnixTimestamp64Milli(max(ultimo)) AS u
            FROM {banco}.origens_por_hora
            WHERE gerenciador = {t.p(gerenciador_id)} AND hora >= {t.p(desde.strftime('%Y-%m-%d %H:%M:%S'), "DateTime('UTC')")} AND notEmpty(local)
            GROUP BY local, hora""", t.parametros)
    origens = {}
    for l in linhas:
        o = origens.setdefault(l["local"], {"ultimo": 0.0, "horas": {}})
        o["horas"][int(l["h"])] = (int(l["e"]), int(l["d"]))
        o["ultimo"] = max(o["ultimo"], float(l["u"]))
    for o in origens.values():
        o["primeira"] = min(o["horas"])
    return origens


def somar(origens, agora=None):
    """Junta as origens de uma fonte numa conta só."""
    agora = agora or datetime.now(timezone.utc)
    atual = int(_hora(agora).timestamp())
    ultima = atual - 3600
    horas = [atual - 3600 * i for i in range(HORAS - 1, -1, -1)]
    serie = [0] * HORAS
    eventos_24h = entendidos_24h = ultima_hora = mesma_hora = 0
    ultimo, primeira = 0.0, None
    for o in origens:
        ultimo = max(ultimo, o["ultimo"])
        primeira = o["primeira"] if primeira is None else min(primeira, o["primeira"])
        for i, h in enumerate(horas):
            e, d = o["horas"].get(h, (0, 0))
            serie[i] += e
            eventos_24h += e
            entendidos_24h += d
        ultima_hora += o["horas"].get(ultima, (0, 0))[0]
        mesma_hora += sum(o["horas"].get(ultima - 86400 * k, (0, 0))[0] for k in range(1, DIAS_DO_NORMAL + 1))
    # A média vale só pelos dias em que a fonte já existia: uma fonte de dois dias não divide por sete.
    dias = min(DIAS_DO_NORMAL, (ultima - primeira) // 86400) if primeira is not None else 0
    normal = round(mesma_hora / dias) if dias >= 1 else None
    return {
        "eventos_24h": eventos_24h,
        "eps": round(eventos_24h / (HORAS * 3600), 3),
        "entendidos": round(100 * entendidos_24h / eventos_24h, 1) if eventos_24h else None,
        "horas": serie,
        "ultima_hora": ultima_hora,
        "normal_da_hora": normal,
        "abaixo_do_normal": normal is not None and normal >= MINIMO_DO_NORMAL and ultima_hora < normal * FRACAO_DA_QUEDA,
        "ultimo": ultimo or None,
    }


def origens_da_fonte(fonte, origens):
    """{local: origem} que pertencem à fonte: no syslog, os endereços da lista; na nuvem, o nome do módulo."""
    if fonte["tipo"] == "syslog":
        redes = [ipaddress.ip_network(r) for r in fonte["config"]["origens"]]
        achadas = {}
        for local, o in origens.items():
            try:
                if any(ipaddress.ip_address(local) in rede for rede in redes):
                    achadas[local] = o
            except ValueError:
                continue  # Agentes aparecem aqui com o caminho do arquivo, não com um endereço.
        return achadas
    nome = NOME_DO_MODULO.get(fonte["tipo"], fonte["tipo"])
    return {nome: origens[nome]} if nome in origens else {}


def _iso(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat() if ms else None


def da_fonte(fonte, origens, agora=None):
    """A conta da fonte, e no syslog a de cada equipamento (os quietos primeiro)."""
    proprias = origens_da_fonte(fonte, origens)
    total = somar(proprias.values(), agora)
    total["ultimo"] = _iso(total["ultimo"])
    if fonte["tipo"] == "syslog":
        equipamentos = []
        for local, o in proprias.items():
            conta = somar([o], agora)
            equipamentos.append({"endereco": local, "ultimo": _iso(conta["ultimo"]), "eventos_24h": conta["eventos_24h"],
                                 "entendidos": conta["entendidos"], "ultima_hora": conta["ultima_hora"],
                                 "normal_da_hora": conta["normal_da_hora"], "abaixo_do_normal": conta["abaixo_do_normal"]})
        equipamentos.sort(key=lambda q: (not q["abaixo_do_normal"], q["ultimo"] or "", q["endereco"]))
        total["equipamentos"] = equipamentos
    return total
