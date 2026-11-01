#!/usr/bin/env python3
"""A correlação do Wazuh atravessa agentes? Sem hipótese nenhuma do Roar, só o gerenciador.

    /opt/panthera-roar/venv/bin/python testes/fase1/investigar_correlacao.py

1. Controle: B sozinho dispara a regra de força bruta.
2. Silêncio: A dispara e, em seguida, B ataca de outro IP.
3. Mistura: A e B recebem, cada um, parte das tentativas do mesmo IP.
"""

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from testar_ingestao import Ambiente, escrever_falhas, subir_agente  # noqa: E402


def contar(amb, ip):
    consulta = {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {"data.srcip": ip}}]}},
        "aggs": {"a": {"terms": {"field": "agent.id"}, "aggs": {"r": {"terms": {"field": "rule.id"}}}}},
    }
    r = amb.indexer.sessao.post(f"{amb.indexer.url}/wazuh-alerts-*/_search", json=consulta, timeout=60)
    r.raise_for_status()
    return {b["key"]: {x["key"]: x["doc_count"] for x in b["r"]["buckets"]}
            for b in r.json()["aggregations"]["a"]["buckets"]}


def esperar_chegar(amb, ip, total, limite=120):
    fim = time.time() + limite
    while time.time() < fim:
        visto = contar(amb, ip)
        if sum(sum(r.values()) for r in visto.values()) >= total:
            break
        time.sleep(5)
    # A regra composta chega junto; dá tempo de indexar o que faltar.
    time.sleep(15)
    return contar(amb, ip)


def main():
    amb = Ambiente()
    base = int(time.time()) % 200 + 20
    ips = [f"192.0.2.{base + i}" for i in range(4)]
    try:
        pasta = Path(tempfile.mkdtemp(prefix="roar-correlacao-"))
        id_a, log_a = subir_agente(amb, pasta, "a")
        id_b, log_b = subir_agente(amb, pasta, "b")
        print(f"Agentes: A={id_a} B={id_b}", flush=True)
        time.sleep(90)

        print("\n1. Controle: B sozinho, 10 tentativas", flush=True)
        escrever_falhas(log_b, ips[0], "roar")
        print("  ", esperar_chegar(amb, ips[0], 10), flush=True)
        time.sleep(70)

        print("\n2. Silêncio: A ataca e, logo depois, B ataca de outro IP", flush=True)
        escrever_falhas(log_a, ips[1], "roar")
        escrever_falhas(log_b, ips[2], "roar")
        print("   A:", esperar_chegar(amb, ips[1], 10), flush=True)
        print("   B:", esperar_chegar(amb, ips[2], 10), flush=True)
        time.sleep(70)

        print("\n3. Mistura: o mesmo IP, 5 tentativas em A e 5 em B", flush=True)
        escrever_falhas(log_a, ips[3], "roar", quantidade=5)
        escrever_falhas(log_b, ips[3], "roar", quantidade=5)
        print("  ", esperar_chegar(amb, ips[3], 10), flush=True)
    finally:
        amb.limpar()


if __name__ == "__main__":
    main()
