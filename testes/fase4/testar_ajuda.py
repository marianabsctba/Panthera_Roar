#!/usr/bin/env python3
"""A ajuda acompanha as telas, os atalhos levam a algum lugar, e o que ela afirma bate com o código.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_ajuda.py
"""

import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor"), str(RAIZ / "ueba")]

from roar_api.app import ESTATICO, app  # noqa: E402
from roar_ingestao.cves import prioridade  # noqa: E402

RESULTADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    ajuda = (ESTATICO / "ajuda.js").read_text(encoding="utf-8")
    menu = (RAIZ / "web/src/Aplicacao.tsx").read_text(encoding="utf-8")
    tela = (RAIZ / "web/src/telas/Ajuda.tsx").read_text(encoding="utf-8")

    print("== Telas", flush=True)
    telas = set(re.findall(r'\{ id: "([a-z]+)", rotulo:', menu)) - {"ajuda"}
    artigos_de_tela = set(re.findall(r'vista: "([a-z]+)"', ajuda))
    registrar("há telas para conferir", len(telas) >= 14, str(len(telas)))
    registrar("toda tela tem artigo", not telas - artigos_de_tela, str(telas - artigos_de_tela))
    registrar("todo artigo aponta para uma tela que existe", not artigos_de_tela - telas, str(artigos_de_tela - telas))

    print("\n== Atalhos", flush=True)
    ids = re.findall(r'\{ id: "([a-z-]+)"', ajuda)
    registrar("ids sem repetição", len(ids) == len(set(ids)))
    alvos = set(re.findall(r'artigo: "([a-z-]+)"', ajuda))
    registrar("há atalhos para conferir", alvos)
    registrar("todo atalho leva a um artigo", not alvos - set(ids), str(alvos - set(ids)))
    registrar("o artigo inicial existe", '|| "primeiros-passos"' in tela and "primeiros-passos" in ids)

    print("\n== Página", flush=True)
    registrar("a tela usa a ajuda", "AJUDA" in tela)
    registrar("nenhum recurso externo", "http://" not in ajuda and "https://" not in ajuda)
    for proibido in ("wazuh", "opensearch", "temporal", "keycloak", "postgres", "rabbitmq"):
        registrar(f"sem nome de bastidor: {proibido}", proibido not in ajuda.lower())
    registrar("sem travessão", "—" not in ajuda and "–" not in ajuda)
    registrar("não monta HTML com texto", "innerHTML" not in ajuda and "insertAdjacentHTML" not in ajuda)

    # A tela e o CSS podem ser pesados, mas nada do mapa vem de fora.
    registrar("o mapa vem do próprio servidor", (ESTATICO / "mapa-paises.json").stat().st_size > 1000)

    print("\n== O que a ajuda afirma", flush=True)
    registrar("KEV vem antes de tudo", prioridade("2024-01-01", 0.0, 1.0) == "agora" and "catálogo KEV" in ajuda)
    registrar("EPSS de 50% é alta", prioridade(None, 0.5, 1.0) == "alta" and prioridade(None, 0.49, 1.0) != "alta" and "EPSS de 50%" in ajuda)
    registrar("CVSS 9 é alta", prioridade(None, 0.0, 9.0) == "alta" and prioridade(None, 0.0, 8.9) != "alta" and "CVSS 9" in ajuda)
    registrar("EPSS de 5% é média", prioridade(None, 0.05, 1.0) == "media" and prioridade(None, 0.04, 1.0) != "media" and "EPSS de 5%" in ajuda)
    registrar("CVSS 7 é média", prioridade(None, 0.0, 7.0) == "media" and prioridade(None, 0.0, 6.9) != "media" and "CVSS 7" in ajuda)
    registrar("sem nota não vira baixa", prioridade(None, 0.0, None) == "sem_dados" and "Sem nota" in ajuda)
    from roar_api import mfa
    registrar("10 códigos de recuperação", mfa.CODIGOS_DE_RECUPERACAO == 10 and "10 códigos de recuperação" in ajuda)
    registrar("o limite do risco é o da tela", "O alerta abre em 60 pontos" in ajuda and "O alerta abre em 60 pontos" in (RAIZ / "web/src/telas/Regras.tsx").read_text(encoding="utf-8"))
    from roar_motor.blocos import ACOES_CONHECIDAS
    registrar("a ajuda cobre as ações dos playbooks", set(ACOES_CONHECIDAS) == {"bloquear_ip", "desativar_conta", "webhook", "registrar"}, str(ACOES_CONHECIDAS))

    from roar_ueba.motor import FATOR_DA_CRITICIDADE, PESOS, Parametros
    sinais = dict(re.findall(r'(\w+): "([^"]+)"', (RAIZ / "web/src/formato.ts").read_text(encoding="utf-8").split("export const SINAIS")[1].split("};")[0]))
    faltam = [t for tipo, t in sinais.items() if tipo in PESOS and t not in ajuda]
    registrar("todo sinal de comportamento está na ajuda", set(PESOS) <= set(sinais) and not faltam, str(faltam or set(PESOS) - set(sinais)))
    errados = [t for tipo, t in sinais.items() if tipo in PESOS and tipo != "regra_disparada" and f'["{t}", "{int(PESOS[tipo])} pontos"]' not in ajuda]
    registrar("os pontos de cada sinal são os do motor", not errados, str(errados))
    p = Parametros()
    registrar("o aprendizado é o do motor", (p.aprendizado_dias, p.aprendizado_sucessos) == (14, 20) and "14 dias e 20 acessos" in ajuda)
    registrar("o desconto dos pares é o do motor", p.fracao_com_pares == 1 / 3 and "soma um terço" in ajuda)
    registrar("a criticidade pesa o que a ajuda diz", FATOR_DA_CRITICIDADE == {"baixa": 0.5, "normal": 1.0, "alta": 1.5, "critica": 2.0}
              and "metade, o normal, 1,5 vez ou o dobro" in ajuda)
    from roar_api.app import LIMITE_DA_EXPORTACAO_OCSF, PRAZO_DO_CASO
    registrar("os prazos dos casos são os da API", {k: v.total_seconds() / 3600 for k, v in PRAZO_DO_CASO.items()} == {"critica": 4, "alta": 24, "media": 72, "baixa": 168}
              and all(f'["{r}", "{t}"]' in ajuda for r, t in (("Crítica", "4 h"), ("Alta", "24 h"), ("Média", "3 dias"), ("Baixa", "7 dias"))))
    registrar("o limite da exportação OCSF é o da API", LIMITE_DA_EXPORTACAO_OCSF == 10_000 and "até 10.000 eventos" in ajuda)

    print("\n== Entrega", flush=True)
    with TestClient(app, base_url="https://testserver") as http:
        r = http.get("/estatico/ajuda.js")
        registrar("o navegador recebe o arquivo", r.status_code == 200 and "AJUDA" in r.text, str(r.status_code))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
