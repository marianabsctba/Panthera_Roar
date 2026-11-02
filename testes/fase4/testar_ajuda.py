#!/usr/bin/env python3
"""A ajuda acompanha as telas, os atalhos levam a algum lugar, e o que ela afirma bate com o código.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_ajuda.py
"""

import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api.app import ESTATICO, app  # noqa: E402
from roar_ingestao.cves import prioridade  # noqa: E402

RESULTADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    ajuda = (ESTATICO / "ajuda.js").read_text(encoding="utf-8")
    html = (ESTATICO / "index.html").read_text(encoding="utf-8")
    js = (ESTATICO / "roar.js").read_text(encoding="utf-8")

    print("== Telas", flush=True)
    telas = set(re.findall(r'data-vista="([a-z]+)"', html)) - {"ajuda"}
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
    registrar("o artigo inicial existe", 'artigoAberto = "primeiros-passos"' in js and "primeiros-passos" in ids)

    print("\n== Página", flush=True)
    registrar("o código da tela importa a ajuda", 'import { AJUDA } from "/estatico/ajuda.js";' in js)
    registrar("nenhum recurso externo", "http://" not in ajuda and "https://" not in ajuda)
    for proibido in ("wazuh", "opensearch", "temporal", "keycloak", "be safe", "campus", "postgres", "rabbitmq"):
        registrar(f"sem nome de bastidor: {proibido}", proibido not in ajuda.lower())
    registrar("sem travessão", "—" not in ajuda and "–" not in ajuda)
    registrar("não monta HTML com texto", "innerHTML" not in ajuda and "insertAdjacentHTML" not in ajuda)

    # Um nome declarado duas vezes derruba o módulo inteiro, e a tela abre em branco.
    declarados = re.findall(r"^(?:const|let|function|async function) +([A-Za-z_$][\w$]*)", js, re.M)
    repetidos = {n for n in declarados if declarados.count(n) > 1}
    registrar("nenhum nome declarado duas vezes no código da tela", not repetidos, str(repetidos))

    print("\n== O que a ajuda afirma", flush=True)
    registrar("KEV vem antes de tudo", prioridade("2024-01-01", 0.0, 1.0) == "agora" and "catálogo KEV" in ajuda)
    registrar("EPSS de 50% é alta", prioridade(None, 0.5, 1.0) == "alta" and prioridade(None, 0.49, 1.0) != "alta" and "EPSS de 50%" in ajuda)
    registrar("CVSS 9 é alta", prioridade(None, 0.0, 9.0) == "alta" and prioridade(None, 0.0, 8.9) != "alta" and "CVSS 9" in ajuda)
    registrar("EPSS de 5% é média", prioridade(None, 0.05, 1.0) == "media" and prioridade(None, 0.04, 1.0) != "media" and "EPSS de 5%" in ajuda)
    registrar("CVSS 7 é média", prioridade(None, 0.0, 7.0) == "media" and prioridade(None, 0.0, 6.9) != "media" and "CVSS 7" in ajuda)
    registrar("sem nota não vira baixa", prioridade(None, 0.0, None) == "sem_dados" and "Sem nota" in ajuda)
    from roar_api import mfa
    registrar("10 códigos de recuperação", mfa.CODIGOS_DE_RECUPERACAO == 10 and "10 códigos de recuperação" in ajuda)
    registrar("o limite do risco é o da tela", "O alerta abre em 60 pontos" in ajuda and "O alerta abre em 60 pontos" in html)
    from roar_motor.blocos import ACOES_CONHECIDAS
    registrar("a ajuda cobre as ações dos playbooks", set(ACOES_CONHECIDAS) == {"bloquear_ip", "desativar_conta", "webhook", "registrar"}, str(ACOES_CONHECIDAS))

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
