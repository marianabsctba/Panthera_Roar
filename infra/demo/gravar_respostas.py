#!/usr/bin/env python3
"""Grava as respostas da API para a demonstração estática da console (infra/demo/LEIAME.md).

    sudo /opt/panthera-roar/venv/bin/python infra/demo/gravar_respostas.py --email <usuário da Demonstração> --senha-em <arquivo> --saida web/public-demo/dados-demo.json

Entra na API como o usuário dado (use um da organização Demonstração, só com dados fictícios), percorre as rotas GET que
a console usa, acha os ids nas listas para pedir os detalhes, roda os blocos dos painéis e dos modelos, e grava tudo num
JSON. No fim, troca o que for da máquina ou de pessoas reais (TROCAS) e confere que nada disso sobrou.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao")]

from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# O que não entra: arquivos (PDF, CSV, XML), saídas para fora, login e o que gera algo a cada chamada.
FORA = re.compile(r"/(exportar|pdf|relatorio$|relatorios$|evidencia|evidencias/|sso/|passkeys/|mfa/|sair|entrar|logos|arquivos/[^/]+$)")
ITENS_POR_DETALHE = 5
TENTATIVAS_POR_DETALHE = 40


def valores(dado, chave):
    """Os valores da chave em qualquer objeto da resposta, em qualquer nível."""
    vistos, fila = [], [dado]
    while fila and len(vistos) < 50:
        atual = fila.pop(0)
        if isinstance(atual, dict):
            v = atual.get(chave)
            if isinstance(v, (int, str)) and not isinstance(v, bool) and v not in vistos and len(str(v)) < 200:
                vistos.append(v)
            fila.extend(x for x in atual.values() if isinstance(x, (dict, list)))
        elif isinstance(atual, list):
            fila.extend(x for x in atual[:50] if isinstance(x, (dict, list)))
    return vistos


def principal():
    args = argparse.ArgumentParser()
    args.add_argument("--email", required=True)
    args.add_argument("--senha-em", required=True)
    args.add_argument("--saida", required=True)
    args.add_argument("--trocas", default=str(Path(__file__).with_name("trocas.json")))
    a = args.parse_args()
    os.environ.setdefault("ROAR_COOKIE_SEGURO", "1")
    from roar_api.app import app

    respostas = {}
    with TestClient(app, base_url="https://testserver") as http:
        r = http.post("/api/entrar", json={"email": a.email, "senha": Path(a.senha_em).read_text().strip()})
        if r.status_code not in (200, 204):
            raise SystemExit(f"não entrou: {r.status_code} {r.text[:200]}")

        def pegar(caminho, metodo="GET", corpo=None):
            resposta = http.request(metodo, caminho, json=corpo)
            if resposta.status_code == 200 and resposta.headers.get("content-type", "").startswith("application/json"):
                chave = f"{metodo} {caminho}" + (f" {json.dumps(corpo, sort_keys=True, ensure_ascii=False)}" if corpo is not None else "")
                respostas[chave] = resposta.json()
                return respostas[chave]
            return None

        rotas = [r for r in app.routes if isinstance(r, APIRoute) and "GET" in r.methods and r.path.startswith("/api/") and not FORA.search(r.path)]
        simples = [r.path for r in rotas if "{" not in r.path]
        for caminho in simples:
            pegar(caminho)
        # Os detalhes: os ids vêm da lista "mãe" (o caminho até o primeiro parâmetro) e, se faltar, de todas as respostas.
        # Duas passadas: um detalhe pode depender de outro (o id da entidade vem no detalhe do risco).
        detalhadas = set()
        for rota in [r for _ in range(2) for r in sorted((r for r in rotas if "{" in r.path), key=lambda r: r.path.count("{"))]:
            if rota.path in detalhadas:
                continue
            parametros = re.findall(r"\{(\w+)(?::\w+)?\}", rota.path)
            if len(parametros) > 1:
                continue
            nome = parametros[0]
            # /api/entidades/{identificador} procura também entidade_id: é como a outra ponta chama o mesmo id.
            segmento = rota.path.split("{")[0].rstrip("/").rsplit("/", 1)[-1]
            ligado = f"{segmento[:-1]}_id" if segmento.endswith("s") else f"{segmento}_id"
            mae = respostas.get(f"GET {rota.path.split('{')[0].rstrip('/')}")
            # Primeiro os ids com o nome certo, em todas as respostas; o "id" genérico só depois.
            candidatos = []
            for chaves in ([nome, f"{nome}_id", ligado], ["id"]):
                for fonte in [mae] + list(respostas.values()):
                    for chave in dict.fromkeys(chaves):
                        for v in valores(fonte, chave):
                            if v not in candidatos:
                                candidatos.append(v)
            achados = 0
            for v in candidatos[:TENTATIVAS_POR_DETALHE]:
                caminho = re.sub(r"\{\w+(?::\w+)?\}", str(v).replace("/", "%2F"), rota.path)
                if pegar(caminho) is not None:
                    achados += 1
                    detalhadas.add(rota.path)
                    if achados >= ITENS_POR_DETALHE:
                        break
        # Os painéis desenham cada bloco por POST: grava os dos painéis salvos e os dos modelos.
        blocos = []
        for painel in (respostas.get("GET /api/paineis") or {}).get("paineis", []):
            completo = pegar(f"/api/paineis/{painel['id']}") or painel
            blocos += completo.get("blocos", [])
        for modelo in ((respostas.get("GET /api/buscas/opcoes") or {}).get("modelos") or {}).values():
            blocos += modelo.get("blocos", [])
        for b in blocos:
            pegar("/api/buscas/bloco", "POST", {k: b.get(k) for k in ("texto", "tipo", "minutos", "campo", "tamanho")})
        # A tela de logs pede com estes parâmetros ao abrir.
        for caminho in ("/api/logs?busca=&dias=7&filtros=", "/api/logs?dias=7", "/api/volume?dias=30", "/api/volume?dias=7"):
            pegar(caminho)

    texto = json.dumps({"rotas": sorted({r.path for r in rotas}), "respostas": respostas}, ensure_ascii=False)
    trocas = json.loads(Path(a.trocas).read_text()) if Path(a.trocas).exists() else {}
    for de, para in trocas.get("trocar", {}).items():
        texto = re.sub(re.escape(de), para, texto, flags=re.I)
    # Senha de inscrição de agentes, que vem no comando de instalação da tela de Fontes: nunca sai na demonstração.
    # O valor vem entre aspas simples (Linux) ou entre aspas duplas escapadas no JSON (Windows).
    texto = re.sub(r"(REGISTRATION_PASSWORD=(?:'|\\\"))[^'\"\\]+", r"\1senha-de-inscricao-ficticia", texto)
    sobrou = [p for p in trocas.get("nunca", []) if re.search(re.escape(p), texto, re.I)]
    if re.search(r"REGISTRATION_PASSWORD=(?:'|\\\")(?!senha-de-inscricao-ficticia)", texto):
        raise SystemExit("ainda tem senha de inscrição de agente na gravação")
    if sobrou:
        raise SystemExit(f"ainda tem dado real na gravação: {sobrou}")
    Path(a.saida).parent.mkdir(parents=True, exist_ok=True)
    Path(a.saida).write_text(texto)
    print(f"{len(respostas)} respostas gravadas em {a.saida} ({len(texto) // 1024} KB)")


if __name__ == "__main__":
    principal()
