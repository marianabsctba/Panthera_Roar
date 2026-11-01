#!/usr/bin/env python3
"""Linguagem de consulta dos logs, sem depender de nada no ar.

    python testes/fase4/testar_consulta.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api" / "roar_api"))

from consulta import ConsultaInvalida, analisar  # noqa: E402

RESULTADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def invalida(texto):
    try:
        analisar(texto)
        return False
    except ConsultaInvalida:
        return True


def main():
    print("== Português e inglês dão o mesmo resultado")
    pares = [
        ("ativo=srv-rh E origem=1.2.3.4", "agent.name=srv-rh AND data.srcip=1.2.3.4"),
        ("ativo=a OU ativo=b", "agent.name=a OR agent.name=b"),
        ("NAO ativo=a", "NOT agent.name=a"),
        ("não ativo=a", "not agent.name=a"),
    ]
    for pt, en in pares:
        registrar(pt, analisar(pt).filtro == analisar(en).filtro)
    pt, en = analisar("x | contar por usuario | limite 5"), analisar("x | stats count by data.srcuser | head 5")
    registrar("comandos nas duas línguas", pt.contar_por == en.contar_por == "data.srcuser" and pt.limite == en.limite == 5)
    registrar("campos nas duas línguas", analisar("| campos ativo, origem").colunas == analisar("| fields agent.name data.srcip").colunas == ["agent.name", "data.srcip"])
    registrar("ordenar nas duas línguas", analisar("| ordenar -quando").ordem == analisar("| sort -timestamp").ordem == ("timestamp", "desc"))

    print("\n== Significado")
    registrar("vazio pega tudo", analisar("").filtro == {"match_all": {}})
    registrar("palavras soltas buscam no log", analisar("sshd").filtro == {"match_phrase": {"full_log": "sshd"}})
    registrar("palavras em sequência precisam estar todas", len(analisar("a b").filtro["bool"]["filter"]) == 2)
    registrar("aspas viram uma frase", analisar('"falha de login"').filtro == {"match_phrase": {"full_log": "falha de login"}})
    registrar("igual é exato", analisar("ativo=a").filtro == {"term": {"agent.name": "a"}})
    registrar("diferente nega", analisar("ativo!=a").filtro == {"bool": {"must_not": [{"term": {"agent.name": "a"}}]}})
    registrar("asterisco é curinga", "wildcard" in analisar("origem=10.*").filtro)
    registrar("til é contém", analisar("usuario~mar").filtro["wildcard"]["data.srcuser"]["value"] == "*mar*")
    registrar("comparação numérica", analisar("nivel>=10").filtro == {"range": {"rule.level": {"gte": "10"}}})
    registrar("E pesa mais que OU", "should" in analisar("a=1 OU b=2 E c=3").filtro["bool"])
    registrar("parênteses mudam a ordem", "filter" in analisar("(a=1 OU b=2) E c=3").filtro["bool"])
    registrar("aspas com barra dentro", analisar('a="x | y"').filtro == {"term": {"a": "x | y"}})
    registrar("nome técnico continua valendo", analisar("data.win.system.eventID=4720").filtro == {"term": {"data.win.system.eventID": "4720"}})
    registrar("palavra e, ou, nao entre aspas é texto", analisar('"e"').filtro == {"match_phrase": {"full_log": "e"}})

    print("\n== Erros explicados, nunca repassados")
    for nome, ruim in (
        ("parêntese aberto", "(a=1"), ("parêntese sobrando", "a=1)"), ("aspas abertas", '"abc'), ("sem valor", "a="), ("operador solto", "=1"),
        ("comando desconhecido", "a | apagar tudo"), ("sem comando", "a |"), ("limite absurdo", "a | limite 999999"), ("limite com texto", "a | limite x"),
        ("campo com injeção", '"a"} OR {"b"=1'), ("campo interno", "_index=x"), ("profundidade", "(" * 40 + "a" + ")" * 40),
        ("tamanho", "a" * 3000), ("condições demais", " ".join(f"p{i}" for i in range(60))), ("só E", "E"), ("termina em OU", "a OU"),
    ):
        registrar(f"recusa: {nome}", invalida(ruim))

    print("\n== Nada do texto vira estrutura do indexer")
    def so_clausulas_permitidas(no):
        """Texto do usuário pode virar valor ou nome de campo, nunca uma cláusula da consulta."""
        if set(no) - {"bool", "match_phrase", "term", "wildcard", "range", "match_all"}:
            return False
        if no.get("match_all") not in (None, {}):
            return False
        interno = no.get("bool", {})
        return all(so_clausulas_permitidas(filho) for chave in ("filter", "should", "must_not") for filho in interno.get(chave, []))

    for texto in ('{"script": {"source": "x"}}', '{"match_all":{}}', 'a={"script":1}', "script=x", "_source=x", '"query":{"match_all":{}}',
                  'ativo="x\\"} OR {\\"script\\":1"', "(a=1 OU script=2) E NAO b=3"):
        try:
            seguro = so_clausulas_permitidas(analisar(texto).filtro)
        except ConsultaInvalida:
            seguro = True
        registrar(f"seguro: {texto[:30]}", seguro)

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
