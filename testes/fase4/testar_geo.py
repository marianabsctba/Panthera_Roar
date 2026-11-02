#!/usr/bin/env python3
"""País de origem no Panorama, nos eventos, na busca e nos playbooks, com banco real.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_geo.py
"""

import json
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api import app as modulo  # noqa: E402
from roar_api import consulta  # noqa: E402
from roar_motor import blocos  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    print("== Condição de playbook", flush=True)
    se_e = {"campo": "pais", "op": "e", "valor": "Brazil"}
    nao_e = {"campo": "pais", "op": "nao_e", "valor": "Brazil"}
    registrar("é o país", blocos.condicao_verdadeira(se_e, {"pais": "Brazil"}))
    registrar("não é o país", not blocos.condicao_verdadeira(se_e, {"pais": "Russia"}))
    registrar("fora do país", blocos.condicao_verdadeira(nao_e, {"pais": "Russia"}))
    registrar("do próprio país não passa em 'não é'", not blocos.condicao_verdadeira(nao_e, {"pais": "Brazil"}))
    registrar("sem país não passa em 'é'", not blocos.condicao_verdadeira(se_e, {}))
    registrar("sem país não passa em 'não é': interno não é estrangeiro", not blocos.condicao_verdadeira(nao_e, {"pais": None}))
    registrar("a validação aceita", not _recusa(se_e) and not _recusa(nao_e))
    for ruim in ({"campo": "pais", "op": "igual", "valor": "Brazil"}, {"campo": "pais", "op": "e", "valor": ""}, {"campo": "pais", "op": "e", "valor": 5}, {"campo": "pais", "op": "e", "valor": "x" * 200}):
        registrar(f"a validação recusa {str(ruim)[:50]}", _recusa(ruim))

    print("\n== Busca", flush=True)
    pedido = consulta.analisar("pais=Brazil")
    registrar("pais vira o campo certo", "GeoLocation.country_name" in json.dumps(pedido.filtro), json.dumps(pedido.filtro)[:120])
    registrar("país com acento também", "GeoLocation.country_name" in json.dumps(consulta.analisar("país=Brazil").filtro))
    registrar("cidade também", "GeoLocation.city_name" in json.dumps(consulta.analisar("cidade=Curitiba").filtro))
    registrar("estado também", "GeoLocation.region_name" in json.dumps(consulta.analisar("estado=Parana").filtro))
    registrar("contar por país", consulta.analisar("| contar por pais").contar_por == "GeoLocation.country_name")

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    clientes, gerenciadores = [], []

    def criar(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        g = uuid.uuid4().hex[:12]
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 53000 + secrets.randbelow(7000)))
        senha, email = secrets.token_urlsafe(18), f"geo-{uuid.uuid4().hex[:8]}@exemplo.test"
        admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Pessoa', %s, 'analista_n1')", (c, email, PasswordHasher().hash(senha)))
        clientes.append(c)
        gerenciadores.append(g)
        return c, g, email, senha

    def evento(c, g, pais, severidade="alta", nivel=10, cidade=None, regiao=None, lat=-25.5):
        bruto = {"rule": {"id": "5712"}}
        if pais:
            bruto["GeoLocation"] = {"country_name": pais, "location": {"lat": 1, "lon": 1}}
        if cidade:
            bruto["GeoLocation"].update(city_name=cidade, region_name=regiao, location={"lat": lat, "lon": -49.3})
        admin.execute("""INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao, gerenciador_id, agente_id, bruto)
                         VALUES (%s, 'wazuh', %s, %s, %s, %s, '5712', 'Teste', %s, '001', %s)""",
                      (c, uuid.uuid4().hex, datetime.now(timezone.utc), nivel, severidade, g, Jsonb(bruto)))

    try:
        ca, ga, email_a, senha_a = criar("geo-a")
        cb, gb, email_b, senha_b = criar("geo-b")
        for _ in range(5):
            evento(ca, ga, "Russia")
        for _ in range(2):
            evento(ca, ga, "Brazil", "media", 8)
        evento(ca, ga, None)
        evento(ca, ga, "Brazil", "baixa", 1)
        evento(cb, gb, "China")

        with TestClient(modulo.app, base_url="https://testserver") as _:
            http = TestClient(modulo.app, base_url="https://testserver")
            http.post("/api/entrar", json={"email": email_a, "senha": senha_a})

            print("\n== Panorama", flush=True)
            paises = http.get("/api/panorama").json()["paises"]
            registrar("conta por país, do maior para o menor", [p["pais"] for p in paises] == ["Russia", "Brazil"], str(paises))
            registrar("conta o total", paises[0]["total"] == 5, str(paises[0]))
            registrar("separa os graves", paises[0]["graves"] == 5 and paises[1]["graves"] == 0, str(paises))
            registrar("alerta sem país fica de fora", all(p["pais"] for p in paises))
            registrar("evento abaixo do nível da fila fica de fora", paises[1]["total"] == 2, str(paises[1]))
            outra = TestClient(modulo.app, base_url="https://testserver")
            outra.post("/api/entrar", json={"email": email_b, "senha": senha_b})
            registrar("cada cliente vê só os dele", [p["pais"] for p in outra.get("/api/panorama").json()["paises"]] == ["China"])

            print("\n== Cidades", flush=True)
            for _ in range(3):
                evento(ca, ga, "Brazil", "alta", 10, "Curitiba", "Parana")
            evento(ca, ga, "Brazil", "media", 8, "Recife", "Pernambuco")
            evento(ca, ga, "Brazil", "baixa", 1, "Manaus", "Amazonas")
            evento(ca, ga, "Argentina", "alta", 10, "Rosario", "Santa Fe")
            evento(ca, ga, "Brazil", "alta", 10, "Forjada", "Texto", lat="abc")
            evento(cb, gb, "Brazil", "alta", 10, "Natal", "Rio Grande do Norte")
            resposta = http.get("/api/panorama")
            registrar("posição que não é número não derruba o panorama", resposta.status_code == 200)
            cidades = resposta.json()["cidades"]
            nomes = [c["cidade"] for c in cidades]
            registrar("conta por cidade, da maior para a menor", nomes[0] == "Curitiba" and cidades[0]["total"] == 3 and cidades[0]["graves"] == 3, str(cidades)[:200])
            registrar("traz estado, país e posição", cidades[0]["regiao"] == "Parana" and cidades[0]["pais"] == "Brazil" and abs(cidades[0]["lat"] + 25.5) < 1e-6 and abs(cidades[0]["lon"] + 49.3) < 1e-6, str(cidades[0]))
            registrar("posição que não é número vem vazia", next(c for c in cidades if c["cidade"] == "Forjada")["lat"] is None)
            registrar("cidades do mundo, não só do Brasil", "Rosario" in nomes)
            registrar("diz quantos alertas não têm cidade", resposta.json()["sem_cidade"] == 7, str(resposta.json()["sem_cidade"]))
            registrar("abaixo do nível da fila fica de fora", "Manaus" not in nomes)
            registrar("não mostra cidade de outro cliente", "Natal" not in nomes)
            e = http.get("/api/eventos", params={"pais": "Brazil", "cidade": "Curitiba"}).json()["eventos"]
            registrar("filtra por cidade", len(e) == 3 and all(x["cidade"] == "Curitiba" and x["regiao"] == "Parana" for x in e), str(len(e)))
            registrar("cidade de outro cliente não filtra", http.get("/api/eventos", params={"cidade": "Natal"}).json()["eventos"] == [])
            registrar("injeção no filtro de cidade não quebra", http.get("/api/eventos", params={"cidade": "'; DROP TABLE eventos; --"}).json()["eventos"] == [])
            registrar("a automação não lê a cidade", not admin.execute("SELECT has_column_privilege('roar_soar', 'eventos', 'cidade', 'SELECT') OR has_column_privilege('roar_soar', 'eventos', 'regiao', 'SELECT')").fetchone()[0])
            admin.execute("DELETE FROM eventos WHERE cidade IS NOT NULL AND cliente_id = ANY(%s)", (clientes,))

            print("\n== O que cada número do panorama abre", flush=True)
            hoje = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            registrar("só alertas conta como o panorama", len(http.get("/api/eventos", params={"alertas": True}).json()["eventos"]) == 8)
            registrar("altos e críticos", all(x["severidade"] in ("alta", "critica") for x in http.get("/api/eventos", params={"severidades": "alta,critica"}).json()["eventos"]) and len(http.get("/api/eventos", params={"severidades": "alta,critica"}).json()["eventos"]) == 6)
            registrar("severidade inventada não filtra nem quebra", http.get("/api/eventos", params={"severidades": "x'; DROP TABLE eventos; --"}).status_code == 200)
            registrar("o dia de hoje traz os eventos", len(http.get("/api/eventos", params={"dia": hoje}).json()["eventos"]) >= 7)
            registrar("outro dia não traz", http.get("/api/eventos", params={"dia": "2001-01-01"}).json()["eventos"] == [])
            registrar("dia em formato estranho é ignorado", http.get("/api/eventos", params={"dia": "ontem; DROP"}).status_code == 200)
            registrar("origem sem evento vem vazia", http.get("/api/eventos", params={"origem": "1.2.3.4"}).json()["eventos"] == [])
            registrar("sinal sem evento vem vazio", http.get("/api/eventos", params={"sinal": "viagem_impossivel"}).json()["eventos"] == [])
            registrar("pessoa sem evento vem vazia", http.get("/api/eventos", params={"entidade": "ninguem"}).json()["eventos"] == [])
            registrar("filtro de mudança em arquivos responde", http.get("/api/arquivos", params={"mudanca": "added"}).status_code == 200 and http.get("/api/arquivos", params={"mudanca": "x'--"}).status_code == 200)

            print("\n== Eventos", flush=True)
            e = http.get("/api/eventos", params={"pais": "Russia"}).json()["eventos"]
            registrar("filtra por país", len(e) == 5 and all(x["pais"] == "Russia" for x in e), str(len(e)))
            registrar("sem filtro vem tudo", len(http.get("/api/eventos").json()["eventos"]) == 9)
            registrar("sem país o campo vem vazio", any(x["pais"] is None for x in http.get("/api/eventos").json()["eventos"]))
            registrar("país de outro cliente não aparece", http.get("/api/eventos", params={"pais": "China"}).json()["eventos"] == [])
            registrar("injeção no filtro não quebra", http.get("/api/eventos", params={"pais": "'; DROP TABLE eventos; --"}).json()["eventos"] == [])
            registrar("texto enorme não quebra", http.get("/api/eventos", params={"pais": "x" * 5000}).status_code == 200)

        print("\n== Tela", flush=True)
        js = (modulo.ESTATICO / "roar.js").read_text(encoding="utf-8")
        mapa = json.loads((modulo.ESTATICO / "mapa-paises.json").read_text(encoding="utf-8"))
        codigos = {p["c"] for p in mapa["paises"]} | {p["c"] for p in mapa["pontos"]}
        registrar("o mapa tem os países", len(codigos) > 200 and {"BR", "US", "RU", "CN", "SG", "HK"} <= codigos, str(len(codigos)))
        registrar("nome diferente aponta para país que existe no mapa", all(c in codigos for c in ("HK", "MO", "MM", "CD", "CG", "CI", "BA", "TT", "PS", "NL")))
        registrar("a tela desenha o mapa sem montar HTML", "createElementNS" in js and "desenharMapa" in js)
        # A posição do ponto só faz sentido se usar a mesma projeção do desenho: Andorra está no próprio arquivo do mapa.
        andorra = next(p for p in mapa["pontos"] if p["c"] == "AD")
        f, l = 42.5 * 3.141592653589793 / 180, 1.52 * 3.141592653589793 / 180
        f2, f4 = f * f, f ** 4
        x = mapa["largura"] / 2 + mapa["escala"] * l * (0.8707 - 0.131979 * f2 + f4 * (-0.013791 + f4 * (0.003971 * f2 - 0.001529 * f4)))
        y = (mapa["yNorte"] - f * (1.007226 + f2 * (0.015085 + f4 * (-0.044475 + 0.028874 * f2 - 0.005916 * f4)))) * mapa["escala"]
        registrar("a conta do ponto cai no lugar do desenho", abs(x - andorra["x"]) < 1 and abs(y - andorra["y"]) < 1, f"{x:.1f},{y:.1f} {andorra}")
        registrar("a tela usa a mesma conta", "0.131979" in js and "0.028874" in js)
    finally:
        admin.execute("DELETE FROM eventos WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM auditoria WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM gerenciadores WHERE id = ANY(%s)", (gerenciadores,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))
        admin.close()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


def _recusa(condicao):
    try:
        blocos._validar_condicao(condicao)
        return False
    except blocos.DefinicaoInvalida:
        return True


if __name__ == "__main__":
    sys.exit(main())
