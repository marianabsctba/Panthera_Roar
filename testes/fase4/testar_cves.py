#!/usr/bin/env python3
"""Base de CVEs: o critério de prioridade e a consulta, sobre a base carregada de verdade.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_cves.py
"""

import secrets
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import psycopg
import requests
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import cves  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    print("== Critério", flush=True)
    for nome, entrada, esperado in (("KEV vence nota baixa", ("2020-01-01", 0.001, 2.0), "agora"), ("KEV sem nota", ("2020-01-01", None, None), "agora"),
                                    ("EPSS alto", (None, 0.5, 2.0), "alta"), ("CVSS crítico", (None, 0.001, 9.0), "alta"), ("EPSS médio", (None, 0.05, 2.0), "media"),
                                    ("CVSS alto", (None, 0.001, 7.0), "media"), ("nota baixa e chance baixa", (None, 0.001, 3.0), "baixa"),
                                    ("sem nota com chance baixa não é baixa", (None, 0.001, None), "sem_dados"), ("sem nada", (None, None, None), "sem_dados"),
                                    ("nota baixa sem EPSS", (None, None, 3.0), "baixa")):
        registrar(nome, cves.prioridade(*entrada) == esperado, cves.prioridade(*entrada))

    print("\n== Registro hostil", flush=True)
    registrar("registro rejeitado", cves.ler_registro({"cveMetadata": {"state": "REJECTED", "cveId": "CVE-2020-1"}})["rejeitado"])
    r = cves.ler_registro({"cveMetadata": {"cveId": "CVE-2020-2", "state": "PUBLISHED"}, "containers": {"cna": {"title": "a\x00b", "metrics": [{"cvssV3_1": {"baseScore": "alto"}}], "descriptions": [{"lang": "pt", "value": "x"}]}}})
    registrar("nulo sai do texto, e nota que não é número é ignorada", r["titulo"] == "ab" and r["cvss"] is None and r["descricao"] == "x", str(r)[:120])
    registrar("registro vazio não derruba", cves.ler_registro({})["cve"] is None)

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    sufixo = uuid.uuid4().hex[:8]
    cliente = admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"cves-{sufixo}",)).fetchone()[0]
    senha, email = secrets.token_urlsafe(18), f"cves-{sufixo}@exemplo.test"
    admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'x', %s, 'auditor')", (cliente, email, PasswordHasher().hash(senha)))
    try:
        with TestClient(app, base_url="https://testserver") as http:
            registrar("exige sessão", http.get("/api/cves").status_code == 401)
            http.post("/api/entrar", json={"email": email, "senha": senha})
            print("\n== Consulta na base real", flush=True)
            geral = http.get("/api/cves").json()
            registrar("a base está carregada", geral["carga"] and geral["carga"]["total"] > 300000, str(geral["carga"]["total"] if geral["carga"] else None))
            registrar("a primeira página vem com exploração confirmada", geral["cves"] and geral["cves"][0]["prioridade"] == "agora")
            registrar("a contagem soma as prioridades", sum(int(c["total"]) for c in geral["contagem"]) > 300000, str({c["prioridade"]: c["total"] for c in geral["contagem"]}))
            log4j = http.get("/api/cves", params={"busca": "cve-2021-44228"}).json()["cves"]
            registrar("acha pelo número, sem diferenciar maiúsculas", len(log4j) == 1 and log4j[0]["cve"] == "CVE-2021-44228" and log4j[0]["prioridade"] == "agora", str(log4j[:1])[:140])
            palavra = http.get("/api/cves", params={"busca": "log4j"}).json()["cves"]
            registrar("acha por palavra", palavra and any("CVE-2021-44228" == c["cve"] for c in palavra), f"{len(palavra)} na página")
            so = http.get("/api/cves", params={"prioridade": "alta"}).json()["cves"]
            registrar("filtra por prioridade", so and all(c["prioridade"] == "alta" for c in so))
            registrar("prioridade inventada não quebra", http.get("/api/cves", params={"prioridade": "x'; DROP"}).status_code == 200)
            registrar("texto estranho na busca não quebra", http.get("/api/cves", params={"busca": "a' OR 1=1 --"}).status_code == 200)
            registrar("deslocamento negativo não quebra", http.get("/api/cves", params={"deslocamento": -5}).status_code == 200)
            detalhe = http.get("/api/cves/CVE-2021-44228").json()
            registrar("detalhe traz os sinais", detalhe["kev_desde"] and detalhe["cvss"] == 10 and detalhe["descricao"])
            registrar("CVE que não existe", http.get("/api/cves/CVE-1999-99999999").status_code == 404)
            registrar("identificador inválido", http.get("/api/cves/abc").status_code == 404)
            registrar("rejeitada não entra na lista", all(not c["rejeitado"] for c in geral["cves"]))
            registrar("rejeitada não aparece como prioridade", admin.execute("SELECT count(*) FROM cves WHERE rejeitado AND prioridade NOT IN ('sem_dados', 'agora')").fetchone()[0] == 0)

            print("\n== Atualização automática", flush=True)
            antes = admin.execute("SELECT carregada_em FROM cves_carga").fetchone()[0]
            total_antes = admin.execute("SELECT count(*) FROM cves").fetchone()[0]
            url = f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar"
            with psycopg.connect(url, autocommit=True) as con:
                banco = SimpleNamespace(con=con)

                class Parar(Exception):
                    pass

                def dormir(segundos):
                    esperas.append(segundos)
                    raise Parar()

                def rodar(carga):
                    try:
                        cves.rodar_para_sempre(banco, carga=carga, dormir=dormir)
                    except Parar:
                        pass

                chamadas, esperas = [], []
                rodar(lambda b: chamadas.append(1) or 1)
                registrar("base recente não baixa de novo", not chamadas and esperas == [cves.SEGUNDOS_ENTRE_CONFERENCIAS])

                admin.execute("UPDATE cves_carga SET carregada_em = now() - interval '4 days'")
                esperas.clear()

                def falha(b):
                    raise cves.FonteEstranha("EPSS veio pequeno demais")

                rodar(falha)
                registrar("fonte estranha: tenta de novo mais tarde", esperas == [cves.SEGUNDOS_APOS_FALHA], str(esperas))
                registrar("fonte estranha: a base anterior continua", admin.execute("SELECT count(*) FROM cves").fetchone()[0] == total_antes)
                carga = http.get("/api/cves").json()["carga"]
                registrar("a tela avisa da falha e da base velha", carga["falha"] == "EPSS veio pequeno demais" and carga["velha"] is True, str((carga["falha"], carga["velha"])))

                def caiu(b):
                    raise requests.ConnectionError("https://interno.exemplo/segredo")

                esperas.clear()
                rodar(caiu)
                carga = http.get("/api/cves").json()["carga"]
                registrar("rede fora: a tela não recebe endereço nenhum", "interno" not in carga["falha"] and esperas == [cves.SEGUNDOS_APOS_FALHA], carga["falha"])
                chamadas.clear()
                rodar(lambda b: chamadas.append(1) or 1)
                registrar("base velha dispara a carga", chamadas == [1])
            admin.execute("UPDATE cves_carga SET carregada_em = %s, falha = NULL, falha_em = NULL", (antes,))

            print("\n== Conferência da base", flush=True)
            registrar("todo KEV está em agora", admin.execute("SELECT count(*) FROM cves WHERE kev_desde IS NOT NULL AND prioridade <> 'agora'").fetchone()[0] == 0)
            registrar("ninguém sem nota está em baixa", admin.execute("SELECT count(*) FROM cves WHERE cvss IS NULL AND prioridade = 'baixa'").fetchone()[0] == 0)
            registrar("a API não grava na base", _api_nao_grava())
    finally:
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = %s)", (cliente,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))
        admin.close()
    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


def _api_nao_grava():
    with psycopg.connect(f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar") as con:
        try:
            con.execute("DELETE FROM cves WHERE cve = 'CVE-0000-0'")
            return False
        except psycopg.errors.InsufficientPrivilege:
            return True


if __name__ == "__main__":
    sys.exit(main())
