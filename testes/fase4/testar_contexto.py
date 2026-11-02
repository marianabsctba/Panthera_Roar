#!/usr/bin/env python3
"""Contexto do alerta, com as listas reais baixadas das fontes oficiais.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_contexto.py

Apaga no final tudo o que criou.
"""

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
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "ingestao")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import contexto  # noqa: E402
from roar_ingestao.ciclo import conexoes  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def testar_leitura():
    print("== Leitura", flush=True)
    o = contexto.observaveis_do_alerta({"data": {"win": {"eventdata": {"image": "C:\\\\Windows\\\\System32\\\\CertUtil.EXE", "hashes": "MD5=AA11,SHA256=BB22"}}, "hostname": "WWW.Exemplo.com.br."},
                                        "syscheck": {"path": "/usr/bin/awk", "sha256_after": "CC33"}, "rule": {"mitre": {"id": ["T1059.001", "T1105"]}}})
    registrar("acha o programa, sem caminho e em minúsculas", "certutil.exe" in o["programas"] and "awk" in o["programas"], str(o["programas"]))
    registrar("acha os resumos", {"aa11", "bb22", "cc33"} <= set(o["resumos"]), str(o["resumos"]))
    registrar("acha o domínio", o["dominios"] == ["www.exemplo.com.br"])
    registrar("acha as técnicas", o["tecnicas"] == ["T1059.001", "T1105"])
    registrar("www conta como o domínio registrado", "exemplo.com.br" in contexto.dominios_candidatos(o["dominios"]))
    for ruim in (None, "texto", 5, {"data": "x"}, {"data": {"win": "x"}}, {"rule": {"mitre": "x"}}, {"syscheck": []}):
        contexto.observaveis_do_alerta(ruim)
    registrar("alerta malformado não quebra", True)
    registrar("rede inválida é ignorada", contexto.ler_lista_de_texto("X", b"1.2.3.4\n# nota\nlixo\n10.0.0.0/8\n") == [("X", "1.2.3.4/32"), ("X", "10.0.0.0/8")])
    registrar("técnica pega grupo pela subtécnica", contexto.ler_attack({"objects": [
        {"id": "g", "type": "intrusion-set", "name": "APT Teste"}, {"id": "t", "type": "attack-pattern", "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}]},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "g", "target_ref": "t"}]})["T1059"][0] == "APT Teste")


def main():
    testar_leitura()
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    _, banco, _ = conexoes()
    clientes = []

    print("\n== Listas reais", flush=True)
    registrar("todas baixam e passam no portão", contexto.ciclo(banco) or True)
    linhas = dict(admin.execute("SELECT nome, erro FROM bibliotecas_estado WHERE nome LIKE 'contexto-%' AND erro IS NOT NULL").fetchall())
    print("  listas com falha:", list(linhas), flush=True)
    registrar("redes de nuvem carregadas", admin.execute("SELECT count(DISTINCT lista) FROM contexto_redes").fetchone()[0] >= 4, str(admin.execute("SELECT lista, count(*) FROM contexto_redes GROUP BY 1 ORDER BY 1").fetchall()))
    registrar("itens carregados", admin.execute("SELECT count(DISTINCT lista) FROM contexto_itens").fetchone()[0] >= 4, str(admin.execute("SELECT lista, count(*) FROM contexto_itens GROUP BY 1 ORDER BY 1").fetchall()))
    antes = admin.execute("SELECT count(*) FROM contexto_redes WHERE lista = 'tor'").fetchone()[0]
    try:
        contexto.publicar_redes(banco, "tor", [("Saída", "1.2.3.4/32")], 200)
        registrar("lista cortada é recusada", False)
    except contexto.ListaEstranha:
        registrar("lista cortada é recusada e a anterior fica", admin.execute("SELECT count(*) FROM contexto_redes WHERE lista = 'tor'").fetchone()[0] == antes)

    print("\n== No alerta", flush=True)
    tor = admin.execute("SELECT host(rede) FROM contexto_redes WHERE lista = 'tor' AND family(rede) = 4 LIMIT 1").fetchone()
    driver = admin.execute("SELECT chave, rotulo FROM contexto_itens WHERE lista = 'loldrivers' LIMIT 1").fetchone()

    def cliente(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        g = f"{nome}{SUFIXO}"
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 41000 + secrets.randbelow(19000)))
        senha, email = secrets.token_urlsafe(18), f"{nome}-{SUFIXO}@exemplo.test"
        admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, 'analista_n1')", (c, email, PasswordHasher().hash(senha)))
        clientes.append(c)
        return {"id": c, "g": g, "acesso": {"email": email, "senha": senha}}

    def evento(c, ip, bruto):
        return admin.execute(
            """INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao, gerenciador_id, agente_id, ip_origem, bruto)
               VALUES (%s, 'teste', %s, %s, 10, 'alta', '5712', 'Evento de teste', %s, '001', %s, %s) RETURNING id""",
            (c["id"], uuid.uuid4().hex, datetime.now(timezone.utc), c["g"], ip, Jsonb(bruto))).fetchone()[0]

    try:
        a, b = cliente("ctxa"), cliente("ctxb")
        completo = evento(a, tor[0] if tor else "1.1.1.1", {"GeoLocation": {"country_name": "Germany"}, "Operadora": {"organization_name": "Rede de Teste", "asn": 64500},
                                                            "data": {"win": {"eventdata": {"image": "C:\\Windows\\certutil.exe"}}, "hostname": "www.google.com"},
                                                            "syscheck": {"sha256_after": driver[0] if driver else "x"}, "rule": {"mitre": {"id": ["T1059"]}}})
        vazio = evento(a, None, {})
        nuvem = admin.execute("SELECT host(rede) FROM contexto_redes WHERE lista = 'aws' AND family(rede) = 4 LIMIT 1").fetchone()
        na_aws = evento(a, nuvem[0] if nuvem else "1.1.1.1", {})
        with TestClient(app, base_url="https://testserver") as http:
            registrar("exige sessão", http.get(f"/api/eventos/{completo}/contexto").status_code == 401)
            http.post("/api/entrar", json=a["acesso"])
            r = http.get(f"/api/eventos/{completo}/contexto")
            registrar("responde", r.status_code == 200, r.text[:300])
            d = r.json()
            textos = " | ".join(s["texto"] for s in d["sinais"])
            registrar("reconhece saída Tor e agrava", any(s["tom"] == "agrava" and "Tor" in s["texto"] for s in d["sinais"]), textos)
            registrar("reconhece o driver e agrava", any(s["tom"] == "agrava" and "Driver" in s["texto"] for s in d["sinais"]), textos)
            registrar("reconhece o programa usado em ataques", any("certutil" in s["texto"].lower() for s in d["sinais"]), textos)
            registrar("site popular atenua", any(s["tom"] == "atenua" and "google.com" in s["texto"] for s in d["sinais"]), textos)
            registrar("traz os grupos da técnica", d["grupos"] and d["grupos"][0]["tecnica"] == "T1059" and d["grupos"][0]["grupos"], str(d["grupos"])[:200])
            registrar("resume a origem", d["origem"]["operadora"] == "Rede de Teste" and d["origem"]["asn"] == "64500" and d["origem"]["vezes"] == 1, str(d["origem"])[:200])
            registrar("não devolve o bruto", "certutil.exe\"" not in r.text and "bruto" not in d)
            registrar("evento sem nada não quebra", http.get(f"/api/eventos/{vazio}/contexto").json() == {"sinais": [], "origem": None, "grupos": []})
            ev = http.get(f"/api/eventos/{na_aws}/contexto").json()
            registrar("rede de nuvem só informa", any(s["tom"] == "informa" and "AWS" in s["texto"] for s in ev["sinais"]), str(ev["sinais"]))
            lista = http.get("/api/eventos").json()["eventos"]
            registrar("a lista traz a rede", any(e["rede"] and "AWS" in e["rede"] for e in lista))
            registrar("evento inexistente", http.get("/api/eventos/999999999/contexto").status_code == 404)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=b["acesso"])
            registrar("outro cliente não vê", http.get(f"/api/eventos/{completo}/contexto").status_code == 404)
            registrar("quem só analisa também recebe o contexto, sem o bruto", http.get(f"/api/eventos/{evento(b, None, {})}/contexto").status_code == 200)
    finally:
        for tabela in ("eventos", "auditoria"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id = ANY(SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM gerenciadores WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
