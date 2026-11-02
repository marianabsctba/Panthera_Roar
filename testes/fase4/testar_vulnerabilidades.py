#!/usr/bin/env python3
"""Gestão de vulnerabilidades: a lógica comum a qualquer ferramenta, com banco real e achados simulados.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_vulnerabilidades.py

Não prova nenhum scanner: isso fica nos testes de cada ponte.
"""

import csv
import io
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api import app as modulo  # noqa: E402
from roar_ingestao import cofre  # noqa: E402
from roar_ingestao import vulnerabilidades as vuln  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
TABELAS = ("vuln_historico", "vuln_achados", "vuln_ativos", "vuln_varreduras", "vuln_alvos", "vuln_modelos")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    print("== Peças", flush=True)
    for cvss, esperado in ((9.8, "critica"), (9.0, "critica"), (8.9, "alta"), (7.0, "alta"), (6.9, "media"), (4.0, "media"), (3.9, "baixa"), (0.1, "baixa"), (0, "informativa"), (None, "informativa")):
        registrar(f"CVSS {cvss} é {esperado}", vuln.severidade_do_cvss(cvss) == esperado)
    for bom, normal in (("10.0.0.5", "10.0.0.5"), ("10.0.1.9/24", "10.0.1.0/24"), ("SRV-rh.Exemplo.test", "srv-rh.exemplo.test"), ("2001:db8::1", "2001:db8::1")):
        registrar(f"aceita {bom}", vuln.validar_host(bom) == normal)
    for ruim in ("", "-oX/tmp/x", "10.0.0.0/8", "a b", "x;rm -rf", "$(id)", "http://x", "../x"):
        try:
            vuln.validar_host(ruim)
            registrar(f"recusa {ruim!r}", False)
        except vuln.HostInvalido:
            registrar(f"recusa {ruim!r}", True)

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    clientes = []

    def criar_cliente(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        clientes.append(c)
        return c

    def criar_usuario(cliente, perfil):
        senha, email = secrets.token_urlsafe(18), f"{perfil}-{uuid.uuid4().hex[:8]}@exemplo.test"
        admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, %s, %s, %s)", (cliente, email, f"Pessoa {perfil}", PasswordHasher().hash(senha), perfil))
        return {"email": email, "senha": senha}

    def entrar(u):
        http = TestClient(modulo.app, base_url="https://testserver")
        http.post("/api/entrar", json={"email": u["email"], "senha": u["senha"]})
        return http

    try:
        a, b = criar_cliente("vuln-a"), criar_cliente("vuln-b")
        ana, ivo, bia = criar_usuario(a, "administrador"), criar_usuario(a, "analista_n2"), criar_usuario(b, "administrador")

        with TestClient(modulo.app, base_url="https://testserver") as _:
            http, http_ivo, http_b = entrar(ana), entrar(ivo), entrar(bia)

            print("\n== Modelos e alvos", flush=True)
            r = http.post("/api/vuln/modelos", json={"nome": "Mensal", "ferramenta": "rede"})
            modelo = r.json()["id"]
            registrar("cria modelo", r.status_code == 201)
            registrar("nome repetido é recusado", http.post("/api/vuln/modelos", json={"nome": "Mensal", "ferramenta": "rede"}).status_code == 409)
            registrar("tipo estranho é recusado", http.post("/api/vuln/modelos", json={"nome": "X", "ferramenta": "qualquer"}).status_code == 422)
            registrar("analista não cria modelo", http_ivo.post("/api/vuln/modelos", json={"nome": "Y", "ferramenta": "rede"}).status_code == 403)
            r = http.post("/api/vuln/alvos", json={"nome": "Servidores", "hosts": ["10.0.0.5", "10.0.0.6"], "modelo_id": modelo})
            alvo = r.json()["id"]
            registrar("cria alvo", r.status_code == 201, r.text[:120])
            registrar("host malicioso é recusado", http.post("/api/vuln/alvos", json={"nome": "Mau", "hosts": ["-oX/tmp/x"], "modelo_id": modelo}).status_code == 422)
            registrar("rede grande demais é recusada, com explicação", "/16" in http.post("/api/vuln/alvos", json={"nome": "Grande", "hosts": ["10.0.0.0/8"], "modelo_id": modelo}).json()["detail"])
            registrar("modelo de outro cliente é recusado", http_b.post("/api/vuln/alvos", json={"nome": "Z", "hosts": ["10.0.0.5"], "modelo_id": modelo}).status_code == 422)
            registrar("credencial incompleta é recusada", http.post("/api/vuln/alvos", json={"nome": "C", "hosts": ["10.0.0.7"], "modelo_id": modelo, "credencial_tipo": "ssh"}).status_code == 422)
            senha_de_varredura = f"senha-{secrets.token_hex(8)}"
            r = http.post("/api/vuln/alvos", json={"nome": "Com credencial", "hosts": ["10.0.0.8"], "modelo_id": modelo, "credencial_tipo": "ssh", "credencial_usuario": "scanner", "credencial_senha": senha_de_varredura})
            registrar("cria alvo com credencial", r.status_code == 201, r.text[:120])
            lista = http.get("/api/vuln/alvos")
            registrar("a senha não volta para a tela", senha_de_varredura not in lista.text and "selado" not in lista.text)
            guardado = admin.execute("SELECT s.nome, s.selado FROM segredos s JOIN vuln_alvos v ON v.credencial_segredo = s.nome WHERE v.cliente_id = %s", (a,)).fetchone()
            registrar("a senha fica cifrada no cofre", senha_de_varredura.encode() not in bytes(guardado[1]))
            registrar("o serviço consegue abrir", cofre.abrir(cofre.ler_privada(), a, guardado[0], bytes(guardado[1])) == senha_de_varredura)
            registrar("outro cliente não vê o alvo", http_b.get("/api/vuln/alvos").json()["alvos"] == [])

            print("\n== Pedir varredura", flush=True)
            r = http.post("/api/vuln/varreduras", json={"alvo_id": alvo})
            varredura = r.json()["id"]
            registrar("pede varredura", r.status_code == 201)
            registrar("não acumula pedidos no mesmo alvo", http.post("/api/vuln/varreduras", json={"alvo_id": alvo}).status_code == 409)
            registrar("outro cliente não varre meu alvo", http_b.post("/api/vuln/varreduras", json={"alvo_id": alvo}).status_code == 404)
            registrar("a agenda não duplica o pedido", vuln.agendar_vencidas(banco, a) == 1, "só o alvo com credencial estava livre")

            print("\n== Primeira varredura", flush=True)
            achados = [
                vuln.Achado("10.0.0.5", "regra-a", "Falha crítica", 9.8, ["CVE-2021-44228"], "443/tcp", "versão vulnerável", "Atualize", "srv-a"),
                vuln.Achado("10.0.0.5", "regra-b", "Falha média", 5.0, [], "80/tcp"),
                vuln.Achado("10.0.0.6", "regra-c", "Só com credencial", 7.5, []),
            ]
            feito = vuln.concluir_varredura(banco, a, varredura, vuln.Resultado("rede", ["10.0.0.5", "10.0.0.6"], achados, autenticada=True))
            registrar("três novos", feito == (3, 0, 0), str(feito))
            d = http.get("/api/vuln/achados").json()["achados"]
            registrar("o mais grave vem primeiro", [x["severidade"] for x in d] == ["critica", "alta", "media"], str([x["severidade"] for x in d]))
            registrar("a prioridade vem da base de CVEs", d[0]["prioridade"] == "agora", str(d[0]["prioridade"]))
            registrar("outro cliente não vê", http_b.get("/api/vuln/achados").json()["achados"] == [])
            registrar("outro cliente não abre o detalhe", http_b.get(f"/api/vuln/achados/{d[0]['id']}").status_code == 404)
            h = http.get(f"/api/vuln/achados/{d[0]['id']}").json()
            registrar("o detalhe traz solução, evidência e história", h["solucao"] == "Atualize" and h["evidencia"] == "versão vulnerável" and h["historico"][0]["para"] == "aberto")
            i = http.get("/api/vuln/indicadores").json()
            registrar("indicadores contam por severidade", i["abertos"]["critica"] == 1 and i["abertos"]["alta"] == 1 and i["abertos"]["media"] == 1, str(i["abertos"]))
            registrar("exposição é a conta anunciada: (10+5+2) x peso 3", i["exposicao"] == 51, str(i["exposicao"]))
            registrar("evolução mostra os abertos de hoje", i["evolucao"][-1]["abertos"] == 3, str(i["evolucao"][-1]))

            print("\n== Peso do ativo", flush=True)
            ativo = next(t for t in http.get("/api/vuln/ativos").json()["ativos"] if t["host"] == "10.0.0.5")
            registrar("o ativo tem nome e exposição", ativo["nome"] == "srv-a" and ativo["exposicao"] == 36, str(ativo))
            registrar("muda o peso", http.put(f"/api/vuln/ativos/{ativo['id']}", json={"peso": 5}).status_code == 204)
            registrar("o peso muda a conta", http.get("/api/vuln/indicadores").json()["exposicao"] == 75, str(http.get("/api/vuln/indicadores").json()["exposicao"]))
            registrar("peso fora da faixa é recusado", http.put(f"/api/vuln/ativos/{ativo['id']}", json={"peso": 9}).status_code == 422)
            registrar("analista não muda peso", http_ivo.put(f"/api/vuln/ativos/{ativo['id']}", json={"peso": 1}).status_code == 403)
            registrar("outro cliente não muda peso", http_b.put(f"/api/vuln/ativos/{ativo['id']}", json={"peso": 1}).status_code == 404)

            def rodar(resultado):
                nova = http.post("/api/vuln/varreduras", json={"alvo_id": alvo}).json()["id"]
                return vuln.concluir_varredura(banco, a, nova, resultado), nova

            print("\n== Corrigido só com prova", flush=True)
            sem_cred = vuln.Achado("10.0.0.5", "regra-a", "Falha crítica", 9.8, ["CVE-2021-44228"], "443/tcp")
            feito, _ = rodar(vuln.Resultado("rede", ["10.0.0.5", "10.0.0.6"], [sem_cred], autenticada=False))
            registrar("sem credencial não fecha o que exigiu credencial", feito == (0, 0, 0), str(feito))
            feito, _ = rodar(vuln.Resultado("web", ["10.0.0.5", "10.0.0.6"], []))
            registrar("outra ferramenta não fecha", feito == (0, 0, 0), str(feito))
            feito, _ = rodar(vuln.Resultado("rede", ["10.0.0.6"], [vuln.Achado("10.0.0.6", "regra-c", "Só com credencial", 7.5)], autenticada=True))
            registrar("host fora do ar não fecha", feito == (0, 0, 0), str(feito))
            feito, _ = rodar(vuln.Resultado("rede", ["10.0.0.5", "10.0.0.6"], [sem_cred], autenticada=True))
            registrar("varredura equivalente fecha os que sumiram", feito == (0, 0, 2), str(feito))
            registrar("corrigido é contado", http.get("/api/vuln/indicadores").json()["corrigidos"] == 2)
            registrar("tempo para corrigir sai", http.get("/api/vuln/indicadores").json()["dias_para_corrigir"] is not None)
            corrigido = http.get("/api/vuln/achados", params={"estado": "corrigido"}).json()["achados"][0]
            registrar("a história diz qual varredura provou", http.get(f"/api/vuln/achados/{corrigido['id']}").json()["historico"][0]["varredura_id"] is not None)
            registrar("corrigido não é marcado na mão", http.post(f"/api/vuln/achados/{corrigido['id']}/estado", json={"estado": "aceito", "motivo": "tentando mudar um corrigido"}).status_code == 409)
            registrar("a tela não oferece marcar corrigido", http.post(f"/api/vuln/achados/{d[0]['id']}/estado", json={"estado": "corrigido", "motivo": "marcando na mão sem prova"}).status_code == 422)

            print("\n== Voltou", flush=True)
            feito, _ = rodar(vuln.Resultado("rede", ["10.0.0.5", "10.0.0.6"], [sem_cred, vuln.Achado("10.0.0.5", "regra-b", "Falha média", 5.0, [], "80/tcp")], autenticada=True))
            registrar("reabre o que voltou", feito == (0, 1, 0), str(feito))
            reaberto = next(x for x in http.get("/api/vuln/achados").json()["achados"] if x["titulo"] == "Falha média")
            passos = [x["para"] for x in http.get(f"/api/vuln/achados/{reaberto['id']}").json()["historico"]]
            registrar("a história guarda o vai e volta", passos == ["aberto", "corrigido", "aberto"], str(passos))

            print("\n== Decisão de risco", flush=True)
            registrar("sem motivo é recusado", http.post(f"/api/vuln/achados/{reaberto['id']}/estado", json={"estado": "aceito", "motivo": "ok"}).status_code == 422)
            motivo = "Sistema sai do ar em dezembro, decidido pela direção."
            registrar("aceita com motivo", http.post(f"/api/vuln/achados/{reaberto['id']}/estado", json={"estado": "aceito", "motivo": motivo}).status_code == 204)
            registrar("o motivo fica na história", http.get(f"/api/vuln/achados/{reaberto['id']}").json()["historico"][0]["motivo"] == motivo)
            registrar("a decisão fica na auditoria", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'mudar_achado'", (a,)).fetchone()[0] == 1)
            registrar("analista não aceita risco", http_ivo.post(f"/api/vuln/achados/{d[0]['id']}/estado", json={"estado": "aceito", "motivo": "tentando sem permissão"}).status_code == 403)
            feito, _ = rodar(vuln.Resultado("rede", ["10.0.0.5", "10.0.0.6"], [sem_cred, vuln.Achado("10.0.0.5", "regra-b", "Falha média", 5.0, [], "80/tcp")], autenticada=True))
            registrar("a varredura não desfaz a decisão", http.get(f"/api/vuln/achados/{reaberto['id']}").json()["estado"] == "aceito")
            feito, _ = rodar(vuln.Resultado("rede", ["10.0.0.5", "10.0.0.6"], [sem_cred], autenticada=True))
            registrar("risco aceito que sumiu continua como decidido", feito == (0, 0, 0) and http.get(f"/api/vuln/achados/{reaberto['id']}").json()["estado"] == "aceito", str(feito))
            registrar("reabre por decisão", http.post(f"/api/vuln/achados/{reaberto['id']}/estado", json={"estado": "aberto"}).status_code == 204)

            print("\n== Falha", flush=True)
            antes = http.get("/api/vuln/indicadores").json()["abertos"]
            nova = http.post("/api/vuln/varreduras", json={"alvo_id": alvo}).json()["id"]
            vuln.falhar_varredura(banco, a, nova, "Scanner fora do ar")
            registrar("falha não fecha nada", http.get("/api/vuln/indicadores").json()["abertos"] == antes)
            registrar("a tela mostra a falha", any(v["estado"] == "falhou" and v["mensagem"] == "Scanner fora do ar" for v in http.get("/api/vuln/varreduras").json()["varreduras"]))
            registrar("depois da falha pode pedir de novo", http.post("/api/vuln/varreduras", json={"alvo_id": alvo}).status_code == 201)

            print("\n== Agenda", flush=True)
            r = http.post("/api/vuln/alvos", json={"nome": "Sob demanda", "hosts": ["10.0.0.9"], "modelo_id": modelo, "a_cada_dias": 0})
            r2 = http.post("/api/vuln/alvos", json={"nome": "Semanal", "hosts": ["10.0.0.10"], "modelo_id": modelo, "a_cada_dias": 7})
            agendado = r2.json()["id"]
            quantos = vuln.agendar_vencidas(banco, a)
            registrar("a agenda enfileira o que venceu, e sob demanda não", quantos == 1, str(quantos))
            registrar("a agenda marca quem pediu como ninguém", any(v["agendada"] and v["alvo"] == "Semanal" for v in http.get("/api/vuln/varreduras").json()["varreduras"]))
            proxima = admin.execute("SELECT proxima_em FROM vuln_alvos WHERE id = %s", (agendado,)).fetchone()[0]
            registrar("a próxima fica no período pedido", timedelta(days=6) < proxima - datetime.now(timezone.utc) <= timedelta(days=7), str(proxima))
            registrar("rodar de novo não duplica", vuln.agendar_vencidas(banco, a) == 0)
            registrar("desativa alvo", http.delete(f"/api/vuln/alvos/{r.json()['id']}").status_code == 204)
            registrar("desativar não apaga os achados", http.get("/api/vuln/achados").json()["achados"])

            print("\n== Busca e exportação", flush=True)
            registrar("busca por CVE", len(http.get("/api/vuln/achados", params={"busca": "cve-2021-44228"}).json()["achados"]) == 1)
            registrar("busca por endereço", http.get("/api/vuln/achados", params={"busca": "10.0.0.5"}).json()["achados"])
            registrar("curinga é tratado como texto", http.get("/api/vuln/achados", params={"busca": "%"}).json()["achados"] == [])
            registrar("injeção na busca não quebra", http.get("/api/vuln/achados", params={"busca": "'; DROP TABLE vuln_achados; --"}).status_code == 200)
            registrar("filtra por severidade", {x["severidade"] for x in http.get("/api/vuln/achados", params={"severidade": "critica"}).json()["achados"]} == {"critica"})
            vuln.concluir_varredura(banco, a, admin.execute("SELECT id FROM vuln_varreduras WHERE alvo_id = %s AND estado = 'pendente'", (agendado,)).fetchone()[0],
                                    vuln.Resultado("web", ["10.0.0.10"], [vuln.Achado("10.0.0.10", "formula", '=HYPERLINK("http://mal")', 3.0)]))
            r = http.get("/api/vuln/achados/exportar", params={"estado": ""})
            tabela = list(csv.reader(io.StringIO(r.text)))
            registrar("exporta em CSV", r.status_code == 200 and tabela[0][0] == "host" and len(tabela) >= 4)
            registrar("fórmula de planilha é neutralizada", any(c.startswith("'=") for l in tabela for c in l) and not any(c.startswith("=") for l in tabela for c in l))
            registrar("exportar fica na auditoria", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'exportar_vulnerabilidades'", (a,)).fetchone()[0] == 1)

        print("\n== Banco", flush=True)
        with psycopg.connect(f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar") as con:
            con.execute("SELECT set_config('roar.cliente', %s, false)", (a,))
            for sql, nome in (("DELETE FROM vuln_historico", "apagar a história"), ("UPDATE vuln_historico SET motivo = 'x'", "reescrever a história"), ("DELETE FROM vuln_achados", "apagar achado"), ("UPDATE vuln_achados SET titulo = 'x'", "reescrever achado")):
                try:
                    con.execute(sql)
                    registrar(f"a API não consegue {nome}", False)
                except psycopg.errors.InsufficientPrivilege:
                    registrar(f"a API não consegue {nome}", True)
                con.rollback()
                con.execute("SELECT set_config('roar.cliente', %s, false)", (a,))
    finally:
        for tabela in TABELAS:
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM segredos WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM auditoria WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM notificacoes WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))
        admin.close()
        banco.fechar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
