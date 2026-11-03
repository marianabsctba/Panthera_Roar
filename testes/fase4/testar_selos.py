#!/usr/bin/env python3
"""Selos de integridade: adulteração de verdade no indexador real e no banco real, e o pacote conferido por fora.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_selos.py
"""

import copy
import hashlib
import io
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from pypdf import PdfReader

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

PASTA = tempfile.mkdtemp(prefix="selo-")
os.environ["ROAR_SELO_PASTA"] = PASTA

from roar_api import app as modulo  # noqa: E402
from roar_api import evidencia  # noqa: E402
from roar_ingestao import provisao, selo, verificador_de_evidencia as verificador  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402
from roar_ingestao.ciclo import conexoes  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def mth(folhas):
    """A definição da RFC 9162, escrita direto, para comparar com a implementação iterativa."""
    if not folhas:
        return hashlib.sha256(b"").digest()
    if len(folhas) == 1:
        return folhas[0]
    k = 1
    while k * 2 < len(folhas):
        k *= 2
    return hashlib.sha256(b"\x01" + mth(folhas[:k]) + mth(folhas[k:])).digest()


def tipos(achados):
    return {a["tipo"] for a in achados}


def main():
    print("== Merkle", flush=True)
    todas = [hashlib.sha256(bytes([i])).digest() for i in range(70)]
    registrar("a raiz é a da RFC 9162 em todos os tamanhos", all(selo.raiz_de_merkle(todas[:n]) == mth(todas[:n]) for n in range(0, 71)))
    certos = errados = 0
    for n in range(1, 71):
        for i in range(n):
            caminho = selo.caminho_de_merkle(todas[:n], i)
            certos += selo.raiz_pelo_caminho(todas[i], i, n, caminho) == mth(todas[:n])
            certos += verificador.raiz_pelo_caminho(todas[i], i, n, caminho) == mth(todas[:n])
            errados += selo.raiz_pelo_caminho(todas[(i + 1) % n], i, n, caminho) == mth(todas[:n]) and n > 1
            errados += verificador.raiz_pelo_caminho(todas[(i + 1) % n], i, n, caminho) == mth(todas[:n]) and n > 1
    registrar("todo caminho fecha", certos == 2 * sum(range(1, 71)), str(certos))
    registrar("folha trocada não fecha", errados == 0, str(errados))
    registrar("folha e nó têm domínios separados", selo.hash_da_folha(b"s" * 32, "a", {}) != selo._no(b"s" * 32, b"a"))
    registrar("a ordem dos campos não muda o resumo", selo.canonico({"a": 1, "b": 2}) == selo.canonico({"b": 2, "a": 1}))
    registrar("o sal muda a folha do mesmo evento", selo.hash_da_folha(b"a" * 32, "x", {"k": 1}) != selo.hash_da_folha(b"b" * 32, "x", {"k": 1}))
    pares = [("b", b"\x01" * 32), ("á-c", b"\x02" * 32)]
    registrar("folhas guardadas voltam iguais", selo.desempacotar_folhas(selo.empacotar_folhas(pares)) == pares)

    print("\n== Chave", flush=True)
    chave, publica = selo.carregar_chave()
    registrar("a chave privada fica só para o dono", (Path(PASTA) / "privada").stat().st_mode & 0o077 == 0)
    registrar("carregar de novo mantém a chave", selo.carregar_chave()[1] == publica)

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    indexer_a = provisao.indexer_admin(ENV)
    url = indexer_a.url if hasattr(indexer_a, "url") else None
    leitor, _, _ = conexoes()
    url = leitor.url
    sessao_a = indexer_a.sessao if hasattr(indexer_a, "sessao") else indexer_a
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    clientes, gerenciadores = [], []

    def criar(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        g = uuid.uuid4().hex[:12]
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 50000 + secrets.randbelow(9000)))
        clientes.append(c)
        gerenciadores.append(g)
        return c, g

    def gravar(g, fonte, momento, texto, identificador=None):
        r = sessao_a.post(f"{url}/{selo.FONTES[fonte]}{g}-2020.01.01/_doc" + (f"/{identificador}" if identificador else "") + "?refresh=true",
                          json={"timestamp": momento.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "full_log": texto, "agent": {"name": "srv-teste"}}, timeout=30)
        r.raise_for_status()
        return r.json()["_id"]

    def indice(g, fonte="logs"):
        return f"{selo.FONTES[fonte]}{g}-2020.01.01"

    def selar(g, c, fonte="logs", agora=None):
        return selo.selar_novas_janelas(leitor, banco, chave, publica, g, c, fonte, agora=agora)

    try:
        ca, ga = criar("selo-a")
        cb, gb = criar("selo-b")
        agora = datetime.now(timezone.utc)
        base = selo._piso(agora - timedelta(hours=3))

        print("\n== Selar", flush=True)
        registrar("sem evento, nada a selar", selar(ga, ca) == 0)
        ids = [gravar(ga, "logs", base + timedelta(minutes=i), f"log {i} de A") for i in range(5)]
        ids_seg = [gravar(ga, "logs", base + timedelta(minutes=20 + i), f"log {i} segunda janela") for i in range(3)]
        recente = gravar(ga, "logs", agora - timedelta(minutes=2), "log recente demais")
        alerta = gravar(ga, "alertas", base + timedelta(minutes=1), "alerta de A")
        # Quinze dias de silêncio entre dois eventos não podem virar mil selos vazios.
        selados = selar(ga, ca)
        linhas = admin.execute("SELECT n, inicio, fim, total FROM selos WHERE gerenciador_id = %s AND fonte = 'logs' ORDER BY n", (ga,)).fetchall()
        registrar("sela janela com evento e trecho vazio", selados >= 2 and linhas[0][3] == 5 and linhas[1][3] == 3, str([l[3] for l in linhas]))
        registrar("a janela aberta fica de fora", all(l[2] <= selo._piso(agora - selo.MARGEM) for l in linhas))
        registrar("o evento recente ainda não foi selado", sum(l[3] for l in linhas) == 8)
        registrar("janelas não se sobrepõem", all(a[2] == b[1] for a, b in zip(linhas, linhas[1:])))
        registrar("rodar de novo não sela duas vezes", selar(ga, ca) == 0)
        selar(ga, ca, "alertas")
        registrar("alertas entram na mesma cadeia", admin.execute("SELECT count(*) FROM selos WHERE gerenciador_id = %s AND fonte = 'alertas'", (ga,)).fetchone()[0] >= 1)
        estado, achados, eventos = selo.verificar(leitor, banco, publica, ga, ca)
        registrar("sem adulteração, tudo confere", estado == "integra" and not achados and eventos == 9, f"{estado} {achados} {eventos}")

        print("\n== Banco", flush=True)
        for sql, nome in (("UPDATE selos SET raiz = 'x' WHERE gerenciador_id = %s", "alterar selo"), ("DELETE FROM selos WHERE gerenciador_id = %s", "apagar selo"),
                          ("DELETE FROM selo_folhas WHERE gerenciador_id = %s", "apagar folhas")):
            try:
                admin.execute(sql, (ga,))
                registrar(f"nem o dono do banco consegue {nome}", False)
            except psycopg.errors.RaiseException:
                registrar(f"nem o dono do banco consegue {nome}", True)
        with psycopg.connect(f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar") as con:
            con.execute("SELECT set_config('roar.cliente', %s, false)", (cb,))
            registrar("outro cliente não vê os selos", con.execute("SELECT count(*) FROM selos WHERE gerenciador_id = %s", (ga,)).fetchone()[0] == 0)
            registrar("outro cliente não vê as folhas", con.execute("SELECT count(*) FROM selo_folhas WHERE gerenciador_id = %s", (ga,)).fetchone()[0] == 0)
            try:
                con.execute("INSERT INTO selo_verificacoes (cliente_id, gerenciador_id, completa, selos_conferidos, eventos_conferidos, estado) VALUES (%s, %s, true, 0, 0, 'integra')", (cb, gb))
                registrar("a API não consegue forjar uma conferência", False)
            except psycopg.errors.InsufficientPrivilege:
                registrar("a API não consegue forjar uma conferência", True)

        print("\n== Pacote de evidência", flush=True)
        senha = secrets.token_urlsafe(18)
        email = f"selo-{SUFIXO}@exemplo.test"
        admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Perita', %s, 'administrador')", (ca, email, PasswordHasher().hash(senha)))
        senha_b = secrets.token_urlsafe(18)
        admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'De B', %s, 'administrador')", (cb, f"b{email}", PasswordHasher().hash(senha_b)))
        senha_c = secrets.token_urlsafe(18)
        admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Auditora', %s, 'auditor')", (ca, f"c{email}", PasswordHasher().hash(senha_c)))
        with TestClient(modulo.app, base_url="https://testserver") as http:
            http.post("/api/entrar", json={"email": email, "senha": senha})
            r = http.get("/api/integridade")
            registrar("a tela mostra a situação", r.status_code == 200 and r.json()["verificacao"]["estado"] == "integra" and r.json()["selos"]["eventos"] == 9, str(r.json().get("selos")))
            r = http.post("/api/integridade/evidencia", json={"fonte": "logs", "ids": [recente]})
            registrar("evento ainda sem selo é recusado com explicação", r.status_code == 409 and "ainda não foi selado" in r.json()["detail"], r.text[:120])
            r = http.post("/api/integridade/evidencia", json={"fonte": "logs", "ids": ["../../x"]})
            registrar("identificador estranho é recusado", r.status_code == 422)
            r = http.post("/api/integridade/evidencia", json={"fonte": "tudo", "ids": [ids[0]]})
            registrar("fonte estranha é recusada", r.status_code == 422)
            r = http.post("/api/integridade/evidencia", json={"fonte": "logs", "ids": [ids[1], ids_seg[0]]})
            registrar("gera o pacote", r.status_code == 200 and r.headers["content-type"] == "application/zip", f"{r.status_code} {r.text[:160] if r.status_code != 200 else ''}")
            z = zipfile.ZipFile(io.BytesIO(r.content))
            registrar("traz prova, laudo, leia-me e programa", {"evidencia.json", "laudo.pdf", "verificar.py", "LEIA-ME.txt"} <= set(z.namelist()), str(z.namelist()))
            pacote = json.loads(z.read("evidencia.json"))
            bruto = z.read("evidencia.json").decode()
            registrar("leva os eventos escolhidos", "log 1 de A" in bruto and "log 0 segunda janela" in bruto)
            registrar("não leva os vizinhos", not any(t in bruto for t in ("log 0 de A", "log 2 de A", "log 1 segunda janela", "log recente")))
            registrar("o sal dos vizinhos não sai", len({e["sal"] for e in pacote["eventos"]}) == 2)
            registrar("a chave privada não sai", (Path(PASTA) / "privada").read_bytes().hex() not in bruto)
            laudo = "".join(p.extract_text() for p in PdfReader(io.BytesIO(z.read("laudo.pdf"))).pages)
            registrar("o laudo traz o limite do que afirma", "não mostra que o conteúdo do log é verdadeiro" in " ".join(laudo.split()).lower(), laudo[:80])
            registrar("o laudo traz a impressão da chave", selo.impressao_da_chave(publica)[:32] in laudo.replace("\n", ""))
            registrar("a geração fica na auditoria com o resumo", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'gerar_evidencia' AND alvo LIKE %s", (ca, f"%sha256:{r.headers['x-resumo-sha256']}")).fetchone()[0] == 1)
            r2 = http.post("/api/integridade/evidencia", json={"fonte": "alertas", "ids": [alerta]})
            registrar("alerta também gera pacote", r2.status_code == 200, str(r2.status_code))

            print("\n== Conferência por fora", flush=True)
            pasta = tempfile.mkdtemp(prefix="evid-")
            z.extractall(pasta)
            saida = subprocess.run([sys.executable, "-I", "verificar.py", "evidencia.json"], cwd=pasta, capture_output=True, text=True, timeout=60)
            registrar("o programa do pacote confere sozinho", saida.returncode == 0 and "CONFERE" in saida.stdout, (saida.stdout + saida.stderr)[:200])
            sem_lib = subprocess.run(["/usr/bin/python3", "-I", "-S", "verificar.py", "evidencia.json"], cwd=pasta, capture_output=True, text=True, timeout=60)
            registrar("sem a biblioteca, confere o resto e avisa", sem_lib.returncode == 0 and "assinatura não foi conferida" in sem_lib.stdout, (sem_lib.stdout + sem_lib.stderr)[:200])

            print("\n== Pacote para perícia de um período", flush=True)
            r = http.post("/api/logs/evidencia", json={"dias": 7})
            registrar("gera o pacote do período", r.status_code == 200 and r.headers["content-type"] == "application/zip", f"{r.status_code} {r.text[:160] if r.status_code != 200 else ''}")
            zp = zipfile.ZipFile(io.BytesIO(r.content))
            bruto_p = zp.read("evidencia.json").decode()
            registrar("leva todos os logs selados", all(t in bruto_p for t in ("log 0 de A", "log 1 de A", "log 0 segunda janela")), r.headers.get("x-logs"))
            registrar("deixa de fora o que ainda não foi selado, e diz quantos", "log recente" not in bruto_p and int(r.headers["x-fora-do-pacote"]) >= 1, r.headers.get("x-fora-do-pacote"))
            pasta_p = tempfile.mkdtemp(prefix="pericia-")
            zp.extractall(pasta_p)
            saida = subprocess.run([sys.executable, "-I", "verificar.py", "evidencia.json"], cwd=pasta_p, capture_output=True, text=True, timeout=120)
            registrar("o pacote do período confere sozinho", saida.returncode == 0 and "CONFERE" in saida.stdout, (saida.stdout + saida.stderr)[:200])
            laudo_p = " ".join("".join(p.extract_text() for p in PdfReader(io.BytesIO(zp.read("laudo.pdf"))).pages).split())
            registrar("o laudo diz o que foi pedido", "O que foi pedido" in laudo_p and "últimos 7 dias" in laudo_p, laudo_p[:120])
            registrar("fica na auditoria com o resumo", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'gerar_evidencia_de_periodo' AND alvo LIKE %s",
                                                                      (ca, f"%sha256:{r.headers['x-resumo-sha256']}")).fetchone()[0] == 1)
            r = http.post("/api/logs/evidencia", json={"dias": 7, "busca": "segunda"})
            bruto_f = zipfile.ZipFile(io.BytesIO(r.content)).read("evidencia.json").decode() if r.status_code == 200 else ""
            registrar("respeita a busca da tela", "segunda janela" in bruto_f and "de A" not in bruto_f.replace("segunda janela", ""), f"{r.status_code} {r.headers.get('x-logs')}")
            filtro = json.dumps([{"campo": "agent.name", "valor": "srv-teste", "negar": True}])
            registrar("respeita os filtros da tela", http.post("/api/logs/evidencia", json={"dias": 7, "filtros": filtro}).status_code == 409)
            registrar("contagem é recusada", http.post("/api/logs/evidencia", json={"dias": 7, "busca": "| contar por usuario"}).status_code == 422)
            registrar("busca sem resultado explica", http.post("/api/logs/evidencia", json={"dias": 7, "busca": "palavraquenaoexiste"}).status_code == 409)
            registrar("período fora do limite é recusado", http.post("/api/logs/evidencia", json={"dias": 400}).status_code == 422)
            muitos = {**pacote, "eventos": pacote["eventos"] * 101}
            html = evidencia._laudo(muitos, {"cliente_nome": "X", "nome": "Y"}, datetime.now(timezone.utc), [("Período", "últimos 7 dias")])
            registrar("com muitos logs, o laudo lista e não imprime cada um", "Por serem muitos" in html and html.count("<pre>") == 0)

            def adulterar(mudanca):
                p = copy.deepcopy(pacote)
                mudanca(p)
                return verificador.conferir(p)[0]

            def mudar_doc(p):
                p["eventos"][0]["documento"]["full_log"] = "outra coisa"

            def mudar_campo_novo(p):
                p["eventos"][0]["documento"]["extra"] = 1

            def trocar_sal(p):
                p["eventos"][0]["sal"] = "00" * 32

            def trocar_indice(p):
                p["eventos"][0]["indice"] += 1

            def tirar_irmao(p):
                p["eventos"][0]["caminho"] = p["eventos"][0]["caminho"][:-1]

            def mudar_raiz(p):
                p["selos"][0]["raiz"] = "00" * 32

            def mudar_data_e_refazer_hash(p):
                # Atacante com o pacote: acerta o resumo, mas não tem a chave para assinar.
                p["selos"][0]["selado_em"] = "2020-01-01T00:00:00+00:00"
                p["selos"][0]["hash"] = verificador.hash_do_selo(p["selos"][0])

            def mudar_total(p):
                # O total entra no resumo do selo: é ele que amarra o tamanho da árvore.
                p["selos"][0]["total"] += 1

            def tirar_selo_do_meio(p):
                if len(p["selos"]) > 2:
                    del p["selos"][1]
                else:
                    p["selos"].pop()

            def outra_chave(p):
                p["chave_publica"] = "11" * 32

            for nome, mudanca in (("mudar o texto do evento", mudar_doc), ("acrescentar campo", mudar_campo_novo), ("trocar o sal", trocar_sal), ("trocar a posição", trocar_indice),
                                  ("tirar um irmão do caminho", tirar_irmao), ("mudar a raiz", mudar_raiz), ("mudar o total", mudar_total), ("mudar a data e refazer o resumo", mudar_data_e_refazer_hash),
                                  ("tirar selo do meio", tirar_selo_do_meio), ("trocar a chave", outra_chave)):
                registrar(f"o programa acusa: {nome}", adulterar(mudanca))
            registrar("pacote malformado não derruba o programa", verificador.conferir({"eventos": 1})[0])
            json.dump({**pacote, "eventos": [{**pacote["eventos"][0], "documento": {"full_log": "forjado"}}]}, open(f"{pasta}/ruim.json", "w", encoding="utf-8"))
            ruim = subprocess.run([sys.executable, "-I", "verificar.py", "ruim.json"], cwd=pasta, capture_output=True, text=True, timeout=60)
            registrar("o programa sai com erro quando não confere", ruim.returncode == 1 and "NÃO CONFERE" in ruim.stdout)

            print("\n== Outros clientes e perfis", flush=True)
            with_b = TestClient(modulo.app, base_url="https://testserver")
            with_b.post("/api/entrar", json={"email": f"b{email}", "senha": senha_b})
            registrar("outro cliente não gera pacote de um evento meu", with_b.post("/api/integridade/evidencia", json={"fonte": "logs", "ids": [ids[0]]}).status_code in (404, 409))
            auditora = TestClient(modulo.app, base_url="https://testserver")
            auditora.post("/api/entrar", json={"email": f"c{email}", "senha": senha_c})
            registrar("auditoria vê a situação", auditora.get("/api/integridade").status_code == 200)
            registrar("auditoria não gera pacote com log bruto", auditora.post("/api/integridade/evidencia", json={"fonte": "logs", "ids": [ids[0]]}).status_code == 403)
            registrar("auditoria não gera pacote de período", auditora.post("/api/logs/evidencia", json={"dias": 7}).status_code == 403)
            r = with_b.post("/api/logs/evidencia", json={"dias": 7})
            registrar("o pacote de outro cliente não leva logs meus", r.status_code != 200 or "de A" not in zipfile.ZipFile(io.BytesIO(r.content)).read("evidencia.json").decode(), str(r.status_code))

            print("\n== Adulteração real no indexador", flush=True)
            sessao_a.post(f"{url}/{indice(ga)}/_update/{ids[2]}?refresh=true", json={"doc": {"full_log": "log adulterado"}}, timeout=30).raise_for_status()
            estado, achados, _ = selo.verificar(leitor, banco, publica, ga, ca)
            registrar("alterar um evento é apontado", estado == "violada" and {"tipo": "evento_alterado", "n": linhas[0][0], "evento": ids[2]} in achados, str(achados)[:200])
            registrar("só ele é acusado", len(achados) == 1, str(len(achados)))
            r = http.post("/api/integridade/evidencia", json={"fonte": "logs", "ids": [ids[2]]})
            registrar("pacote de evento alterado é recusado", r.status_code == 409 and "alterado depois da selagem" in r.json()["detail"], r.text[:140])
            registrar("a tela mostra qual foi", any(a.get("evento") == ids[2] for a in http.get("/api/integridade").json()["verificacao"]["achados"]))
            registrar("o evento intacto ao lado ainda gera pacote", http.post("/api/integridade/evidencia", json={"fonte": "logs", "ids": [ids[3]]}).status_code == 200)
            sessao_a.delete(f"{url}/{indice(ga)}/_doc/{ids_seg[1]}?refresh=true", timeout=30).raise_for_status()
            estado, achados, _ = selo.verificar(leitor, banco, publica, ga, ca)
            registrar("apagar um evento é apontado", {"tipo": "evento_apagado", "n": linhas[1][0], "evento": ids_seg[1]} in achados, str(achados)[:200])
            intruso = gravar(ga, "logs", base + timedelta(minutes=3), "log incluído depois")
            estado, achados, _ = selo.verificar(leitor, banco, publica, ga, ca)
            registrar("incluir um evento é apontado", any(a["tipo"] == "evento_sem_selo" and a["evento"] == intruso for a in achados), str(achados)[:200])

            print("\n== Tardios", flush=True)
            # Quem chega dentro do horizonte entra marcado, em vez de sumir nem fingir que estava lá.
            antes = admin.execute("SELECT count(*) FROM selos WHERE gerenciador_id = %s AND tardio", (ga,)).fetchone()[0]
            selados = selo.selar_tardios(leitor, banco, chave, publica, ga, ca, "logs")
            depois = admin.execute("SELECT total FROM selos WHERE gerenciador_id = %s AND tardio ORDER BY n DESC LIMIT 1", (ga,)).fetchone()
            registrar("chegou depois: selo próprio, marcado", selados == 1 and antes == 0 and depois[0] == 1, f"{selados} {depois}")
            estado, achados, _ = selo.verificar(leitor, banco, publica, ga, ca)
            registrar("deixa de ser acusado como sem selo", not any(a.get("evento") == intruso for a in achados), str(achados)[:200])
            registrar("a tela conta os tardios", http.get("/api/integridade").json()["selos"]["tardios"] == 1)
            registrar("rodar de novo não repete", selo.selar_tardios(leitor, banco, chave, publica, ga, ca, "logs") == 0)
            # Antes do horizonte não vira tardio: continua acusado.
            velho = gravar(ga, "logs", base - timedelta(hours=30), "log muito antigo incluído agora")
            registrar("muito antigo não vira tardio", selo.selar_tardios(leitor, banco, chave, publica, ga, ca, "logs") == 0)

            print("\n== Retenção", flush=True)
            cc, gc = criar("selo-retencao")
            antigo = agora - timedelta(days=200)
            id_antigo = gravar(gc, "logs", antigo, "evento antigo")
            selar(gc, cc, agora=antigo + timedelta(hours=2))
            sessao_a.delete(f"{url}/{indice(gc)}/_doc/{id_antigo}?refresh=true", timeout=30).raise_for_status()
            estado, achados, _ = selo.verificar(leitor, banco, publica, gc, cc, retencao_dias=90)
            registrar("evento além da retenção pode sumir", estado == "integra", str(achados)[:160])
            registrar("com retenção maior, o mesmo sumiço é acusado", selo.verificar(leitor, banco, publica, gc, cc, retencao_dias=400)[0] == "violada")

            print("\n== Banco adulterado por quem tem acesso total", flush=True)
            cd, gd = criar("selo-banco")
            gravar(gd, "logs", base, "evento d")
            gravar(gd, "logs", base + timedelta(minutes=20), "evento d2")
            selar(gd, cd)
            registrar("começa íntegro", selo.verificar(leitor, banco, publica, gd, cd)[0] == "integra")
            tabela = "ALTER TABLE selos {} TRIGGER so_acrescenta"
            admin.execute(tabela.format("DISABLE"))
            try:
                admin.execute("UPDATE selos SET raiz = %s WHERE gerenciador_id = %s AND n = 1", ("00" * 32, gd))
                _, achados, _ = selo.verificar(leitor, banco, publica, gd, cd)
                registrar("selo alterado é acusado", "selo_alterado" in tipos(achados), str(tipos(achados)))
                admin.execute("UPDATE selos SET raiz = %s, hash = %s WHERE gerenciador_id = %s AND n = 1", ("00" * 32, "ab" * 32, gd))
                _, achados, _ = selo.verificar(leitor, banco, publica, gd, cd)
                registrar("refazer o resumo quebra a sequência", "cadeia_quebrada" in tipos(achados), str(tipos(achados)))
                # O ataque completo sem a chave: refaz resumo e encadeia, mas assina com outra.
                falsa = selo.Ed25519PrivateKey.generate()
                linha = admin.execute(f"SELECT {selo.COLUNAS} FROM selos WHERE gerenciador_id = %s AND n = 1", (gd,)).fetchone()
                forjado = selo._selo_da_linha(linha)
                forjado["raiz"] = "11" * 32
                forjado["hash"] = selo.hash_do_selo(forjado)
                assinatura = falsa.sign(bytes.fromhex(forjado["hash"])).hex()
                admin.execute("UPDATE selos SET raiz = %s, hash = %s, assinatura = %s WHERE gerenciador_id = %s AND n = 1", (forjado["raiz"], forjado["hash"], assinatura, gd))
                registrar("assinar com outra chave é acusado", "assinatura_invalida" in tipos(selo.verificar(leitor, banco, publica, gd, cd)[1]))
            finally:
                admin.execute(tabela.format("ENABLE"))

            print("\n== Âncora", flush=True)
            ce, ge = criar("selo-ancora")
            gravar(ge, "logs", base, "evento e")
            selar(ge, ce)
            enviados = []

            def falso(calendario, resumo_da_ponta):
                enviados.append((calendario, resumo_da_ponta))
                return b"\xf1\x04abcd"

            registrar("ancora nos dois calendários", selo.ancorar(banco, ge, ce, falso) == 2)
            ponta = selo.GENESE
            with banco.con.transaction():
                banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (ce,))
                _, ponta = selo._ponta_da_cadeia(banco, ge)
            registrar("só o resumo da ponta sai", all(r == bytes.fromhex(ponta) for _, r in enviados), str(len(enviados)))
            registrar("no mesmo dia não ancora de novo", selo.ancorar(banco, ge, ce, falso) == 0)

            def caiu(calendario, resumo_da_ponta):
                raise OSError("sem rede")

            cf, gf = criar("selo-sem-rede")
            gravar(gf, "logs", base, "evento f")
            selar(gf, cf)
            registrar("sem rede não derruba a selagem", selo.ancorar(banco, gf, cf, caiu) == 0)
            registrar("o arquivo tem o formato aberto", selo.arquivo_ots("ab" * 32, b"xy").startswith(selo.MAGICA_OTS + b"\x01\x08" + bytes.fromhex("ab" * 32)))

        print("\n== Volume", flush=True)
        documentos = [(uuid.uuid4().hex, {"timestamp": "2026-01-01T00:00:00.000+0000", "full_log": "x" * 300, "agent": {"id": "001", "name": "srv"}}) for _ in range(100_000)]
        inicio = time.monotonic()
        pares = selo.folhas_em_ordem(secrets.token_bytes(32), documentos)
        raiz = selo.raiz_de_merkle([h for _, h in pares])
        empacotado = selo.empacotar_folhas(pares)
        duracao = time.monotonic() - inicio
        registrar("100 mil eventos são selados em tempo aceitável", duracao < 15 and raiz, f"{duracao:.1f}s, {len(empacotado) / 100_000:.0f} bytes por evento guardado")
    finally:
        for tabela in ("selos", "selo_folhas", "selo_verificacoes", "selo_ancoras"):
            admin.execute(f"ALTER TABLE {tabela} DISABLE TRIGGER so_acrescenta")
        try:
            for tabela in ("selo_ancoras", "selo_verificacoes", "selo_folhas", "selos"):
                admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        finally:
            for tabela in ("selos", "selo_folhas", "selo_verificacoes", "selo_ancoras"):
                admin.execute(f"ALTER TABLE {tabela} ENABLE TRIGGER so_acrescenta")
        admin.execute("DELETE FROM auditoria WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM gerenciadores WHERE id = ANY(%s)", (gerenciadores,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))
        admin.close()
        for g in gerenciadores:
            sessao_a.delete(f"{url}/wazuh-*-4.x-{g}-*", timeout=30)
        banco.fechar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
