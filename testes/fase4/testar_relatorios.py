#!/usr/bin/env python3
"""Relatório completo: conteúdo, sumário, isolamento e texto hostil, sobre dados no banco real.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_relatorios.py [--guardar caminho.pdf]
"""

import hashlib
import io
import json
import re
import secrets
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from pypdf import PdfReader

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]

from roar_api import relatorios  # noqa: E402
from roar_api.app import app  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
ACESSOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class Espiao(BaseHTTPRequestHandler):
    def do_GET(self):
        ACESSOS.append(self.path)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def texto_do_pdf(conteudo):
    leitor = PdfReader(io.BytesIO(conteudo))
    return leitor, [p.extract_text() or "" for p in leitor.pages]


def main():
    servidor = HTTPServer(("127.0.0.1", 0), Espiao)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    espiao = f"http://127.0.0.1:{servidor.server_address[1]}/vazou"
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    sufixo = uuid.uuid4().hex[:8]
    clientes = []

    def criar_cliente(nome):
        c = admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{sufixo}",)).fetchone()[0]
        clientes.append(c)
        g = f"{nome}{sufixo}"
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 50000 + secrets.randbelow(9000)))
        senha, email = secrets.token_urlsafe(18), f"{nome}-{sufixo}@exemplo.test"
        admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, %s, %s, 'auditor')", (c, email, f"Pessoa {nome}", PasswordHasher().hash(senha)))
        return {"id": c, "g": g, "acesso": {"email": email, "senha": senha}}

    def evento(cl, regra, descricao, nivel, severidade, quando, ip="1.1.1.1", usuario="maria", mitre=(), extra=None, grupos=("teste",)):
        bruto = {"rule": {"id": regra, "gdpr": ["IV_35.7.d"], "pci_dss": ["10.2.5"]}, "GeoLocation": {"country_name": "Brasil"}, **(extra or {})}
        admin.execute(
            """INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao, regra_grupos, mitre, gerenciador_id, agente_id, agente_nome, ip_origem, usuario, bruto)
               VALUES (%s, 't', %s, %s, %s, %s, %s, %s, %s, %s, %s, '001', 'srv-a', %s, %s, %s)""",
            (cl["id"], uuid.uuid4().hex, quando, nivel, severidade, regra, descricao, list(grupos), list(mitre), cl["g"], ip, usuario, json.dumps(bruto)))

    try:
        a, b = criar_cliente("rela"), criar_cliente("relb")
        agora = datetime.now(timezone.utc)
        marca_b = f"segredodeb{uuid.uuid4().hex[:10]}"
        hostil = f'<img src="{espiao}"><script>alert(1)</script><link rel=stylesheet href="{espiao}">{{{{ 7*7 }}}}'
        for dia in range(1, 11):
            evento(a, "5712", "Força bruta em SSH", 12, "critica", agora - timedelta(days=dia), mitre=("T1110",))
            evento(a, "5710", "Login inexistente", 5, "media", agora - timedelta(days=dia), ip="1.0.0.1")
        evento(a, "9999", hostil, 10, "alta", agora - timedelta(hours=2), usuario=hostil[:60])
        for dia in range(31, 35):
            evento(a, "5712", "Força bruta em SSH", 12, "critica", agora - timedelta(days=dia))
        evento(a, "550", "Arquivo alterado", 7, "media", agora - timedelta(days=1), grupos=("syscheck",), extra={"syscheck": {"path": "/etc/passwd", "event": "modified"}})
        evento(b, "7777", marca_b, 12, "critica", agora - timedelta(days=1), ip="1.0.0.7", usuario=marca_b)

        with TestClient(app, base_url="https://testserver") as http:
            registrar("exige sessão", http.get("/api/relatorios").status_code == 401)
            http.post("/api/entrar", json=a["acesso"])
            r = http.get("/api/relatorios", params={"dias": 30})
            registrar("gera o PDF", r.status_code == 200 and r.content[:5] == b"%PDF-", f"{r.status_code}, {len(r.content):,} bytes".replace(",", "."))
            registrar("baixa como arquivo", 'attachment; filename="relatorio-completo-' in r.headers.get("content-disposition", ""))
            if "--guardar" in sys.argv:
                Path(sys.argv[sys.argv.index("--guardar") + 1]).write_bytes(r.content)
            leitor, paginas = texto_do_pdf(r.content)
            tudo = "\n".join(paginas)
            print(f"   {len(paginas)} páginas", flush=True)

            print("\n== Estrutura", flush=True)
            registrar("tem várias páginas", len(paginas) >= 12, str(len(paginas)))
            capitulos = ["Sumário", "Resumo executivo", "Alertas", "Risco de comportamento", "Técnicas de ataque", "Integridade de arquivos", "Vulnerabilidades", "Automação e resposta",
                         "Inventário de ativos", "Fontes de dados", "Conformidade por norma", "Trilha de auditoria", "Método e limites"]
            faltam = [c for c in capitulos if c not in tudo]
            registrar("todos os capítulos estão lá", not faltam, str(faltam))
            sumario = paginas[1]
            registrar("o sumário é a segunda página", "Sumário" in sumario and "Resumo executivo" in sumario)
            numeros = [l for l in sumario.splitlines() if "Conformidade por norma" in l]
            alvo = int(numeros[0].split()[-1]) if numeros and numeros[0].split()[-1].isdigit() else None
            registrar("o sumário aponta a página certa", alvo and "Conformidade por norma" in paginas[alvo - 1], f"página {alvo}")
            registrar("rodapé numerado", f"Página 3 de {len(paginas)}" in paginas[2])
            registrar("aviso de confidencial nas páginas", "Confidencial" in paginas[2])

            print("\n== Números", flush=True)
            registrar("compara com o período anterior", "sobre o período anterior" in " ".join(tudo.split()))
            svg = relatorios.grafico_por_dia([{"dia": agora, "critica": 0, "alta": 0, "media": 3, "baixa": 0}])
            registrar("o eixo do gráfico só tem número inteiro", all(float(v).is_integer() for v in re.findall(r'text-anchor="end"[^>]*>([\d.]+)<', svg)) and svg.count('text-anchor="end"') >= 2, svg.count('text-anchor="end"'))
            registrar("a regra do cliente aparece", "Força bruta em SSH" in tudo and "5712" in tudo)
            registrar("o que está fora do período não conta", relatorios.coletar is not None and _regras_contam(http, 10))
            registrar("a norma aparece com o controle", "IV_35.7.d" in tudo and "10.2.5" in tudo)
            registrar("a técnica aparece", "T1110" in tudo)
            registrar("o arquivo alterado aparece", "/etc/passwd" in tudo)
            registrar("o relatório diz o que não sabe sobre vulnerabilidades", "ainda não está ligada" in tudo)
            registrar("os limites aparecem", "não atesta conformidade" in tudo)
            registrar("o método não promete o que não há", "não inclui o conteúdo bruto" in tudo)

            print("\n== Texto hostil", flush=True)
            registrar("nada foi buscado de fora", not ACESSOS, str(ACESSOS))
            registrar("marcação vira texto no papel", "<script>" in tudo.replace("\n", "") or "script" in tudo, "")
            registrar("modelo não executa o texto do alerta", "{{ 7*7 }}" in tudo.replace("\n", " ") or "7*7" in tudo)
            html = relatorios.montar_html(relatorios_dados(http, a), {"fuso": "America/Sao_Paulo", "cliente_nome": '<b>x</b>', "nome": "<i>y</i>"}, 30, "completo")
            registrar("o HTML sai escapado", "<script>alert" not in html and "&lt;script&gt;" in html and "<b>x</b>" not in html)
            try:
                relatorios._nao_buscar_nada(espiao)
                registrar("o gerador recusa recurso externo", False)
            except ValueError:
                registrar("o gerador recusa recurso externo", True)

            print("\n== Isolamento", flush=True)
            registrar("o relatório de A não traz nada de B", marca_b not in tudo)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=b["acesso"])
            _, paginas_b = texto_do_pdf(http.get("/api/relatorios").content)
            texto_b = "\n".join(paginas_b).replace("\n", "")
            registrar("o de B traz o de B", marca_b in texto_b)
            registrar("o de B não traz nada de A", "Força bruta em SSH" not in texto_b and "/etc/passwd" not in texto_b)
            registrar("o de B não traz as pessoas de A", "Pessoa rela" not in texto_b and "Pessoa relb" in texto_b)
            http.post("/api/sair")
            http.cookies.clear()

            print("\n== Outras opções", flush=True)
            http.post("/api/entrar", json=a["acesso"])
            r2 = http.get("/api/relatorios", params={"tipo": "executivo", "dias": 7})
            _, execu = texto_do_pdf(r2.content)
            registrar("o executivo é menor", len(execu) < len(paginas), f"{len(execu)} páginas")
            registrar("o executivo tem o que importa", "Resumo executivo" in "".join(execu) and "Método e limites" in "".join(execu))
            r3 = http.get("/api/relatorios", params={"formato": "json"})
            registrar("sai também em JSON", r3.status_code == 200 and "resumo" in r3.json())
            registrar("tipo inventado é recusado", http.get("/api/relatorios", params={"tipo": "x"}).status_code == 422)
            registrar("formato inventado é recusado", http.get("/api/relatorios", params={"formato": "exe"}).status_code == 422)
            registrar("período absurdo não quebra", http.get("/api/relatorios", params={"dias": 99999, "formato": "json"}).status_code == 200)

            print("\n== Auditoria e integridade", flush=True)
            resumo = hashlib.sha256(r2.content).hexdigest()
            registrar("cabeçalho traz o resumo do arquivo", r2.headers.get("x-resumo-sha256") == resumo)
            registrar("a geração fica registrada com o resumo", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'gerar_relatorio' AND alvo LIKE %s", (a["id"], f"%{resumo}")).fetchone()[0] == 1)
            registrar("o bruto do alerta não vai no JSON", "IV_35" not in json.dumps(r3.json()["regras"]))
    finally:
        servidor.shutdown()
        for tabela in ("auditoria", "eventos"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM gerenciadores WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))
        admin.close()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


def _regras_contam(http, esperado):
    dados = http.get("/api/relatorios", params={"formato": "json", "dias": 30}).json()
    # Dez dentro do período; os quatro de mais de 30 dias ficam só na comparação.
    regra = next(r for r in dados["regras"] if r["regra_id"] == "5712")
    return regra["total"] == esperado and dados["resumo"]["anterior"] == 4


def relatorios_dados(http, cliente):
    dados = http.get("/api/relatorios", params={"formato": "json", "dias": 30}).json()
    # Volta ao tipo que o modelo espera: o JSON traz datas como texto, e o filtro de data aceita texto.
    dados["por_dia"] = []
    return dados


if __name__ == "__main__":
    sys.exit(main())
