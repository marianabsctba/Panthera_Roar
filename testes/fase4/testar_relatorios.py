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
        # A pessoa de B vê dado pessoal mascarado: com a marca no nome do usuário, a descrição também sairia mascarada.
        evento(b, "7777", marca_b, 12, "critica", agora - timedelta(days=1), ip="1.0.0.7", usuario="joana")

        def checagem(cl, id_, titulo, resultado, quando):
            evento(cl, "19007", "Checagem de configuração", 7, "media", quando, grupos=("sca",), extra={"data": {"sca": {
                "type": "check", "policy": "CIS Debian 12", "policy_id": "cis_debian12",
                "check": {"id": id_, "title": titulo, "result": resultado, "compliance": {"pci_dss_v4": {"0": "2.2.4,8.3.1"}, "cis": "1.1"}}}}})
        # Uma varredura concluída em A, com uma crítica aberta e uma corrigida no período.
        modelo = admin.execute("INSERT INTO vuln_modelos (cliente_id, nome, ferramenta, criado_por) VALUES (%s, 'Rede', 'rede', %s) RETURNING id", (a["id"], uuid.uuid4())).fetchone()[0]
        alvo = admin.execute("INSERT INTO vuln_alvos (cliente_id, nome, hosts, modelo_id, criado_por) VALUES (%s, 'Servidores', '{10.0.0.5}', %s, %s) RETURNING id",
                             (a["id"], modelo, uuid.uuid4())).fetchone()[0]
        admin.execute("INSERT INTO vuln_varreduras (cliente_id, alvo_id, modelo_id, estado, terminada_em) VALUES (%s, %s, %s, 'concluida', %s)", (a["id"], alvo, modelo, agora - timedelta(days=1)))
        ativo_vuln = admin.execute("INSERT INTO vuln_ativos (cliente_id, host, nome, peso) VALUES (%s, '10.0.0.5', 'srv-folha', 5) RETURNING id", (a["id"],)).fetchone()[0]
        admin.execute("""INSERT INTO vuln_achados (cliente_id, ativo_id, chave, fonte, titulo, cves, cvss, severidade, estado, primeira_vez) VALUES
                         (%s, %s, 'k1', 'openvas', 'OpenSSH vulnerável a execução remota', '{CVE-2024-6387}', 8.1, 'critica', 'aberto', %s)""", (a["id"], ativo_vuln, agora - timedelta(days=5)))
        admin.execute("""INSERT INTO vuln_achados (cliente_id, ativo_id, chave, fonte, titulo, severidade, estado, primeira_vez, corrigido_em) VALUES
                         (%s, %s, 'k2', 'openvas', 'Cabeçalho HTTP fraco', 'baixa', 'corrigido', %s, %s)""", (a["id"], ativo_vuln, agora - timedelta(days=9), agora - timedelta(days=2)))
        checagem(a, "1", "Garantir senha forte", "failed", agora - timedelta(days=2))
        checagem(a, "2", "Garantir tmp separado", "failed", agora - timedelta(days=3))
        checagem(a, "2", "Garantir tmp separado", "passed", agora - timedelta(days=1))

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
            sem_quebra = " ".join(tudo.split())
            registrar("as vulnerabilidades da organização entram no relatório", "OpenSSH vulnerável a execução remota" in sem_quebra and "CVE-2024-6387" in "".join(tudo.split())
                      and "srv-folha" in sem_quebra and "críticas e altas abertas" in sem_quebra,
                      str([t for t in ("OpenSSH vulnerável a execução remota", "srv-folha", "críticas e altas abertas") if t not in sem_quebra]))
            registrar("o resumo executivo destaca as vulnerabilidades", "1 vulnerabilidades críticas e altas abertas" in sem_quebra)
            vj = http.get("/api/relatorios", params={"formato": "json", "dias": 30}).json()["vuln"]
            registrar("o JSON conta abertas e corrigidas no período", (vj["abertos"]["critica"], vj["periodo"]["corrigidos"], vj["periodo"]["ativos_expostos"]) == (1, 1, 1), str(vj["periodo"]))
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
            registrar("sem varredura, o relatório diz o que não sabe", "Nenhuma varredura de vulnerabilidade foi concluída" in " ".join(texto_b.split())
                      or "Nenhuma varredura de vulnerabilidade foi concluída" in " ".join("".join(paginas_b).split()))
            registrar("B não vê o histórico de A", all(r["nome"].startswith("relatorio-") for r in http.get("/api/relatorios/historico").json()["relatorios"])
                      and not any(r["tipo"] == "norma" for r in http.get("/api/relatorios/historico").json()["relatorios"]))
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

            print("\n== Relatório de norma", flush=True)
            rn = http.get("/api/normas/relatorio", params={"norma": "pci_dss", "dias": 30})
            _, paginas_n = texto_do_pdf(rn.content)
            texto_n = "\n".join(paginas_n)
            registrar("o relatório de norma sai em PDF", rn.status_code == 200 and "Relatório de conformidade: PCI DSS" in texto_n.replace("\n", " "), texto_n[:120])
            registrar("o PDF da norma traz os controles com alerta", "10.2.5" in texto_n and "Força bruta em SSH" in " ".join(texto_n.split()))
            jn = http.get("/api/normas/relatorio", params={"norma": "pci_dss", "dias": 30, "formato": "json"}).json()
            controle = next((c for c in jn["controles"] if c["controle"] == "10.2.5"), {})
            registrar("o JSON conta os alertas do controle no período", controle.get("total") == 25 and controle.get("severidade") == "critica", str(controle)[:160])
            registrar("o controle vem com o nome em português", controle.get("nome") == "Registrar o uso e a mudança de identificação e autenticação", str(controle.get("nome")))
            registrar("o PDF da norma traz o que cada controle pede", "Registrar o uso e a mudança de" in " ".join(texto_n.split()))
            registrar("checagem do PCI 4.0 leva o nome do requisito principal",
                      {c["controle"]: c["nome"] for c in jn["configuracao"]}.get("8.3.1") == "Identificar e autenticar o acesso")
            reprovadas = {c["controle"]: c for c in jn["configuracao"]}
            registrar("checagem reprovada aparece no controle que ela atende", set(reprovadas) == {"2.2.4", "8.3.1"}
                      and reprovadas["2.2.4"]["exemplos"] == ["Garantir senha forte"], str(jn["configuracao"])[:200])
            registrar("checagem que voltou a passar não conta", all(c["total"] == 1 for c in jn["configuracao"]))
            registrar("o relatório traz a guarda dos registros", "retencao_alertas_dias" in jn["guarda"] and "selos" in jn["guarda"])
            registrar("norma inventada é recusada", http.get("/api/normas/relatorio", params={"norma": "iso_inventada"}).status_code == 422)
            registrar("a geração do relatório de norma fica registrada", admin.execute(
                "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'gerar_relatorio_de_norma' AND alvo LIKE %s",
                (a["id"], f"%{hashlib.sha256(rn.content).hexdigest()}")).fetchone()[0] == 1)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=b["acesso"])
            jb = http.get("/api/normas/relatorio", params={"norma": "pci_dss", "dias": 30, "formato": "json"}).json()
            registrar("o relatório de norma de B não traz nada de A", not jb["configuracao"] and "Força bruta" not in json.dumps(jb))
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=a["acesso"])

            print("\n== Histórico", flush=True)
            historico = http.get("/api/relatorios/historico").json()["relatorios"]
            registrar("todo relatório gerado fica no histórico", len(historico) >= 5 and {"completo", "executivo", "norma"} <= {r["tipo"] for r in historico}, str(len(historico)))
            guardado = next(r for r in historico if r["tipo"] == "executivo")
            baixado = http.get(f"/api/relatorios/historico/{guardado['id']}")
            registrar("baixar de novo devolve o mesmo arquivo", baixado.status_code == 200 and hashlib.sha256(baixado.content).hexdigest() == guardado["sha256"] == hashlib.sha256(r2.content).hexdigest())
            registrar("a pessoa mascarada gerou mascarado", guardado["mascarado"] is True)
            admin.execute("UPDATE relatorios_gerados SET mascarado = false WHERE id = %s", (guardado["id"],))
            registrar("quem vê mascarado não baixa o que saiu sem máscara", http.get(f"/api/relatorios/historico/{guardado['id']}").status_code == 403
                      and not next(r for r in http.get("/api/relatorios/historico").json()["relatorios"] if r["id"] == guardado["id"])["pode_baixar"])
            de_outra = admin.execute("""INSERT INTO relatorios_gerados (cliente_id, tipo, dias, formato, nome, conteudo, tamanho, sha256, mascarado, gerado_por, gerado_por_nome)
                                        VALUES (%s, 'completo', 30, 'pdf', 'relatorio-outra.pdf', '\\x00', 1, 'x', true, %s, 'Outra pessoa') RETURNING id""", (a["id"], uuid.uuid4())).fetchone()[0]
            registrar("não apaga o relatório de outra pessoa", http.request("DELETE", f"/api/relatorios/historico/{de_outra}").status_code == 403)
            registrar("apaga o próprio relatório", http.request("DELETE", f"/api/relatorios/historico/{guardado['id']}").status_code == 204
                      and http.get(f"/api/relatorios/historico/{guardado['id']}").status_code == 404)
            registrar("apagar fica na auditoria com o resumo", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'apagar_relatorio' AND alvo LIKE %s",
                                                                             (a["id"], f"%{guardado['sha256']}")).fetchone()[0] == 1)

            print("\n== Auditoria e integridade", flush=True)
            resumo = hashlib.sha256(r2.content).hexdigest()
            registrar("cabeçalho traz o resumo do arquivo", r2.headers.get("x-resumo-sha256") == resumo)
            registrar("a geração fica registrada com o resumo", admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'gerar_relatorio' AND alvo LIKE %s", (a["id"], f"%{resumo}")).fetchone()[0] == 1)
            registrar("o bruto do alerta não vai no JSON", "IV_35" not in json.dumps(r3.json()["regras"]))
    finally:
        servidor.shutdown()
        for tabela in ("relatorios_gerados", "vuln_historico", "vuln_achados", "vuln_ativos", "vuln_varreduras", "vuln_alvos", "vuln_modelos", "auditoria", "eventos"):
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
