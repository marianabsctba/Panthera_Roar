#!/usr/bin/env python3
"""Vulnerabilidades vistas pelo agente: abre, reabre, fecha e respeita a decisão de uma pessoa, com banco real.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_vuln_agentes.py

Os documentos imitam os do detector do Wazuh. A prova com o detector de verdade fica no experimento descrito em docs/arquitetura.md.
"""

import sys
import uuid
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao")]

from roar_ingestao import vuln_agentes  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
TABELAS = ("vuln_historico", "vuln_achados", "vuln_ativos")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def documento(agente, pacote, versao, cve, nota=None, severidade="High"):
    return {"agent": {"id": agente, "name": f"srv-{agente}"}, "package": {"name": pacote, "version": versao},
            "vulnerability": {"id": cve, "severity": severidade, "score": {"base": nota} if nota else {}, "reference": f"https://exemplo.test/{cve}"}}


def testar_portao():
    """O portão responde só o pedido de criar modelo; o resto segue igual, sem acrescentar nada."""
    import asyncio

    import httpx

    from roar_ingestao import portao

    recebidos = []

    def indexador(pedido):
        recebidos.append(pedido)
        return httpx.Response(403 if pedido.url.path == "/outro-indice/_doc" else 200, json={"ok": True}, headers={"x-interno": "nao-deve-sair"})

    async def rodar():
        portao.app.state.cliente = httpx.AsyncClient(transport=httpx.MockTransport(indexador))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=portao.app), base_url="https://portao") as http:
            modelo = await http.put("/_index_template/wazuh-states-vulnerabilities", json={"index_patterns": ["x"]})
            antigo = await http.put("/_template/qualquer", json={})
            lote = await http.post("/_bulk?refresh=wait_for", content=b'{"index":{}}\n{"a":1}\n',
                                   headers={"Authorization": "Basic Z2VyOnNlbmhh", "Content-Type": "application/x-ndjson", "X-Forwarded-For": "1.2.3.4", "Cookie": "c=1"})
            negado = await http.post("/outro-indice/_doc", json={})
            leitura = await http.get("/_index_template/wazuh-states-vulnerabilities")
            grande = await http.post("/_bulk", content=b"x" * (portao.LIMITE_DO_CORPO + 1))
        await portao.app.state.cliente.aclose()
        return modelo, antigo, lote, negado, leitura, grande

    modelo, antigo, lote, negado, leitura, grande = asyncio.run(rodar())
    registrar("pedido de criar modelo é respondido sem chegar ao indexador", modelo.json() == {"acknowledged": True} and antigo.status_code == 200
              and not any("template" in r.url.path and r.method == "PUT" for r in recebidos))
    enviado = next(r for r in recebidos if r.url.path == "/_bulk")
    registrar("o resto segue com método, caminho, consulta e corpo iguais", enviado.method == "POST" and enviado.url.query == b"refresh=wait_for"
              and enviado.content == b'{"index":{}}\n{"a":1}\n' and lote.status_code == 200)
    registrar("só seguem a credencial e o tipo do conteúdo", enviado.headers.get("authorization") == "Basic Z2VyOnNlbmhh"
              and "x-forwarded-for" not in enviado.headers and "cookie" not in enviado.headers)
    registrar("a recusa do indexador volta para o gerenciador", negado.status_code == 403)
    registrar("ler o modelo segue para o indexador decidir", leitura.status_code == 200 and any(r.method == "GET" and "template" in r.url.path for r in recebidos))
    registrar("cabeçalho interno do indexador não sai", "x-interno" not in lote.headers)
    registrar("corpo grande demais é recusado", grande.status_code == 413)


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"vulnagente-{uuid.uuid4().hex[:8]}",)).fetchone()[0])
    agentes = {"001": ("10.0.0.1", "srv-001", True), "002": ("10.0.0.2", "srv-002", True)}

    def rodar(docs, quais=None):
        with banco.con.transaction():
            banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
            return vuln_agentes.gravar(banco.con, cliente, "teste", docs, quais or agentes)

    def achado(pacote):
        return admin.execute("SELECT id, estado, severidade, cvss, cves, autenticada FROM vuln_achados WHERE cliente_id = %s AND chave LIKE %s",
                             (cliente, f"agente|{pacote}|%")).fetchone()

    print("== Portão", flush=True)
    testar_portao()

    try:
        print("\n== Peças", flush=True)
        registrar("o índice tem o nome do host do gerenciador", vuln_agentes.indice_do("abc123") == "wazuh-states-vulnerabilities-gerenciador-abc123")

        def paginas(url, json, timeout):
            class Resposta:
                def raise_for_status(self):
                    pass

                def json(self):
                    depois = (json.get("search_after") or [0])[0]
                    lote = [{"_source": {"n": i}, "sort": [i]} for i in range(depois + 1, min(depois + 2, 3) + 1)]
                    return {"hits": {"hits": lote}}
            return Resposta()
        original = vuln_agentes.LOTE
        vuln_agentes.LOTE = 2
        registrar("lê o índice de lote em lote", [d["n"] for d in vuln_agentes.ler(paginas, "https://x", "g")] == [1, 2, 3])
        vuln_agentes.LOTE = original

        print("\n== Ciclo", flush=True)
        openssl = documento("001", "openssl", "3.0.2", "CVE-2024-0001", nota=9.8)
        curl = documento("002", "curl", "7.81", "CVE-2024-0002", severidade="Medium")
        estranho = documento("099", "bash", "5.1", "CVE-2024-0003", nota=7.5)
        registrar("o que o agente acha entra como achado", rodar([openssl, curl, estranho]) == (2, 0, 0))
        a = achado("openssl")
        registrar("a nota define a severidade e o CVE vai junto", (a[1], a[2], a[3], a[4], a[5]) == ("aberto", "critica", 9.8, ["CVE-2024-0001"], True), str(a))
        registrar("sem nota, vale a severidade do detector", achado("curl")[2] == "media")
        registrar("agente que não é desta organização fica de fora", achado("bash") is None)
        registrar("a mesma volta não duplica nem fecha nada", rodar([openssl, curl]) == (0, 0, 0))
        registrar("o pacote atualizado fecha o achado", rodar([curl]) == (0, 0, 1) and achado("openssl")[1] == "corrigido")
        registrar("o pacote vulnerável de volta reabre", rodar([openssl, curl]) == (0, 1, 0) and achado("openssl")[1] == "aberto")
        registrar("agente desconectado não fecha nada", rodar([openssl], {**agentes, "002": ("10.0.0.2", "srv-002", False)}) == (0, 0, 0)
                  and achado("curl")[1] == "aberto")
        admin.execute("UPDATE vuln_achados SET estado = 'aceito' WHERE id = %s", (achado("curl")[0],))
        rodar([openssl, curl])
        registrar("risco aceito por uma pessoa continua aceito", achado("curl")[1] == "aceito")
        admin.execute("UPDATE vuln_achados SET estado = 'correcao_informada' WHERE id = %s", (achado("openssl")[0],))
        registrar("correção informada que não aconteceu volta a aberto", rodar([openssl, curl]) == (0, 1, 0) and achado("openssl")[1] == "aberto")
        historia = [r[0] for r in admin.execute("SELECT motivo FROM vuln_historico WHERE achado_id = %s ORDER BY id", (achado("openssl")[0],)).fetchall()]
        registrar("a história conta cada passo", historia == ["O agente encontrou o pacote vulnerável.", "O agente deixou de encontrar: o pacote foi atualizado ou removido.",
                                                              "O agente voltou a encontrar.", "O agente ainda encontra o pacote vulnerável."], str(historia))
    finally:
        for tabela in TABELAS:
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
