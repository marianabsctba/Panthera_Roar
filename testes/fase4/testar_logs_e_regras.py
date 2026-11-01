#!/usr/bin/env python3
"""Logs brutos, retenção e catálogo de regras, com gerenciadores e agentes Wazuh reais.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_logs_e_regras.py

Apaga no final tudo o que criou.
"""

import json
import secrets
import sys
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "testes/fase1")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import provisao  # noqa: E402
from roar_ingestao.ciclo import ler_env  # noqa: E402
from roar_ingestao.fonte_wazuh import Indexer  # noqa: E402
from roar_ingestao.regras import sincronizar  # noqa: E402
from testar_ingestao import Ambiente, agente_ativo, esperar_gerenciador, subir_agente  # noqa: E402

RESULTADOS = []
CA = str(provisao.CERTIFICADOS / "root-ca.pem")
URL = "https://127.0.0.1:9200"


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def criar_usuario(amb, g):
    senha = secrets.token_urlsafe(18)
    email = f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
    amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash) VALUES (%s, %s, 'Analista', %s)",
                      (g["cliente"], email, PasswordHasher().hash(senha)))
    return {"email": email, "senha": senha}


def main():
    amb = Ambiente()
    env = ler_env(provisao.DESTINO / ".env")
    try:
        a, b = amb.gerenciador("logs-a"), amb.gerenciador("logs-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))

        print("\n== Regras do Wazuh", flush=True)
        _, banco, _ = amb.leitor, amb.banco, None
        total, falhas = sincronizar(banco)
        registrar("sincronização sem falhas", not falhas, str({k: str(v)[:160] for k, v in falhas.items()}))
        por_a = amb.um("SELECT count(*) FROM regras WHERE gerenciador_id = %s", a["id"])
        registrar("catálogo real foi copiado", por_a > 1000, f"{por_a} regras em cada gerenciador")
        registrar("regra real tem nível, grupos, MITRE e normas", amb.um(
            "SELECT nivel = 10 AND 'T1110' = ANY(mitre) AND array_length(grupos, 1) > 0 AND descricao IS NOT NULL"
            " AND normas ? 'gdpr' FROM regras WHERE gerenciador_id = %s AND regra_id = '5712'", a["id"]))
        registrar("D3FEND trouxe defesas para técnica real", amb.um(
            "SELECT count(*) FROM tecnicas_defesa WHERE tecnica = 'T1110'") >= 5,
            f"{amb.um('SELECT count(DISTINCT tecnica) FROM tecnicas_defesa')} técnicas com defesa")
        registrar("cada cliente tem o seu catálogo", amb.um(
            "SELECT count(*) FROM regras WHERE gerenciador_id = %s AND cliente_id = %s", b["id"], b["cliente"]) == por_a)
        sincronizar(banco)
        registrar("sincronizar de novo não duplica", amb.um(
            "SELECT count(*) FROM regras WHERE gerenciador_id = %s", a["id"]) == por_a)

        print("\n== Retenção", flush=True)
        politica = amb.indexer.sessao.get(f"{URL}/_plugins/_ism/policies/roar-retencao", timeout=30)
        registrar("política de retenção existe", politica.ok)
        idade = politica.json()["policy"]["states"][0]["transitions"][0]["conditions"]["min_index_age"]
        registrar("retenção segue a configuração", idade == f"{env.get('RETENCAO_DIAS', '90')}d", idade)

        print("\n== Logs brutos", flush=True)
        pasta = Path(tempfile.mkdtemp(prefix="roar-logs-"))
        c_a, log_a = subir_agente(amb, a, pasta, "a", a["senha_inscricao"])
        c_b, log_b = subir_agente(amb, b, pasta, "b", b["senha_inscricao"])
        registrar("agentes ativos", agente_ativo(a, c_a, 180) and agente_ativo(b, c_b, 180))
        time.sleep(60)
        sincronizar(banco)
        ativo = amb.admin.execute("SELECT nome, estado, sistema, ip FROM ativos WHERE gerenciador_id = %s AND agente_id <> '000'",
                                  (a["id"],)).fetchone()
        registrar("ativo real aparece com estado e sistema", ativo and ativo[1] == "active" and ativo[2], str(ativo))
        registrar("ativo real fica no cliente certo", amb.um(
            "SELECT count(*) FROM ativos WHERE gerenciador_id = %s AND cliente_id = %s", b["id"], a["cliente"]) == 0)
        marca_a, marca_b = f"marcaroar{uuid.uuid4().hex}", f"marcaroar{uuid.uuid4().hex}"
        # Linha que nenhuma regra transforma em alerta.
        for arquivo, marca in ((log_a, marca_a), (log_b, marca_b)):
            with open(arquivo, "a") as f:
                carimbo = datetime.now().strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
                f.write(f"{carimbo} servidor aplicacao[77]: operacao comum {marca}\n")

        indice_a = provisao.indice_bruto_do(a["id"])
        consulta = {"query": {"simple_query_string": {"query": marca_a, "fields": ["full_log"]}}}
        total_a = 0
        fim = time.time() + 180
        while time.time() < fim and not total_a:
            amb.indexer.sessao.post(f"{URL}/{indice_a}*/_refresh", timeout=30)
            r = amb.indexer.sessao.post(f"{URL}/{indice_a}*/_count", json=consulta, timeout=30)
            total_a = r.json().get("count", 0) if r.ok else 0
            time.sleep(5)
        registrar("log comum chega ao índice bruto do cliente", total_a >= 1, f"{total_a} documento")
        registrar("log comum não vira alerta", amb.indexer.sessao.post(
            f"{URL}/{provisao.indice_do(a['id'])}*/_count", json=consulta, timeout=30).json()["count"] == 0)
        registrar("log de A não está no índice de B", amb.indexer.sessao.post(
            f"{URL}/{provisao.indice_bruto_do(b['id'])}*/_count", json=consulta, timeout=30).json()["count"] == 0)

        print("\n== Permissões", flush=True)
        escritor = Indexer(URL, a["indexer_usuario"], a["indexer_senha"], CA).sessao
        corpo = {"timestamp": "2026-11-01T12:00:00.000+0000", "full_log": "x"}
        registrar("A grava no próprio índice bruto", escritor.post(f"{URL}/{indice_a}teste/_doc", json=corpo, timeout=30).ok)
        negado = escritor.post(f"{URL}/{provisao.indice_bruto_do(b['id'])}teste/_doc", json=corpo, timeout=30)
        registrar("A não grava no índice bruto de B", negado.status_code == 403)
        registrar("A não lê o índice bruto de B", escritor.get(
            f"{URL}/{provisao.indice_bruto_do(b['id'])}*/_search", timeout=30).status_code == 403)
        registrar("leitor não grava no bruto", amb.leitor.sessao.post(
            f"{URL}/{indice_a}teste/_doc", json=corpo, timeout=30).status_code == 403)

        print("\n== Tela", flush=True)
        ua, ub = criar_usuario(amb, a), criar_usuario(amb, b)
        with TestClient(app, base_url="https://testserver") as http:
            registrar("logs exigem sessão", http.get("/api/logs").status_code == 401)
            http.post("/api/entrar", json=ua)
            achados = http.get("/api/logs", params={"busca": marca_a}).json()["logs"]
            registrar("A encontra o próprio log", achados and marca_a in achados[0]["bruto"]["full_log"])
            registrar("A não encontra o log de B", http.get("/api/logs", params={"busca": marca_b}).json()["logs"] == [])
            registrar("busca fica registrada", amb.um(
                "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'buscar_logs' AND alvo = %s",
                a["cliente"], marca_a) == 1)
            registrar("sintaxe estranha na busca não quebra", http.get(
                "/api/logs", params={"busca": '"((( AND :: * index:*'}).status_code == 200)
            registrar("cursor inválido é recusado", http.get("/api/logs", params={"depois_de": "{]"}).status_code == 422
                      and http.get("/api/logs", params={"depois_de": '{"a":1}'}).status_code == 422)
            registrar("catálogo aparece na API", http.get("/api/regras").json()["catalogo"] == por_a)
            resposta = http.get("/api/logs", params={"busca": marca_a}).json()
            registrar("logs trazem total e linha do tempo", resposta["total"] >= 1 and resposta["linha_do_tempo"], str(resposta["total"]))
            ativo_a = achados[0]["bruto"]["agent"]["name"]
            registrar("campos trazem valores com contagem", any(v["valor"] == ativo_a for v in resposta["campos"]["agent.name"]))
            filtro = json.dumps([{"campo": "agent.name", "valor": ativo_a}])
            registrar("filtro por campo encontra", http.get("/api/logs", params={"busca": marca_a, "filtros": filtro}).json()["total"] >= 1)
            excluir = json.dumps([{"campo": "agent.name", "valor": ativo_a, "negar": True}])
            registrar("excluir por campo tira do resultado", http.get("/api/logs", params={"busca": marca_a, "filtros": excluir}).json()["total"] == 0)
            for nome, ruim in (("texto qualquer", "nao-e-json"), ("campo com injeção", json.dumps([{"campo": "a b\"}", "valor": "x"}])),
                               ("consulta embutida", json.dumps([{"campo": "agent.name", "valor": {"match_all": {}}}])),
                               ("filtros demais", json.dumps([{"campo": "a", "valor": "b"}] * 21))):
                registrar(f"filtro recusado: {nome}", http.get("/api/logs", params={"filtros": ruim}).status_code == 422)
            campo_de_b = json.dumps([{"campo": "_index", "valor": f"wazuh-archives-4.x-{b['id']}-x"}])
            registrar("filtrar pelo índice de outro cliente não abre nada", http.get("/api/logs", params={"filtros": campo_de_b}).json()["logs"] == [])
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ub)
            registrar("B não encontra o log de A", http.get("/api/logs", params={"busca": marca_a}).json()["logs"] == [])
    finally:
        amb.admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", ([g["cliente"] for g in amb.gerenciadores],))
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
