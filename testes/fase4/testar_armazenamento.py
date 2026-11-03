#!/usr/bin/env python3
"""Armazenamento por organização, com gerenciador real: prazos no indexador e log bruto ligado e desligado no gerenciador.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_armazenamento.py

Apaga no final tudo o que criou.
"""

import secrets
import sys
import time
import uuid
from pathlib import Path

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import copia_fria, fontes, provisao  # noqa: E402
from testar_ingestao import Ambiente, esperar_gerenciador  # noqa: E402

RESULTADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def conta(amb, cliente, perfil="administrador"):
    senha, email = secrets.token_urlsafe(18), f"arm-{uuid.uuid4().hex[:8]}@exemplo.test"
    amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Pessoa', %s, %s)",
                      (cliente, email, PasswordHasher().hash(senha), perfil))
    http = TestClient(app, base_url="https://testserver")
    # Sem entrar no contexto, a aplicação não abre a conexão com o banco.
    http.__enter__()
    http.post("/api/entrar", json={"email": email, "senha": senha})
    return http


def politica_do_indice(amb, indice):
    r = amb.indexer.sessao.get(f"{amb.indexer.url}/_plugins/_ism/explain/{indice}", timeout=30).json()
    return (r.get(indice) or {}).get("index.plugins.index_state_management.policy_id") or (r.get(indice) or {}).get("policy_id")


def dias_da_politica(amb, nome):
    r = amb.indexer.sessao.get(f"{amb.indexer.url}/_plugins/_ism/policies/{nome}", timeout=30)
    if not r.ok:
        return None
    return r.json()["policy"]["states"][0]["transitions"][0]["conditions"]["min_index_age"]


def logall(g):
    return provisao._compose(provisao.DESTINO / "gerenciadores" / g["id"], g["id"], "exec", "-T", "gerenciador", "grep", "-o", "<logall_json>[a-z]*</logall_json>", "/var/ossec/etc/ossec.conf").stdout.strip()


def main():
    amb = Ambiente()
    try:
        a, b = amb.gerenciador("arm-a"), amb.gerenciador("arm-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        # Um índice de log bruto de cada, como o gerenciador criaria.
        for g in (a, b):
            amb.indexer.sessao.put(f"{amb.indexer.url}/{provisao.indice_bruto_do(g['id'])}2026.11.01", timeout=30)
        admin_a, admin_b, analista = conta(amb, a["cliente"]), conta(amb, b["cliente"]), conta(amb, a["cliente"], "analista_n1")

        print("== Padrão", flush=True)
        atual = admin_a.get("/api/organizacao/armazenamento").json()
        registrar("seis meses para os dois, guardando log bruto", (atual["retencao_alertas_dias"], atual["retencao_logs_dias"], atual["guardar_logs"]) == (180, 180, True), str(atual))
        registrar("o log bruto começa ligado", logall(a) == "<logall_json>yes</logall_json>", logall(a))

        print("== Quem pode", flush=True)
        registrar("analista não vê", analista.get("/api/organizacao/armazenamento").status_code == 403)
        registrar("analista não muda", analista.put("/api/organizacao/armazenamento", json={"retencao_alertas_dias": 30, "retencao_logs_dias": 7, "guardar_logs": False}).status_code == 403)
        for nome, corpo in (("alertas abaixo do mínimo", {"retencao_alertas_dias": 10, "retencao_logs_dias": 30, "guardar_logs": True}),
                            ("logs abaixo do mínimo", {"retencao_alertas_dias": 90, "retencao_logs_dias": 3, "guardar_logs": True}),
                            ("acima de dez anos", {"retencao_alertas_dias": 5000, "retencao_logs_dias": 30, "guardar_logs": True}),
                            ("sem a escolha do log bruto", {"retencao_alertas_dias": 90, "retencao_logs_dias": 30})):
            registrar(f"recusa: {nome}", admin_a.put("/api/organizacao/armazenamento", json=corpo).status_code == 422)

        print("== Prazos", flush=True)
        registrar("muda os prazos", admin_a.put("/api/organizacao/armazenamento", json={"retencao_alertas_dias": 365, "retencao_logs_dias": 30, "guardar_logs": True}).status_code == 204)
        registrar("fica pendente até aplicar", admin_a.get("/api/organizacao/armazenamento").json()["estado"] == "pendente")
        registrar("fica na auditoria", amb.um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'definir_armazenamento'", a["cliente"]) == 1)
        registrar("a outra organização não muda", admin_b.get("/api/organizacao/armazenamento").json()["retencao_logs_dias"] == 180)
        fontes.aplicar_armazenamento(amb.banco)
        registrar("aplicado", admin_a.get("/api/organizacao/armazenamento").json()["estado"] == "aplicado")
        registrar("alertas com um ano no indexador", dias_da_politica(amb, f"roar-retencao-alertas-{a['id']}") == "365d")
        registrar("logs brutos com trinta dias no indexador", dias_da_politica(amb, f"roar-retencao-logs-{a['id']}") == "30d")
        registrar("a outra organização fica nos seis meses", dias_da_politica(amb, f"roar-retencao-logs-{b['id']}") == "180d")
        bruto_a = f"{provisao.indice_bruto_do(a['id'])}2026.11.01"
        fim_ = time.time() + 120
        while politica_do_indice(amb, bruto_a) != f"roar-retencao-logs-{a['id']}" and time.time() < fim_:
            time.sleep(10)
        registrar("o índice que já existia passa para a política nova", politica_do_indice(amb, bruto_a) == f"roar-retencao-logs-{a['id']}", str(politica_do_indice(amb, bruto_a)))
        visao = admin_a.get("/api/volume").json()
        registrar("a estimativa usa os prazos da organização", (visao.get("ocupado") or {}).get("retencao_logs_dias") == 30, str(visao.get("ocupado"))[:120])

        print("== Organização sem índice ainda", flush=True)
        amb.indexer.sessao.delete(f"{amb.indexer.url}/{provisao.indice_bruto_do(b['id'])}*", timeout=30)
        admin_b.put("/api/organizacao/armazenamento", json={"retencao_alertas_dias": 90, "retencao_logs_dias": 30, "guardar_logs": True})
        fontes.aplicar_armazenamento(amb.banco)
        registrar("aplica mesmo sem índice", admin_b.get("/api/organizacao/armazenamento").json()["estado"] == "aplicado")
        registrar("e o primeiro índice já nasce no prazo", dias_da_politica(amb, f"roar-retencao-logs-{b['id']}") == "30d")

        print("== Cópia fria", flush=True)
        arquivo = admin_a.get("/api/organizacao/armazenamento").json()["arquivo"]
        registrar("a tela sabe da cópia fria", arquivo is not None and arquivo["dias"] == 365, str(arquivo))
        nome_copia = f"prova-{uuid.uuid4().hex[:8]}"
        r = amb.indexer.sessao.put(f"{amb.indexer.url}/_snapshot/{provisao.ARQUIVO}/{nome_copia}?wait_for_completion=true",
                                   json={"indices": f"{provisao.indice_bruto_do(a['id'])}*", "include_global_state": False}, timeout=300)
        registrar("a cópia fria grava", r.ok and r.json()["snapshot"]["state"] == "SUCCESS", r.text[:160])
        registrar("a cópia diária está agendada", amb.indexer.sessao.get(f"{amb.indexer.url}/_plugins/_sm/policies/{provisao.ARQUIVO}", timeout=30).ok)
        amb.indexer.sessao.delete(f"{amb.indexer.url}/{bruto_a}", timeout=30)

        print("== Trazer de volta", flush=True)
        visao = admin_a.get("/api/organizacao/copia-fria").json()
        registrar("a tela mostra o dia que saiu", "2026-11-01" in (visao["disponivel"] or {}).get("logs", []), str(visao["disponivel"])[:120])
        registrar("a outra organização não vê esse dia", "2026-11-01" not in (admin_b.get("/api/organizacao/copia-fria").json()["disponivel"] or {}).get("logs", []))
        registrar("analista não pede", analista.post("/api/organizacao/copia-fria", json={"de": "2026-11-01", "ate": "2026-11-01", "tipo": "logs"}).status_code == 403)
        registrar("período ao contrário é recusado", admin_a.post("/api/organizacao/copia-fria", json={"de": "2026-11-02", "ate": "2026-11-01", "tipo": "logs"}).status_code == 422)
        registrar("período longo é recusado", admin_a.post("/api/organizacao/copia-fria", json={"de": "2026-01-01", "ate": "2026-03-01", "tipo": "logs"}).status_code == 422)
        registrar("tipo inventado é recusado", admin_a.post("/api/organizacao/copia-fria", json={"de": "2026-11-01", "ate": "2026-11-01", "tipo": "tudo"}).status_code == 422)
        r = admin_a.post("/api/organizacao/copia-fria", json={"de": "2026-10-31", "ate": "2026-11-01", "tipo": "logs", "dias_de_consulta": 3})
        registrar("pedido aceito", r.status_code == 201, str(r.status_code))
        pedido = r.json()["id"]
        registrar("um de cada vez", admin_a.post("/api/organizacao/copia-fria", json={"de": "2026-11-01", "ate": "2026-11-01", "tipo": "logs"}).status_code == 409)
        registrar("o pedido fica na auditoria", amb.um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'recuperar_copia_fria'", a["cliente"]) == 1)
        env = provisao.ler_env(provisao.DESTINO / ".env")
        copia_fria.processar(env)
        p = next(x for x in admin_a.get("/api/organizacao/copia-fria").json()["pedidos"] if x["id"] == pedido)
        registrar("o dia voltou", p["estado"] == "pronto" and p["indices"] == 1 and amb.indexer.sessao.head(f"{amb.indexer.url}/{bruto_a}", timeout=30).status_code == 200, str(p))
        registrar("com prazo para sair", p["expira_em"] is not None)
        explicado = amb.indexer.sessao.get(f"{amb.indexer.url}/_plugins/_ism/explain/{bruto_a}", timeout=30).json().get(bruto_a, {})
        registrar("a retenção não apaga o que voltou", not explicado.get("policy_id") and not explicado.get("index.plugins.index_state_management.policy_id"), str(explicado)[:120])
        registrar("o dia que voltou some da lista de disponíveis", "2026-11-01" not in (admin_a.get("/api/organizacao/copia-fria").json()["disponivel"] or {}).get("logs", []))
        registrar("a outra organização não devolve o pedido desta", admin_b.post(f"/api/organizacao/copia-fria/{pedido}/devolver").status_code == 409)
        registrar("devolver antes responde", admin_a.post(f"/api/organizacao/copia-fria/{pedido}/devolver").status_code == 202)
        copia_fria.processar(env)
        registrar("devolvido, o dia sai do índice", amb.indexer.sessao.head(f"{amb.indexer.url}/{bruto_a}", timeout=30).status_code == 404)
        registrar("e volta para a lista de disponíveis", "2026-11-01" in (admin_a.get("/api/organizacao/copia-fria").json()["disponivel"] or {}).get("logs", []))
        admin_a.post("/api/organizacao/copia-fria", json={"de": "2026-11-01", "ate": "2026-11-01", "tipo": "logs", "dias_de_consulta": 1})
        copia_fria.processar(env)
        amb.admin.execute("UPDATE recuperacoes SET expira_em = now() - interval '1 minute' WHERE cliente_id = %s AND estado = 'pronto'", (a["cliente"],))
        copia_fria.processar(env)
        registrar("vencido o prazo, sai sozinho", amb.indexer.sessao.head(f"{amb.indexer.url}/{bruto_a}", timeout=30).status_code == 404)
        r = admin_a.post("/api/organizacao/copia-fria", json={"de": "2020-01-01", "ate": "2020-01-02", "tipo": "ambos"})
        copia_fria.processar(env)
        p = next(x for x in admin_a.get("/api/organizacao/copia-fria").json()["pedidos"] if x["id"] == r.json()["id"])
        registrar("período fora da cópia avisa", p["estado"] == "falhou" and "cópia fria" in (p["mensagem"] or ""), str(p))
        amb.indexer.sessao.delete(f"{amb.indexer.url}/_snapshot/{provisao.ARQUIVO}/{nome_copia}", timeout=120)
        amb.indexer.sessao.put(f"{amb.indexer.url}/{bruto_a}", timeout=30)

        print("== Log bruto", flush=True)
        registrar("desliga o log bruto", admin_a.put("/api/organizacao/armazenamento", json={"retencao_alertas_dias": 365, "retencao_logs_dias": 30, "guardar_logs": False}).status_code == 204)
        fontes.ciclo(amb.banco)
        registrar("o gerenciador para de guardar", logall(a) == "<logall_json>no</logall_json>", logall(a))
        registrar("o gerenciador volta", esperar_gerenciador(a, 240))
        registrar("o outro gerenciador continua guardando", logall(b) == "<logall_json>yes</logall_json>", logall(b))
        registrar("o que já foi guardado fica", amb.indexer.sessao.head(f"{amb.indexer.url}/{bruto_a}", timeout=30).status_code == 200)
        fontes.ciclo(amb.banco)
        registrar("sem mudança, não reinicia de novo", logall(a) == "<logall_json>no</logall_json>")
        admin_a.put("/api/organizacao/armazenamento", json={"retencao_alertas_dias": 365, "retencao_logs_dias": 30, "guardar_logs": True})
        fontes.ciclo(amb.banco)
        registrar("religa o log bruto", logall(a) == "<logall_json>yes</logall_json>", logall(a))
    finally:
        clientes = [g["cliente"] for g in amb.gerenciadores]
        amb.admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        amb.admin.execute("DELETE FROM recuperacoes WHERE cliente_id = ANY(%s)", (clientes,))
        ids = [g["id"] for g in amb.gerenciadores]
        amb.limpar()
        registrar("as políticas da organização somem com ela", all(dias_da_politica(amb, f"roar-retencao-logs-{i}") is None for i in ids))

    falhas = [n for n, p in RESULTADOS if not p]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for nome in falhas:
        print(f"  falhou: {nome}")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main()
