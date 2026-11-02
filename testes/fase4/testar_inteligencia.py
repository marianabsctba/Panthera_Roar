#!/usr/bin/env python3
"""Inteligência de ameaças. TAXII contra o servidor de referência da OASIS (medallion), de verdade.

    sudo bash testes/rodar.sh testes/fase4/testar_inteligencia.py

O MISP aqui é um servidor mínimo, que só responde como a documentação do MISP descreve. Não prova o MISP real.
"""

import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao"), str(RAIZ / "motor")]
os.environ["ROAR_DESTINO_INTERNO"] = "1"

from roar_api import app as modulo  # noqa: E402
from roar_ingestao import cofre  # noqa: E402
from roar_ingestao import inteligencia as intel  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

intel.plataforma_local = lambda: None  # Estes testes usam só fontes próprias.
RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
IP_MAU, IP_MAU2, IP_NOVO = "8.8.4.4", "1.0.0.1", "9.9.9.9"
HASH_MAU = "a" * 64
CHAVE_MISP = secrets.token_hex(20)
PEDIDOS_MISP = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class MispFalso(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        corpo = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        PEDIDOS_MISP.append({"caminho": self.path, "corpo": corpo, "auth": self.headers.get("Authorization")})
        if self.headers.get("Authorization") != CHAVE_MISP:
            self.send_response(403)
            self.end_headers()
            return
        pagina = corpo.get("page", 1)
        atributos = [
            {"type": "ip-dst", "value": IP_MAU, "to_ids": True, "comment": "C2 conhecido"},
            {"type": "domain", "value": "Mau.Exemplo.test", "to_ids": True},
            {"type": "filename|sha256", "value": f"mal.exe|{HASH_MAU}", "to_ids": True},
            {"type": "ip-src", "value": "10.0.0.1", "to_ids": True, "comment": "interno: precisa ser ignorado"},
            {"type": "ip-src", "value": "1.1.1.1", "to_ids": False, "comment": "não é para detecção"},
            {"type": "text", "value": "qualquer coisa", "to_ids": True},
        ] if pagina == 1 else []
        saida = json.dumps({"response": {"Attribute": atributos}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(saida)))
        self.end_headers()
        self.wfile.write(saida)


def main():
    print("== Normalização", flush=True)
    for tipo, valor, esperado in (("ip", "8.8.8.8", "8.8.8.8"), ("ip", "10.0.0.1", None), ("ip", "127.0.0.1", None), ("ip", "lixo", None), ("dominio", "Mau.Exemplo.Test.", "mau.exemplo.test"), ("dominio", "semponto", None), ("dominio", "a b.c", None),
                                  ("url", "https://x.test/a", "https://x.test/a"), ("url", "ftp://x", None), ("md5", "A" * 32, "a" * 32), ("md5", "a" * 31, None), ("sha256", "z" * 64, None)):
        registrar(f"{tipo} {valor[:20]!r}", intel.normalizar(tipo, valor) == esperado)

    print("\n== STIX", flush=True)
    agora = datetime(2026, 11, 1, tzinfo=timezone.utc)
    ind = lambda padrao, **k: {"type": "indicator", "pattern": padrao, "pattern_type": "stix", "name": "N", **k}
    registrar("ip", intel.ler_stix([ind("[ipv4-addr:value = '8.8.8.8']")], agora)[0]["valor"] == "8.8.8.8")
    registrar("domínio", intel.ler_stix([ind("[domain-name:value = 'mau.test']")], agora)[0]["tipo"] == "dominio")
    registrar("resumo de arquivo", intel.ler_stix([ind(f"[file:hashes.'SHA-256' = '{HASH_MAU}']")], agora)[0] == {"tipo": "sha256", "valor": HASH_MAU, "descricao": "N"})
    registrar("mais de uma comparação", len(intel.ler_stix([ind("[ipv4-addr:value = '8.8.8.8' OR domain-name:value = 'a.test']")], agora)) == 2)
    registrar("revogado fica de fora", intel.ler_stix([ind("[ipv4-addr:value = '8.8.8.8']", revoked=True)], agora) == [])
    registrar("vencido fica de fora", intel.ler_stix([ind("[ipv4-addr:value = '8.8.8.8']", valid_until="2020-01-01T00:00:00Z")], agora) == [])
    registrar("outra linguagem de padrão fica de fora", intel.ler_stix([{"type": "indicator", "pattern": "x", "pattern_type": "yara"}], agora) == [])
    registrar("o que não é indicador fica de fora", intel.ler_stix([{"type": "malware", "name": "x"}], agora) == [])

    print("\n== Observáveis", flush=True)
    obs = intel.observaveis("8.8.8.8", {"data": {"dstip": "1.1.1.1", "hostname": "Mau.test", "url": "https://x.test/"}, "syscheck": {"sha256_after": HASH_MAU}})
    registrar("acha tudo no evento", obs == {("ip", "8.8.8.8"), ("ip", "1.1.1.1"), ("dominio", "mau.test"), ("url", "https://x.test/"), ("sha256", HASH_MAU)}, str(obs))
    registrar("evento estranho não quebra", intel.observaveis(None, "lixo") == set() and intel.observaveis(None, {"data": "x", "syscheck": 5}) == set())

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    clientes, gerenciadores = [], []

    def criar(nome):
        c = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        g = uuid.uuid4().hex[:12]
        admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (g, c, 54000 + secrets.randbelow(6000)))
        senha, email = secrets.token_urlsafe(18), f"intel-{uuid.uuid4().hex[:8]}@exemplo.test"
        admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Pessoa', %s, 'administrador')", (c, email, PasswordHasher().hash(senha)))
        clientes.append(c)
        gerenciadores.append(g)
        return c, g, email, senha

    def evento(c, g, ip=None, bruto=None):
        return admin.execute("""INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao, gerenciador_id, agente_id, agente_nome, ip_origem, bruto)
                                VALUES (%s, 'wazuh', %s, now() - interval '3 days', 10, 'alta', '5712', 'Regra de teste', %s, '001', 'srv-a', %s, %s) RETURNING id""",
                             (c, uuid.uuid4().hex, g, ip, Jsonb(bruto or {}))).fetchone()[0]

    # Servidor MISP mínimo.
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), MispFalso)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    url_misp = f"http://127.0.0.1:{servidor.server_address[1]}"

    # TAXII de verdade: o servidor de referência.
    pasta = tempfile.mkdtemp()
    colecao = "91a7b528-80eb-42ed-a74d-c6fbd5a26116"
    senha_taxii = secrets.token_hex(8)
    config = {"backend": {"module": "medallion.backends.memory_backend", "module_class": "MemoryBackend", "filename": f"{pasta}/dados.json"}, "users": {"leitor": senha_taxii}, "taxii": {"max_page_size": 100}}
    Path(pasta, "config.json").write_text(json.dumps(config))
    dados = {"/discovery": {"title": "Teste", "default": "http://127.0.0.1:56565/api1/", "api_roots": ["http://127.0.0.1:56565/api1/"]},
             "api1": {"information": {"title": "API", "versions": ["application/taxii+json;version=2.1"], "max_content_length": 9765625}, "status": [],
                      "collections": [{"id": colecao, "title": "Indicadores", "can_read": True, "can_write": False, "media_types": ["application/stix+json;version=2.1"], "objects": [
                          {"type": "indicator", "spec_version": "2.1", "id": "indicator--6770298f-0fd8-471a-ab8c-1c658a46574e", "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z", "name": "Servidor de comando",
                           "pattern": f"[ipv4-addr:value = '{IP_MAU2}']", "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00.000Z"},
                          {"type": "malware", "spec_version": "2.1", "id": "malware--6770298f-0fd8-471a-ab8c-1c658a46574f", "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z", "name": "x", "is_family": True}],
                          "manifest": [{"id": "indicator--6770298f-0fd8-471a-ab8c-1c658a46574e", "date_added": "2026-01-01T00:00:00.000Z", "version": "2026-01-01T00:00:00.000Z", "media_type": "application/stix+json;version=2.1"},
                                       {"id": "malware--6770298f-0fd8-471a-ab8c-1c658a46574f", "date_added": "2026-01-01T00:00:00.000Z", "version": "2026-01-01T00:00:00.000Z", "media_type": "application/stix+json;version=2.1"}]}]}}
    Path(pasta, "dados.json").write_text(json.dumps(dados))
    taxii = subprocess.Popen(["/tmp/medallion/bin/medallion", "--host", "127.0.0.1", "--port", "56565", f"{pasta}/config.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(4)

    try:
        ca, ga, email_a, senha_a = criar("intel-a")
        cb, gb, email_b, senha_b = criar("intel-b")
        antigo_misp = evento(ca, ga, IP_MAU)
        antigo_dominio = evento(ca, ga, None, {"data": {"hostname": "mau.exemplo.test"}})
        antigo_hash = evento(ca, ga, None, {"syscheck": {"sha256_after": HASH_MAU}})
        antigo_taxii = evento(ca, ga, IP_MAU2)
        de_b = evento(cb, gb, IP_MAU)
        inocente = evento(ca, ga, "8.8.8.8")

        with TestClient(modulo.app, base_url="https://testserver") as _:
            http = TestClient(modulo.app, base_url="https://testserver")
            http.post("/api/entrar", json={"email": email_a, "senha": senha_a})

            print("\n== Ligar", flush=True)
            registrar("sem nenhuma fonte, nada muda", http.get("/api/inteligencia").json() == {"fontes": [], "ocorrencias": []})
            registrar("TAXII sem coleção é recusado", http.post("/api/inteligencia/fontes", json={"nome": "T", "tipo": "taxii", "endereco": "http://127.0.0.1:56565/api1/"}).status_code == 422)
            r = http.post("/api/inteligencia/fontes", json={"nome": "MISP", "tipo": "misp", "endereco": url_misp, "credencial": CHAVE_MISP})
            registrar("cria a fonte MISP", r.status_code == 201, r.text[:120])
            registrar("nome repetido é recusado", http.post("/api/inteligencia/fontes", json={"nome": "MISP", "tipo": "misp", "endereco": url_misp}).status_code == 409)
            lista = http.get("/api/inteligencia")
            registrar("a credencial não volta para a tela", CHAVE_MISP not in lista.text and lista.json()["fontes"][0]["com_credencial"] is True)
            guardado = admin.execute("SELECT selado FROM segredos WHERE cliente_id = %s", (ca,)).fetchone()[0]
            registrar("a credencial fica cifrada", CHAVE_MISP.encode() not in bytes(guardado))

            print("\n== MISP (servidor mínimo)", flush=True)
            intel.ciclo(banco, ca)
            situacao = http.get("/api/inteligencia").json()
            f = situacao["fontes"][0]
            registrar("buscou sem erro", f["ultimo_erro"] is None and f["ultima_em"], str(f["ultimo_erro"]))
            registrar("pediu só o que serve para detecção", PEDIDOS_MISP[0]["corpo"]["to_ids"] is True and PEDIDOS_MISP[0]["caminho"] == "/attributes/restSearch")
            registrar("mandou a chave certa", PEDIDOS_MISP[0]["auth"] == CHAVE_MISP)
            registrar("nada foi enviado além da busca", all(p["caminho"] == "/attributes/restSearch" for p in PEDIDOS_MISP) and "sighting" not in json.dumps(PEDIDOS_MISP).lower())
            registrar("guarda só os indicadores bons", f["indicadores"] == 3, str(f["indicadores"]))
            achados = {o["evento_id"]: o for o in situacao["ocorrencias"]}
            registrar("acha o IP nos eventos antigos", antigo_misp in achados and achados[antigo_misp]["no_passado"] is True, str(sorted(achados)))
            registrar("acha o domínio nos eventos antigos", antigo_dominio in achados)
            registrar("acha o resumo do arquivo nos eventos antigos", antigo_hash in achados)
            registrar("não acusa quem não tem nada a ver", inocente not in achados)
            registrar("o aviso aparece", any(a["tipo"] == "indicador_encontrado" and a["alvo"] == IP_MAU for a in http.get("/api/notificacoes").json()["avisos"]))

            print("\n== Outro cliente", flush=True)
            outra = TestClient(modulo.app, base_url="https://testserver")
            outra.post("/api/entrar", json={"email": email_b, "senha": senha_b})
            intel.ciclo(banco, cb)
            registrar("o indicador de um não acusa o evento do outro", outra.get("/api/inteligencia").json() == {"fontes": [], "ocorrencias": []})
            registrar("a fonte de um não aparece para o outro", outra.post(f"/api/inteligencia/fontes/{f['id']}/sincronizar").status_code == 404)
            registrar("de_b segue sem ocorrência", not admin.execute("SELECT 1 FROM intel_ocorrencias WHERE evento_id = %s", (de_b,)).fetchone())

            print("\n== Evento novo", flush=True)
            novo = evento(ca, ga, IP_MAU)
            registrar("acha na chegada", intel.buscar_nos_eventos_novos(banco, ca) >= 1)
            o = next((x for x in http.get("/api/inteligencia").json()["ocorrencias"] if x["evento_id"] == novo), None)
            registrar("marcado como na chegada", o and o["no_passado"] is False, str(o))
            registrar("rodar de novo não duplica", intel.buscar_nos_eventos_novos(banco, ca) == 0)

            print("\n== Fonte com problema", flush=True)
            r = http.post("/api/inteligencia/fontes", json={"nome": "Chave errada", "tipo": "misp", "endereco": url_misp, "credencial": "errada"})
            r2 = http.post("/api/inteligencia/fontes", json={"nome": "Fora do ar", "tipo": "misp", "endereco": "http://127.0.0.1:9", "credencial": "x"})
            intel.ciclo(banco, ca)
            fontes = {x["nome"]: x for x in http.get("/api/inteligencia").json()["fontes"]}
            registrar("credencial recusada aparece na tela", "recusou" in (fontes["Chave errada"]["ultimo_erro"] or ""), str(fontes["Chave errada"]["ultimo_erro"]))
            registrar("fonte fora do ar aparece na tela", "não respondeu" in (fontes["Fora do ar"]["ultimo_erro"] or ""), str(fontes["Fora do ar"]["ultimo_erro"]))
            registrar("a fonte boa continua", fontes["MISP"]["ultimo_erro"] is None)
            for x in (r, r2):
                http.delete(f"/api/inteligencia/fontes/{x.json()['id']}")
            registrar("desativar tira da lista", len(http.get("/api/inteligencia").json()["fontes"]) == 1)

            print("\n== TAXII de verdade (medallion)", flush=True)
            basico = "Basic " + base64.b64encode(f"leitor:{senha_taxii}".encode()).decode()
            r = http.post("/api/inteligencia/fontes", json={"nome": "TAXII", "tipo": "taxii", "endereco": "http://127.0.0.1:56565/api1/", "colecao": colecao, "credencial": basico})
            registrar("cria a fonte TAXII", r.status_code == 201, r.text[:120])
            registrar("o servidor de referência está no ar", taxii.poll() is None)
            intel.ciclo(banco, ca)
            situacao = http.get("/api/inteligencia").json()
            t = next(x for x in situacao["fontes"] if x["nome"] == "TAXII")
            registrar("buscou sem erro", t["ultimo_erro"] is None, str(t["ultimo_erro"]))
            registrar("trouxe o indicador", t["indicadores"] == 1, str(t["indicadores"]))
            registrar("achou o evento antigo", any(o["evento_id"] == antigo_taxii and o["fonte"] == "TAXII" for o in situacao["ocorrencias"]))
            senha_errada = http.post("/api/inteligencia/fontes", json={"nome": "TAXII errado", "tipo": "taxii", "endereco": "http://127.0.0.1:56565/api1/", "colecao": colecao, "credencial": "Basic ZXJyYWRvOmVycmFkbw=="}).json()["id"]
            intel.ciclo(banco, ca)
            registrar("senha errada aparece na tela", "recusou" in (next(x for x in http.get("/api/inteligencia").json()["fontes"] if x["id"] == senha_errada)["ultimo_erro"] or ""))

            print("\n== Busca", flush=True)
            registrar("busca por indicador", all(o["valor"] == IP_MAU2 for o in http.get("/api/inteligencia", params={"busca": IP_MAU2}).json()["ocorrencias"]))
            registrar("curinga é tratado como texto", http.get("/api/inteligencia", params={"busca": "%"}).json()["ocorrencias"] == [])
            registrar("endereço sem https é recusado em produção", _sem_https(http))

        print("\n== Banco", flush=True)
        with psycopg.connect(f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar") as con:
            con.execute("SELECT set_config('roar.cliente', %s, false)", (ca,))
            for sql, nome in (("DELETE FROM intel_ocorrencias", "apagar ocorrência"), ("DELETE FROM intel_indicadores", "apagar indicador"), ("UPDATE intel_fontes SET endereco = 'x'", "trocar o endereço de uma fonte")):
                try:
                    con.execute(sql)
                    registrar(f"a API não consegue {nome}", False)
                except psycopg.errors.InsufficientPrivilege:
                    registrar(f"a API não consegue {nome}", True)
                con.rollback()
                con.execute("SELECT set_config('roar.cliente', %s, false)", (ca,))
    finally:
        taxii.terminate()
        servidor.shutdown()
        admin.execute("DELETE FROM intel_ocorrencias WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM intel_indicadores WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM intel_fontes WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM intel_cursor WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM notificacoes WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM segredos WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM eventos WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM auditoria WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM sessoes WHERE usuario_id IN (SELECT id FROM usuarios WHERE cliente_id = ANY(%s))", (clientes,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        admin.execute("DELETE FROM gerenciadores WHERE id = ANY(%s)", (gerenciadores,))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (clientes,))
        admin.close()
        banco.fechar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


def _sem_https(http):
    del os.environ["ROAR_DESTINO_INTERNO"]
    try:
        return http.post("/api/inteligencia/fontes", json={"nome": "Aberto", "tipo": "misp", "endereco": "http://exemplo.test"}).status_code == 422
    finally:
        os.environ["ROAR_DESTINO_INTERNO"] = "1"


if __name__ == "__main__":
    sys.exit(main())
