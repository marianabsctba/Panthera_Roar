#!/usr/bin/env python3
"""Módulos de nuvem com gerenciador real e credencial falsa. Requer infra/subir.sh e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_fontes_nuvem.py

Prova a configuração, o caminho da credencial e que o módulo roda. Sem conta real, não prova que
os dados da nuvem chegam. Apaga no final tudo o que criou.
"""

import json
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import cofre, fontes  # noqa: E402
from testar_ingestao import Ambiente, esperar_gerenciador  # noqa: E402

RESULTADOS = []
GUID_A, GUID_B = "11111111-2222-3333-4444-555555555555", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def criar_usuario(amb, cliente):
    senha, email = secrets.token_urlsafe(18), f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
    amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash) VALUES (%s, %s, 'Analista', %s)",
                      (cliente, email, PasswordHasher().hash(senha)))
    return {"email": email, "senha": senha}


def main():
    cofre.gerar()
    amb = Ambiente()
    try:
        a, b = amb.gerenciador("nuvem-a"), amb.gerenciador("nuvem-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        conteiner = f"roar-ger-{a['id']}-gerenciador-1"

        def no_gerenciador(*comando):
            return subprocess.run(["docker", "exec", conteiner, *comando], capture_output=True, text=True, timeout=120).stdout

        ua, ub = criar_usuario(amb, a["cliente"]), criar_usuario(amb, b["cliente"])
        # Caracteres de XML no meio: se escaparem, a configuração quebra ou ganha um bloco a mais.
        token = f"tok-{uuid.uuid4().hex}</api_token><injetado>&'\""
        with TestClient(app, base_url="https://testserver") as http:
            registrar("exige sessão", http.post("/api/fontes/nuvem", json={}).status_code == 401)
            http.post("/api/entrar", json=ua)

            print("\n== Entradas ruins", flush=True)
            for nome, corpo in (("organização com XML", {"tipo": "github", "campos": {"organizacao": "a</org_name>"}}),
                                ("organização vazia", {"tipo": "github", "campos": {}}),
                                ("identificador que não é GUID", {"tipo": "office365", "campos": {"locatario": "x", "aplicativo": GUID_A}}),
                                ("tipo desconhecido", {"tipo": "aws", "campos": {}})):
                registrar(f"recusado: {nome}", http.post("/api/fontes/nuvem", json={"nome": "x", "segredo": "s", **corpo}).status_code == 422)
            registrar("recusado: sem credencial", http.post("/api/fontes/nuvem", json={"nome": "x", "tipo": "github", "campos": {"organizacao": "acme"}, "segredo": ""}).status_code == 422)

            print("\n== Credencial", flush=True)
            r = http.post("/api/fontes/nuvem", json={"nome": "GitHub da empresa", "tipo": "github", "campos": {"organizacao": "acme"}, "segredo": token})
            registrar("fonte criada", r.status_code == 201, r.text[:100])
            github = r.json()["id"]
            r = http.post("/api/fontes/nuvem", json={"nome": "Microsoft", "tipo": "office365", "campos": {"locatario": GUID_A, "aplicativo": GUID_B}, "segredo": "segredo-ms-" + uuid.uuid4().hex})
            registrar("segunda fonte criada", r.status_code == 201, r.text[:100])
            visto = http.get("/api/fontes").text
            registrar("a credencial não volta pela tela", token not in visto and "tok-" not in visto)
            config = amb.admin.execute("SELECT config FROM fontes WHERE id = %s", (github,)).fetchone()[0]
            registrar("a fonte guarda só o nome da credencial", token not in json.dumps(config) and config["segredo"].startswith("fonte-"), str(config))
            selado = bytes(amb.admin.execute("SELECT selado FROM segredos WHERE nome = %s", (config["segredo"],)).fetchone()[0])
            registrar("no banco a credencial está cifrada", token.encode() not in selado)
            registrar("o cofre abre o valor certo", cofre.abrir(cofre.ler_privada(), a["cliente"], config["segredo"], selado) == token)

            print("\n== No gerenciador", flush=True)
            fontes.ciclo(amb.banco)
            time.sleep(20)
            registrar("gerenciador volta", esperar_gerenciador(a, 240))
            estados = {f["id"]: f for f in http.get("/api/fontes").json()["fontes"]}
            registrar("fonte fica ativa", estados[github]["estado"] == "ativa", str(estados[github]["mensagem"]))
            registrar("antes de chegar dado, a tela diz que nada chegou", estados[github]["saude"] == "nunca_recebeu", str(estados[github]["saude"]))
            conf = no_gerenciador("cat", "/var/ossec/etc/ossec.conf")
            registrar("os dois módulos estão na configuração", "<github>" in conf and "<office365>" in conf)
            registrar("o XML do segredo foi escapado", "<injetado>" not in conf and "&lt;/api_token&gt;&lt;injetado&gt;" in conf)
            registrar("a configuração é só do cliente dono", token.split("<")[0] not in subprocess.run(
                ["docker", "exec", f"roar-ger-{b['id']}-gerenciador-1", "cat", "/var/ossec/etc/ossec.conf"], capture_output=True, text=True).stdout)
            fim, rodou = time.time() + 120, ""
            while time.time() < fim and not ("github" in rodou and "office365" in rodou):
                rodou = no_gerenciador("sh", "-c", "grep -E 'wazuh-modulesd:(github|office365)' /var/ossec/logs/ossec.log | tail -6")
                time.sleep(5)
            registrar("os dois módulos estão rodando", "github" in rodou and "office365" in rodou, rodou.replace("\n", " | ")[:300])

            print("\n== Isolamento", flush=True)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ub)
            registrar("outro cliente não vê a fonte", http.get("/api/fontes").json()["fontes"] == [])
            registrar("outro cliente não desativa", http.post(f"/api/fontes/{github}/desativar").status_code == 404)
            http.post("/api/sair")
            http.cookies.clear()

            print("\n== Desativar", flush=True)
            http.post("/api/entrar", json=ua)
            registrar("desativar responde", http.post(f"/api/fontes/{github}/desativar").status_code == 204)
            registrar("a credencial é apagada", amb.um("SELECT count(*) FROM segredos WHERE nome = %s", config["segredo"]) == 0)
            fontes.ciclo(amb.banco)
            time.sleep(20)
            registrar("gerenciador volta depois de tirar", esperar_gerenciador(a, 240))
            conf = no_gerenciador("cat", "/var/ossec/etc/ossec.conf")
            registrar("o módulo sai da configuração, com o segredo", "<github>" not in conf and "tok-" not in conf and "<office365>" in conf)
    finally:
        clientes = [g["cliente"] for g in amb.gerenciadores]
        for tabela in ("fontes", "segredos", "usuarios"):
            amb.admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
