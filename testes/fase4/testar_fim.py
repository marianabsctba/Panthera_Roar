#!/usr/bin/env python3
"""FIM com gerenciador e agente reais: configurar pela tela, mudar arquivo e ver o alerta.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_fim.py

Apaga no final tudo o que criou.
"""

import os
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import fim, fontes, provisao  # noqa: E402
from roar_ingestao.regras import buscar_ativos, gravar_ativos  # noqa: E402
from testar_ingestao import AGENTE_CONF, SUFIXO, Ambiente, agente_ativo, esperar_gerenciador  # noqa: E402

RESULTADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def sh(*args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=300)
    return (r.stdout + r.stderr).strip()


def esperar(condicao, limite=120, passo=5):
    fim_ = time.time() + limite
    valor = condicao()
    while not valor and time.time() < fim_:
        time.sleep(passo)
        valor = condicao()
    return valor


def criar_usuario(amb, cliente):
    senha, email = secrets.token_urlsafe(18), f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
    amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, 'administrador')",
                      (cliente, email, PasswordHasher().hash(senha)))
    return {"email": email, "senha": senha}


def testar_validacao():
    print("== Caminhos", flush=True)

    def recusado(caminho, sistema="linux", modo="agendado"):
        try:
            fim.validar_caminho(caminho, sistema, modo)
            return False
        except fim.CaminhoInvalido:
            return True

    for nome, caminho, sistema in (("raiz do Linux", "/", "linux"), ("raiz com barra", "//", "linux"), ("disco do Windows", "C:\\", "windows"), ("proc", "/proc", "linux"),
                                   ("relativo", "etc/ssh", "linux"), ("com XML", "/etc</directories><x>", "linux"), ("com &", "/a&b", "linux"), ("com '..'", "/etc/../root", "linux"),
                                   ("Windows em Linux", "C:\\a", "linux"), ("Linux em Windows", "/etc", "windows"), ("curinga no Windows", "C:\\a\\*", "windows"), ("quebra de linha", "/a\n/b", "linux")):
        registrar(f"recusado: {nome}", recusado(caminho, sistema))
    registrar("recusado: modo inventado", recusado("/etc", "linux", "rm"))
    registrar("recusado: sistema inventado", recusado("/etc", "bsd"))
    registrar("barra final é tirada", fim.validar_caminho("/var/www/", "linux", "agendado") == "/var/www")
    registrar("caminho de Windows passa", fim.validar_caminho("C:\\Program Files\\App", "windows", "tempo_real") == "C:\\Program Files\\App")
    xml = fim.conteudo_do_agent_conf([{"caminho": "/a", "sistema": "linux", "modo": "tempo_real"}, {"caminho": "C:\\b", "sistema": "windows", "modo": "agendado"}])
    registrar("cada sistema tem seu bloco", 'os="Linux"' in xml and 'os="Windows"' in xml and 'realtime="yes"' in xml)


def main():
    testar_validacao()
    amb = Ambiente()
    try:
        a, b = amb.gerenciador("fim-a"), amb.gerenciador("fim-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        pasta = Path(tempfile.mkdtemp(prefix="roar-fim-"))
        conf, passe, log = pasta / "c.conf", pasta / "c.pass", pasta / "c.log"
        conf.write_text(AGENTE_CONF.format(host=a["host"]))
        log.touch()
        passe.write_text(a["senha_inscricao"] + "\n")
        os.chmod(pasta, 0o755)
        nome = f"roar-teste-fim-{SUFIXO}"
        sh("docker", "run", "-d", "--name", nome, "--hostname", nome, "--network", provisao.REDE, "-e", f"WAZUH_MANAGER_SERVER={a['host']}",
           "-v", f"{conf}:/wazuh-config-mount/etc/ossec.conf", "-v", f"{passe}:/wazuh-config-mount/etc/authd.pass", "-v", f"{log}:/var/log/roar-teste.log", "wazuh/wazuh-agent:4.14.9")
        amb.conteineres.append(nome)
        agente = agente_ativo(a, nome, 180)
        registrar("agente ativo", agente, str(agente))
        sh("docker", "exec", nome, "mkdir", "-p", "/opt/roar-fim")
        sh("docker", "exec", nome, "sh", "-c", "echo inicial > /opt/roar-fim/ja-existia.txt")
        gravar_ativos(amb.banco, a["id"], a["cliente"], buscar_ativos(a["id"]))
        ua, ub = criar_usuario(amb, a["cliente"]), criar_usuario(amb, b["cliente"])

        with TestClient(app, base_url="https://testserver") as http:
            registrar("FIM exige sessão", http.get("/api/fim").status_code == 401)
            http.post("/api/entrar", json=ua)
            registrar("ativo aparece", any(x["agente_id"] == agente for x in http.get("/api/fim").json()["ativos"]))

            print("\n== Configurar pela tela", flush=True)
            r = http.post("/api/fim/caminhos", json={"caminho": "/opt/roar-fim", "sistema": "linux", "modo": "tempo_real"})
            registrar("caminho criado", r.status_code == 201, r.text[:100])
            caminho = r.json()["id"]
            registrar("repetido é recusado", http.post("/api/fim/caminhos", json={"caminho": "/opt/roar-fim", "sistema": "linux"}).status_code == 409)
            registrar("inválido é recusado", http.post("/api/fim/caminhos", json={"caminho": "/", "sistema": "linux"}).status_code == 422)
            registrar("criação fica na auditoria", amb.um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'criar_caminho_fim'", a["cliente"]) == 1)
            fontes.ciclo(amb.banco)
            estado = next(c for c in http.get("/api/fim").json()["caminhos"] if c["id"] == caminho)
            registrar("caminho fica ativo", estado["estado"] == "ativo", str(estado)[:160])
            registrar("chega ao agente", esperar(lambda: "/opt/roar-fim" in sh("docker", "exec", nome, "cat", "/var/ossec/etc/shared/agent.conf"), limite=180),
                      sh("docker", "exec", nome, "sh", "-c", "tail -5 /var/ossec/etc/shared/agent.conf")[:200])
            registrar("o outro gerenciador não recebe", "/opt/roar-fim" not in sh("docker", "exec", f"roar-ger-{b['id']}-gerenciador-1", "cat", "/var/ossec/etc/shared/default/agent.conf"))

            print("\n== Configuração recusada", flush=True)
            antes = sh("docker", "exec", f"roar-ger-{a['id']}-gerenciador-1", "md5sum", "/var/ossec/etc/shared/default/agent.conf")
            ok, _ = provisao.aplicar_agent_conf(a["id"], "<agent_config><syscheck><naoexiste>")
            registrar("gerenciador reprova", not ok)
            registrar("a configuração anterior volta", sh("docker", "exec", f"roar-ger-{a['id']}-gerenciador-1", "md5sum", "/var/ossec/etc/shared/default/agent.conf") == antes)

            print("\n== Mudar arquivo de verdade", flush=True)
            # O agente reinicia ao receber a configuração, e a primeira varredura cria a base.
            registrar("agente volta", agente_ativo(a, nome, 180))
            time.sleep(40)
            marca = f"novo-{uuid.uuid4().hex[:10]}.txt"
            sh("docker", "exec", nome, "sh", "-c", f"echo conteudo > /opt/roar-fim/{marca}")

            def achou():
                amb.ciclo(a)
                return [x for x in http.get("/api/arquivos", params={"busca": marca}).json()["arquivos"] if marca in (x["caminho"] or "")]

            achados = esperar(achou, limite=180)
            registrar("arquivo novo vira alerta", achados, str(achados[:1])[:240])
            registrar("o alerta traz a mudança", achados and achados[0]["mudanca"] == "added")
            registrar("os números da tela contam", sum(int(d["total"]) for d in http.get("/api/fim").json()["por_dia"]) >= 1)

            print("\n== Varrer agora e base do ativo", flush=True)
            registrar("pedir varredura", http.post("/api/fim/varreduras", json={"agente_id": agente}).status_code == 202)
            registrar("ativo inexistente não aceita", http.post("/api/fim/varreduras", json={"agente_id": "999"}).status_code == 404)
            registrar("valor estranho é recusado", http.post("/api/fim/varreduras", json={"agente_id": "1;id"}).status_code == 422)
            fim.enviar_varreduras(amb.banco, a["id"], a["cliente"])
            registrar("a varredura sai", amb.um("SELECT estado FROM fim_varreduras WHERE cliente_id = %s ORDER BY id DESC LIMIT 1", a["cliente"]) == "enviada")
            time.sleep(30)

            def base():
                fim.atualizar_base(amb.banco, a["id"], a["cliente"], ultima={})
                return http.get(f"/api/fim/ativos/{agente}/arquivos", params={"busca": "roar-fim"}).json()["arquivos"]

            linhas = esperar(base, limite=120)
            registrar("a base traz os arquivos com hash", linhas and any(marca in l["caminho"] and l["sha256"] for l in linhas), str(linhas[:1])[:240])
            ativo = next(x for x in http.get("/api/fim").json()["ativos"] if x["agente_id"] == agente)
            registrar("a tela mostra a última varredura", ativo["fim_inicio"] or ativo["fim_fim"], str((ativo["fim_inicio"], ativo["fim_fim"])))

            print("\n== Isolamento", flush=True)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ub)
            visto = http.get("/api/fim").json()
            registrar("outro cliente não vê nada", visto["caminhos"] == [] and visto["ativos"] == [] and visto["por_dia"] == [])
            registrar("outro cliente não lê a base", http.get(f"/api/fim/ativos/{agente}/arquivos").json()["arquivos"] == [])
            registrar("outro cliente não pede varredura", http.post("/api/fim/varreduras", json={"agente_id": agente}).status_code == 404)
            registrar("outro cliente não tira o caminho", http.post(f"/api/fim/caminhos/{caminho}/desativar").status_code == 404)
            http.post("/api/sair")
            http.cookies.clear()

            print("\n== Tirar", flush=True)
            http.post("/api/entrar", json=ua)
            registrar("tirar responde", http.post(f"/api/fim/caminhos/{caminho}/desativar").status_code == 204)
            fontes.ciclo(amb.banco)
            registrar("sai da configuração do gerenciador", "/opt/roar-fim" not in sh("docker", "exec", f"roar-ger-{a['id']}-gerenciador-1", "cat", "/var/ossec/etc/shared/default/agent.conf"))
            registrar("sem caminho, a configuração ainda é válida", esperar_gerenciador(a, 60))
    finally:
        clientes = [g["cliente"] for g in amb.gerenciadores]
        for tabela in ("fim_base", "fim_varreduras", "fim_caminhos", "usuarios"):
            amb.admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
