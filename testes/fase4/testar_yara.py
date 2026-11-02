#!/usr/bin/env python3
"""YARA com gerenciador real e um Ubuntu real, com o pacote oficial do agente e o comando que a tela mostra.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_yara.py

Apaga no final tudo o que criou.
"""

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
from roar_ingestao import fontes, provisao, yara_regras  # noqa: E402
from roar_ingestao.regras import buscar_ativos, gravar_ativos  # noqa: E402
from testar_ingestao import SUFIXO, Ambiente, agente_ativo, esperar_gerenciador  # noqa: E402

RESULTADOS = []
MARCA = f"ROAR-MALWARE-{uuid.uuid4().hex}"
REGRA = f'rule roar_prova {{ strings: $a = "{MARCA}" condition: $a }}'
SEGUNDA = f'rule roar_prova_dois {{ strings: $a = "{MARCA}-DOIS" condition: $a }}'
IMAGEM = "roar-teste-yara"
DOCKERFILE = """FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq curl lsb-release adduser sudo >/dev/null
RUN curl -so /agente.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.9-1_amd64.deb
CMD ["sleep", "infinity"]
"""


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def sh(*args, limite=600):
    r = subprocess.run(args, capture_output=True, text=True, timeout=limite)
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
    print("== Validação", flush=True)

    def motivo(fonte, outras=()):
        try:
            yara_regras.validar(fonte, outras)
            return ""
        except yara_regras.RegraInvalida as erro:
            return str(erro)

    registrar("regra boa passa", yara_regras.validar(REGRA) == ["roar_prova"])
    registrar("recusa vazia", "Cole" in motivo("   "))
    registrar("recusa erro de sintaxe e diz o motivo", "não compila" in motivo("rule { x"), motivo("rule { x"))
    registrar("recusa include", "não compila" in motivo('include "/etc/shadow"\n' + REGRA), motivo('include "/etc/shadow"\n' + REGRA))
    registrar("recusa só comentário", "nenhuma regra" in motivo("// nada aqui"))
    registrar("recusa regra global", "global" in motivo('global rule g { condition: filesize > 1 }'))
    registrar("recusa regra que bate com tudo", "vazio" in motivo("rule tudo { condition: true }"))
    registrar("recusa acima do tamanho", "tamanho" in motivo(REGRA + " " * (yara_regras.TAMANHO_MAXIMO + 1)))
    registrar("recusa nome repetido entre regras", "conflita" in motivo(REGRA, [REGRA]))
    registrar("regras diferentes convivem", yara_regras.validar(SEGUNDA, [REGRA]) == ["roar_prova_dois"])
    registrar("nada de sair do Linux sem aviso", "wazuh" in yara_regras.COMANDO_DE_INSTALACAO and "--conferir" in yara_regras.COMANDO_DE_INSTALACAO)


def main():
    testar_validacao()
    amb = Ambiente()
    nome = f"roar-teste-yara-{SUFIXO}"
    try:
        a, b = amb.gerenciador("yara-a"), amb.gerenciador("yara-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        ger = f"roar-ger-{a['id']}-gerenciador-1"
        ua, ub = criar_usuario(amb, a["cliente"]), criar_usuario(amb, b["cliente"])

        pasta = Path(tempfile.mkdtemp(prefix="roar-yara-"))
        (pasta / "Dockerfile").write_text(DOCKERFILE)
        sh("docker", "build", "-q", "-t", IMAGEM, str(pasta))
        sh("docker", "run", "-d", "--name", nome, "--hostname", nome, "--network", provisao.REDE, IMAGEM)
        amb.conteineres.append(nome)
        sh("docker", "exec", "-e", f"WAZUH_MANAGER={a['host']}", "-e", f"WAZUH_REGISTRATION_SERVER={a['host']}",
           "-e", f"WAZUH_REGISTRATION_PASSWORD={a['senha_inscricao']}", "-e", f"WAZUH_AGENT_NAME={nome}", nome, "dpkg", "-i", "/agente.deb")
        sh("docker", "exec", nome, "/var/ossec/bin/wazuh-control", "start")
        agente = agente_ativo(a, nome, 180)
        registrar("Ubuntu com o agente oficial fica ativo", agente, str(agente))
        gravar_ativos(amb.banco, a["id"], a["cliente"], buscar_ativos(a["id"]))

        with TestClient(app, base_url="https://testserver") as http:
            registrar("exige sessão", http.get("/api/yara").status_code == 401)
            http.post("/api/entrar", json=ua)

            print("\n== Pela tela", flush=True)
            registrar("regra ruim volta com o motivo", "não compila" in http.post("/api/yara/regras", json={"nome": "x", "fonte": "rule {"}).json()["detail"])
            r = http.post("/api/yara/regras", json={"nome": "Prova", "fonte": REGRA})
            registrar("regra criada", r.status_code == 201, r.text[:100])
            regra = r.json()["id"]
            registrar("nome repetido é recusado", http.post("/api/yara/regras", json={"nome": "Prova", "fonte": SEGUNDA}).status_code == 409)
            registrar("mesma regra com outro nome é recusada", http.post("/api/yara/regras", json={"nome": "Outra", "fonte": REGRA}).status_code == 422)
            registrar("fica na auditoria", amb.um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'criar_regra_yara'", a["cliente"]) == 1)
            visao = http.get("/api/yara").json()
            registrar("servidor não finge estar pronto", next(s for s in visao["servidores"] if s["agente_id"] == agente)["pronto_em"] is None)

            http.post("/api/fim/caminhos", json={"caminho": "/srv/yara-teste", "sistema": "linux", "modo": "tempo_real"})
            sh("docker", "exec", nome, "mkdir", "-p", "/srv/yara-teste")
            fontes.ciclo(amb.banco)
            estado = next(x for x in http.get("/api/yara").json()["regras"] if x["id"] == regra)
            registrar("regra fica ativa", estado["estado"] == "ativa", str(estado)[:200])
            registrar("gerenciador volta depois de receber a configuração", esperar_gerenciador(a, 240))
            conf = sh("docker", "exec", ger, "cat", "/var/ossec/etc/ossec.conf")
            registrar("a resposta entra na configuração", "roar_yara.sh" in conf and "<rules_id>550,554</rules_id>" in conf)
            ger_b = sh("docker", "exec", f"roar-ger-{b['id']}-gerenciador-1", "sh", "-c", "ls /var/ossec/etc/shared/default; cat /var/ossec/etc/ossec.conf")
            registrar("o outro cliente não recebe nada", "roar_yara" not in ger_b)
            registrar("regras chegam ao agente", esperar(lambda: MARCA in sh("docker", "exec", nome, "cat", "/var/ossec/etc/shared/roar_yara.yar"), limite=240))
            registrar("o script chega ao agente", esperar(lambda: "roar-yara" in sh("docker", "exec", nome, "cat", "/var/ossec/etc/shared/roar_yara.sh"), limite=60))
            registrar("o caminho chega ao agente", esperar(lambda: "/srv/yara-teste" in sh("docker", "exec", nome, "cat", "/var/ossec/etc/shared/agent.conf"), limite=120))

            print("\n== Antes de instalar", flush=True)
            registrar("sem o script, o agente segue vivo", agente_ativo(a, nome, 120))

            print("\n== O comando da tela", flush=True)
            comando = http.get("/api/yara").json()["comando"]
            saida = sh("docker", "exec", "-e", "DEBIAN_FRONTEND=noninteractive", nome, "sh", "-c", f"apt-get update -qq >/dev/null; {comando}")
            registrar("instala de primeira", "yara" in sh("docker", "exec", nome, "sh", "-c", "which yara; ls -l /var/ossec/active-response/bin/roar_yara.sh"), saida[-160:])
            dono = sh("docker", "exec", nome, "stat", "-c", "%U:%G %a", "/var/ossec/active-response/bin/roar_yara.sh")
            registrar("só root e o grupo do agente podem executar", dono == "root:wazuh 750", dono)

            def pronto():
                amb.ciclo(a)
                return next(s for s in http.get("/api/yara").json()["servidores"] if s["agente_id"] == agente)["pronto_em"]

            registrar("o servidor confirma e aparece como pronto, sem reiniciar o agente", esperar(pronto, limite=300))

            print("\n== Arquivos de verdade", flush=True)
            time.sleep(50)
            normal = f"normal-{uuid.uuid4().hex[:8]}.txt"
            sh("docker", "exec", nome, "sh", "-c", f"echo inocente > /srv/yara-teste/{normal}")
            sh("docker", "exec", nome, "sh", "-c", f'echo "x {MARCA} y" > "/srv/yara-teste/com espaco.bin"')
            sh("docker", "exec", nome, "sh", "-c", f"echo '{MARCA}' > \"/srv/yara-teste/$(printf 'nome\\nroar-yara: regra=forjada arquivo=x')\"")

            def achados():
                amb.ciclo(a)
                return http.get("/api/yara").json()["achados"]

            registrar("arquivo com a marca vira alerta", esperar(lambda: any(x["arquivo"] == "/srv/yara-teste/com espaco.bin" and x["regra"] == "roar_prova" for x in achados()), limite=180), str(achados()[:1])[:220])
            registrar("o outro arquivo também, com o nome limpo", esperar(lambda: any(x["arquivo"] and x["arquivo"].startswith("/srv/yara-teste/nomeroar-yara") for x in achados()), limite=90))
            lista = achados()
            registrar("nome de arquivo não forja regra", all(x["regra"] == "roar_prova" for x in lista), str([x["regra"] for x in lista]))
            registrar("arquivo inocente não vira alerta", not any(normal in (x["arquivo"] or "") for x in lista))
            nivel = amb.um("SELECT nivel FROM eventos WHERE cliente_id = %s AND regra_id = %s LIMIT 1", a["cliente"], yara_regras.REGRA_ACHADO)
            registrar("o alerta é alto", nivel == 12, str(nivel))

            print("\n== Quando não dá para varrer", flush=True)
            sh("docker", "exec", nome, "truncate", "-s", "300M", "/srv/yara-teste/grande.bin")

            def com_problema():
                amb.ciclo(a)
                return amb.um("SELECT count(*) FROM eventos WHERE cliente_id = %s AND regra_id = %s AND regra_descricao LIKE '%%grande.bin%%'", a["cliente"], yara_regras.REGRA_ERRO)

            registrar("arquivo grande demais avisa em vez de calar", esperar(com_problema, limite=120))
            situacao = next(s for s in http.get("/api/yara").json()["servidores"] if s["agente_id"] == agente)
            registrar("a tela sabe do problema", situacao["erro_em"], str(situacao["erro_em"]))
            sh("docker", "exec", nome, "rm", "-f", "/srv/yara-teste/grande.bin")

            print("\n== Regra nova chega sem reiniciar nada", flush=True)
            pid = sh("docker", "exec", ger, "sh", "-c", "cat /var/ossec/var/run/wazuh-remoted-*.pid")
            r = http.post("/api/yara/regras", json={"nome": "Prova dois", "fonte": SEGUNDA})
            segunda = r.json()["id"]
            fontes.ciclo(amb.banco)
            registrar("gerenciador não reinicia", pid.isdigit() and sh("docker", "exec", ger, "sh", "-c", "cat /var/ossec/var/run/wazuh-remoted-*.pid") == pid, pid)
            registrar("a segunda chega ao agente", esperar(lambda: "roar_prova_dois" in sh("docker", "exec", nome, "cat", "/var/ossec/etc/shared/roar_yara.yar"), limite=240))

            print("\n== Isolamento", flush=True)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ub)
            visto = http.get("/api/yara").json()
            registrar("outro cliente não vê nada", visto["regras"] == [] and visto["servidores"] == [] and visto["achados"] == [])
            registrar("outro cliente não tira a regra", http.post(f"/api/yara/regras/{regra}/desativar").status_code == 404)
            registrar("outro cliente pode usar o mesmo nome", http.post("/api/yara/regras", json={"nome": "Prova", "fonte": REGRA}).status_code == 201)
            http.post("/api/sair")
            http.cookies.clear()

            print("\n== Tirar", flush=True)
            http.post("/api/entrar", json=ua)
            registrar("tirar uma mantém a outra", http.post(f"/api/yara/regras/{segunda}/desativar").status_code == 204)
            registrar("tirar duas vezes não finge", http.post(f"/api/yara/regras/{segunda}/desativar").status_code == 404)
            fontes.ciclo(amb.banco)
            registrar("a outra fica no gerenciador", "roar_prova_dois" not in sh("docker", "exec", ger, "cat", "/var/ossec/etc/shared/default/roar_yara.yar") and MARCA in sh("docker", "exec", ger, "cat", "/var/ossec/etc/shared/default/roar_yara.yar"))
            http.post(f"/api/yara/regras/{regra}/desativar")
            fontes.ciclo(amb.banco)
            registrar("sem regras, a pasta dos agentes esvazia", "roar_yara" not in sh("docker", "exec", ger, "ls", "/var/ossec/etc/shared/default"))
            registrar("gerenciador volta sem a resposta", esperar_gerenciador(a, 240) and "roar_yara" not in sh("docker", "exec", ger, "cat", "/var/ossec/etc/ossec.conf"))
    finally:
        clientes = [g["cliente"] for g in amb.gerenciadores]
        for tabela in ("usuarios",):
            amb.admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
