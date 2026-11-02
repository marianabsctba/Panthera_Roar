#!/usr/bin/env python3
"""Do log de ataque ao firewall do ativo, com gerenciador, agente e Temporal reais. Requer infra/subir.sh e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_bloqueio_real.py

Apaga no final tudo o que criou.
"""

import asyncio
import json
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
from temporalio.client import Client

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import provisao  # noqa: E402
from roar_motor import acoes  # noqa: E402
from roar_motor.disparo import ciclo_do_cliente, url_do_banco  # noqa: E402
from testar_ingestao import AGENTE_CONF, SUFIXO, Ambiente, agente_ativo, esperar_gerenciador, escrever_falhas, subir_agente  # noqa: E402

RESULTADOS = []
ATACANTE = "1.1.1.1"
EXTERNO = {"campo": "alvo_externo", "op": "igual", "valor": True}


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def sh(*args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=400)
    return (r.stdout + r.stderr).strip()


def subir_agente_com_firewall(amb, g, pasta):
    conf, passe, log = pasta / "fw.conf", pasta / "fw.pass", pasta / "fw.log"
    # O registro da resposta ativa é coletado como em qualquer agente padrão: é o que confirma o bloqueio.
    conf.write_text(AGENTE_CONF.format(host=g["host"]).replace("</ossec_config>",
                    "  <localfile><log_format>syslog</log_format><location>/var/ossec/logs/active-responses.log</location></localfile>\n</ossec_config>"))
    log.touch()
    passe.write_text(g["senha_inscricao"] + "\n")
    os.chmod(pasta, 0o755)
    os.chmod(log, 0o644)
    nome = f"roar-teste-fw-{SUFIXO}"
    sh("docker", "run", "-d", "--name", nome, "--hostname", nome, "--cap-add", "NET_ADMIN", "--network", provisao.REDE,
       "-e", f"WAZUH_MANAGER_SERVER={g['host']}", "-v", f"{conf}:/wazuh-config-mount/etc/ossec.conf",
       "-v", f"{passe}:/wazuh-config-mount/etc/authd.pass", "-v", f"{log}:/var/log/roar-teste.log", "wazuh/wazuh-agent:4.14.9")
    amb.conteineres.append(nome)
    sh("docker", "exec", nome, "sh", "-c", "yum install -y -q iptables")
    return nome, log


def regras_de_firewall(conteiner):
    return sh("docker", "exec", conteiner, "sh", "-c", "iptables -S INPUT")


async def principal():
    amb = Ambiente()
    worker = None
    try:
        g = amb.gerenciador("bloqueio")
        registrar("gerenciador no ar", esperar_gerenciador(g))
        registrar("prazos são os mesmos no gerenciador e na ação", tuple(m * 60 for m in acoes.DURACOES_EM_MINUTOS) == provisao.SEGUNDOS_DE_BLOQUEIO)
        pasta = Path(tempfile.mkdtemp(prefix="roar-fw-"))
        fw, log = subir_agente_com_firewall(amb, g, pasta)
        agente = agente_ativo(g, fw, 180)
        registrar("agente com firewall ativo", agente, str(agente))
        fim = time.time() + 120
        recebeu = ""
        while time.time() < fim and "firewall-drop3600" not in recebeu:
            recebeu = sh("docker", "exec", fw, "sh", "-c", "grep firewall /var/ossec/etc/shared/ar.conf")
            await asyncio.sleep(5)
        registrar("os três prazos chegam ao agente", all(f"firewall-drop{s} " in recebeu for s in provisao.SEGUNDOS_DE_BLOQUEIO), recebeu.replace("\n", " | "))

        senha, email = secrets.token_urlsafe(18), f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
        amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, 'administrador')",
                          (g["cliente"], email, PasswordHasher().hash(senha)))
        ambiente = {**os.environ, "PYTHONPATH": str(RAIZ / "motor")}
        cliente = str(g["cliente"])
        worker = subprocess.Popen([sys.executable, "-m", "roar_motor.worker", "--cliente", cliente], env=ambiente,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        temporal = await Client.connect("127.0.0.1:7233", namespace="roar")
        url = url_do_banco()

        with TestClient(app, base_url="https://testserver") as http:
            http.post("/api/entrar", json={"email": email, "senha": senha})
            r = http.post("/api/automacao/playbooks", json={"nome": "Força bruta", "definicao": {
                "quando": {"tipo": "evento", "regra_id": "5712"}, "se": [EXTERNO],
                "blocos": [{"tipo": "aprovacao"}, {"tipo": "acao", "acao": "bloquear_ip", "parametros": {"duracao_minutos": 60}}]}})
            registrar("playbook criado", r.status_code == 201, r.text[:160])
            registrar("firewall começa sem o atacante", ATACANTE not in regras_de_firewall(fw))

            print("\n== Ataque de verdade", flush=True)
            escrever_falhas(log, ATACANTE, "raiz", 14)
            pendente = None
            fim = time.time() + 180
            while time.time() < fim and not pendente:
                amb.ciclo(g)
                await ciclo_do_cliente(url, temporal, cliente)
                pendente = next((a for a in http.get("/api/automacao").json()["aprovacoes"] if a["estado"] == "pendente"), None)
                await asyncio.sleep(3)
            registrar("o ataque vira pedido de aprovação", pendente and pendente["alvo"] == ATACANTE, str(pendente)[:200])
            registrar("nada é bloqueado antes de aprovar", ATACANTE not in regras_de_firewall(fw))

            print("\n== Aprovar e bloquear", flush=True)
            registrar("aprovação aceita", http.post(f"/api/automacao/aprovacoes/{pendente['id']}/aprovar", json={}).status_code == 204)
            bloqueado = False
            fim = time.time() + 60
            while time.time() < fim and not bloqueado:
                await ciclo_do_cliente(url, temporal, cliente)
                bloqueado = f"-s {ATACANTE}/32 -j DROP" in regras_de_firewall(fw)
                await asyncio.sleep(2)
            registrar("a regra entra no firewall do ativo", bloqueado, regras_de_firewall(fw).replace("\n", " | "))
            registrar("o prazo escolhido é o que foi usado", "firewall-drop" in sh("docker", "exec", fw, "sh", "-c", "tail -5 /var/ossec/logs/active-responses.log"))

            print("\n== Confirmação", flush=True)
            confirmada = False
            fim = time.time() + 120
            while time.time() < fim and not confirmada:
                amb.ciclo(g)
                execucao = http.get("/api/automacao").json()["execucoes"][0]
                confirmada = execucao["bloqueio_confirmado"]
                await asyncio.sleep(5)
            registrar("o alerta do ativo confirma o bloqueio na tela", confirmada, json.dumps(execucao["resultado"], ensure_ascii=False)[:200])
            registrar("execução concluída", execucao["estado"] == "concluida", execucao["estado"])

            print("\n== Ativo sem firewall", flush=True)
            sem, _ = subir_agente(amb, g, pasta, "sem", g["senha_inscricao"])
            agente_sem = agente_ativo(g, sem, 180)
            # Agente recém-inscrito ainda não recebeu a configuração e recusa o comando por um tempo.
            saida, fim = None, time.time() + 180
            while time.time() < fim and not saida:
                try:
                    saida = acoes.bloquear_ip(g["id"], {"alvo": "1.0.0.1", "agente_id": agente_sem}, {"duracao_minutos": 60})
                except RuntimeError:
                    await asyncio.sleep(10)
            registrar("a API diz que enviou", saida and saida["enviado"] == "1.0.0.1")
            await asyncio.sleep(45)
            amb.ciclo(g)
            confirmou = amb.um("SELECT count(*) FROM eventos WHERE cliente_id = %s AND regra_id = '651' AND agente_id = %s", g["cliente"], agente_sem)
            registrar("sem firewall nada confirma, e a tela não finge", confirmou == 0, f"{confirmou} confirmações")

            print("\n== Ativo que não existe", flush=True)
            try:
                acoes.bloquear_ip(g["id"], {"alvo": "1.0.0.1", "agente_id": "999"}, {})
                registrar("ativo inexistente vira erro", False)
            except Exception as erro:
                registrar("ativo inexistente vira erro", True, str(erro)[:140])
    finally:
        if worker:
            worker.terminate()
        clientes = [g["cliente"] for g in amb.gerenciadores]
        for tabela in ("aprovacoes", "execucoes", "playbooks", "soar_cursor"):
            amb.admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (clientes,))
        amb.admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(principal()))
