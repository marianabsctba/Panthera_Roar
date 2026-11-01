#!/usr/bin/env python3
"""Deixa automações funcionando no cliente de demonstração, com gerenciador e agente reais.

    /opt/panthera-roar/venv/bin/python testes/fase4/semear_automacao.py

Não muda o acesso da demonstração. Fica rodando para trazer os alertas; rodar de novo reaproveita
o que já existe. Os endereços do ataque são públicos, mas o bloqueio só afeta o contêiner do agente.
"""

import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "testes/fase1")]

import psycopg  # noqa: E402
from roar_ingestao import provisao  # noqa: E402
from roar_ingestao.ciclo import conexoes, rodar_gerenciador  # noqa: E402
from testar_ingestao import AGENTE_CONF, agente_ativo, escrever_falhas, esperar_gerenciador  # noqa: E402

ESTADO = Path("/opt/panthera-roar/demo-automacao.json")
PASTA = Path("/opt/panthera-roar/demo-automacao")
ATIVO = "srv-demonstracao"
ATACANTE = "1.1.1.1"
EXTERNO = {"campo": "alvo_externo", "op": "igual", "valor": True}
PLAYBOOKS = [
    ("Força bruta em SSH: pedir aprovação e bloquear", True, {
        "quando": {"tipo": "evento", "regra_id": "5712"}, "se": [EXTERNO],
        "blocos": [{"tipo": "aprovacao"},
                   {"tipo": "acao", "acao": "bloquear_ip", "parametros": {"duracao_minutos": 60, "protegidos": ["8.8.8.8"]}}]}),
    ("Risco alto: bloquear se externo, anotar se interno", True, {
        "quando": {"tipo": "risco", "severidade": "alta"}, "se": [],
        "blocos": [{"tipo": "se", "condicao": EXTERNO,
                    "entao": [{"tipo": "aprovacao"}, {"tipo": "acao", "acao": "bloquear_ip", "parametros": {"duracao_minutos": 1440, "protegidos": []}}],
                    "senao": [{"tipo": "acao", "acao": "registrar", "parametros": {"texto": "Risco alto com origem sem endereço público: revisar com a pessoa."}}]}]}),
    ("Exemplo de ações ao mesmo tempo (desligado)", False, {
        "quando": {"tipo": "evento", "regra_id": "100002"}, "se": [],
        "blocos": [{"tipo": "paralelo", "ramos": [
            [{"tipo": "acao", "acao": "registrar", "parametros": {"texto": "Possível ransomware: acionar a equipe."}}],
            [{"tipo": "acao", "acao": "registrar", "parametros": {"texto": "Possível ransomware: separar o ativo."}}]]}]}),
]


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=400)


def preparar(admin, cliente):
    g = provisao.criar("demo-automacao")
    print("gerenciador no ar:", esperar_gerenciador(g), flush=True)
    # O gerenciador novo passa a ser do cliente de demonstração, que assim mantém o mesmo acesso.
    admin.execute("UPDATE gerenciadores SET cliente_id = %s WHERE id = %s", (cliente, g["id"]))
    admin.execute("DELETE FROM clientes WHERE id = %s", (g["cliente"],))
    PASTA.mkdir(mode=0o755, exist_ok=True)
    conf, passe, log = PASTA / "agente.conf", PASTA / "authd.pass", PASTA / "ataque.log"
    conf.write_text(AGENTE_CONF.format(host=g["host"]).replace("</ossec_config>",
                    "  <localfile><log_format>syslog</log_format><location>/var/ossec/logs/active-responses.log</location></localfile>\n</ossec_config>"))
    passe.write_text(g["senha_inscricao"] + "\n")
    log.touch()
    os.chmod(log, 0o644)
    sh("docker", "rm", "-f", ATIVO)
    sh("docker", "run", "-d", "--name", ATIVO, "--hostname", ATIVO, "--cap-add", "NET_ADMIN", "--network", provisao.REDE,
       "-e", f"WAZUH_MANAGER_SERVER={g['host']}", "-v", f"{conf}:/wazuh-config-mount/etc/ossec.conf",
       "-v", f"{passe}:/wazuh-config-mount/etc/authd.pass", "-v", f"{log}:/var/log/roar-teste.log", "wazuh/wazuh-agent:4.14.9")
    sh("docker", "exec", ATIVO, "sh", "-c", "yum install -y -q iptables")
    print("agente ativo:", agente_ativo(g, ATIVO, 180), flush=True)
    estado = {"gerenciador": g["id"]}
    ESTADO.write_text(json.dumps(estado))
    os.chmod(ESTADO, 0o600)
    return estado


def main():
    leitor, banco, env = conexoes()
    admin = psycopg.connect(f"postgresql://roar_admin:{env['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    cliente, usuario = admin.execute(
        "SELECT c.id, u.id FROM clientes c JOIN usuarios u ON u.cliente_id = c.id WHERE c.nome = 'Demonstração' LIMIT 1").fetchone()
    estado = json.loads(ESTADO.read_text()) if ESTADO.exists() else preparar(admin, cliente)
    for nome, ativo, definicao in PLAYBOOKS:
        if not admin.execute("SELECT 1 FROM playbooks WHERE cliente_id = %s AND nome = %s", (cliente, nome)).fetchone():
            admin.execute("INSERT INTO playbooks (cliente_id, nome, ativo, definicao, criado_por) VALUES (%s, %s, %s, %s, %s)",
                          (cliente, nome, ativo, json.dumps(definicao), usuario))
    print("playbooks prontos", flush=True)
    # Dá tempo de o disparo marcar o início antes de o ataque chegar.
    time.sleep(15)
    escrever_falhas(PASTA / "ataque.log", ATACANTE, "raiz", 14)
    print("ataque escrito no log", flush=True)
    while True:
        rodar_gerenciador(leitor, banco, estado["gerenciador"], cliente, limite=1000)
        time.sleep(10)


if __name__ == "__main__":
    main()
