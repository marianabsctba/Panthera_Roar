#!/usr/bin/env python3
"""Cria um cliente de demonstração com dados de exemplo, passando pelo UEBA de verdade.

    /opt/panthera-roar/venv/bin/python testes/fase4/semear_demonstracao.py

O acesso gerado fica em /opt/panthera-roar/demonstracao.txt, só para root.
"""

import json
import os
import random
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg
import requests
import urllib3
from argon2 import PasswordHasher
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ueba"), str(RAIZ / "ingestao")]

from roar_ingestao import provisao  # noqa: E402
from roar_ingestao.regras import buscar_regras, linha_da_regra  # noqa: E402
from roar_ueba.motor import Motor, Parametros  # noqa: E402

ENV = {}
for linha in Path("/opt/panthera-roar/.env").read_text().splitlines():
    if "=" in linha and not linha.startswith("#"):
        k, v = linha.split("=", 1)
        ENV[k] = v
ADMIN = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
FUSO = ZoneInfo("America/Sao_Paulo")
NOME = "Demonstração"
SUCESSO, FALHA, SUDO = ["authentication_success"], ["authentication_failed"], ["sudo"]
PESSOAS = ["maria.silva", "joao.souza", "ana.lima", "pedro.alves", "carla.dias", "rafael.nunes", "beatriz.rocha", "lucas.melo"]
SERVIDORES = {"001": "srv-financeiro", "002": "srv-rh", "003": "srv-arquivos", "004": "srv-dominio"}
# Marcações como as regras reais do Wazuh trazem: técnica, tática e normas.
MARCAS = {
    "5760": {"mitre": {"id": ["T1110.001"], "technique": ["Password Guessing"], "tactic": ["Credential Access"]},
             "gdpr": ["IV_35.7.d", "IV_32.2"], "pci_dss": ["10.2.4", "10.2.5"], "hipaa": ["164.312.b"], "nist_800_53": ["AU.14", "AC.7"], "tsc": ["CC6.1", "CC7.2"]},
    "5710": {"mitre": {"id": ["T1110.001"], "technique": ["Password Guessing"], "tactic": ["Credential Access"]},
             "gdpr": ["IV_35.7.d", "IV_32.2"], "pci_dss": ["10.2.4", "10.6.1"], "nist_800_53": ["AU.14", "AC.7"], "tsc": ["CC6.1"]},
    "40111": {"mitre": {"id": ["T1110"], "technique": ["Brute Force"], "tactic": ["Credential Access"]},
              "gdpr": ["IV_35.7.d", "IV_32.2"], "pci_dss": ["10.2.4", "11.4"], "hipaa": ["164.312.b"], "nist_800_53": ["SI.4", "AC.7"], "tsc": ["CC7.2"]},
    "5402": {"mitre": {"id": ["T1548.003"], "technique": ["Sudo and Sudo Caching"], "tactic": ["Privilege Escalation", "Defense Evasion"]},
             "gdpr": ["IV_32.2"], "pci_dss": ["10.2.5", "10.2.2"], "nist_800_53": ["AU.14", "AC.6"], "tsc": ["CC6.8"]},
    "100002": {"mitre": {"id": ["T1486"], "technique": ["Data Encrypted for Impact"], "tactic": ["Impact"]},
               "gdpr": ["IV_32.2", "IV_35.7.d"], "pci_dss": ["11.4"], "hipaa": ["164.308.a.1"], "nist_800_53": ["SI.4"], "tsc": ["CC7.3"]},
    "550": {"mitre": {"id": ["T1565.001"], "technique": ["Stored Data Manipulation"], "tactic": ["Impact"]},
            "gdpr": ["II_5.1.f"], "pci_dss": ["11.5"], "hipaa": ["164.312.c.1"], "nist_800_53": ["SI.7"], "tsc": ["PI1.4"]},
    "31151": {"mitre": {"id": ["T1190"], "technique": ["Exploit Public-Facing Application"], "tactic": ["Initial Access"]},
              "pci_dss": ["6.5", "11.4"], "nist_800_53": ["SA.11", "SI.4"], "tsc": ["CC6.6"]},
}
ARQUIVOS = ["/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config", "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "/var/www/html/index.php", "/usr/local/bin/backup.sh"]


def main():
    r = random.Random(7)
    antigo = ADMIN.execute("SELECT id FROM clientes WHERE nome = %s", (NOME,)).fetchone()
    if antigo:
        for tabela in ("regras_proprias", "ativos", "auditoria", "regras", "sinais", "alertas_risco", "falhas_por_hora", "horas", "vistos", "entidades",
                       "ueba_cursor", "eventos", "grupos_alerta", "gerenciadores", "usuarios"):
            ADMIN.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", antigo)
        ADMIN.execute("DELETE FROM clientes WHERE id = %s", antigo)

    cliente = ADMIN.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (NOME,)).fetchone()[0]
    ger = "demonstracao"
    ADMIN.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, 65000)", (ger, cliente))
    # Recriar a demonstração não muda o acesso de quem já está usando.
    arquivo = Path("/opt/panthera-roar/demonstracao.txt")
    senha = arquivo.read_text().splitlines()[1] if arquivo.exists() else secrets.token_urlsafe(16)
    email = "demonstracao@exemplo.test"
    ADMIN.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, 'administrador')",
                  (cliente, email, PasswordHasher().hash(senha)))

    n = [0]

    def ev(quando, usuario, grupos, agente, ip, regra, descricao, nivel=3, bruto=None):
        n[0] += 1
        severidade = "critica" if nivel >= 15 else "alta" if nivel >= 12 else "media" if nivel >= 7 else "baixa"
        grupo = ADMIN.execute(
            """INSERT INTO grupos_alerta AS g (cliente_id, chave, dia, gerenciador_id, agente_id, ip_origem, nivel,
                 severidade, regras, primeira_em, ultima_em)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cliente_id, chave) DO UPDATE SET total = g.total + 1,
                 nivel = GREATEST(g.nivel, EXCLUDED.nivel),
                 severidade = CASE WHEN EXCLUDED.nivel > g.nivel THEN EXCLUDED.severidade ELSE g.severidade END,
                 regras = ARRAY(SELECT DISTINCT unnest(g.regras || EXCLUDED.regras)),
                 ultima_em = GREATEST(g.ultima_em, EXCLUDED.ultima_em) RETURNING id""",
            (cliente, f"{agente}|{ip}|{quando.date()}", quando.date(), ger, agente, ip, nivel, severidade, [regra],
             quando, quando)).fetchone()[0]
        ADMIN.execute(
            """INSERT INTO eventos (cliente_id, grupo_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel, severidade,
                 regra_id, regra_descricao, regra_grupos, mitre, agente_id, agente_nome, ip_origem, usuario, bruto)
               VALUES (%s, %s, %s, 'wazuh', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (cliente, grupo, ger, f"d{n[0]}", quando, nivel, severidade, regra, descricao, grupos,
             MARCAS.get(regra, {}).get("mitre", {}).get("id", []), agente,
             SERVIDORES[agente], ip, usuario, Jsonb({
                 "timestamp": quando.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                 "agent": {"id": agente, "name": SERVIDORES[agente]},
                 "manager": {"name": f"gerenciador-{ger}"},
                 "rule": {"id": regra, "level": nivel, "description": descricao, "groups": grupos, **MARCAS.get(regra, {})},
                 **({"syscheck": {"path": r.choice(ARQUIVOS), "event": r.choice(["modified", "modified", "added", "deleted"]),
                                  "uname_after": "root", "sha256_after": f"{r.getrandbits(256):064x}"}} if regra == "550" else {}),
                 "decoder": {"name": "sshd"},
                 "location": "/var/log/auth.log",
                 "full_log": f"{quando:%b %d %H:%M:%S} {SERVIDORES[agente]} sshd[2231]: {descricao} {usuario or ''} from {ip} port 52114 ssh2",
                 "data": {"srcip": ip, "srcuser": usuario, **(bruto or {}).get("data", {})},
             })))

    agora = datetime.now(timezone.utc)
    hoje = agora.astimezone(FUSO).replace(hour=0, minute=0, second=0, microsecond=0)
    for d in range(30, 0, -1):
        dia = hoje - timedelta(days=d)
        if dia.weekday() >= 5:
            continue
        for i, p in enumerate(PESSOAS):
            agente = list(SERVIDORES)[i % 3]
            for h in (9, 11, 14, 17):
                ev(dia.replace(hour=h, minute=r.randint(0, 59)).astimezone(timezone.utc), p, SUCESSO, agente,
                   f"10.10.{i}.20", "5715", "sshd: authentication success.")

    # Ruído de todo dia: alertas comuns, que o Wazuh detecta sem envolver identidade.
    externos = [f"198.51.100.{i}" for i in (11, 23, 42, 58)] + ["203.0.113.9", "203.0.113.31"]
    comuns = [
        ("550", "Integrity checksum changed.", 7),
        ("510", "Host-based anomaly detection event (rootcheck).", 7),
        ("31151", "Multiple web server 400 error codes from same source ip.", 10),
        ("5551", "PAM: Multiple failed logins in a small period of time.", 10),
        ("40111", "Multiple authentication failures.", 12),
    ]
    for d in range(30, -1, -1):
        dia = hoje - timedelta(days=d)
        for _ in range(r.randint(3, 12) if dia.weekday() < 5 else r.randint(0, 4)):
            regra, descricao, nivel = r.choices(comuns, weights=(8, 4, 3, 2, 1))[0]
            quando = dia.replace(hour=r.randint(0, 23), minute=r.randint(0, 59)).astimezone(timezone.utc)
            if quando < agora:
                ev(quando, None, ["syscheck"] if regra == "550" else ["alertas"], r.choice(list(SERVIDORES)), r.choice(externos), regra, descricao, nivel=nivel)
    # Um dia ruim, para o gráfico mostrar o que chama atenção.
    pico = (hoje - timedelta(days=6)).replace(hour=14).astimezone(timezone.utc)
    for i in range(35):
        ev(pico + timedelta(minutes=i), None, ["attack"], "004", "203.0.113.31", "40111", "Multiple authentication failures.", nivel=12)
    for i in range(3):
        ev(pico + timedelta(minutes=40 + i), None, ["attack"], "004", "203.0.113.31", "100002", "Possible ransomware activity.", nivel=15)

    # Credencial roubada: ativo e endereço novos, de madrugada, com privilégio.
    q = (hoje.replace(hour=3, minute=12) if agora.astimezone(FUSO).hour > 3 else hoje - timedelta(hours=21)).astimezone(timezone.utc)
    ev(q, "maria.silva", SUCESSO, "004", "203.0.113.45", "5715", "sshd: authentication success.")
    ev(q + timedelta(minutes=2), "maria.silva", SUDO, "004", "203.0.113.45", "5402", "Successful sudo to ROOT executed.",
       nivel=3, bruto={"data": {"dstuser": "root"}})
    # Força bruta que funcionou.
    t = q + timedelta(minutes=40)
    for i in range(14):
        ev(t + timedelta(seconds=i * 6), "joao.souza", FALHA, "001", "198.51.100.77", "5760",
           "sshd: authentication failed.", nivel=5)
    ev(t + timedelta(seconds=120), "joao.souza", SUCESSO, "001", "198.51.100.77", "5715", "sshd: authentication success.")
    # Nome hostil, para ver a tela tratando como texto.
    for i in range(30):
        ev(t + timedelta(minutes=5, seconds=i), '<img src=x onerror="alert(1)">', FALHA, "003", "198.51.100.200", "5710",
           "sshd: Attempt to login using a non-existent user", nivel=5)
    ev(t + timedelta(minutes=9), "ana.lima", SUCESSO, "003", "10.10.2.20", "5715", "sshd: authentication success.")

    # Catálogo real do Wazuh, guardado da primeira vez em que a demonstração é criada.
    guardado = Path("/opt/panthera-roar/catalogo-exemplo.json")
    if not guardado.exists():
        temporario = provisao.criar(f"catalogo-{secrets.token_hex(3)}")
        try:
            for _ in range(60):
                try:
                    regras_reais = buscar_regras(temporario["id"])
                    break
                except requests.RequestException:
                    time.sleep(5)
            guardado.write_text(json.dumps(regras_reais))
        finally:
            provisao.remover(temporario["id"])
    for regra in json.loads(guardado.read_text()):
        linha = linha_da_regra(regra)
        ADMIN.execute(
            "INSERT INTO regras (cliente_id, gerenciador_id, regra_id, nivel, descricao, grupos, mitre, arquivo, ativa, normas, detalhes)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (cliente, ger, *linha))
    # Regras dos eventos de exemplo que não vêm com o Wazuh.
    for regra, descricao, nivel in ADMIN.execute(
            "SELECT DISTINCT regra_id, regra_descricao, max(nivel) FROM eventos WHERE cliente_id = %s GROUP BY 1, 2", (cliente,)).fetchall():
        ADMIN.execute(
            "INSERT INTO regras (cliente_id, gerenciador_id, regra_id, nivel, descricao, mitre, normas) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (gerenciador_id, regra_id) DO UPDATE SET mitre = EXCLUDED.mitre, nivel = EXCLUDED.nivel,"
            " descricao = EXCLUDED.descricao, normas = EXCLUDED.normas",
            (cliente, ger, regra, nivel, descricao, MARCAS.get(regra, {}).get("mitre", {}).get("id", []),
             Jsonb({k: v for k, v in MARCAS.get(regra, {}).items() if k != "mitre"})))

    # Ativos como a sincronização com o gerenciador real traz.
    agora_ativo = datetime.now(timezone.utc)
    for agente, (sistema, estado_ativo, nota, ip) in {
        "001": ("Ubuntu 22.04", "active", 78, "10.10.0.21"), "002": ("Ubuntu 24.04", "active", 64, "10.10.0.22"),
        "003": ("Debian 12", "active", 52, "10.10.0.23"), "004": ("Windows Server 2022", "disconnected", 41, "10.10.0.10"),
    }.items():
        ADMIN.execute(
            """INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, ip, sistema, versao, estado, grupos, ultima_conexao,
                 sca_politica, sca_nota, sca_aprovados, sca_reprovados)
               VALUES (%s, %s, %s, %s, %s, %s, 'v4.14.9', %s, '{default}', %s, 'CIS Benchmark', %s, %s, %s)""",
            (cliente, ger, agente, SERVIDORES[agente], ip, sistema, estado_ativo,
             agora_ativo - timedelta(minutes=1 if estado_ativo == "active" else 300), nota, nota * 2, (100 - nota) * 2))

    # Logs brutos, inclusive os que não viraram alerta, no índice do cliente.
    indexer = requests.Session()
    indexer.auth = (ENV["WAZUH_INDEXER_USERNAME"], ENV["WAZUH_INDEXER_PASSWORD"])
    indexer.verify = False
    urllib3.disable_warnings()
    indice = f"wazuh-archives-4.x-{ger}-demonstracao"
    indexer.delete(f"https://127.0.0.1:9200/{indice}", timeout=30)
    modelos = [
        ("sshd[{p}]: Accepted publickey for {u} from {ip} port 5{o}12 ssh2", "/var/log/auth.log", "sshd", "sshd", True),
        ("CRON[{p}]: pam_unix(cron:session): session opened for user {u}", "/var/log/auth.log", "pam", "CRON", False),
        ("nginx[{p}]: {ip} GET /index.php HTTP/1.1 200 5120", "/var/log/nginx/access.log", "web-accesslog", "nginx", True),
        ("systemd[1]: Started Daily apt download activities.", "journald", "systemd", "systemd", False),
        ("kernel: [UFW BLOCK] IN=eth0 SRC={ip} DST=10.10.0.21 PROTO=TCP DPT=445", "/var/log/kern.log", "kernel", "kernel", True),
    ]
    enderecos = [f"10.10.0.{i}" for i in (21, 22, 34, 77)] + ["198.51.100.42", "198.51.100.77", "203.0.113.31"]
    linhas = []
    for i in range(600):
        quando = agora - timedelta(minutes=i * 11)
        modelo, origem, decoder, programa, com_ip = r.choice(modelos)
        agente = r.choice(list(SERVIDORES))
        usuario, ip = r.choice(PESSOAS), r.choice(enderecos)
        texto = modelo.format(p=r.randint(1000, 9000), u=usuario, ip=ip, o=r.randint(2, 200))
        dados = {"srcip": ip} if com_ip else {}
        if decoder in ("sshd", "pam"):
            dados["srcuser"] = usuario
        if decoder == "kernel":
            dados["protocol"] = "TCP"
        linhas.append(json.dumps({"index": {"_index": indice}}))
        linhas.append(json.dumps({
            "timestamp": quando.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "id": f"demo-{i}", "location": origem,
            "agent": {"id": agente, "name": SERVIDORES[agente]}, "manager": {"name": f"gerenciador-{ger}"},
            "decoder": {"name": decoder}, "predecoder": {"program_name": programa, "hostname": SERVIDORES[agente]},
            "data": dados, "full_log": f"{quando:%b %d %H:%M:%S} {SERVIDORES[agente]} {texto}",
        }))
    indexer.post("https://127.0.0.1:9200/_bulk?refresh=true", data="\n".join(linhas) + "\n",
                 headers={"Content-Type": "application/x-ndjson"}, timeout=120).raise_for_status()

    motor = Motor(f"postgresql://roar_ueba:{ENV['ROAR_UEBA_SENHA']}@127.0.0.1:5433/roar", Parametros(atraso_segundos=0))
    while motor.processar_cliente(cliente, "America/Sao_Paulo") == motor.p.lote:
        pass
    motor.fechar()

    arquivo.write_text(f"{email}\n{senha}\n")
    os.chmod(arquivo, 0o600)
    total = ADMIN.execute("SELECT count(*) FROM alertas_risco WHERE cliente_id = %s", (cliente,)).fetchone()[0]
    print(f"Demonstração criada: {n[0]} eventos, {total} alertas de risco. Acesso em {arquivo}.")


if __name__ == "__main__":
    main()
