#!/usr/bin/env python3
"""Põe na demonstração tentativas de acesso vindas de endereços que estão hoje nas fontes de inteligência.

Os eventos são inventados; os endereços são reais e maliciosos, tirados da fonte da própria demonstração.
Nada é enviado a eles: o Roar só compara com o que já está no banco. Pode rodar de novo, e cada vez usa
os endereços que a fonte tiver no momento.

    /opt/panthera-roar/venv/bin/python testes/fase4/semear_indicadores_demonstracao.py
"""

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

ENV = dict(l.strip().split("=", 1) for l in Path("/opt/panthera-roar/.env").read_text().splitlines() if "=" in l and not l.startswith("#"))
NOME = "Demonstração"
GERENCIADOR, AGENTE, ATIVO = "demonstracao", "001", "srv-financeiro"
TENTATIVAS = (("5710", "sshd: Attempt to login using a non-existent user", 5, ["syslog", "sshd", "authentication_failed", "invalid_login"], "admin"),
              ("5712", "sshd: brute force trying to get access to the system. Non existent user.", 10, ["syslog", "sshd", "authentication_failures"], "root"),
              ("5710", "sshd: Attempt to login using a non-existent user", 5, ["syslog", "sshd", "authentication_failed", "invalid_login"], "oracle"))


def publico(valor):
    try:
        return ipaddress.ip_address(valor).is_global
    except ValueError:
        return False


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    cliente = admin.execute("SELECT id FROM clientes WHERE nome = %s", (NOME,)).fetchone()
    if not cliente:
        print("sem cliente de demonstração")
        return
    cliente = cliente[0]
    candidatos = [l[0] for l in admin.execute(
        """SELECT i.valor FROM intel_indicadores i JOIN intel_fontes f ON f.id = i.fonte_id
           WHERE i.cliente_id = %s AND f.ativa AND i.tipo = 'ip' ORDER BY i.id DESC LIMIT 200""", (cliente,)).fetchall()]
    enderecos = [v for v in candidatos if publico(v)][:len(TENTATIVAS)]
    if not enderecos:
        print("a fonte ainda não tem endereços")
        return
    agora = datetime.now(timezone.utc)
    marca = f"{agora:%Y%m%d%H%M%S}"
    for n, (ip, (regra, descricao, nivel, grupos, usuario)) in enumerate(zip(enderecos, TENTATIVAS)):
        quando = agora - timedelta(minutes=10 - n)
        severidade = "alta" if nivel >= 12 else "media" if nivel >= 7 else "baixa"
        grupo = admin.execute(
            """INSERT INTO grupos_alerta AS g (cliente_id, chave, dia, gerenciador_id, agente_id, ip_origem, nivel, severidade, regras, primeira_em, ultima_em)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cliente_id, chave) DO UPDATE SET total = g.total + 1, ultima_em = GREATEST(g.ultima_em, EXCLUDED.ultima_em) RETURNING id""",
            (cliente, f"{AGENTE}|{ip}|{quando.date()}", quando.date(), GERENCIADOR, AGENTE, ip, nivel, severidade, [regra], quando, quando)).fetchone()[0]
        admin.execute(
            """INSERT INTO eventos (cliente_id, grupo_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel, severidade,
                 regra_id, regra_descricao, regra_grupos, mitre, agente_id, agente_nome, ip_origem, usuario, bruto)
               VALUES (%s, %s, %s, 'wazuh', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (cliente, grupo, GERENCIADOR, f"indicador-{marca}-{n}", quando, nivel, severidade, regra, descricao, grupos, ["T1110"], AGENTE, ATIVO, ip, usuario, Jsonb({
                "timestamp": quando.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "agent": {"id": AGENTE, "name": ATIVO}, "manager": {"name": f"gerenciador-{GERENCIADOR}"},
                "rule": {"id": regra, "level": nivel, "description": descricao, "groups": grupos, "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}},
                "decoder": {"name": "sshd"}, "location": "/var/log/auth.log",
                "full_log": f"{quando:%b %d %H:%M:%S} {ATIVO} sshd[4120]: Invalid user {usuario} from {ip} port 40122",
                "data": {"srcip": ip, "srcuser": usuario},
            })))
        print(regra, "de um endereço que está na fonte")
    print(len(enderecos), "eventos gravados; a comparação roda na próxima volta do serviço de inteligência")


if __name__ == "__main__":
    main()
