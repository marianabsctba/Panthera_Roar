#!/usr/bin/env python3
"""Mantém riscos abertos na demonstração, que sem isso esvaziam a Fila em menos de dois dias.

O risco cai pela metade a cada 24 horas e o alerta se encerra sozinho: é o certo em produção, mas a demonstração não
recebe ataques novos. Repete os sinais mais recentes de cada pessoa sem alerta aberto e deixa o próprio motor abrir o
alerta. Só mexe no cliente da demonstração.

    /opt/panthera-roar/venv/bin/python testes/fase4/renovar_riscos_demonstracao.py
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ueba")]

from roar_ueba.motor import Motor  # noqa: E402

ENV = dict(l.strip().split("=", 1) for l in Path("/opt/panthera-roar/.env").read_text().splitlines() if "=" in l and not l.startswith("#"))
NOME = "Demonstração"
PESSOAS = ("joao.souza", "maria.silva")


def main():
    with psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar") as admin:
        linha = admin.execute("SELECT id FROM clientes WHERE nome = %s", (NOME,)).fetchone()
    if not linha:
        print("sem cliente de demonstração")
        return
    cliente = linha[0]
    motor = Motor(f"postgresql://roar_ueba:{ENV['ROAR_UEBA_SENHA']}@127.0.0.1:5433/roar")
    agora = datetime.now(timezone.utc)
    with motor.con.transaction():
        motor.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        for pessoa in PESSOAS:
            linha = motor.con.execute("SELECT id FROM entidades WHERE cliente_id = %s AND chave = %s", (cliente, pessoa)).fetchone()
            if not linha:
                continue
            entidade = linha[0]
            if motor.con.execute("SELECT 1 FROM alertas_risco WHERE cliente_id = %s AND entidade_id = %s AND estado = 'aberto'", (cliente, entidade)).fetchone():
                continue
            motor.con.execute(
                """INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id, detalhes)
                   SELECT cliente_id, entidade_id, tipo, valor, %s, peso, %s, evento_id, detalhes FROM sinais
                   WHERE cliente_id = %s AND entidade_id = %s AND dia = (SELECT max(dia) FROM sinais WHERE cliente_id = %s AND entidade_id = %s)
                   ON CONFLICT (cliente_id, entidade_id, tipo, valor, dia) DO NOTHING""",
                (agora.date(), agora, cliente, entidade, cliente, entidade))
            print(pessoa, round(motor._atualizar_risco(cliente, entidade, agora)))
    motor.fechar()


if __name__ == "__main__":
    main()
