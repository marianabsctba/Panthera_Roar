#!/usr/bin/env python3
"""Um chamado de exemplo na organização Demonstração, para o quadro Chamado do caso não aparecer vazio.

    sudo /opt/panthera-roar/venv/bin/python infra/demo/semear_chamado.py

Cadastra um ServiceNow de exemplo (sem credencial: nunca é chamado) e põe no caso mais antigo da Demonstração um chamado
já resolvido, com as notas que o serviço escreveria. Resolvido, o serviço de fontes não confere mais: nada sai daqui.
Rodar de novo não duplica.
"""

from pathlib import Path

import psycopg

ENV = dict(l.strip().split("=", 1) for l in Path("/opt/panthera-roar/.env").read_text().splitlines() if "=" in l and not l.startswith("#"))
NOME = "Demonstração"
FERRAMENTA = "ServiceNow (exemplo)"
NUMERO = "INC0010042"
ENDERECO = "https://exemplo.service-now.com/nav_to.do?uri=incident.do?sys_id=exemplo"


def main():
    with psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True) as admin:
        linha = admin.execute("""SELECT c.id, g.id, u.id FROM clientes c JOIN gerenciadores g ON g.cliente_id = c.id JOIN usuarios u ON u.cliente_id = c.id
                                 WHERE c.nome = %s ORDER BY g.criado_em, u.criado_em LIMIT 1""", (NOME,)).fetchone()
        if not linha:
            print("sem organização de demonstração")
            return
        cliente, gerenciador, usuario = linha
        caso = admin.execute("SELECT id, criado_em FROM casos WHERE cliente_id = %s ORDER BY criado_em LIMIT 1", (cliente,)).fetchone()
        if not caso:
            print("a Demonstração não tem caso: rode semear_vitrine.py antes")
            return
        fonte = admin.execute("SELECT id FROM fontes WHERE cliente_id = %s AND nome = %s", (cliente, FERRAMENTA)).fetchone()
        if not fonte:
            fonte = admin.execute(
                """INSERT INTO fontes (cliente_id, gerenciador_id, tipo, nome, config, estado, criada_por)
                   VALUES (%s, %s, 'servicenow', %s, '{"instancia": "exemplo.service-now.com", "usuario": "roar.integracao", "segredo": "sem-segredo"}', 'ativa', %s)
                   RETURNING id""", (cliente, gerenciador, FERRAMENTA, usuario)).fetchone()
        if admin.execute("SELECT 1 FROM chamados WHERE caso_id = %s", (caso[0],)).fetchone():
            print("o chamado de exemplo já existe")
            return
        admin.execute(
            """INSERT INTO chamados (cliente_id, caso_id, fonte_id, estado, numero, id_externo, endereco, situacao_externa, pedido_por_nome,
                                     pedido_em, aberto_em, resolvido_em, conferido_em)
               VALUES (%s, %s, %s, 'resolvido', %s, 'exemplo', %s, 'Resolvido', 'Ana Souza', %s + interval '20 minutes', %s + interval '21 minutes',
                       %s + interval '1 day', %s + interval '1 day')""",
            (cliente, caso[0], fonte[0], NUMERO, ENDERECO, caso[1], caso[1], caso[1], caso[1]))
        for minutos, texto in ((21, f"Chamado {NUMERO} aberto no ServiceNow: {ENDERECO}"),
                               (1440, f"O chamado {NUMERO} ficou resolvido no ServiceNow. Confira se o caso também pode ser encerrado.")):
            admin.execute("""INSERT INTO casos_notas (cliente_id, caso_id, autor_nome, automatica, texto, criado_em)
                             VALUES (%s, %s, 'Panthera Roar', true, %s, %s + make_interval(mins => %s))""", (cliente, caso[0], texto, caso[1], minutos))
        print(f"chamado {NUMERO} no caso {caso[0]}")


if __name__ == "__main__":
    main()
