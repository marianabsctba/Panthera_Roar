#!/usr/bin/env python3
"""Trazer de volta da cópia fria do armazém de eventos (ingestao/roar_ingestao/copia_do_armazem.py): o dia copiado fica
registrado para a tela, volta para a tabela de recuperados quando sai do armazém, aparece na tela de logs em qualquer
período, não volta duas vezes, e sai quando o pedido vence ou é devolvido.

    sudo bash testes/rodar.sh testes/fase4/testar_copia_do_armazem.py
"""

import json
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "testes/fase4")]

from roar_api import consulta as linguagem, leitor_armazem  # noqa: E402
from roar_ingestao import armazem, copia_do_armazem, copia_fria, provisao  # noqa: E402
from roar_ingestao.ciclo import ler_env  # noqa: E402
from testar_selos_do_armazem import inserir, linha  # noqa: E402

RESULTADOS = []
ENV = ler_env(provisao.DESTINO / ".env")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def contar(adm, banco, tabela, onde="1"):
    return int(adm.linhas(f"SELECT count() AS n FROM {banco}.{tabela} WHERE {onde}")[0]["n"])


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    adm, leitor = armazem.admin(ENV), armazem.leitor(ENV)
    raiz = copia_do_armazem.pasta(ENV)
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"copia-{uuid.uuid4().hex[:6]}",)).fetchone()[0])
    gerenciador = f"cop{uuid.uuid4().hex[:8]}"
    admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, 64300)", (gerenciador, cliente))
    banco = armazem.criar_organizacao(adm, cliente, 180, 180)
    usuario = admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Teste', 'x', 'administrador') RETURNING id",
                            (cliente, f"copia-{uuid.uuid4().hex[:6]}@exemplo.test")).fetchone()[0]
    try:
        print("== Cópia e registro", flush=True)
        dia = (datetime.now(timezone.utc) - timedelta(days=5)).replace(hour=12, minute=0, second=0, microsecond=0)
        nome_do_dia = dia.strftime("%Y%m%d")
        inserir(adm, banco, "logs", [linha(gerenciador, dia + timedelta(minutes=i), i) for i in range(20)])
        inserir(adm, banco, "alertas", [linha(gerenciador, dia + timedelta(minutes=i), 100 + i) for i in range(3)])
        copia_do_armazem.copiar(adm, raiz)
        copia_do_armazem.registrar(admin, raiz)
        registrar("o dia copiado fica registrado para a tela", admin.execute("SELECT count(*) FROM copias_do_armazem WHERE cliente_id = %s AND dia = %s",
                                                                              (cliente, dia.date())).fetchone()[0] == 1)

        print("\n== O dia sai do armazém e volta", flush=True)
        registrar("enquanto está no armazém, não aparece para trazer", ("logs", nome_do_dia) in copia_do_armazem.presentes(leitor, banco))
        for tabela in ("logs", "alertas"):
            adm.executar(f"ALTER TABLE {banco}.{tabela} DROP PARTITION {nome_do_dia}")
        registrar("depois que o prazo apaga, o dia fica disponível", ("logs", nome_do_dia) not in copia_do_armazem.presentes(leitor, banco))
        voltaram = copia_do_armazem.recuperar(adm, raiz, cliente, dia.date(), dia.date(), "ambos")
        registrar("o dia volta, logs e alertas, para a tabela de recuperados", sorted(voltaram) == [f"alertas:{nome_do_dia}", f"logs:{nome_do_dia}"]
                  and contar(adm, banco, "logs_recuperados") == 20 and contar(adm, banco, "alertas_recuperados") == 3 and contar(adm, banco, "logs") == 0, str(voltaram))
        registrar("pedir de novo não traz duas vezes", copia_do_armazem.recuperar(adm, raiz, cliente, dia.date(), dia.date(), "ambos") == []
                  and contar(adm, banco, "logs_recuperados") == 20)
        pedido = linguagem.analisar("evento selado")
        tela = leitor_armazem.logs(leitor, banco, pedido, [], [], 1, None, 50, (), True)
        registrar("a tela de logs mostra o dia que voltou, mesmo no período de um dia", tela["total"] == 20, str(tela.get("total")))
        registrar("o selo e o volume continuam só com a tabela de sempre", contar(adm, banco, "logs") == 0)

        print("\n== Devolver", flush=True)
        copia_do_armazem.devolver(adm, cliente, voltaram + ["logs:x; DROP TABLE y", "outra:20260101"])
        registrar("devolver apaga o dia que voltou e ignora o que não é dia", contar(adm, banco, "logs_recuperados") == 0 and contar(adm, banco, "alertas_recuperados") == 0)

        print("\n== Pedido de verdade, pelo serviço", flush=True)
        pedido_id = admin.execute("""INSERT INTO recuperacoes (cliente_id, de, ate, tipo, dias_de_consulta, pedido_por, origem)
                                     VALUES (%s, %s, %s, 'logs', 2, %s, 'armazem') RETURNING id""", (cliente, dia.date(), dia.date(), usuario)).fetchone()[0]
        copia_fria.processar(ENV)
        estado, indices, expira = admin.execute("SELECT estado, indices, expira_em FROM recuperacoes WHERE id = %s", (pedido_id,)).fetchone()
        registrar("o serviço atende o pedido, com prazo", estado == "pronto" and indices == [f"logs:{nome_do_dia}"] and expira is not None
                  and contar(adm, banco, "logs_recuperados") == 20, f"{estado} {indices}")
        admin.execute("UPDATE recuperacoes SET estado = 'devolver' WHERE id = %s", (pedido_id,))
        copia_fria.processar(ENV)
        registrar("e devolve quando pedem", admin.execute("SELECT estado FROM recuperacoes WHERE id = %s", (pedido_id,)).fetchone()[0] == "devolvido"
                  and contar(adm, banco, "logs_recuperados") == 0)
        vazio = admin.execute("""INSERT INTO recuperacoes (cliente_id, de, ate, tipo, dias_de_consulta, pedido_por, origem)
                                 VALUES (%s, '2020-01-01', '2020-01-02', 'logs', 2, %s, 'armazem') RETURNING id""", (cliente, usuario)).fetchone()[0]
        copia_fria.processar(ENV)
        estado, mensagem = admin.execute("SELECT estado, mensagem FROM recuperacoes WHERE id = %s", (vazio,)).fetchone()
        registrar("período sem cópia avisa", estado == "falhou" and "fora do armazém" in (mensagem or ""), str(mensagem))
    finally:
        admin.execute("DELETE FROM recuperacoes WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM copias_do_armazem WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM usuarios WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM gerenciadores WHERE id = %s", (gerenciador,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))
        armazem.remover_organizacao(adm, cliente)
        shutil.rmtree(raiz / banco, ignore_errors=True)

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
