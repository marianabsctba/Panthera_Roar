#!/usr/bin/env python3
"""Serviço de parsers: atende os testes da console e instala os parsers, com banco real e gerenciador de mentira.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_parsers.py

A prova com o gerenciador de verdade (teste do log e instalação) está descrita em docs/arquitetura.md.
"""

import sys
import tempfile
import uuid
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao")]

from roar_ingestao import parsers  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class GerenciadorDeMentira:
    """Aceita tudo, menos XML com a palavra quebrado. Guarda o que ficou instalado."""

    def __init__(self):
        self.instalado, self.chamadas = None, []

    def aplicar_regras(self, gerenciador_id, nome, xml, reiniciar=True, tipo="rules"):
        self.chamadas.append(("aplicar", nome, tipo))
        if "quebrado" in xml:
            return False, {"saida": "erro"}
        self.instalado = xml
        return True, {}

    def remover_regras(self, gerenciador_id, nome, tipo="rules"):
        self.chamadas.append(("remover", nome, tipo))
        self.instalado = None
        return True, {}


def main():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"parsers-{uuid.uuid4().hex[:8]}",)).fetchone()[0])
    ger = f"gerparser{uuid.uuid4().hex[:6]}"
    admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, 64100)", (ger, cliente))
    pasta = Path(tempfile.mkdtemp(prefix="roar-parsers-"))
    (pasta / ger).mkdir()
    parsers.PASTA_GERENCIADORES = pasta
    falso = GerenciadorDeMentira()

    def parser(nome, xml, estado="pendente"):
        return admin.execute("INSERT INTO parsers (cliente_id, nome, titulo, modo, xml, estado) VALUES (%s, %s, %s, 'xml', %s, %s) RETURNING id",
                             (cliente, nome, nome, xml, estado)).fetchone()[0]

    def estado(i):
        return admin.execute("SELECT estado, mensagem IS NOT NULL FROM parsers WHERE id = %s", (i,)).fetchone()

    try:
        print("== Testes pedidos pela console", flush=True)
        vistos = []

        def testar(gerenciador_id, log, xml=None):
            vistos.append((gerenciador_id, log, xml))
            decodificado = {"name": "roar_fw"} if xml else {}
            return {"saida": {"decoder": decodificado, "data": {"srcip": "1.2.3.4"} if xml else None, "predecoder": {"program_name": "FWX"},
                              "rule": {"id": "1", "level": 3, "description": "x"}}, "mensagens": ["WARNING: aviso"] if xml else []}

        t1 = admin.execute("INSERT INTO parser_testes (cliente_id, gerenciador_id, log, xml) VALUES (%s, %s, 'FWX: src=1.2.3.4', '<decoder/>') RETURNING id", (cliente, ger)).fetchone()[0]
        t2 = admin.execute("INSERT INTO parser_testes (cliente_id, gerenciador_id, log) VALUES (%s, %s, 'só como lê hoje') RETURNING id", (cliente, ger)).fetchone()[0]
        registrar("atende os pedidos pendentes", parsers.atender_testes(banco, testar) >= 2)
        r1, r2 = (admin.execute("SELECT estado, resultado FROM parser_testes WHERE id = %s", (t,)).fetchone() for t in (t1, t2))
        registrar("com parser, roda hoje e com o parser novo", r1[0] == "pronto" and r1[1]["hoje"]["decodificador"] is None and r1[1]["novo"]["campos"] == {"srcip": "1.2.3.4"}
                  and r1[1]["avisos"] == ["WARNING: aviso"] and r1[1]["novo"]["previo"]["program_name"] == "FWX", str(r1))
        registrar("sem parser, só como lê hoje", r2[0] == "pronto" and r2[1]["novo"] is None and len([v for v in vistos if v[1] == "só como lê hoje"]) == 1, str(r2))
        registrar("o mesmo pedido não roda duas vezes", parsers.atender_testes(banco, testar) == 0)

        def quebrou(gerenciador_id, log, xml=None):
            raise ConnectionError("https://127.0.0.1:65017 recusou")
        t3 = admin.execute("INSERT INTO parser_testes (cliente_id, gerenciador_id, log) VALUES (%s, %s, 'x') RETURNING id", (cliente, ger)).fetchone()[0]
        parsers.atender_testes(banco, quebrou)
        r3 = admin.execute("SELECT estado, resultado FROM parser_testes WHERE id = %s", (t3,)).fetchone()
        registrar("servidor fora do ar vira erro, sem endereço interno na tela", r3[0] == "erro" and "127.0.0.1" not in str(r3[1]), str(r3))

        print("\n== Instalação", flush=True)
        registrar("sem parser, nada a instalar", parsers.aplicar(banco, ger, cliente, falso) == 0 and falso.chamadas == [("remover", "roar_parsers.xml", "decoders")])
        bom = parser("fw", '<decoder name="roar_fw"/>\n')
        registrar("instala o parser novo como decodificador", parsers.aplicar(banco, ger, cliente, falso) == 1 and falso.instalado == '<decoder name="roar_fw"/>\n'
                  and falso.chamadas[-1] == ("aplicar", "roar_parsers.xml", "decoders") and estado(bom) == ("aplicado", False))
        falso.chamadas.clear()
        registrar("sem mudança, não mexe no servidor", parsers.aplicar(banco, ger, cliente, falso) == 0 and falso.chamadas == [])
        ruim = parser("quebrado", '<decoder name="roar_quebrado"/>\n')
        parsers.aplicar(banco, ger, cliente, falso)
        registrar("parser que o servidor recusa fica recusado, com o motivo", estado(ruim) == ("recusado", True))
        registrar("e o que já valia continua instalado", falso.instalado == '<decoder name="roar_fw"/>\n' and estado(bom) == ("aplicado", False))
        admin.execute("UPDATE parsers SET ativo = false WHERE id = %s", (ruim,))
        admin.execute("UPDATE parsers SET ativo = false, estado = 'pendente' WHERE id = %s", (bom,))
        parsers.aplicar(banco, ger, cliente, falso)
        registrar("desligados, o arquivo sai do servidor", falso.instalado is None and falso.chamadas[-1][0] == "remover")
    finally:
        for tabela in ("parser_testes", "parsers"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM gerenciadores WHERE id = %s", (ger,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
