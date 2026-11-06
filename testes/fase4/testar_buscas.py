#!/usr/bin/env python3
"""Buscas agendadas: rodam na hora, avisam no sino só quando a condição vale e guardam a história, com banco real.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_buscas.py

O índice é de mentira: devolve o total que o teste manda.
"""

import sys
import tempfile
import uuid
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_ingestao import buscas  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class Indice:
    def __init__(self):
        self.total, self.pedidos, self.falhar = 0, [], False

    def post(self, url, json, timeout):
        self.pedidos.append((url, json))
        if self.falhar:
            raise ConnectionError("https://127.0.0.1:9200 recusou")
        total = self.total

        class Resposta:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"hits": {"total": {"value": total}, "hits": []}}
        return Resposta()


def main():
    print("== Condição", flush=True)
    registrar("alguma coisa", buscas.disparou("qualquer", 0, 1) and not buscas.disparou("qualquer", 0, 0))
    registrar("mais que o limite", buscas.disparou("mais_de", 5, 6) and not buscas.disparou("mais_de", 5, 5))
    registrar("nada, para fonte que parou de mandar", buscas.disparou("nenhum", 0, 0) and not buscas.disparou("nenhum", 0, 1))

    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"buscas-{uuid.uuid4().hex[:8]}",)).fetchone()[0])
    ger = f"gerbusca{uuid.uuid4().hex[:6]}"
    admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, 64200)", (ger, cliente))
    indice = Indice()
    pasta = Path(tempfile.mkdtemp(prefix="roar-buscas-"))
    (pasta / ger).mkdir()
    buscas.PASTA_GERENCIADORES = pasta

    def busca(nome, condicao="qualquer", limite=0, intervalo=15, texto="usuario=admin"):
        return admin.execute("""INSERT INTO buscas_salvas (cliente_id, nome, texto, janela_minutos, a_cada_minutos, condicao, limite)
                                VALUES (%s, %s, %s, 60, %s, %s, %s) RETURNING id""", (cliente, nome, texto, intervalo, condicao, limite)).fetchone()[0]

    def avisos():
        return admin.execute("SELECT alvo, contagem FROM notificacoes WHERE cliente_id = %s AND tipo = 'busca_agendada' ORDER BY alvo", (cliente,)).fetchall()

    try:
        print("\n== Rodadas", flush=True)
        acima = busca("Acima do limite", "mais_de", 5)
        abaixo = busca("Abaixo do limite", "mais_de", 50)
        guardada = admin.execute("INSERT INTO buscas_salvas (cliente_id, nome, texto, janela_minutos) VALUES (%s, 'Só guardada', '', 60) RETURNING id", (cliente,)).fetchone()[0]
        indice.total = 10
        buscas.rodar_vencidas(banco, indice.post, "https://indice")
        meus = [p for p in indice.pedidos if ger in p[0]]
        registrar("roda as agendadas e não a só guardada, no índice desta organização", len(meus) == 2, str(len(meus)))
        registrar("o texto vira filtro, e conta só a janela da busca", meus[0][1]["aggs"]["atual"] == {"filter": {"range": {"timestamp": {"gte": "now-60m"}}}})
        registrar("avisa só a que passou do limite", avisos() == [("Acima do limite", 1)], str(avisos()))
        estado = admin.execute("SELECT ultimo_total, proxima_em > now() + interval '14 minutes', ultimo_erro FROM buscas_salvas WHERE id = %s", (acima,)).fetchone()
        registrar("guarda o total e marca a próxima rodada", estado == (10, True, None), str(estado))
        registrar("a só guardada fica parada", admin.execute("SELECT ultima_em FROM buscas_salvas WHERE id = %s", (guardada,)).fetchone()[0] is None)
        historia = admin.execute("SELECT busca_id, total, disparou FROM buscas_execucoes WHERE cliente_id = %s ORDER BY busca_id", (cliente,)).fetchall()
        registrar("a história conta cada rodada", historia == [(acima, 10, True), (abaixo, 10, False)], str(historia))
        antes = len(indice.pedidos)
        buscas.rodar_vencidas(banco, indice.post, "https://indice")
        registrar("antes do horário, não roda de novo", len([p for p in indice.pedidos[antes:] if ger in p[0]]) == 0)
        admin.execute("UPDATE buscas_salvas SET proxima_em = now() - interval '1 minute' WHERE cliente_id = %s", (cliente,))
        buscas.rodar_vencidas(banco, indice.post, "https://indice")
        registrar("o aviso repetido soma no mesmo, sem encher o sino", avisos() == [("Acima do limite", 2)], str(avisos()))
        admin.execute("UPDATE buscas_salvas SET proxima_em = now() - interval '1 minute' WHERE id = %s", (abaixo,))
        indice.falhar = True
        buscas.rodar_vencidas(banco, indice.post, "https://indice")
        erro = admin.execute("SELECT ultimo_erro FROM buscas_salvas WHERE id = %s", (abaixo,)).fetchone()[0]
        registrar("índice fora do ar vira aviso na tela, sem endereço interno", erro and "127.0.0.1" not in erro and "9200" not in erro, str(erro))
    finally:
        admin.execute("DELETE FROM notificacoes WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM buscas_salvas WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM gerenciadores WHERE id = %s", (ger,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
