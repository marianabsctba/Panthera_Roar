#!/usr/bin/env python3
"""Vigia dos coletores (docs/clickhouse.md, etapa 5): quando reinicia e quando deixa quieto. Sem Docker nem armazém:
o armazém e as horas de escrita são de mentira.

    python3 testes/fase4/testar_vigia_do_coletor.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao")]

from roar_ingestao import armazem, vigia_do_coletor as vigia  # noqa: E402

RESULTADOS = []
AGORA = datetime(2026, 11, 6, 19, 40, tzinfo=timezone.utc)


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class ArmazemDeMentira:
    def __init__(self, bancos, entregas):
        self.bancos, self.entregas = bancos, entregas

    def linhas(self, sql, parametros=None):
        if "system.databases" in sql:
            return [{"name": b} for b in self.bancos]
        quando = self.entregas.get(parametros["g"])
        return [{"m": str(int(quando.timestamp() * 1000)) if quando else "0", "n": "1" if quando else "0"}]


def main():
    minuto = timedelta(minutes=1)
    print("== Regra", flush=True)
    registrar("escreveu e entregou depois: em dia", not vigia.parado(AGORA - 10 * minuto, AGORA - 9 * minuto, AGORA))
    registrar("escreveu agora há pouco: ainda dá tempo de entregar", not vigia.parado(AGORA - 2 * minuto, AGORA - 30 * minuto, AGORA))
    registrar("escreveu há mais de 5 minutos e nada chegou depois: parado", vigia.parado(AGORA - 7 * minuto, AGORA - 11 * minuto, AGORA))
    registrar("escreveu e nunca entregou nada na janela: parado", vigia.parado(AGORA - 7 * minuto, None, AGORA))
    registrar("sem arquivo de logs: não mexe", not vigia.parado(None, None, AGORA))

    print("\n== Conferir", flush=True)
    clientes = {"a": "11111111-1111-1111-1111-111111111111", "b": "22222222-2222-2222-2222-222222222222", "c": "33333333-3333-3333-3333-333333333333"}
    bancos = [armazem.banco_do(clientes["a"]), armazem.banco_do(clientes["b"])]
    escritas = {"ga": AGORA - 7 * minuto, "gb": AGORA - 7 * minuto, "gc": AGORA - 7 * minuto}
    entregas = {"ga": AGORA - 11 * minuto, "gb": AGORA - 6 * minuto}
    adm = ArmazemDeMentira(bancos, entregas)
    reiniciados = []
    gerenciadores = [("ga", clientes["a"]), ("gb", clientes["b"]), ("gc", clientes["c"])]
    feitos = vigia.conferir(adm, gerenciadores, AGORA, escritas.get, reiniciados.append)
    registrar("reinicia só o parado; o em dia e o sem armazém ficam", feitos == ["ga"] and reiniciados == ["ga"], str(reiniciados))
    feitos = vigia.conferir(adm, gerenciadores, AGORA + 5 * minuto, escritas.get, reiniciados.append)
    registrar("não reinicia de novo antes do intervalo", feitos == [], str(feitos))
    feitos = vigia.conferir(adm, gerenciadores, AGORA + 16 * minuto, escritas.get, reiniciados.append)
    registrar("passado o intervalo, tenta de novo se continua parado", feitos == ["ga"], str(feitos))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
