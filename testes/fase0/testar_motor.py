#!/usr/bin/env python3
"""Fase 0: o motor próprio cumpre os requisitos? Requer infra/subir.sh já executado.

    /opt/panthera-roar/venv/bin/python testes/fase0/testar_motor.py

1. Integração MIT roda sem o Shuffle e sem falar com a Shuffle.
2. Cada cliente só é atendido pela sua fila.
3. Playbook sobrevive à morte do worker sem repetir o passo que já terminou.
"""

import asyncio
import collections
import http.server
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import timedelta
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ / "motor"))

from temporalio.client import Client, WorkflowFailureError  # noqa: E402

from roar_motor.playbook import fila_do_cliente  # noqa: E402

RESULTADOS = []
ACESSOS = collections.Counter()
SEGURAR = threading.Event()


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class Servidor(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ACESSOS[self.path] += 1
        if self.path.startswith("/lento") and ACESSOS[self.path] == 1:
            SEGURAR.set()
            threading.Event().wait(30)
        corpo = f"resposta-de{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        try:
            self.wfile.write(corpo)
        except OSError:
            pass

    def log_message(self, *args):
        pass


# Registra todo destino de rede do worker, para provar por onde os dados saem.
AUDITOR = """
import os, runpy, sys
destino = open(os.environ["ROAR_AUDITORIA"], "a", buffering=1)
def auditar(evento, args):
    if evento == "socket.getaddrinfo":
        destino.write(f"nome {args[0]}\\n")
    elif evento == "socket.connect":
        destino.write(f"conexao {args[1]}\\n")
sys.addaudithook(auditar)
sys.argv = ["worker", "--cliente", sys.argv[1]]
runpy.run_module("roar_motor.worker", run_name="__main__")
"""


def iniciar_worker(cliente, auditoria):
    ambiente = dict(os.environ, PYTHONPATH=str(RAIZ / "motor"), ROAR_AUDITORIA=auditoria)
    return subprocess.Popen([sys.executable, "-c", AUDITOR, cliente], env=ambiente,
                            stdout=subprocess.DEVNULL, stderr=open(auditoria + ".err", "a"))


def passo(pid, url, **extra):
    return {"id": pid, "integracao": "http", "versao": "1.4.0", "acao": "GET",
            "parametros": {"url": url}, **extra}


async def iniciar(conexao, cliente, passos, fila=None):
    return await conexao.start_workflow(
        "ExecutarPlaybook",
        {"cliente": cliente, "passos": passos},
        id=f"{cliente}-{uuid.uuid4().hex}",
        task_queue=fila or fila_do_cliente(cliente),
        execution_timeout=timedelta(seconds=180),
    )


async def rodando(handle):
    descricao = await handle.describe()
    return descricao.status.name == "RUNNING"


async def main():
    servidor = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Servidor)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{servidor.server_address[1]}"

    pasta = tempfile.mkdtemp(prefix="roar-")
    auditoria = os.path.join(pasta, "rede.log")
    conexao = await Client.connect("127.0.0.1:7233", namespace="roar")
    sufixo = uuid.uuid4().hex[:6]
    a, b = f"a{sufixo}", f"b{sufixo}"

    worker_a = iniciar_worker(a, auditoria)
    worker_b = None
    try:
        print("== Integração sem o Shuffle", flush=True)
        h = await iniciar(conexao, a, [passo("p1", f"{base}/ola")])
        r = await asyncio.wait_for(h.result(), 90)
        registrar("integração roda em worker nosso", "resposta-de/ola" in json.dumps(r), str(r)[:120])
        registrar("ação chegou ao destino uma vez", ACESSOS["/ola"] == 1)

        h = await iniciar(conexao, a, [{"id": "x", "integracao": "http", "versao": "1.4.0",
                                        "acao": "run", "parametros": {}}])
        try:
            await asyncio.wait_for(h.result(), 60)
            registrar("método do SDK não vira ação", False)
        except WorkflowFailureError:
            registrar("método do SDK não vira ação", True)

        h = await iniciar(conexao, a, [{"id": "x", "integracao": "../../etc", "versao": "1.4.0",
                                        "acao": "GET", "parametros": {}}])
        try:
            await asyncio.wait_for(h.result(), 60)
            registrar("caminho malicioso é recusado", False)
        except WorkflowFailureError:
            registrar("caminho malicioso é recusado", True)

        print("\n== Fila por cliente", flush=True)
        h_b = await iniciar(conexao, b, [passo("p1", f"{base}/de-b")])
        await asyncio.sleep(10)
        registrar("sem worker de B, nada de B roda", await rodando(h_b) and ACESSOS["/de-b"] == 0)

        h = await iniciar(conexao, b, [passo("p1", f"{base}/furou")], fila=fila_do_cliente(a))
        # O fluxo de B na fila de A despacha a ação para a fila de B, que está parada.
        await asyncio.sleep(8)
        registrar("worker de A não executa ação de B", ACESSOS["/furou"] == 0)
        await h.terminate("fim do teste")

        worker_b = iniciar_worker(b, auditoria)
        r = await asyncio.wait_for(h_b.result(), 90)
        registrar("com worker de B, o fluxo de B termina", "resposta-de/de-b" in json.dumps(r))

        print("\n== Sobrevive à morte do worker", flush=True)
        h = await iniciar(conexao, a, [
            passo("p1", f"{base}/primeiro"),
            passo("p2", f"{base}/lento", limite_s=8, tentativas=5),
        ])
        await asyncio.get_running_loop().run_in_executor(None, SEGURAR.wait, 60)
        worker_a.send_signal(signal.SIGKILL)
        worker_a.wait()
        registrar("worker morto no meio do passo 2", SEGURAR.is_set() and await rodando(h))
        worker_a = iniciar_worker(a, auditoria)
        r = await asyncio.wait_for(h.result(), 120)
        registrar("playbook termina com o worker novo", "resposta-de/lento" in json.dumps(r))
        registrar("passo 1 não repetiu", ACESSOS["/primeiro"] == 1, f"{ACESSOS['/primeiro']} acesso")
        registrar("passo 2 foi refeito", ACESSOS["/lento"] == 2, f"{ACESSOS['/lento']} acessos")
    finally:
        for w in (worker_a, worker_b):
            if w and w.poll() is None:
                w.kill()
                w.wait()
        servidor.shutdown()

    print("\n== Por onde os dados saem", flush=True)
    linhas = Path(auditoria).read_text().splitlines()
    nomes = sorted({l.split()[1] for l in linhas if l.startswith("nome ") and l.split()[1] != "None"})
    registrar("nenhum acesso à Shuffle", not [l for l in linhas if "shuffler" in l], f"nomes consultados: {nomes}")
    externos = [l for l in linhas if l.startswith("conexao") and "127.0.0.1" not in l and "AF_UNIX" not in l]
    registrar("nenhuma conexão externa", not externos, str(sorted(set(externos)))[:300])

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    if falhas:
        print(f"Erros do worker: {auditoria}.err")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
