#!/usr/bin/env python3
"""Automação de ponta a ponta, com banco, Temporal e workers reais. Requer infra/subir.sh.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_soar.py

O bloqueio num agente Wazuh real é provado em testar_bloqueio_real.py. Apaga no final tudo o que criou.
"""

import asyncio
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from temporalio.client import Client

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "motor")]

from roar_api.app import app  # noqa: E402
from roar_motor import blocos  # noqa: E402
from roar_motor.disparo import LIMITE_AUTOMATICO_POR_HORA, ciclo_do_cliente, url_do_banco  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
EXTERNO = {"campo": "alvo_externo", "op": "igual", "valor": True}
IP_PUBLICO = "1.1.1.1"
RECEBIDOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class Receptor(BaseHTTPRequestHandler):
    def do_POST(self):
        corpo = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        RECEBIDOS.append({"caminho": self.path, **corpo})
        self.send_response(204 if self.path != "/falha" else 400)
        self.end_headers()

    def log_message(self, *args):
        pass


class Cenario:
    def __init__(self, admin):
        self.admin, self.clientes = admin, []

    def cliente(self, nome):
        cliente = str(self.admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{SUFIXO}",)).fetchone()[0])
        gerenciador = f"{nome}{SUFIXO}"
        self.admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)",
                           (gerenciador, cliente, 40000 + secrets.randbelow(20000)))
        senha, email = secrets.token_urlsafe(18), f"{nome}-{SUFIXO}@exemplo.test"
        usuario = self.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash) VALUES (%s, %s, %s, %s) RETURNING id",
                                     (cliente, email, f"Analista {nome}", PasswordHasher().hash(senha))).fetchone()[0]
        c = {"id": cliente, "gerenciador": gerenciador, "usuario": usuario, "acesso": {"email": email, "senha": senha}}
        self.clientes.append(c)
        return c

    def evento(self, c, regra="5712", ip=IP_PUBLICO, nivel=10, quando=None):
        return self.admin.execute(
            """INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao,
                                    gerenciador_id, agente_id, ip_origem, bruto)
               VALUES (%s, 'teste', %s, %s, %s, 'alta', %s, 'Evento de teste', %s, '001', %s, '{"segredo": "bruto"}') RETURNING id""",
            (c["id"], uuid.uuid4().hex, quando or datetime.now(timezone.utc), nivel, regra, c["gerenciador"], ip)).fetchone()[0]

    def playbook(self, c, definicao, nome="teste", intervalo=0):
        return self.admin.execute(
            "INSERT INTO playbooks (cliente_id, nome, definicao, intervalo_minutos, criado_por) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (c["id"], nome, json.dumps(definicao), intervalo, c["usuario"])).fetchone()[0]

    def execucoes(self, playbook):
        return self.admin.execute("SELECT id, estado, alvo, resultado FROM execucoes WHERE playbook_id = %s ORDER BY id", (playbook,)).fetchall()

    def limpar(self):
        ids = [c["id"] for c in self.clientes]
        for tabela in ("aprovacoes", "execucoes", "playbooks", "soar_cursor", "sinais", "alertas_risco", "entidades", "eventos",
                       "auditoria", "sessoes"):
            coluna = "usuario_id = ANY(SELECT id FROM usuarios WHERE cliente_id = ANY(%s))" if tabela == "sessoes" else "cliente_id = ANY(%s)"
            self.admin.execute(f"DELETE FROM {tabela} WHERE {coluna}", (ids,))
        self.admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (ids,))
        self.admin.execute("DELETE FROM gerenciadores WHERE cliente_id = ANY(%s)", (ids,))
        self.admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", (ids,))


def iniciar_worker(cliente):
    ambiente = {**os.environ, "PYTHONPATH": str(RAIZ / "motor"), "ROAR_DESTINO_INTERNO": "1"}
    return subprocess.Popen([sys.executable, "-m", "roar_motor.worker", "--cliente", cliente], env=ambiente,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


async def ate(cen, playbook, estados, limite=40, quantos=1):
    fim = time.time() + limite
    while time.time() < fim:
        linhas = cen.execucoes(playbook)
        if len(linhas) >= quantos and all(l[1] in estados for l in linhas):
            return linhas
        await asyncio.sleep(0.5)
    return cen.execucoes(playbook)


def testar_formato():
    print("\n== Formato dos blocos", flush=True)

    def recusado(definicao):
        try:
            blocos.validar(definicao)
            return False
        except blocos.DefinicaoInvalida:
            return True

    quando = {"tipo": "evento", "regra_id": "5712"}
    bloquear = {"tipo": "acao", "acao": "bloquear_ip", "parametros": {}}
    registrar("bloquear sem condição de externo é recusado", recusado({"quando": quando, "blocos": [bloquear]}))
    registrar("bloquear no senão do externo é recusado", recusado({"quando": quando, "blocos": [
        {"tipo": "se", "condicao": EXTERNO, "entao": [], "senao": [bloquear]}]}))
    registrar("bloquear no então do externo é aceito", not recusado({"quando": quando, "blocos": [
        {"tipo": "se", "condicao": EXTERNO, "entao": [bloquear], "senao": []}]}))
    registrar("gatilho sem regra é recusado", recusado({"quando": {"tipo": "evento", "regra_id": ""}, "blocos": [{"tipo": "aprovacao"}]}))
    registrar("regra com injeção é recusada", recusado({"quando": {"tipo": "evento", "regra_id": "1 OR 1=1"}, "blocos": [{"tipo": "aprovacao"}]}))
    registrar("playbook sem bloco é recusado", recusado({"quando": quando, "blocos": []}))
    registrar("bloco desconhecido é recusado", recusado({"quando": quando, "blocos": [{"tipo": "shell", "comando": "id"}]}))
    registrar("campo a mais é recusado", recusado({"quando": quando, "blocos": [{"tipo": "aprovacao"}], "cliente_id": "outro"}))
    aninhado = {"tipo": "aprovacao"}
    for _ in range(6):
        aninhado = {"tipo": "se", "condicao": EXTERNO, "entao": [aninhado], "senao": []}
    registrar("aninhamento demais é recusado", recusado({"quando": quando, "blocos": [aninhado]}))
    registrar("blocos demais são recusados", recusado({"quando": quando, "blocos": [{"tipo": "aprovacao"}] * 31}))
    definicao = {"quando": quando, "se": [EXTERNO], "blocos": [{"tipo": "aprovacao"}]}
    fato = {"origem_tipo": "evento", "regra_id": "5712", "alvo": IP_PUBLICO}
    registrar("casa com endereço público", blocos.atende(definicao, fato))
    registrar("não casa com endereço interno", not blocos.atende(definicao, {**fato, "alvo": "10.0.0.1"}))
    registrar("não casa sem endereço", not blocos.atende(definicao, {**fato, "alvo": None}))
    registrar("não casa com lixo no lugar do endereço", not blocos.atende(definicao, {**fato, "alvo": "1.1.1.1; rm -rf /"}))
    registrar("multicast não conta como externo", not blocos.atende(definicao, {**fato, "alvo": "224.0.0.1"}))
    registrar("nível ausente não passa pela condição", not blocos.condicao_verdadeira({"campo": "nivel", "op": "minimo", "valor": 1}, {}))


async def testar_fluxo(cen, a, b, temporal, url, porta):
    url_soar = url_do_banco()
    base = f"http://127.0.0.1:{porta}"
    aviso = {"tipo": "acao", "acao": "webhook", "parametros": {"url": f"{base}/aviso"}}
    quando = {"tipo": "evento", "regra_id": "5712"}

    print("\n== Histórico e disparo", flush=True)
    antigo = cen.evento(a)
    cen.admin.execute("UPDATE eventos SET recebido_em = now() - interval '1 hour' WHERE id = %s", (antigo,))
    pb = cen.playbook(a, {"quando": quando, "se": [EXTERNO], "blocos": [{"tipo": "aprovacao"}, aviso]})
    await ciclo_do_cliente(url_soar, temporal, a["id"])
    registrar("alerta antigo não dispara", cen.execucoes(pb) == [])
    cen.evento(a, regra="1")
    cen.evento(a, ip="10.0.0.5")
    cen.evento(b)
    await ciclo_do_cliente(url_soar, temporal, a["id"])
    registrar("outra regra, endereço interno e evento de outro cliente não disparam", cen.execucoes(pb) == [])

    print("\n== Aprovação", flush=True)
    cen.evento(a)
    await ciclo_do_cliente(url_soar, temporal, a["id"])
    linhas = await ate(cen, pb, {"aguardando_aprovacao"})
    registrar("execução para e espera a decisão", linhas and linhas[0][1] == "aguardando_aprovacao", str(linhas)[:160])
    registrar("nada sai antes da aprovação", not RECEBIDOS)
    await ciclo_do_cliente(url_soar, temporal, a["id"])
    registrar("alerta não dispara duas vezes", len(cen.execucoes(pb)) == 1)
    aprovacao = cen.admin.execute("SELECT id, descricao FROM aprovacoes WHERE execucao_id = %s", (linhas[0][0],)).fetchone()
    registrar("pedido diz o que vai acontecer", aprovacao and aprovacao[1] == "webhook", str(aprovacao))

    with TestClient(app, base_url="https://testserver") as http:
        registrar("automação exige sessão", http.get("/api/automacao").status_code == 401)
        http.post("/api/entrar", json=b["acesso"])
        visto = http.get("/api/automacao").json()
        registrar("outro cliente não vê playbook nem aprovação", visto["playbooks"] == [] and visto["aprovacoes"] == [])
        registrar("outro cliente não decide", http.post(f"/api/automacao/aprovacoes/{aprovacao[0]}/aprovar", json={}).status_code == 409)
        registrar("outro cliente não edita", http.put(f"/api/automacao/playbooks/{pb}", json={"nome": "x", "definicao": {
            "quando": quando, "blocos": [{"tipo": "aprovacao"}]}}).status_code == 404)
        registrar("outro cliente não desativa", http.post(f"/api/automacao/playbooks/{pb}/desativar").status_code == 404)
        http.post("/api/sair")
        http.cookies.clear()

        http.post("/api/entrar", json=a["acesso"])
        registrar("pendente aparece na tela", any(x["id"] == aprovacao[0] and x["estado"] == "pendente" for x in http.get("/api/automacao").json()["aprovacoes"]))
        registrar("aprovar responde", http.post(f"/api/automacao/aprovacoes/{aprovacao[0]}/aprovar", json={"motivo": "conferi"}).status_code == 204)
        registrar("segundo clique é recusado", http.post(f"/api/automacao/aprovacoes/{aprovacao[0]}/recusar", json={}).status_code == 409)
        registrar("decisão fica na auditoria", cen.admin.execute(
            "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'aprovar_execucao' AND alvo = %s", (a["id"], str(aprovacao[0]))).fetchone()[0] == 1)
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        linhas = await ate(cen, pb, {"concluida", "falhou"})
        registrar("depois de aprovar, executa", linhas[0][1] == "concluida" and len(RECEBIDOS) == 1, str(linhas[0])[:300])
        registrar("alvo chega à ação", RECEBIDOS and RECEBIDOS[0]["alvo"] == IP_PUBLICO)
        registrar("o aviso não leva o bruto do alerta", RECEBIDOS and "segredo" not in json.dumps(RECEBIDOS[0]))
        registrar("tela mostra quem decidiu", any(x["decidida_por"] == "Analista a" for x in http.get("/api/automacao").json()["aprovacoes"]))

        print("\n== Recusa", flush=True)
        RECEBIDOS.clear()
        cen.evento(a)
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        linhas = await ate(cen, pb, {"aguardando_aprovacao", "concluida"}, quantos=2)
        nova = cen.admin.execute("SELECT id FROM aprovacoes WHERE execucao_id = %s", (linhas[-1][0],)).fetchone()
        http.post(f"/api/automacao/aprovacoes/{nova[0]}/recusar", json={"motivo": "é parceiro"})
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        linhas = await ate(cen, pb, {"recusada", "concluida"}, quantos=2)
        registrar("recusa encerra sem executar", linhas[-1][1] == "recusada" and not RECEBIDOS, str(linhas[-1])[:200])
        http.post(f"/api/automacao/playbooks/{pb}/desativar")
        cen.evento(a)
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        registrar("playbook desativado não dispara", len(cen.execucoes(pb)) == 2)

        print("\n== Se, senão e ao mesmo tempo", flush=True)
        ramos = {"tipo": "se", "condicao": EXTERNO,
                 "entao": [{"tipo": "acao", "acao": "webhook", "parametros": {"url": f"{base}/externo"}}],
                 "senao": [{"tipo": "acao", "acao": "webhook", "parametros": {"url": f"{base}/interno"}}]}
        pb_se = cen.playbook(a, {"quando": {"tipo": "evento", "regra_id": "6001"}, "blocos": [ramos]})
        RECEBIDOS.clear()
        cen.evento(a, regra="6001")
        cen.evento(a, regra="6001", ip="10.0.0.9")
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        linhas = await ate(cen, pb_se, {"concluida", "falhou"}, quantos=2)
        caminhos = sorted(r["caminho"] for r in RECEBIDOS)
        registrar("cada alvo segue o seu ramo", caminhos == ["/externo", "/interno"], str(caminhos))

        pb_par = cen.playbook(a, {"quando": {"tipo": "evento", "regra_id": "6002"}, "blocos": [
            {"tipo": "paralelo", "ramos": [[{"tipo": "acao", "acao": "webhook", "parametros": {"url": f"{base}/r1"}}],
                                           [{"tipo": "acao", "acao": "webhook", "parametros": {"url": f"{base}/r2"}}]]},
            {"tipo": "acao", "acao": "webhook", "parametros": {"url": f"{base}/depois"}}]})
        RECEBIDOS.clear()
        cen.evento(a, regra="6002")
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        linhas = await ate(cen, pb_par, {"concluida", "falhou"})
        caminhos = [r["caminho"] for r in RECEBIDOS]
        registrar("ramos paralelos rodam e o seguinte vem depois", linhas[0][1] == "concluida" and sorted(caminhos[:2]) == ["/r1", "/r2"] and caminhos[-1] == "/depois", str(caminhos))

        print("\n== Falhas", flush=True)
        protegido = {"tipo": "acao", "acao": "bloquear_ip", "parametros": {"protegidos": ["1.1.1.0/24"]}}
        pb_prot = cen.playbook(a, {"quando": {"tipo": "evento", "regra_id": "6003"}, "se": [EXTERNO], "blocos": [
            protegido, {"tipo": "acao", "acao": "webhook", "parametros": {"url": f"{base}/nao-deve"}}]})
        RECEBIDOS.clear()
        cen.evento(a, regra="6003")
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        linhas = await ate(cen, pb_prot, {"concluida", "falhou"})
        registrar("endereço protegido não é bloqueado e o motivo fica registrado",
                  linhas[0][1] == "falhou" and "protegidos" in json.dumps(linhas[0][3], ensure_ascii=False), str(linhas[0][3])[:200])
        registrar("falha interrompe os blocos seguintes", not RECEBIDOS)
        pb_ruim = cen.playbook(a, {"quando": {"tipo": "evento", "regra_id": "6004"}, "blocos": [
            {"tipo": "acao", "acao": "webhook", "parametros": {"url": f"{base}/falha"}}]})
        cen.evento(a, regra="6004")
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        linhas = await ate(cen, pb_ruim, {"concluida", "falhou"})
        registrar("aviso recusado pelo destino vira falha", linhas[0][1] == "falhou", str(linhas[0][3])[:160])

        print("\n== Limites", flush=True)
        pb_int = cen.playbook(a, {"quando": {"tipo": "evento", "regra_id": "6005"}, "blocos": [
            {"tipo": "acao", "acao": "registrar", "parametros": {"texto": "x"}}]}, intervalo=60)
        cen.evento(a, regra="6005")
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        cen.evento(a, regra="6005")
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        registrar("mesmo alvo não repete dentro do intervalo", len(cen.execucoes(pb_int)) == 1)
        cen.evento(a, regra="6005", ip="1.0.0.1")
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        registrar("outro alvo dispara dentro do intervalo", len(cen.execucoes(pb_int)) == 2)

        pb_rajada = cen.playbook(a, {"quando": {"tipo": "evento", "regra_id": "6006"}, "blocos": [
            {"tipo": "acao", "acao": "registrar", "parametros": {"texto": "x"}}]})
        total = LIMITE_AUTOMATICO_POR_HORA + 3
        for i in range(total):
            cen.evento(a, regra="6006", ip=f"1.0.1.{i + 1}")
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        linhas = await ate(cen, pb_rajada, {"concluida", "aguardando_aprovacao"}, limite=60, quantos=total)
        presas = sum(1 for l in linhas if l[1] == "aguardando_aprovacao")
        registrar("rajada de alvos volta a pedir aprovação", presas == 3, f"{presas} de {len(linhas)} aguardando")

        print("\n== Risco que sobe", flush=True)
        entidade = cen.admin.execute(
            "INSERT INTO entidades (cliente_id, tipo, chave, primeira_vista, ultima_vista) VALUES (%s, 'usuario', 'maria', now(), now()) RETURNING id", (a["id"],)).fetchone()[0]
        ev = cen.evento(a, regra="7777")
        cen.admin.execute("INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id) VALUES (%s, %s, 't', 'v', current_date, 50, now(), %s)",
                          (a["id"], entidade, ev))
        risco = cen.admin.execute("INSERT INTO alertas_risco (cliente_id, entidade_id, severidade, risco_maximo, aberto_em) VALUES (%s, %s, 'alta', 70, now()) RETURNING id",
                                  (a["id"], entidade)).fetchone()[0]
        pb_risco = cen.playbook(a, {"quando": {"tipo": "risco", "severidade": "critica"}, "blocos": [
            {"tipo": "acao", "acao": "registrar", "parametros": {"texto": "x"}}]})
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        registrar("risco alto não dispara playbook de crítico", cen.execucoes(pb_risco) == [])
        cen.admin.execute("UPDATE alertas_risco SET severidade = 'critica' WHERE id = %s", (risco,))
        await ciclo_do_cliente(url_soar, temporal, a["id"])
        linhas = await ate(cen, pb_risco, {"concluida", "falhou"})
        registrar("o mesmo alerta dispara ao subir para crítico", len(linhas) == 1 and linhas[0][2] == IP_PUBLICO, str(linhas)[:160])

        print("\n== Simular", flush=True)
        antes = cen.admin.execute("SELECT count(*) FROM execucoes WHERE cliente_id = %s", (a["id"],)).fetchone()[0]
        for i in range(4):
            cen.evento(a, regra="8001", quando=datetime.now(timezone.utc) - timedelta(hours=i + 1))
        cen.evento(a, regra="8001", ip="1.0.0.1", quando=datetime.now(timezone.utc) - timedelta(hours=1))
        cen.evento(a, regra="8001", ip="10.0.0.1", quando=datetime.now(timezone.utc) - timedelta(hours=1))
        cen.evento(a, regra="8001", quando=datetime.now(timezone.utc) - timedelta(days=30))
        definicao = {"quando": {"tipo": "evento", "regra_id": "8001"}, "se": [EXTERNO], "blocos": [
            {"tipo": "acao", "acao": "bloquear_ip", "parametros": {"protegidos": ["1.0.0.0/24"]}}]}
        s = http.post("/api/automacao/simular", json={"definicao": definicao, "intervalo_minutos": 0}).json()
        registrar("conta o que teria disparado na janela", s["disparos"] == 5, str({k: s[k] for k in ("disparos", "analisados", "recusas")}))
        registrar("mostra os alvos", {x["alvo"]: x["total"] for x in s["alvos"]} == {IP_PUBLICO: 4, "1.0.0.1": 1}, str(s["alvos"]))
        registrar("avisa o que seria recusado por proteção", s["recusas"] == 1)
        s = http.post("/api/automacao/simular", json={"definicao": definicao, "intervalo_minutos": 600}).json()
        registrar("simulação respeita o intervalo", s["disparos"] == 2, str(s["disparos"]))
        registrar("simular não cria execução", cen.admin.execute("SELECT count(*) FROM execucoes WHERE cliente_id = %s", (a["id"],)).fetchone()[0] == antes)
        http.post("/api/sair")
        http.cookies.clear()
        http.post("/api/entrar", json=b["acesso"])
        registrar("simulação não enxerga outro cliente", http.post("/api/automacao/simular", json={"definicao": definicao, "intervalo_minutos": 0}).json()["disparos"] == 0)
        http.post("/api/sair")
        http.cookies.clear()

        print("\n== Tela: criar, código e ataques", flush=True)
        http.post("/api/entrar", json=a["acesso"])
        corpo = {"nome": "Pela tela", "intervalo_minutos": 30, "definicao": {"quando": {"tipo": "evento", "regra_id": "5712"}, "se": [EXTERNO], "blocos": [
            {"tipo": "aprovacao"}, {"tipo": "acao", "acao": "bloquear_ip", "parametros": {"protegidos": ["8.8.8.8"]}}]}}
        r = http.post("/api/automacao/playbooks", json=corpo)
        registrar("cria pela API", r.status_code == 201, r.text[:200])
        novo = r.json().get("id")
        codigo = http.post("/api/automacao/para-codigo", json=corpo).json()["texto"]
        registrar("vira código legível", "bloquear_ip" in codigo and "Pela tela" in codigo, codigo.splitlines()[0])
        volta = http.post("/api/automacao/de-codigo", json={"texto": codigo}).json()
        registrar("código volta igual", volta["definicao"] == corpo["definicao"] and volta["nome"] == corpo["nome"] and volta["intervalo_minutos"] == 30)
        registrar("YAML com objeto do Python é recusado", http.post("/api/automacao/de-codigo", json={"texto": "!!python/object/apply:os.system ['id']"}).status_code == 422)
        registrar("YAML sem nome é recusado", http.post("/api/automacao/de-codigo", json={"texto": "quando: {tipo: risco, severidade: alta}"}).status_code == 422)
        registrar("YAML com bloco inválido é recusado", http.post("/api/automacao/de-codigo", json={"texto": "nome: x\nquando: {tipo: risco, severidade: alta}\nblocos: [{tipo: shell}]"}).status_code == 422)
        corpo2 = {**corpo, "nome": "Editado"}
        registrar("edita", http.put(f"/api/automacao/playbooks/{novo}", json=corpo2).status_code == 204)
        registrar("edição fica na auditoria", cen.admin.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'alterar_playbook'", (a["id"],)).fetchone()[0] == 1)
        for nome, destino in (("rede interna", "http://10.0.0.1/x"), ("próprio servidor", "http://127.0.0.1:5433/"),
                              ("metadados de nuvem", "http://169.254.169.254/latest/meta-data/"), ("IPv6 local", "http://[::1]/"),
                              ("com senha no endereço", "https://a:b@exemplo.com/"), ("outro protocolo", "file:///etc/passwd")):
            r = http.post("/api/automacao/playbooks", json={"nome": "x", "definicao": {"quando": {"tipo": "risco", "severidade": "alta"}, "blocos": [
                {"tipo": "acao", "acao": "webhook", "parametros": {"url": destino}}]}})
            registrar(f"webhook recusado: {nome}", r.status_code == 422, r.text[:100] if r.status_code != 422 else "")
        r = http.post("/api/automacao/playbooks", json={"nome": "x", "definicao": {"quando": {"tipo": "risco", "severidade": "alta"}, "blocos": [
            {"tipo": "acao", "acao": "bloquear_ip", "parametros": {}}]}})
        registrar("bloqueio sem condição é recusado com explicação", r.status_code == 422 and "externo" in r.json()["detail"])

    print("\n== Permissões no banco", flush=True)

    def negado(sql, *args):
        try:
            with psycopg.connect(url_soar) as con:
                con.execute("SELECT set_config('roar.cliente', %s, true)", (a["id"],))
                con.execute(sql, args)
            return False
        except psycopg.errors.InsufficientPrivilege:
            return True

    registrar("motor não lê o bruto do alerta", negado("SELECT bruto FROM eventos"))
    registrar("motor não lê usuários", negado("SELECT senha_hash FROM usuarios"))
    registrar("motor não altera playbook", negado("UPDATE playbooks SET nome = 'x'"))
    registrar("motor não decide por uma pessoa", negado("UPDATE aprovacoes SET decidida_por = %s", a["usuario"]))
    with psycopg.connect(url_soar) as con:
        registrar("sem cliente definido, motor não vê nada", con.execute("SELECT count(*) FROM playbooks").fetchone()[0] == 0)
    with psycopg.connect(url_soar) as con:
        con.execute("SELECT set_config('roar.cliente', %s, true)", (b["id"],))
        registrar("motor no cliente B não vê playbook de A", con.execute("SELECT count(*) FROM playbooks WHERE id = %s", (pb,)).fetchone()[0] == 0)
    url_api = f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar"
    with psycopg.connect(url_api) as con:
        con.execute("SELECT set_config('roar.cliente', %s, true)", (b["id"],))
        registrar("nome de usuário de outro cliente não sai", con.execute("SELECT roar_nome_do_usuario(%s)", (a["usuario"],)).fetchone()[0] is None)
    try:
        with psycopg.connect(url_api) as con:
            con.execute("SELECT set_config('roar.cliente', %s, true)", (a["id"],))
            con.execute("UPDATE execucoes SET estado = 'concluida'")
        registrar("API não altera execução", False)
    except psycopg.errors.InsufficientPrivilege:
        registrar("API não altera execução", True)

    print("\n== Fila errada", flush=True)
    registrar("worker recusa trabalho de outro cliente", await testar_fila_errada(cen, a, b, temporal, base))


async def testar_fila_errada(cen, a, b, temporal, base):
    from roar_motor.playbook import fila_do_cliente
    RECEBIDOS.clear()
    x = cen.admin.execute("SELECT id FROM execucoes WHERE cliente_id = %s LIMIT 1", (a["id"],)).fetchone()[0]
    pedido = {"cliente": b["id"], "execucao_id": x, "gerenciador_id": a["gerenciador"], "contexto": {"alvo": IP_PUBLICO},
              "blocos": [{"tipo": "acao", "acao": "webhook", "parametros": {"url": f"{base}/furou"}}]}
    # Pedido de B na fila de A: o worker de A precisa recusar antes de chamar qualquer coisa.
    h = await temporal.start_workflow("ExecutarResposta", pedido, id=f"fila-errada-{uuid.uuid4().hex}", task_queue=fila_do_cliente(a["id"]))
    try:
        await asyncio.wait_for(h.result(), timeout=25)
    except Exception:  # A conclusão também é recusada e o workflow termina em falha: basta nada ter saído.
        pass
    return not RECEBIDOS


async def principal():
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    cen = Cenario(admin)
    servidor = HTTPServer(("127.0.0.1", 0), Receptor)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    testar_formato()
    workers = []
    try:
        a, b = cen.cliente("a"), cen.cliente("b")
        workers = [iniciar_worker(a["id"]), iniciar_worker(b["id"])]
        temporal = await Client.connect("127.0.0.1:7233", namespace="roar")
        await testar_fluxo(cen, a, b, temporal, url_do_banco(), servidor.server_address[1])
    finally:
        for w in workers:
            w.terminate()
        servidor.shutdown()
        cen.limpar()
        admin.close()
    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(principal()))
