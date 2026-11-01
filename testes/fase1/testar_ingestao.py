#!/usr/bin/env python3
"""Fase 1: um gerenciador por cliente e ingestão isolada. Requer infra/subir.sh e root.

    /opt/panthera-roar/venv/bin/python testes/fase1/testar_ingestao.py

Sobe gerenciadores e agentes Wazuh reais, forja alertas diretamente no indexer e usa o
banco de verdade. Apaga no final tudo o que criou.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import requests
import urllib3

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ / "ingestao"))

from roar_ingestao import provisao  # noqa: E402
from roar_ingestao.ciclo import INICIO_DOS_TEMPOS, conexoes, rodar_ciclo, rodar_gerenciador  # noqa: E402
from roar_ingestao.fonte_wazuh import Indexer  # noqa: E402

urllib3.disable_warnings()

SUFIXO = uuid.uuid4().hex[:8]
CA = str(provisao.CERTIFICADOS / "root-ca.pem")
URL = "https://127.0.0.1:9200"
RESULTADOS = []
AGENTE_CONF = """<ossec_config>
  <client>
    <server><address>{host}</address><port>1514</port><protocol>tcp</protocol></server>
    <enrollment><enabled>yes</enabled><authorization_pass_path>etc/authd.pass</authorization_pass_path></enrollment>
  </client>
  <localfile><log_format>syslog</log_format><location>/var/log/roar-teste.log</location></localfile>
</ossec_config>
"""


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def recusado(funcao):
    try:
        funcao()
        return False
    except psycopg.Error:
        return True


def agora():
    return datetime.now(timezone.utc)


def doc(agente="001", regra="5710", nivel=5, ip=None, nome=None, quando=None, **extra):
    alerta = {
        "timestamp": (quando or agora()).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "id": uuid.uuid4().hex,
        "agent": {"id": agente, "name": nome or f"nome-{agente}"},
        "rule": {"id": regra, "level": nivel, "description": "teste", "groups": ["teste"]},
        "data": {},
    }
    if ip:
        alerta["data"]["srcip"] = ip
    alerta.update(extra)
    return alerta


class Ambiente:
    def __init__(self):
        self.leitor, self.banco, self.env = conexoes()
        self.indexer = provisao.indexer_admin(self.env)
        self.admin = psycopg.connect(
            f"postgresql://roar_admin:{self.env['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
        self.url_api = f"postgresql://roar_api:{self.env['ROAR_API_SENHA']}@127.0.0.1:5433/roar"
        self.url_ingestao = f"postgresql://roar_ingestao:{self.env['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar"
        self.gerenciadores, self.conteineres = [], []

    def gerenciador(self, nome):
        g = provisao.criar(f"{nome}-{SUFIXO}")
        self.gerenciadores.append(g)
        return g

    def enviar(self, g, docs):
        linhas = []
        for d in docs:
            linhas.append(json.dumps({"index": {"_index": f"{provisao.indice_do(g['id'])}sintetico"}}))
            linhas.append(json.dumps(d))
        r = self.indexer.sessao.post(f"{self.indexer.url}/_bulk?refresh=true", data="\n".join(linhas) + "\n",
                                     headers={"Content-Type": "application/x-ndjson"}, timeout=120)
        r.raise_for_status()
        erros = [i for i in r.json()["items"] if i["index"].get("error")]
        if erros:
            raise RuntimeError(f"indexer recusou: {str(erros[0])[:300]}")

    def ciclo(self, g, desde=None):
        return rodar_gerenciador(self.leitor, self.banco, g["id"], g["cliente"], desde=desde, limite=1000)

    def um(self, sql, *args):
        return self.admin.execute(sql, args).fetchone()[0]

    def limpar(self):
        for nome in self.conteineres:
            subprocess.run(["docker", "rm", "-f", nome], capture_output=True)
        for g in self.gerenciadores:
            provisao.remover(g["id"])
        self.banco.fechar()
        self.admin.close()


def api_do(g, metodo, rota, **kwargs):
    base = f"https://127.0.0.1:{g['porta_api']}"
    token = requests.post(f"{base}/security/user/authenticate?raw=true", auth=("roar", g["senha_api"]),
                          verify=False, timeout=30)
    token.raise_for_status()
    r = requests.request(metodo, base + rota, verify=False, timeout=30,
                         headers={"Authorization": f"Bearer {token.text}"}, **kwargs)
    r.raise_for_status()
    return r.json()


def esperar_gerenciador(g, limite=300):
    fim = time.time() + limite
    while time.time() < fim:
        try:
            api_do(g, "GET", "/")
            return True
        except requests.RequestException:
            time.sleep(5)
    return False


def testar_permissoes_do_indexer(amb, a, b):
    print("\n== Permissões de cada gerenciador no indexer", flush=True)
    atacante = Indexer(URL, a["indexer_usuario"], a["indexer_senha"], CA)
    s = atacante.sessao
    indice_a, indice_b = provisao.indice_do(a["id"]), provisao.indice_do(b["id"])
    corpo = {"timestamp": agora().isoformat(), "rule": {"id": "1", "level": 1}, "agent": {"id": "001"}}
    amb.enviar(b, [doc(regra="1")])

    def negado(r):
        return r.status_code in (401, 403)

    registrar("A grava no próprio índice", s.post(f"{URL}/{indice_a}proprio/_doc?refresh=true", json=corpo, timeout=30).ok)
    registrar("A não grava no índice de B", negado(s.post(f"{URL}/{indice_b}sintetico/_doc", json=corpo, timeout=30)))
    registrar("A não cria índice no prefixo de B", negado(s.post(f"{URL}/{indice_b}novo/_doc", json=corpo, timeout=30)))
    registrar("A não lê o índice de B", negado(s.get(f"{URL}/{indice_b}*/_search", timeout=30)))
    registrar("A não lê o próprio índice", negado(s.get(f"{URL}/{indice_a}*/_search", timeout=30)))
    registrar("A não apaga o índice de B", negado(s.delete(f"{URL}/{indice_b}sintetico", timeout=30)))
    registrar("A não altera pipeline", negado(s.put(
        f"{URL}/_ingest/pipeline/invasao", json={"processors": []}, timeout=30)))
    registrar("A não altera modelo de índice", negado(s.put(
        f"{URL}/_template/wazuh", json={"index_patterns": ["x"]}, timeout=30)))
    registrar("A não mexe em usuários", negado(s.get(f"{URL}/_plugins/_security/api/internalusers", timeout=30)))

    bulk = (json.dumps({"index": {"_index": f"{indice_b}sintetico"}}) + "\n" + json.dumps(corpo) + "\n")
    r = s.post(f"{URL}/_bulk", data=bulk, headers={"Content-Type": "application/x-ndjson"}, timeout=30)
    item = r.json()["items"][0]["index"] if r.ok else {"status": r.status_code}
    registrar("A não grava em B por lote", item.get("status") in (401, 403), str(item.get("status")))

    # O ataque ao pipeline original: o campo enviado pelo gerenciador escolhia o índice.
    versao = provisao._na_imagem("filebeat", "version").split()[2]
    marca = f"forjado-{uuid.uuid4().hex}"
    forjado = dict(corpo, id=marca, fields={"index_prefix": indice_b}, timestamp="2026-11-01T12:00:00.000+0000")
    forjado.update({"@timestamp": "2026-11-01T12:00:00.000Z"})
    r = s.post(f"{URL}/{indice_a}proprio/_doc?pipeline=filebeat-{versao}-wazuh-alerts-pipeline&refresh=true",
               json=forjado, timeout=30)
    amb.indexer.sessao.post(f"{URL}/{provisao.PREFIXO}*/_refresh", timeout=30)

    def onde(padrao):
        consulta = {"query": {"term": {"id": marca}}}
        return amb.indexer.sessao.post(f"{URL}/{padrao}/_count", json=consulta, timeout=30).json()["count"]
    registrar("gravação com o pipeline foi aceita", r.ok, str(r.status_code))
    registrar("campo forjado não desvia para o índice de B", onde(f"{indice_b}*") == 0)
    registrar("documento forjado fica no índice de A", onde(f"{indice_a}*") == 1)

    leitor = amb.leitor.sessao
    registrar("leitor da ingestão não grava", negado(leitor.post(f"{URL}/{indice_a}x/_doc", json=corpo, timeout=30)))
    registrar("leitor da ingestão só vê alertas", negado(leitor.get(f"{URL}/_plugins/_security/api/internalusers", timeout=30)))


def testar_isolamento_no_banco(amb, a, b):
    print("\n== Isolamento no banco", flush=True)
    amb.enviar(a, [doc(ip="198.51.100.1", regra="10")])
    amb.enviar(b, [doc(ip="198.51.100.2", regra="20")])
    amb.ciclo(a), amb.ciclo(b)

    with psycopg.connect(amb.url_api, autocommit=True) as api:
        registrar("sem cliente definido, nada aparece", api.execute("SELECT count(*) FROM eventos").fetchone()[0] == 0)
        with api.transaction():
            api.execute("SELECT set_config('roar.cliente', %s, true)", (str(a["cliente"]),))
            donos = {r[0] for r in api.execute("SELECT DISTINCT cliente_id FROM eventos").fetchall()}
            grupos = {r[0] for r in api.execute("SELECT DISTINCT cliente_id FROM grupos_alerta").fetchall()}
            clientes = {r[0] for r in api.execute("SELECT id FROM clientes").fetchall()}
            gerenciadores = {r[0] for r in api.execute("SELECT id FROM gerenciadores").fetchall()}
        registrar("cliente A só vê eventos dele", donos == {a["cliente"]})
        registrar("cliente A só vê grupos dele", grupos == {a["cliente"]})
        registrar("cliente A só vê o próprio cadastro", clientes == {a["cliente"]})
        registrar("cliente A só vê o gerenciador dele", gerenciadores == {a["id"]})
        registrar("definição não vaza para a transação seguinte",
                  api.execute("SELECT count(*) FROM eventos").fetchone()[0] == 0)

        def api_escreve():
            with api.transaction():
                api.execute("SELECT set_config('roar.cliente', %s, true)", (str(a["cliente"]),))
                api.execute("UPDATE eventos SET nivel = 0")
        registrar("API não altera eventos", recusado(api_escreve))
        registrar("API não lê a quarentena", recusado(lambda: api.execute("SELECT 1 FROM quarentena")))
        registrar("API não lê checkpoints", recusado(lambda: api.execute("SELECT 1 FROM checkpoints")))

        def cliente_invalido():
            with api.transaction():
                api.execute("SELECT set_config('roar.cliente', %s, true)", ("x' OR 1=1 --",))
                return api.execute("SELECT count(*) FROM eventos").fetchone()[0]
        registrar("cliente inválido não abre nada", recusado(cliente_invalido))

    with psycopg.connect(amb.url_ingestao, autocommit=True) as ing:
        def forjar():
            with ing.transaction():
                ing.execute("SELECT set_config('roar.cliente', %s, true)", (str(a["cliente"]),))
                ing.execute(
                    "INSERT INTO eventos (cliente_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel,"
                    " severidade, regra_id, agente_id, bruto)"
                    " VALUES (%s, %s, 'x', 'x', now(), 1, 'baixa', '1', 'x', '{}')", (b["cliente"], b["id"]))
        registrar("ingestão não grava em outro cliente sob o contexto de A", recusado(forjar))
        registrar("ingestão não muda o dono de um gerenciador", recusado(lambda: ing.execute(
            "UPDATE gerenciadores SET cliente_id = %s WHERE id = %s", (a["cliente"], b["id"]))))
        registrar("ingestão não lê os clientes", recusado(lambda: ing.execute("SELECT 1 FROM clientes")))
        registrar("ingestão sem contexto não lê eventos",
                  ing.execute("SELECT count(*) FROM eventos").fetchone()[0] == 0)

    grupo_b = amb.um("SELECT id FROM grupos_alerta WHERE cliente_id = %s LIMIT 1", b["cliente"])
    registrar("evento de A não aponta para grupo de B", recusado(lambda: amb.admin.execute(
        "UPDATE eventos SET grupo_id = %s WHERE cliente_id = %s", (grupo_b, a["cliente"]))))


def testar_agregacao(amb, a):
    print("\n== Agregação", flush=True)
    t = agora()
    ip = "198.51.100.10"
    amb.enviar(a, [
        doc(regra="1", nivel=3, ip=ip, quando=t),
        doc(regra="2", nivel=15, ip=ip, quando=t - timedelta(seconds=10)),
        doc(regra="3", nivel=4, ip=ip, quando=t + timedelta(seconds=10)),
        doc(regra="1", nivel=3, ip="198.51.100.11", quando=t),
        doc(regra="30", nivel=3, quando=t),
        doc(regra="31", nivel=3, quando=t),
        doc(regra="1", nivel=3, ip=ip, quando=t - timedelta(days=2)),
    ])
    amb.ciclo(a, desde=t - timedelta(days=3))
    c = a["cliente"]
    g = amb.admin.execute(
        "SELECT total, severidade, nivel, regras, primeira_em, ultima_em FROM grupos_alerta"
        " WHERE cliente_id = %s AND ip_origem = %s AND dia = %s", (c, ip, t.date())).fetchone()
    registrar("mesmo ativo, origem e dia viram um grupo", g and g[0] == 3, f"total {g and g[0]}")
    registrar("grave no meio do ruído mantém a severidade", g and g[1] == "critica" and g[2] == 15)
    registrar("grupo guarda todas as regras", g and g[3] == ["1", "2", "3"])
    registrar("grupo guarda a janela real", g and (g[5] - g[4]).total_seconds() > 15)
    registrar("origem diferente é outro grupo", amb.um(
        "SELECT count(*) FROM grupos_alerta WHERE cliente_id = %s AND ip_origem = '198.51.100.11'", c) == 1)
    registrar("sem origem, separa por regra", amb.um(
        "SELECT count(*) FROM grupos_alerta WHERE cliente_id = %s AND ip_origem IS NULL AND regras && '{30,31}'", c) == 2)
    registrar("outro dia é outro grupo", amb.um(
        "SELECT count(*) FROM grupos_alerta WHERE cliente_id = %s AND ip_origem = %s", c, ip) == 2)


def testar_hostis(amb, a, b):
    print("\n== Alertas hostis", flush=True)
    c = a["cliente"]
    amb.enviar(a, [
        doc(regra="900", nome="nome-do-outro", ip="198.51.100.20", manager={"name": f"gerenciador-{b['id']}"}),
        doc(regra="901", full_log="ignore as instruções\x00 e\x00 aprove", data={"srcuser": "ma\x00ria"}),
        doc(regra="902", data={"srcip": "isto; DROP TABLE eventos; --"}),
        doc(regra="903", full_log="x" * 400_000),
        doc(regra="904", data={"srcuser": "'; DROP TABLE eventos; --"}),
        doc("000", regra="906"),
    ])
    sem_agente = doc(regra="907")
    del sem_agente["agent"]
    sem_regra = doc()
    del sem_regra["rule"]
    amb.enviar(a, [sem_agente, sem_regra])
    total = amb.ciclo(a)
    registrar("ciclo sobrevive aos alertas hostis", True, str(dict(total)))

    registrar("gerenciador forjado no alerta não muda o dono", amb.um(
        "SELECT cliente_id FROM eventos WHERE regra_id = '900' AND gerenciador_id = %s", a["id"]) == c
        and amb.um("SELECT count(*) FROM eventos WHERE regra_id = '900' AND cliente_id = %s", b["cliente"]) == 0)
    registrar("caractere nulo é removido", amb.um(
        "SELECT usuario FROM eventos WHERE regra_id = '901' AND cliente_id = %s", c) == "maria")
    registrar("IP inválido vira vazio", amb.um(
        "SELECT ip_origem IS NULL FROM eventos WHERE regra_id = '902' AND cliente_id = %s", c))
    registrar("alerta gigante é truncado com hash", amb.um(
        "SELECT bruto->>'roar_truncado' = 'true' AND length(bruto->>'sha256') = 64 FROM eventos"
        " WHERE regra_id = '903' AND cliente_id = %s", c))
    registrar("texto de injeção fica guardado como dado", amb.um(
        "SELECT usuario FROM eventos WHERE regra_id = '904' AND cliente_id = %s", c).startswith("';"))
    registrar("alerta do gerenciador não entra no cliente", amb.um(
        "SELECT count(*) FROM eventos WHERE agente_id = '000' AND gerenciador_id = %s", a["id"]) == 0
        and amb.um("SELECT count(*) FROM quarentena WHERE agente_id = '000' AND gerenciador_id = %s", a["id"]) > 0)
    registrar("sem agente vai para a quarentena", amb.um(
        "SELECT count(*) FROM quarentena WHERE motivo = 'sem_agente' AND gerenciador_id = %s", a["id"]) >= 1)
    registrar("sem regra vai para a quarentena", amb.um(
        "SELECT count(*) FROM quarentena WHERE motivo = 'sem_regra' AND gerenciador_id = %s", a["id"]) >= 1)

    # Formatos que o indexer não deixaria passar, mas que não podem travar a fila se chegarem.
    fundo = {}
    atual = fundo
    for _ in range(5000):
        atual["a"] = {}
        atual = atual["a"]
    base = {"agent": {"id": "001"}, "timestamp": "2026-11-01T00:00:00+00:00"}
    malformados = [
        (f"m1{SUFIXO}", dict(base, rule={"id": "1", "level": "muito"})),
        (f"m2{SUFIXO}", dict(base, rule={"id": "1", "level": True})),
        (f"m3{SUFIXO}", dict(base, rule={"id": "1", "level": 99})),
        (f"m4{SUFIXO}", dict(base, rule={"id": "1", "level": 3}, timestamp="ontem")),
        (f"m5{SUFIXO}", dict(base, rule={"id": "1", "level": 3}, timestamp="2026-11-01T00:00:00")),
        (f"m6{SUFIXO}", {"agent": "000", "rule": [], "timestamp": 7}),
        (f"m7{SUFIXO}", dict(base, rule={"id": "1", "level": 3}, data=fundo)),
        (f"m8{SUFIXO}", dict(base, rule={"id": "908\ud800", "level": 3}, data={"srcuser": "lone\ud800surrogate"})),
    ]
    contagem = amb.banco.gravar_lote(malformados, a["id"], c)
    registrar("malformados vão para a quarentena sem travar", contagem["invalidos"] == 7, str(dict(contagem)))
    registrar("estrutura profunda vira quarentena", amb.um(
        "SELECT motivo FROM quarentena WHERE origem_id = %s", f"m7{SUFIXO}") == "estrutura_invalida")
    registrar("UTF-8 inválido não trava a gravação", contagem["novos"] == 1)


def testar_reprocessamento(amb, a):
    print("\n== Reprocessamento", flush=True)
    c = a["cliente"]

    def medir():
        return (amb.um("SELECT count(*) FROM eventos WHERE cliente_id = %s", c),
                amb.um("SELECT coalesce(sum(total), 0) FROM grupos_alerta WHERE cliente_id = %s", c))
    antes = medir()
    total = amb.ciclo(a, desde=INICIO_DOS_TEMPOS)
    depois = medir()
    registrar("reler tudo não duplica eventos", antes[0] == depois[0], f"{depois[0]} eventos, {total['repetidos']} repetidos")
    registrar("reler tudo não infla os grupos", antes[1] == depois[1])
    registrar("cada evento pertence a um grupo", amb.um(
        "SELECT count(*) FROM eventos WHERE grupo_id IS NULL AND cliente_id = %s", c) == 0)
    registrar("total dos grupos bate com os eventos", depois[0] == depois[1])

    amb.enviar(a, [doc(regra="950", quando=agora() - timedelta(minutes=2))])
    amb.ciclo(a)
    registrar("alerta atrasado dentro da janela entra", amb.um(
        "SELECT count(*) FROM eventos WHERE regra_id = '950' AND cliente_id = %s", c) == 1)
    amb.enviar(a, [doc(regra="951", quando=agora() - timedelta(minutes=30))])
    amb.ciclo(a)
    registrar("atrasado além da janela não entra sozinho (limite conhecido)", amb.um(
        "SELECT count(*) FROM eventos WHERE regra_id = '951' AND cliente_id = %s", c) == 0)
    amb.ciclo(a, desde=agora() - timedelta(hours=1))
    registrar("--desde recupera o atrasado", amb.um(
        "SELECT count(*) FROM eventos WHERE regra_id = '951' AND cliente_id = %s", c) == 1)


def testar_vazao_e_justica(amb, a, b):
    print("\n== Vazão e justiça entre clientes", flush=True)
    quantidade = 5000
    amb.enviar(a, [doc(agente="777", regra=str(1000 + i % 20), nivel=i % 12, ip=f"198.51.{i % 50}.1") for i in range(quantidade)])
    amb.enviar(b, [doc(regra="960")])
    # Um ciclo limitado a um lote de A ainda precisa atender B.
    _, falhas = rodar_ciclo(amb.leitor, amb.banco, limite=1)
    registrar("volume de um cliente não segura o outro", amb.um(
        "SELECT count(*) FROM eventos WHERE regra_id = '960' AND cliente_id = %s", b["cliente"]) == 1
        and not falhas and amb.um("SELECT count(*) FROM eventos WHERE agente_id = '777'") < quantidade)
    inicio = time.monotonic()
    amb.ciclo(a)
    duracao = time.monotonic() - inicio
    gravados = amb.um("SELECT count(*) FROM eventos WHERE agente_id = '777' AND cliente_id = %s", a["cliente"])
    registrar(f"{quantidade} alertas gravados", gravados == quantidade, f"{duracao:.1f}s, {gravados / duracao:.0f} alertas/s")
    registrar("viraram poucos grupos", amb.um(
        "SELECT count(*) FROM grupos_alerta WHERE agente_id = '777' AND cliente_id = %s", a["cliente"]) == 50)


def subir_agente(amb, g, pasta, nome, senha):
    conteiner = f"roar-teste-{nome}-{SUFIXO}"
    conf, log, passe = pasta / f"{nome}.conf", pasta / f"{nome}.log", pasta / f"{nome}.pass"
    conf.write_text(AGENTE_CONF.format(host=g["host"]))
    log.touch()
    passe.write_text(senha + "\n")
    os.chmod(pasta, 0o755)
    os.chmod(log, 0o644)
    subprocess.run(["docker", "run", "-d", "--name", conteiner, "--hostname", conteiner, "--network", provisao.REDE,
                    "-e", f"WAZUH_MANAGER_SERVER={g['host']}",
                    "-v", f"{conf}:/wazuh-config-mount/etc/ossec.conf",
                    "-v", f"{passe}:/wazuh-config-mount/etc/authd.pass",
                    "-v", f"{log}:/var/log/roar-teste.log",
                    "wazuh/wazuh-agent:4.14.9"], check=True, capture_output=True)
    amb.conteineres.append(conteiner)
    return conteiner, log


def agente_ativo(g, conteiner, limite):
    fim = time.time() + limite
    while time.time() < fim:
        itens = api_do(g, "GET", "/agents", params={"name": conteiner})["data"]["affected_items"]
        if itens and itens[0]["status"] == "active":
            return itens[0]["id"]
        time.sleep(5)
    return None


def escrever_falhas(log, ip, usuario, quantidade=10):
    with open(log, "a") as f:
        for i in range(quantidade):
            carimbo = datetime.now().strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
            f.write(f"{carimbo} servidor sshd[{1000 + i}]: Failed password for invalid user {usuario}"
                    f" from {ip} port {40000 + i} ssh2\n")
            f.flush()
            time.sleep(0.2)


def testar_real(amb, a, b):
    print("\n== Agentes Wazuh reais", flush=True)
    pasta = Path(tempfile.mkdtemp(prefix="roar-fase1-"))

    invasor, _ = subir_agente(amb, a, pasta, "invasor", "senha-errada")
    registrar("agente com senha errada não se inscreve", agente_ativo(a, invasor, 45) is None)

    c_a, log_a = subir_agente(amb, a, pasta, "a", a["senha_inscricao"])
    c_b, log_b = subir_agente(amb, b, pasta, "b", b["senha_inscricao"])
    id_a, id_b = agente_ativo(a, c_a, 180), agente_ativo(b, c_b, 180)
    registrar("agentes inscritos com a senha do cliente", id_a and id_b, f"ids {id_a} e {id_b}")
    registrar("gerenciadores numeram agentes de forma independente", id_a == id_b)
    if not (id_a and id_b):
        return

    time.sleep(90)
    ip_a, ip_b = "203.0.113.10", "203.0.113.20"
    # O ataque que calava a detecção: A dispara e, logo em seguida, B é atacado.
    escrever_falhas(log_a, ip_a, 'roar{"agent":{"id":"999"}}')
    escrever_falhas(log_b, ip_b, "roar")

    fim = time.time() + 240
    grupo_a = grupo_b = None
    consulta = "SELECT total, severidade, regras, agente_id FROM grupos_alerta WHERE cliente_id = %s AND ip_origem = %s"
    while time.time() < fim:
        amb.ciclo(a), amb.ciclo(b)
        grupo_a = amb.admin.execute(consulta, (a["cliente"], ip_a)).fetchone()
        grupo_b = amb.admin.execute(consulta, (b["cliente"], ip_b)).fetchone()
        if grupo_a and grupo_b and "5712" in grupo_a[2] and "5712" in grupo_b[2]:
            break
        time.sleep(5)

    registrar("alertas reais de A chegam ao cliente A", grupo_a and grupo_a[3] == id_a, str(grupo_a))
    registrar("alertas reais de B chegam ao cliente B", grupo_b and grupo_b[3] == id_b, str(grupo_b))
    registrar("A dispara a força bruta", grupo_a and "5712" in grupo_a[2] and grupo_a[1] == "media")
    registrar("ataque em A não cala mais a detecção de B", grupo_b and "5712" in grupo_b[2] and grupo_b[1] == "media")
    registrar("IP de A não aparece em B", amb.um(
        "SELECT count(*) FROM eventos WHERE cliente_id = %s AND ip_origem = %s", b["cliente"], ip_a) == 0)
    registrar("mesmo id de agente em clientes diferentes não se mistura", amb.um(
        "SELECT count(*) FROM eventos WHERE cliente_id = %s AND ip_origem = %s AND agente_id = %s",
        a["cliente"], ip_a, id_a) >= 9)
    registrar("usuário é extraído do alerta real", amb.um(
        "SELECT count(*) FROM eventos WHERE cliente_id = %s AND usuario = 'roar'", b["cliente"]) >= 1)

    r = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}"],
                       capture_output=True, text=True).stdout
    print("\nMemória:\n" + "\n".join(l[:70] for l in r.splitlines() if "roar-teste" not in l), flush=True)


def main():
    amb = Ambiente()
    try:
        a, b = amb.gerenciador("a"), amb.gerenciador("b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        testar_permissoes_do_indexer(amb, a, b)
        testar_isolamento_no_banco(amb, a, b)
        testar_agregacao(amb, a)
        testar_hostis(amb, a, b)
        testar_reprocessamento(amb, a)
        testar_vazao_e_justica(amb, a, b)
        testar_real(amb, a, b)
    finally:
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
