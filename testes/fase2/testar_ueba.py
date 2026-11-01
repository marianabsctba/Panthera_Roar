#!/usr/bin/env python3
"""Fase 2: UEBA. Requer infra/subir.sh já executado e root.

    /opt/panthera-roar/venv/bin/python testes/fase2/testar_ueba.py [--sem-real]

Cenários com eventos gravados no banco, uma simulação de 30 dias com ataques conhecidos
e um cenário com agente Wazuh real. Apaga no final tudo o que criou.
"""

import random
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "ueba"), str(RAIZ / "testes/fase1")]

from roar_ueba.identidade import chave_do_usuario  # noqa: E402
from roar_ueba.motor import Motor, Parametros  # noqa: E402

ENV = {}
for linha in Path("/opt/panthera-roar/.env").read_text().splitlines():
    if "=" in linha and not linha.startswith("#"):
        k, v = linha.split("=", 1)
        ENV[k] = v
URL_UEBA = f"postgresql://roar_ueba:{ENV['ROAR_UEBA_SENHA']}@127.0.0.1:5433/roar"
URL_API = f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar"
ADMIN = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
FUSO = ZoneInfo("America/Sao_Paulo")
SUCESSO, FALHA, SUDO = ["authentication_success"], ["authentication_failed"], ["sudo"]
RESULTADOS = []
CRIADOS = []
PORTA = [40000 + random.randint(0, 20000)]


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def um(sql, *args):
    return ADMIN.execute(sql, args).fetchone()[0]


class Cliente:
    """Cliente e gerenciador só no banco. Cada um tem um motor sem interferir nos outros."""

    def __init__(self, nome="c", **parametros):
        sufixo = uuid.uuid4().hex[:10]
        self.id = ADMIN.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{sufixo}",)).fetchone()[0]
        self.ger = f"t{sufixo}"
        PORTA[0] += 3
        ADMIN.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)",
                      (self.ger, self.id, PORTA[0]))
        parametros.setdefault("atraso_segundos", 0)
        self.motor = Motor(URL_UEBA, Parametros(**parametros))
        CRIADOS.append(self)
        self.seq = 0
        self.linhas = []

    def ev(self, quando, usuario, grupos=SUCESSO, host="h1", ip="10.0.0.1", bruto=None, nivel=3):
        self.seq += 1
        self.linhas.append((self.id, self.ger, "wazuh", f"e{self.seq}", quando, nivel, "baixa", "5715", grupos, host,
                            f"nome-{host}", ip, usuario, Jsonb(bruto or {})))

    def gravar(self):
        with ADMIN.cursor() as c:
            c.executemany(
                "INSERT INTO eventos (cliente_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel, severidade,"
                " regra_id, regra_grupos, agente_id, agente_nome, ip_origem, usuario, bruto)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", self.linhas)
        self.linhas = []

    def processar(self):
        self.gravar()
        total = 0
        while True:
            n = self.motor.processar_cliente(self.id, "America/Sao_Paulo")
            total += n
            if n < self.motor.p.lote:
                return total

    def sinais(self, usuario, tipo=None):
        sql = ("SELECT s.tipo FROM sinais s JOIN entidades e ON e.id = s.entidade_id"
               " WHERE s.cliente_id = %s AND e.chave = %s")
        args = [self.id, usuario]
        if tipo:
            sql += " AND s.tipo = %s"
            args.append(tipo)
        return [r[0] for r in ADMIN.execute(sql, args).fetchall()]

    def alertas(self, usuario):
        return ADMIN.execute(
            "SELECT a.severidade, a.estado, a.risco_maximo FROM alertas_risco a JOIN entidades e ON e.id = a.entidade_id"
            " WHERE a.cliente_id = %s AND e.chave = %s", (self.id, usuario)).fetchall()

    def risco(self, usuario):
        return ADMIN.execute("SELECT risco FROM entidades WHERE cliente_id = %s AND chave = %s",
                             (self.id, usuario)).fetchone()[0]

    def rotina(self, usuario, inicio, dias=20, host="h1", ip="10.0.0.1", hora=9):
        """Duas entradas por dia útil, em horário comercial local."""
        for d in range(dias):
            dia = inicio + timedelta(days=d)
            for h in (hora, hora + 5):
                self.ev(dia.astimezone(FUSO).replace(hour=h, minute=5).astimezone(timezone.utc), usuario, host=host, ip=ip)


def base(dias_atras=30):
    return datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=dias_atras)


def local(dia, hora, minuto=0):
    return dia.astimezone(FUSO).replace(hour=hora, minute=minuto, second=0).astimezone(timezone.utc)


def testar_identidade():
    print("\n== Identidade", flush=True)
    registrar("variações viram a mesma chave", {chave_do_usuario(n) for n in
              ("Maria", "MARIA ", "EMPRESA\\maria", "maria@empresa.com")} == {"maria"})
    registrar("contas de sistema não viram pessoa", all(chave_do_usuario(n) is None for n in
              ("SYSTEM", "-", "ANONYMOUS LOGON", "SERVIDOR01$", "", None, 7)))
    registrar("nome com espaço ou controle é recusado", all(chave_do_usuario(n) is None for n in
              ("a b", "a\nb", "a\x07b", "x" * 200)))


def testar_sinais():
    print("\n== Sinais", flush=True)
    t = base()
    c = Cliente()
    c.rotina("maria", t)
    c.processar()
    registrar("rotina normal não gera sinal nenhum", c.sinais("maria") == [], str(c.sinais("maria")))
    fim = t + timedelta(days=20)

    c.ev(local(fim, 10), "EMPRESA\\Maria", host="h9")
    c.processar()
    registrar("host novo gera sinal", c.sinais("maria", "primeiro_host") == ["primeiro_host"])
    registrar("variação do nome cai na mesma entidade", um(
        "SELECT count(*) FROM entidades WHERE cliente_id = %s AND tipo = 'usuario'", c.id) == 1)

    c.ev(local(fim, 11), "maria", ip="10.9.9.9")
    c.processar()
    registrar("IP novo gera sinal", c.sinais("maria", "primeiro_ip") == ["primeiro_ip"])

    c.ev(local(fim + timedelta(days=1), 3), "maria")
    c.processar()
    registrar("madrugada gera sinal de horário", c.sinais("maria", "horario_incomum") == ["horario_incomum"])

    c.ev(local(fim + timedelta(days=1), 8, 30), "maria")
    c.processar()
    registrar("hora vizinha da rotina não é incomum", len(c.sinais("maria", "horario_incomum")) == 1)

    c2 = Cliente()
    c2.rotina("joao", t)
    c2.processar()
    c2.ev(local(fim, 10), "joao", grupos=SUDO, host="h1", bruto={"data": {"dstuser": "root"}})
    c2.processar()
    registrar("primeiro sudo gera sinal", c2.sinais("joao", "primeiro_privilegio") == ["primeiro_privilegio"])
    c2.ev(local(fim, 11), "joao", grupos=SUDO, host="h1", bruto={"data": {"dstuser": "root"}})
    c2.processar()
    registrar("sudo repetido não conta de novo", len(c2.sinais("joao", "primeiro_privilegio")) == 1)

    c3 = Cliente()
    c3.rotina("ana", t)
    c3.processar()
    for i in range(6):
        c3.ev(local(fim, 10, i), f"tentativa{i}", grupos=FALHA, ip="203.0.113.7")
    c3.ev(local(fim, 10, 7), "ana", ip="203.0.113.7")
    c3.processar()
    registrar("sucesso depois de falhas do mesmo IP gera sinal", "sucesso_apos_falhas" in c3.sinais("ana"))
    registrar("ativo também acumula esse sinal", um(
        "SELECT count(*) FROM sinais s JOIN entidades e ON e.id = s.entidade_id"
        " WHERE s.cliente_id = %s AND e.tipo = 'ativo' AND s.tipo = 'sucesso_apos_falhas'", c3.id) == 1)
    registrar("força bruta vencida abre alerta", len(c3.alertas("ana")) == 1, str(c3.alertas("ana")))

    c4 = Cliente()
    sp, tk = {"GeoLocation": {"location": {"lat": -23.55, "lon": -46.63}}}, {"GeoLocation": {"location": {"lat": 35.68, "lon": 139.69}}}
    c4.ev(t, "pedro", ip="198.51.100.1", bruto=sp)
    c4.ev(t + timedelta(hours=1), "pedro", ip="198.51.100.2", bruto=tk)
    c4.ev(t + timedelta(days=3), "pedro", ip="198.51.100.3", bruto=sp)
    c4.processar()
    registrar("São Paulo a Tóquio em 1 hora é viagem impossível", c4.sinais("pedro", "viagem_impossivel") == ["viagem_impossivel"])
    registrar("o mesmo trajeto em 3 dias não é", len(c4.sinais("pedro", "viagem_impossivel")) == 1)
    c4b = Cliente()
    c4b.ev(t, "lia", ip="198.51.100.1", bruto={"GeoLocation": {"location": {"lat": "x", "lon": 999}}})
    c4b.processar()
    registrar("localização inválida é ignorada", c4b.sinais("lia") == [])

    c5 = Cliente()
    c5.rotina("rui", t)
    for d in range(10):
        for i in range(2):
            c5.ev(local(t + timedelta(days=d), 10, i), "rui", grupos=FALHA)
    c5.processar()
    registrar("poucas falhas por dia não viram pico", c5.sinais("rui", "pico_de_falhas") == [])
    for i in range(40):
        c5.ev(local(fim, 10, 0) + timedelta(seconds=i), "rui", grupos=FALHA, ip="203.0.113.9")
    c5.processar()
    registrar("rajada de falhas vira pico", c5.sinais("rui", "pico_de_falhas") == ["pico_de_falhas"])


def testar_corrida():
    print("\n== Sucesso que chega antes das falhas", flush=True)
    t = base()
    fim = t + timedelta(days=20)
    c = Cliente(atraso_segundos=4)
    c.rotina("bia", t)
    c.gravar()
    time.sleep(5)
    while c.motor.processar_cliente(c.id, "America/Sao_Paulo") == c.motor.p.lote:
        pass
    c.ev(local(fim, 3, 10), "bia", host="h1", ip="203.0.113.80")
    c.gravar()
    registrar("evento recente espera antes de ser analisado",
              c.motor.processar_cliente(c.id, "America/Sao_Paulo") == 0)
    for i in range(6):
        c.ev(local(fim, 3, i), "bia", grupos=FALHA, host="h1", ip="203.0.113.80")
    c.gravar()
    time.sleep(5)
    c.motor.processar_cliente(c.id, "America/Sao_Paulo")
    registrar("falhas que chegam depois ainda contam", "sucesso_apos_falhas" in c.sinais("bia"), str(c.sinais("bia")))


def testar_score(t=None):
    print("\n== Score", flush=True)
    t = base()
    fim = t + timedelta(days=20)
    c = Cliente()
    c.rotina("maria", t)
    c.processar()

    noite = fim + timedelta(days=1)
    c.ev(local(noite, 3), "maria", host="h9", ip="10.9.9.9")
    c.processar()
    registrar("um acesso estranho sozinho não vira alerta", c.alertas("maria") == [], f"risco {c.risco('maria'):.0f}")
    c.ev(local(noite, 3, 5), "maria", grupos=SUDO, host="h9", bruto={"data": {"dstuser": "root"}})
    c.processar()
    alertas = c.alertas("maria")
    registrar("desvios combinados viram alerta", len(alertas) == 1, str(alertas))

    tipos = {r[0] for r in ADMIN.execute(
        "SELECT s.tipo FROM sinais s JOIN entidades e ON e.id = s.entidade_id"
        " JOIN eventos v ON v.id = s.evento_id AND v.cliente_id = s.cliente_id"
        " WHERE s.cliente_id = %s AND e.chave = 'maria'", (c.id,)).fetchall()}
    registrar("todo sinal aponta para o evento que o gerou", {"primeiro_host", "primeiro_privilegio"} <= tipos, str(sorted(tipos)))
    detalhes = um("SELECT detalhes->>'host' FROM sinais s JOIN entidades e ON e.id = s.entidade_id"
                  " WHERE s.cliente_id = %s AND e.chave = 'maria' AND s.tipo = 'primeiro_host'", c.id)
    registrar("sinal explica o que aconteceu", detalhes == "nome-h9", detalhes)

    n = len(c.sinais("maria"))
    for i in range(50):
        c.ev(local(noite, 3, 6 + i % 50), "maria", host="h9", ip="10.9.9.9")
    c.processar()
    registrar("repetir o mesmo desvio no dia não infla o risco", len(c.sinais("maria")) == n)
    registrar("continua um alerta só", len(c.alertas("maria")) == 1)

    registrar("risco alto segue aberto no dia seguinte", c.motor.reavaliar_alertas(c.id, local(noite, 12)) == 0)
    registrar("risco decai e o alerta se encerra", c.motor.reavaliar_alertas(c.id, noite + timedelta(days=6)) == 1
              and c.alertas("maria")[0][1] == "encerrado")

    # Reprocessar do início não pode duplicar sinal nem alerta.
    sinais, alertas = um("SELECT count(*) FROM sinais WHERE cliente_id = %s", c.id), um(
        "SELECT count(*) FROM alertas_risco WHERE cliente_id = %s", c.id)
    ADMIN.execute("UPDATE ueba_cursor SET ultimo_evento_id = 0 WHERE cliente_id = %s", (c.id,))
    c.processar()
    registrar("reprocessar não duplica sinais", um("SELECT count(*) FROM sinais WHERE cliente_id = %s", c.id) == sinais)
    registrar("reprocessar não abre outro alerta para o mesmo sinal", um(
        "SELECT count(*) FROM alertas_risco WHERE cliente_id = %s", c.id) <= alertas + 1,
        f"antes {alertas}, depois {um('SELECT count(*) FROM alertas_risco WHERE cliente_id = %s', c.id)}")


def testar_envenenamento():
    print("\n== Envenenamento do baseline", flush=True)
    t = base()
    fim = t + timedelta(days=20)

    c = Cliente()
    for i in range(5000):
        c.ev(fim + timedelta(seconds=i), f"inventado{i}", grupos=FALHA, ip="203.0.113.50")
    c.processar()
    registrar("5000 falhas com nomes inventados não criam usuários", um(
        "SELECT count(*) FROM entidades WHERE cliente_id = %s AND tipo = 'usuario'", c.id) == 0)
    registrar("o ativo atacado acumula o pico", um(
        "SELECT count(*) FROM sinais s JOIN entidades e ON e.id = s.entidade_id WHERE s.cliente_id = %s"
        " AND e.tipo = 'ativo' AND s.tipo = 'pico_de_falhas'", c.id) >= 1)

    c2 = Cliente()
    c2.rotina("maria", t)
    c2.processar()
    for i in range(6):
        c2.ev(local(fim, 3, i), "maria", grupos=FALHA, host="h9", ip="203.0.113.60")
    c2.ev(local(fim, 3, 10), "maria", host="h9", ip="203.0.113.60")
    c2.ev(local(fim, 3, 11), "maria", host="h9", ip="203.0.113.60")
    c2.processar()
    registrar("ataque em curso abre alerta", len(c2.alertas("maria")) == 1)
    registrar("host do ataque não entra no baseline", um(
        "SELECT count(*) FROM vistos v JOIN entidades e ON e.id = v.entidade_id WHERE v.cliente_id = %s"
        " AND e.chave = 'maria' AND v.valor LIKE %s", c2.id, "%:h9") == 0)
    registrar("IP do ataque não entra no baseline", um(
        "SELECT count(*) FROM vistos v JOIN entidades e ON e.id = v.entidade_id WHERE v.cliente_id = %s"
        " AND e.chave = 'maria' AND v.valor = '203.0.113.60'", c2.id) == 0)
    horas_3 = ADMIN.execute("SELECT contagem FROM horas h JOIN entidades e ON e.id = h.entidade_id"
                            " WHERE h.cliente_id = %s AND e.chave = 'maria' AND h.hora = 3", (c2.id,)).fetchone()
    registrar("horário do ataque não entra no baseline", horas_3 is None)
    # Dias depois, quando o risco decaiu, o mesmo host ainda é novidade.
    c2.ev(local(fim + timedelta(days=8), 10), "maria", host="h9", ip="10.0.0.1")
    c2.processar()
    registrar("volta do atacante ao mesmo host ainda é sinalizada", len(c2.sinais("maria", "primeiro_host")) >= 2,
              str(c2.sinais("maria", "primeiro_host")))

    c3 = Cliente(limite_entidades=50)
    for i in range(200):
        c3.ev(fim + timedelta(seconds=i), f"contacriada{i}")
    c3.processar()
    registrar("limite de entidades segura uma inundação", um(
        "SELECT count(*) FROM entidades WHERE cliente_id = %s", c3.id) <= 50)

    c4 = Cliente(aprendizado_dias=14)
    c4.ev(t, "nova", host="h1")
    c4.ev(t + timedelta(days=1), "nova", host="h2", ip="10.1.1.1")
    c4.processar()
    registrar("durante o aprendizado não há sinal de novidade", c4.sinais("nova") == [])


def testar_isolamento():
    print("\n== Isolamento entre clientes", flush=True)
    t = base()
    fim = t + timedelta(days=20)
    a, b = Cliente("a"), Cliente("b")
    a.rotina("maria", t, host="h1")
    b.rotina("maria", t, host="h7", ip="10.7.7.7")
    a.processar(), b.processar()
    a.ev(local(fim, 10), "maria", host="h7", ip="10.7.7.7")
    a.processar()
    registrar("mesmo nome em clientes diferentes são pessoas diferentes", um(
        "SELECT count(DISTINCT e.id) FROM entidades e WHERE e.chave = 'maria' AND e.cliente_id = ANY(%s)", [a.id, b.id]) == 2)
    registrar("o normal de um cliente não vale para o outro", a.sinais("maria", "primeiro_host") == ["primeiro_host"]
              and b.sinais("maria") == [])

    with psycopg.connect(URL_API, autocommit=True) as api:
        registrar("API sem cliente não vê entidades", api.execute("SELECT count(*) FROM entidades").fetchone()[0] == 0)
        with api.transaction():
            api.execute("SELECT set_config('roar.cliente', %s, true)", (str(a.id),))
            donos = {r[0] for r in api.execute("SELECT DISTINCT cliente_id FROM sinais").fetchall()}
        registrar("API de A só vê sinais de A", donos == {a.id})

    with psycopg.connect(URL_UEBA, autocommit=True) as ueba:
        registrar("UEBA sem cliente não lê eventos", ueba.execute("SELECT count(*) FROM eventos").fetchone()[0] == 0)
        registrar("UEBA não lê o nome dos clientes", _recusado(lambda: ueba.execute("SELECT nome FROM clientes")))

        def forjar():
            with ueba.transaction():
                ueba.execute("SELECT set_config('roar.cliente', %s, true)", (str(a.id),))
                ueba.execute("INSERT INTO entidades (cliente_id, tipo, chave, primeira_vista, ultima_vista)"
                             " VALUES (%s, 'usuario', 'x', now(), now())", (b.id,))
        registrar("UEBA não grava em outro cliente sob o contexto de A", _recusado(forjar))

        def alterar():
            with ueba.transaction():
                ueba.execute("SELECT set_config('roar.cliente', %s, true)", (str(a.id),))
                ueba.execute("UPDATE eventos SET nivel = 0")
        registrar("UEBA não altera eventos", _recusado(alterar))

    b_entidade = um("SELECT id FROM entidades WHERE cliente_id = %s LIMIT 1", b.id)
    registrar("sinal de A não aponta para entidade de B", _recusado(lambda: ADMIN.execute(
        "INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id)"
        " VALUES (%s, %s, 'x', 'x', now(), 1, now(), (SELECT min(id) FROM eventos WHERE cliente_id = %s))",
        (a.id, b_entidade, a.id))))


def _recusado(funcao):
    try:
        funcao()
        return False
    except psycopg.Error:
        return True


def testar_simulacao():
    """Dados sintéticos: mede o comportamento do score, não a precisão em ambiente real."""
    print("\n== Simulação de 30 dias", flush=True)
    r = random.Random(42)
    inicio = base(31)
    c = Cliente("simulacao")
    usuarios = [f"u{i:02d}" for i in range(60)]
    hosts = [f"srv{i}" for i in range(12)]
    perfil = {u: {"hosts": r.sample(hosts, r.randint(1, 3)), "ip": f"10.0.{i}.{r.randint(1, 250)}",
                  "entrada": r.randint(7, 10), "turno": r.random() < 0.1}
              for i, u in enumerate(usuarios)}
    eventos = 0
    for d in range(30):
        dia = inicio + timedelta(days=d)
        if dia.astimezone(FUSO).weekday() >= 5:
            continue
        for u in usuarios:
            p = perfil[u]
            if r.random() < 0.08:
                continue
            for _ in range(r.randint(2, 5)):
                hora = (p["entrada"] + (12 if p["turno"] else 0) + r.randint(0, 8)) % 24
                ip = p["ip"] if r.random() > 0.03 else f"10.1.{r.randint(0, 255)}.{r.randint(1, 250)}"  # VPN, Wi-Fi
                host = r.choice(p["hosts"]) if r.random() > 0.02 else r.choice(hosts)  # acesso ocasional legítimo
                c.ev(local(dia, hora, r.randint(0, 59)), u, host=host, ip=ip)
                eventos += 1
            if r.random() < 0.05:
                c.ev(local(dia, p["entrada"] + 1), u, grupos=FALHA, host=p["hosts"][0], ip=p["ip"])  # senha errada
                eventos += 1
            if r.random() < 0.01:
                c.ev(local(dia, p["entrada"] + 2), u, grupos=SUDO, host=p["hosts"][0],
                     bruto={"data": {"dstuser": "root"}})
                eventos += 1
    c.processar()
    falsos_antes = um("SELECT count(*) FROM alertas_risco WHERE cliente_id = %s", c.id)

    ultimo = inicio + timedelta(days=30)
    # Força bruta vencida, madrugada, de fora.
    for i in range(8):
        c.ev(local(ultimo, 2, i), "u01", grupos=FALHA, host=perfil["u01"]["hosts"][0], ip="203.0.113.10")
    c.ev(local(ultimo, 2, 10), "u01", host=perfil["u01"]["hosts"][0], ip="203.0.113.10")
    # Credencial roubada: sem falhas, host e IP novos, madrugada, sudo.
    alvo = next(h for h in hosts if h not in perfil["u02"]["hosts"])
    c.ev(local(ultimo, 3, 0), "u02", host=alvo, ip="203.0.113.20")
    c.ev(local(ultimo, 3, 2), "u02", grupos=SUDO, host=alvo, bruto={"data": {"dstuser": "root"}})
    # Movimento lateral: a mesma conta em vários hosts novos.
    novos = [h for h in hosts if h not in perfil["u03"]["hosts"]][:5]
    for i, h in enumerate(novos):
        c.ev(local(ultimo, 4, i * 5), "u03", host=h, ip="10.0.3.99")
    c.processar()

    atacados = [u for u in ("u01", "u02", "u03") if c.alertas(u)]
    registrar("os 3 ataques simulados geram alerta", len(atacados) == 3, f"detectados {atacados} em {eventos} eventos")
    por_mes = falsos_antes / len(usuarios)
    registrar("falsos positivos ficam abaixo de 1 a cada 10 usuários por mês", por_mes <= 0.1,
              f"{falsos_antes} alertas em 60 usuários e 30 dias, sem ataque")
    registrar("alerta do ataque é explicável", all(c.sinais(u) for u in ("u01", "u02", "u03")),
              "; ".join(f"{u}: {sorted(set(c.sinais(u)))}" for u in ("u01", "u02", "u03")))


def testar_real():
    print("\n== Agente Wazuh real", flush=True)
    from roar_ingestao import provisao
    from roar_ingestao.ciclo import conexoes, rodar_gerenciador
    from testar_ingestao import Ambiente, agente_ativo, esperar_gerenciador, subir_agente

    amb = Ambiente()
    try:
        g = amb.gerenciador("ueba-real")
        registrar("gerenciador no ar", esperar_gerenciador(g))
        pasta = Path(tempfile.mkdtemp(prefix="roar-fase2-"))
        conteiner, log = subir_agente(amb, g, pasta, "real", g["senha_inscricao"])
        agente = agente_ativo(g, conteiner, 180)
        registrar("agente ativo", agente, str(agente))
        if not agente:
            return

        # Histórico de 20 dias da maria neste host, gravado direto no banco.
        t = base()
        for d in range(20):
            for h in (9, 14):
                ADMIN.execute(
                    "INSERT INTO eventos (cliente_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel, severidade,"
                    " regra_id, regra_grupos, agente_id, agente_nome, ip_origem, usuario, bruto)"
                    " VALUES (%s, %s, 'wazuh', %s, %s, 3, 'baixa', '5715', %s, %s, 'host-real', '10.0.0.1', 'maria', '{}')",
                    (g["cliente"], g["id"], f"hist{d}-{h}", local(t + timedelta(days=d), h), SUCESSO, agente))

        motor = Motor(URL_UEBA)
        motor.processar_cliente(g["cliente"], "America/Sao_Paulo")
        time.sleep(60)
        with open(log, "a") as f:
            carimbo = datetime.now().strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
            for i in range(7):
                f.write(f"{carimbo} servidor sshd[{2000 + i}]: Failed password for maria from 203.0.113.70 port {50000 + i} ssh2\n")
                f.flush()
                time.sleep(0.2)
            f.write(f"{carimbo} servidor sshd[2100]: Accepted password for maria from 203.0.113.70 port 50100 ssh2\n")
            f.flush()
            time.sleep(1)
            f.write(f"{carimbo} servidor sudo:    maria : TTY=pts/0 ; PWD=/home/maria ; USER=root ; COMMAND=/bin/bash\n")
            f.flush()

        leitor, banco, _ = conexoes()
        tipos = set()
        fim = time.time() + 240
        while time.time() < fim:
            rodar_gerenciador(leitor, banco, g["id"], g["cliente"])
            while motor.processar_cliente(g["cliente"], "America/Sao_Paulo") == motor.p.lote:
                pass
            tipos = {r[0] for r in ADMIN.execute(
                "SELECT s.tipo FROM sinais s JOIN entidades e ON e.id = s.entidade_id"
                " WHERE s.cliente_id = %s AND e.chave = 'maria'", (g["cliente"],)).fetchall()}
            if {"sucesso_apos_falhas", "primeiro_ip", "primeiro_privilegio"} <= tipos:
                break
            time.sleep(5)
        banco.fechar()

        ordem = ADMIN.execute(
            "SELECT id, regra_id, ocorrido_em::time(3), recebido_em::time(3) FROM eventos WHERE cliente_id = %s"
            " AND ip_origem = '203.0.113.70' ORDER BY ocorrido_em", (g["cliente"],)).fetchall()
        print("   ordem real (id, regra, ocorrido, recebido):", flush=True)
        for linha in ordem:
            print("    ", *linha, flush=True)
        grupos = ADMIN.execute(
            "SELECT regra_id, regra_grupos FROM eventos WHERE cliente_id = %s AND origem_id NOT LIKE 'hist%%'"
            " AND usuario = 'maria'", (g["cliente"],)).fetchall()
        print("   regras reais:", sorted({(r, tuple(x for x in gr if "authentication" in x or x == "sudo")) for r, gr in grupos}), flush=True)
        registrar("alertas reais da maria chegam ao UEBA", grupos, f"{len(grupos)} eventos")
        registrar("login real gera IP novo", "primeiro_ip" in tipos, str(sorted(tipos)))
        registrar("força bruta real vencida gera sinal", "sucesso_apos_falhas" in tipos)
        registrar("sudo real gera sinal de privilégio", "primeiro_privilegio" in tipos)
        alertas = ADMIN.execute(
            "SELECT a.severidade, a.risco_maximo FROM alertas_risco a JOIN entidades e ON e.id = a.entidade_id"
            " WHERE a.cliente_id = %s AND e.chave = 'maria'", (g["cliente"],)).fetchall()
        registrar("cadeia real abre alerta de risco", alertas, str(alertas))
        motor.fechar()
    finally:
        amb.limpar()
    registrar("remover o cliente apaga também os dados de UEBA", um(
        "SELECT count(*) FROM entidades WHERE cliente_id = %s", g["cliente"]) == 0
        and um("SELECT count(*) FROM clientes WHERE id = %s", g["cliente"]) == 0)


def limpar():
    ids = [c.id for c in CRIADOS]
    for c in CRIADOS:
        c.motor.fechar()
    for tabela in ("sinais", "alertas_risco", "falhas_por_hora", "horas", "vistos", "entidades", "ueba_cursor",
                   "eventos", "grupos_alerta", "quarentena"):
        ADMIN.execute(
            f"DELETE FROM {tabela} WHERE " + ("gerenciador_id = ANY(%s)" if tabela == "quarentena" else "cliente_id = ANY(%s)"),
            ([c.ger for c in CRIADOS] if tabela == "quarentena" else ids,))
    ADMIN.execute("DELETE FROM gerenciadores WHERE cliente_id = ANY(%s)", (ids,))
    ADMIN.execute("DELETE FROM clientes WHERE id = ANY(%s)", (ids,))


def main():
    try:
        testar_identidade()
        testar_sinais()
        testar_corrida()
        testar_score()
        testar_envenenamento()
        testar_isolamento()
        testar_simulacao()
        if "--sem-real" not in sys.argv:
            testar_real()
    finally:
        limpar()
    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
