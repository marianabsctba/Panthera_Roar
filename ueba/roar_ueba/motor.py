"""Transforma eventos de autenticação em sinais, score de risco e alertas.

    python -m roar_ueba.motor [--uma-vez]

Princípios:
- Falha de login não cria usuário: o atacante escolhe esse nome à vontade.
- Durante risco alto, o comportamento não entra no baseline: não se aprende com o ataque.
- Todo alerta aponta para os sinais, e cada sinal para o evento que o gerou.
"""

import argparse
import logging
import math
import os
import re
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import psycopg
from psycopg.types.json import Jsonb

from .identidade import chave_do_usuario

GRUPOS_SUCESSO = {"authentication_success"}
GRUPOS_FALHA = {"authentication_failed", "authentication_failures", "invalid_login"}
GRUPOS_PRIVILEGIO = {"sudo"}
GRUPOS_ARQUIVO = {"syscheck"}
# Já viram sinal de comportamento próprio, ou disparam o tempo todo sem dizer nada de uma pessoa.
GRUPOS_FORA_DO_RISCO_DAS_REGRAS = {"sca", "syscheck"} | GRUPOS_SUCESSO | GRUPOS_FALHA | GRUPOS_PRIVILEGIO
GRUPOS_CONTA_CRIADA = {"adduser"}
# Windows: conta criada; membro posto em grupo global, local e universal.
EVENTOS_CONTA_CRIADA = {"4720"}
EVENTOS_GRUPO = {"4728", "4732", "4756"}
# Quem entra num destes manda na máquina ou no domínio. docker e lxd valem root.
GRUPOS_ADMINISTRATIVOS = {
    "administrators", "administradores", "domain admins", "enterprise admins", "schema admins",
    "account operators", "backup operators", "server operators", "sudo", "wheel", "admin", "root", "docker", "lxd",
}
LINUX_CONTA_CRIADA = re.compile(r"new user: name=([^,\s]+)")
LINUX_GRUPO = (
    re.compile(r"add '([^']+)' to (?:shadow )?group '([^']+)'"),
    re.compile(r"user (\S+) added by \S+ to group (\S+)"),
)
# Arquivo que quase só muda num ataque ou numa mudança planejada, com a técnica que sugere.
ARQUIVOS_SENSIVEIS = (
    (re.compile(r"^/etc/(passwd|shadow|group|gshadow)$"), "T1098"),
    (re.compile(r"^/etc/sudoers(\.d/.*)?$"), "T1548.003"),
    (re.compile(r"/\.ssh/authorized_keys2?$"), "T1098.004"),
    (re.compile(r"^(/etc/crontab|/etc/cron\.[^/]+/.*|/var/spool/cron/.*)$"), "T1053.003"),
    (re.compile(r"^/(etc|lib|usr/lib)/systemd/system/.*"), "T1543.002"),
    (re.compile(r"^/etc/ld\.so\.preload$"), "T1574.006"),
    (re.compile(r"^/etc/pam\.d/.*"), "T1556.003"),
    (re.compile(r"(^/etc/hosts|/windows/system32/drivers/etc/hosts)$"), "T1565.001"),
    (re.compile(r"/windows/system32/config/(sam|security|system)$"), "T1003.002"),
    (re.compile(r"/start menu/programs/startup/"), "T1547.001"),
    (re.compile(r"/windows/system32/tasks/"), "T1053.005"),
)
log = logging.getLogger("roar.ueba")


@dataclass(frozen=True)
class Parametros:
    limite_alerta: float = 60.0
    limite_critico: float = 100.0
    meia_vida_horas: float = 24.0
    aprendizado_dias: int = 14
    aprendizado_sucessos: int = 20
    horario_minimo: int = 30
    # A suavização põe 24 no denominador: abaixo disso, um horário nunca visto não seria incomum.
    horario_probabilidade: float = 0.02
    falhas_janela_minutos: int = 10
    falhas_antes_do_sucesso: int = 5
    pico_minimo: int = 20
    pares_minimos: int = 10
    pares_fracao: float = 0.05
    velocidade_kmh: float = 1000.0
    distancia_minima_km: float = 500.0
    limite_entidades: int = 20000
    limite_vistos: int = 2000
    lote: int = 1000
    # O indexer atualiza cada shard em um momento: o sucesso pode chegar antes das falhas
    # que o antecederam. Esperar um pouco evita perder a força bruta vencida.
    atraso_segundos: int = 30
    pares_a_cada_horas: float = 24.0
    pares_por_entidade: int = 10
    pares_semelhanca_minima: float = 0.2
    # Ativo que mais da metade usa (o servidor de e-mail, por exemplo) não diz quem trabalha com quem.
    pares_ativo_popular: float = 0.5
    regra_nivel_minimo: int = 7
    # Táticas diferentes na mesma entidade em pouco tempo parecem um ataque andando.
    taticas_minimas: int = 3
    taticas_janela_horas: int = 24
    # Primeira vez para a pessoa, mas os pares já fazem: pesa menos.
    fracao_com_pares: float = 1 / 3


PESOS = {
    "primeiro_host": 15.0,
    "primeiro_ip": 10.0,
    "host_raro_no_cliente": 10.0,
    "horario_incomum": 15.0,
    "primeiro_privilegio": 30.0,
    "pico_de_falhas": 20.0,
    "viagem_impossivel": 40.0,
    "sucesso_apos_falhas": 50.0,
    "ioc_tocado": 50.0,
    "grupo_administrativo": 40.0,
    "arquivo_sensivel": 25.0,
    "conta_criada": 20.0,
    "pessoa_em_risco": 20.0,
    "ativo_em_risco": 15.0,
    # O de alta; o peso de cada regra vem da severidade dela, em PESO_DA_REGRA.
    "regra_disparada": 15.0,
    "taticas_em_sequencia": 30.0,
}
# Muita regra fraca junta vira risco: média soma pouco, crítica soma muito.
PESO_DA_REGRA = ((15, 30.0), (12, 15.0), (7, 5.0))
# Multiplica o peso de todo sinal que acontece no ativo.
FATOR_DA_CRITICIDADE = {"baixa": 0.5, "normal": 1.0, "alta": 1.5, "critica": 2.0}
# Sinais que só repassam o risco de outra entidade. O risco repassado não se repassa de novo,
# senão uma pessoa em risco contamina o ativo, que contamina todos que entram nele.
REPASSADOS = ("pessoa_em_risco", "ativo_em_risco")


def _windows(bruto):
    win = (bruto.get("data") or {}).get("win") if isinstance(bruto, dict) else None
    if not isinstance(win, dict):
        return None, {}
    return str((win.get("system") or {}).get("eventID") or ""), win.get("eventdata") or {}


def _texto(bruto):
    return str(bruto.get("full_log") or "") if isinstance(bruto, dict) else ""


def conta_criada(bruto, grupos):
    """(conta nova, quem criou) ou None. No Linux, quem criou quase nunca vem no log."""
    evento, dados = _windows(bruto)
    if evento in EVENTOS_CONTA_CRIADA:
        return dados.get("targetUserName"), dados.get("subjectUserName")
    achado = LINUX_CONTA_CRIADA.search(_texto(bruto))
    if achado:
        return achado.group(1), None
    if grupos & GRUPOS_CONTA_CRIADA:
        return ((bruto.get("data") or {}).get("dstuser") if isinstance(bruto, dict) else None), None
    return None


def grupo_administrativo(bruto):
    """(membro, grupo, quem pôs) quando alguém entra num grupo que manda na máquina, ou None."""
    evento, dados = _windows(bruto)
    if evento in EVENTOS_GRUPO:
        grupo, membro = dados.get("targetUserName"), dados.get("memberName")
        # Vem como "CN=maria,OU=...": o nome é o primeiro pedaço.
        if isinstance(membro, str) and membro.upper().startswith("CN="):
            membro = membro[3:].split(",", 1)[0]
        if not isinstance(membro, str) or membro in ("", "-"):
            membro = dados.get("memberSid")
        autor = dados.get("subjectUserName")
    else:
        texto = _texto(bruto)
        achado = next((a for a in (r.search(texto) for r in LINUX_GRUPO) if a), None)
        if not achado:
            return None
        membro, grupo, autor = achado.group(1), achado.group(2), None
    if not isinstance(grupo, str) or grupo.strip().lower() not in GRUPOS_ADMINISTRATIVOS:
        return None
    return membro, grupo, autor


def arquivo_sensivel(caminho):
    """A técnica do ATT&CK que a mudança sugere, ou None se o arquivo não é sensível."""
    if not isinstance(caminho, str):
        return None
    normal = caminho.replace("\\", "/").lower()
    return next((tecnica for padrao, tecnica in ARQUIVOS_SENSIVEIS if padrao.search(normal)), None)


def distancia_km(lat1, lon1, lat2, lon2):
    f1, f2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin((f2 - f1) / 2) ** 2
         + math.cos(f1) * math.cos(f2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2)
    return 6371.0 * 2 * math.asin(math.sqrt(a))


def _localizacao(bruto):
    geo = bruto.get("GeoLocation") if isinstance(bruto, dict) else None
    local = geo.get("location") if isinstance(geo, dict) else None
    if not isinstance(local, dict):
        return None
    lat, lon = local.get("lat"), local.get("lon")
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and abs(lat) <= 90 and abs(lon) <= 180:
        return float(lat), float(lon)
    return None


class Motor:
    def __init__(self, url, parametros=None):
        self.con = psycopg.connect(url)
        self.p = parametros or Parametros()
        self._no_limite = set()
        # A criticidade do ativo do evento em processamento, que pesa em todo sinal dele.
        self._criticidade = "normal"
        self._criticidades = {}
        self._taticas = None

    def fechar(self):
        self.con.close()

    def clientes(self):
        with self.con.transaction():
            return self.con.execute("SELECT id, fuso FROM clientes ORDER BY id").fetchall()

    # ------------------------------------------------------------------ entidades

    def _entidade(self, cliente, tipo, chave, nome, momento, criar=True):
        linha = self.con.execute(
            "SELECT id, primeira_vista, sucessos FROM entidades WHERE cliente_id = %s AND tipo = %s AND chave = %s",
            (cliente, tipo, chave)).fetchone()
        if linha:
            self.con.execute(
                "UPDATE entidades SET ultima_vista = GREATEST(ultima_vista, %s),"
                " primeira_vista = LEAST(primeira_vista, %s) WHERE id = %s", (momento, momento, linha[0]))
            return linha
        if not criar:
            return None
        total = self.con.execute("SELECT count(*) FROM entidades WHERE cliente_id = %s", (cliente,)).fetchone()[0]
        if total >= self.p.limite_entidades:
            if cliente not in self._no_limite:
                self._no_limite.add(cliente)
                log.warning("cliente %s atingiu o limite de entidades", cliente)
            return None
        return self.con.execute(
            "INSERT INTO entidades (cliente_id, tipo, chave, nome, primeira_vista, ultima_vista)"
            " VALUES (%s, %s, %s, %s, %s, %s) RETURNING id, primeira_vista, sucessos",
            (cliente, tipo, chave, (nome or chave)[:256], momento, momento)).fetchone()

    def _risco_em(self, cliente, entidade, momento, sem=()):
        meia_vida = self.p.meia_vida_horas
        # O que veio antes da decisão do analista já foi julgado: não volta a somar.
        return self.con.execute(
            """SELECT coalesce(sum(peso * power(0.5, greatest(extract(epoch FROM (%s::timestamptz - ocorrido_em)), 0)
                                                   / (3600 * %s::double precision))), 0)
               FROM sinais WHERE cliente_id = %s AND entidade_id = %s
                 AND ocorrido_em > %s::timestamptz - make_interval(hours => %s) AND ocorrido_em <= %s::timestamptz
                 AND ocorrido_em > coalesce((SELECT risco_desde FROM entidades WHERE id = %s), '-infinity')
                 AND NOT (tipo = ANY(%s))""",
            (momento, meia_vida, cliente, entidade, momento, int(meia_vida * 7), momento, entidade, list(sem))).fetchone()[0]

    def _silenciado(self, cliente, entidade, tipo, momento):
        return self.con.execute(
            """SELECT 1 FROM silencios WHERE cliente_id = %s AND tipo = %s AND (entidade_id IS NULL OR entidade_id = %s)
                 AND (expira_em IS NULL OR expira_em > %s) LIMIT 1""", (cliente, tipo, entidade, momento)).fetchone() is not None

    def _sinal(self, cliente, entidade, tipo, valor, momento, evento_id, detalhes, peso=None):
        if self._silenciado(cliente, entidade, tipo, momento):
            return False
        peso = (PESOS[tipo] if peso is None else peso) * FATOR_DA_CRITICIDADE[self._criticidade]
        if self._criticidade != "normal":
            detalhes = {**detalhes, "criticidade": self._criticidade}
        return self.con.execute(
            """INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id, detalhes)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cliente_id, entidade_id, tipo, valor, dia) DO NOTHING RETURNING id""",
            (cliente, entidade, tipo, str(valor)[:256], momento.astimezone(timezone.utc).date(),
             peso, momento, evento_id, Jsonb(detalhes))).fetchone() is not None

    def _atualizar_risco(self, cliente, entidade, momento):
        risco = float(self._risco_em(cliente, entidade, momento))
        self.con.execute("UPDATE entidades SET risco = %s, risco_em = %s WHERE id = %s", (risco, momento, entidade))
        if risco < self.p.limite_alerta:
            return risco
        severidade = "critica" if risco >= self.p.limite_critico else "alta"
        aberto = self.con.execute(
            "SELECT id, risco_maximo FROM alertas_risco WHERE cliente_id = %s AND entidade_id = %s AND estado = 'aberto'",
            (cliente, entidade)).fetchone()
        if aberto:
            if risco > aberto[1]:
                self.con.execute("UPDATE alertas_risco SET risco_maximo = %s, severidade = %s WHERE id = %s",
                                 (risco, severidade, aberto[0]))
        else:
            self.con.execute(
                "INSERT INTO alertas_risco (cliente_id, entidade_id, severidade, risco_maximo, aberto_em)"
                " VALUES (%s, %s, %s, %s, %s)", (cliente, entidade, severidade, risco, momento))
        return risco

    # ------------------------------------------------------------------ baseline

    def _aprendendo(self, primeira_vista, sucessos, momento):
        return (sucessos < self.p.aprendizado_sucessos
                or (momento - primeira_vista) < timedelta(days=self.p.aprendizado_dias))

    def _registrar_visto(self, cliente, entidade, dimensao, valor, momento):
        """Devolve True se é a primeira vez. Acima do limite, para de crescer."""
        visto = self.con.execute(
            "UPDATE vistos SET contagem = contagem + 1 WHERE cliente_id = %s AND entidade_id = %s"
            " AND dimensao = %s AND valor = %s RETURNING 1", (cliente, entidade, dimensao, valor)).fetchone()
        if visto:
            return False
        total = self.con.execute(
            "SELECT count(*) FROM vistos WHERE cliente_id = %s AND entidade_id = %s AND dimensao = %s",
            (cliente, entidade, dimensao)).fetchone()[0]
        if total < self.p.limite_vistos:
            self.con.execute(
                "INSERT INTO vistos (cliente_id, entidade_id, dimensao, valor, primeira_vez) VALUES (%s, %s, %s, %s, %s)",
                (cliente, entidade, dimensao, valor, momento))
        return True

    def _ja_visto(self, cliente, entidade, dimensao, valor):
        return self.con.execute(
            "SELECT 1 FROM vistos WHERE cliente_id = %s AND entidade_id = %s AND dimensao = %s AND valor = %s",
            (cliente, entidade, dimensao, valor)).fetchone() is not None

    def _horario_incomum(self, cliente, entidade, hora):
        contagens = dict(self.con.execute(
            "SELECT hora, contagem FROM horas WHERE cliente_id = %s AND entidade_id = %s",
            (cliente, entidade)).fetchall())
        total = sum(contagens.values())
        if total < self.p.horario_minimo:
            return False
        # Vizinhas contam: quem entra às 8h não é estranho às 7h.
        vizinhas = sum(contagens.get((hora + d) % 24, 0) for d in (-1, 0, 1))
        return (vizinhas + 1) / (total + 24) < self.p.horario_probabilidade

    def _pares_que_ja_viram(self, cliente, entidade, dimensao, valor):
        return self.con.execute(
            """SELECT count(*) FROM pares p JOIN vistos v ON v.cliente_id = p.cliente_id AND v.entidade_id = p.par_id
                 AND v.dimensao = %s AND v.valor = %s
               WHERE p.cliente_id = %s AND p.entidade_id = %s""", (dimensao, valor, cliente, entidade)).fetchone()[0]

    def _primeira_vez(self, cliente, entidade, tipo, dimensao, valor, momento, evento_id, detalhes):
        """Primeira vez para a pessoa. Se os pares já fazem, soma menos e diz isso."""
        pares = self._pares_que_ja_viram(cliente, entidade, dimensao, valor)
        if pares:
            detalhes = {**detalhes, "pares": pares}
        self._sinal(cliente, entidade, tipo, valor, momento, evento_id, detalhes,
                    peso=PESOS[tipo] * self.p.fracao_com_pares if pares else None)
        return pares

    def _host_raro(self, cliente, host):
        usuarios = self.con.execute(
            "SELECT count(*) FROM entidades WHERE cliente_id = %s AND tipo = 'usuario' AND sucessos > 0",
            (cliente,)).fetchone()[0]
        if usuarios < self.p.pares_minimos:
            return False
        no_host = self.con.execute(
            "SELECT count(DISTINCT entidade_id) FROM vistos WHERE cliente_id = %s AND dimensao = 'host' AND valor = %s",
            (cliente, host)).fetchone()[0]
        return no_host / usuarios < self.p.pares_fracao

    # ------------------------------------------------------------------ eventos

    def _criticidade_do_ativo(self, cliente, gerenciador, agente):
        chave = (cliente, gerenciador, agente)
        if chave not in self._criticidades:
            linha = self.con.execute("SELECT criticidade FROM ativos WHERE cliente_id = %s AND gerenciador_id = %s AND agente_id = %s",
                                     (cliente, gerenciador, agente)).fetchone()
            self._criticidades[chave] = linha[0] if linha else "normal"
        return self._criticidades[chave]

    def _repassar(self, cliente, pessoa, ativo, usuario, agente_nome, host, momento, evento_id):
        """Pessoa em risco que entra no ativo, e ativo em risco onde a pessoa entra: um salto só."""
        da_pessoa = float(self._risco_em(cliente, pessoa, momento, sem=REPASSADOS))
        do_ativo = float(self._risco_em(cliente, ativo, momento, sem=REPASSADOS))
        if da_pessoa >= self.p.limite_alerta and self._sinal(
                cliente, ativo, "pessoa_em_risco", chave_do_usuario(usuario), momento, evento_id,
                {"usuario": usuario, "risco": round(da_pessoa), "host": agente_nome}):
            self._atualizar_risco(cliente, ativo, momento)
        if do_ativo >= self.p.limite_alerta:
            self._sinal(cliente, pessoa, "ativo_em_risco", host, momento, evento_id,
                        {"host": agente_nome, "risco": round(do_ativo)})

    def _sucesso(self, cliente, fuso, ev):
        evento_id, momento, gerenciador, agente, agente_nome, ip, usuario, bruto = ev[:8]
        chave = chave_do_usuario(usuario)
        host = f"{gerenciador}:{agente}"
        ativo = self._entidade(cliente, "ativo", host, agente_nome, momento)

        # Vale para qualquer usuário, conhecido ou não: é o ataque de força bruta que funcionou.
        apos_falhas = 0
        if ip:
            apos_falhas = self.con.execute(
                """SELECT count(*) FROM eventos WHERE cliente_id = %s AND ip_origem = %s
                     AND gerenciador_id = %s AND agente_id = %s AND regra_grupos && %s
                     AND ocorrido_em >= %s AND ocorrido_em < %s""",
                (cliente, ip, gerenciador, agente, list(GRUPOS_FALHA),
                 momento - timedelta(minutes=self.p.falhas_janela_minutos), momento)).fetchone()[0]
        forca_bruta = apos_falhas >= self.p.falhas_antes_do_sucesso
        if forca_bruta and ativo:
            self._sinal(cliente, ativo[0], "sucesso_apos_falhas", ip, momento, evento_id,
                        {"ip": str(ip), "falhas": apos_falhas, "usuario": usuario})
            self._atualizar_risco(cliente, ativo[0], momento)

        if not chave:
            return
        linha = self._entidade(cliente, "usuario", chave, usuario, momento)
        if not linha:
            return
        entidade, primeira_vista, sucessos = linha

        if forca_bruta:
            self._sinal(cliente, entidade, "sucesso_apos_falhas", ip, momento, evento_id,
                        {"ip": str(ip), "falhas": apos_falhas, "host": agente_nome})

        aprendendo = self._aprendendo(primeira_vista, sucessos, momento)
        hora = momento.astimezone(ZoneInfo(fuso)).hour
        if not aprendendo:
            if not self._ja_visto(cliente, entidade, "host", host):
                pares = self._primeira_vez(cliente, entidade, "primeiro_host", "host", host, momento, evento_id,
                                           {"host": agente_nome, "ip": ip and str(ip)})
                # Raro na organização, mas comum entre os pares: é o trabalho daquela equipe.
                if not pares and self._host_raro(cliente, host):
                    self._sinal(cliente, entidade, "host_raro_no_cliente", host, momento, evento_id,
                                {"host": agente_nome})
            if ip and not self._ja_visto(cliente, entidade, "ip", str(ip)):
                self._primeira_vez(cliente, entidade, "primeiro_ip", "ip", str(ip), momento, evento_id,
                                   {"ip": str(ip), "host": agente_nome})
            if self._horario_incomum(cliente, entidade, hora):
                self._sinal(cliente, entidade, "horario_incomum", hora, momento, evento_id,
                            {"hora_local": hora, "fuso": fuso, "host": agente_nome})

        # Depende só da física, então não espera o aprendizado.
        local = _localizacao(bruto)
        if local:
            anterior = self.con.execute(
                "SELECT ultima_lat, ultima_lon, ultima_geo_em FROM entidades WHERE id = %s", (entidade,)).fetchone()
            if anterior[2] and momento > anterior[2]:
                km = distancia_km(anterior[0], anterior[1], *local)
                horas = (momento - anterior[2]).total_seconds() / 3600
                if km >= self.p.distancia_minima_km and km / max(horas, 1 / 60) >= self.p.velocidade_kmh:
                    self._sinal(cliente, entidade, "viagem_impossivel", ip or "-", momento, evento_id,
                                {"km": round(km), "horas": round(horas, 2), "ip": ip and str(ip)})
            if not anterior[2] or momento > anterior[2]:
                self.con.execute("UPDATE entidades SET ultima_lat = %s, ultima_lon = %s, ultima_geo_em = %s WHERE id = %s",
                                 (*local, momento, entidade))

        if ativo:
            self._repassar(cliente, entidade, ativo[0], usuario, agente_nome, host, momento, evento_id)
        risco = self._atualizar_risco(cliente, entidade, momento)

        # Sob risco alto não se aprende: senão o próprio ataque vira o normal.
        if risco < self.p.limite_alerta and not forca_bruta:
            self._registrar_visto(cliente, entidade, "host", host, momento)
            if ip:
                self._registrar_visto(cliente, entidade, "ip", str(ip), momento)
            self.con.execute(
                "INSERT INTO horas (cliente_id, entidade_id, hora, contagem) VALUES (%s, %s, %s, 1)"
                " ON CONFLICT (cliente_id, entidade_id, hora) DO UPDATE SET contagem = horas.contagem + 1",
                (cliente, entidade, hora))
            self.con.execute("UPDATE entidades SET sucessos = sucessos + 1 WHERE id = %s", (entidade,))

    def _falha(self, cliente, ev):
        evento_id, momento, gerenciador, agente, agente_nome, ip, usuario = ev[:7]
        alvos = []
        ativo = self._entidade(cliente, "ativo", f"{gerenciador}:{agente}", agente_nome, momento)
        if ativo:
            alvos.append(ativo[0])
        chave = chave_do_usuario(usuario)
        if chave:
            # Só usuário que já existe. Nome inventado por atacante não cria entidade.
            linha = self._entidade(cliente, "usuario", chave, usuario, momento, criar=False)
            if linha:
                alvos.append(linha[0])

        inicio = momento.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        for entidade in alvos:
            contagem = self.con.execute(
                """INSERT INTO falhas_por_hora (cliente_id, entidade_id, inicio, contagem) VALUES (%s, %s, %s, 1)
                   ON CONFLICT (cliente_id, entidade_id, inicio)
                   DO UPDATE SET contagem = falhas_por_hora.contagem + 1 RETURNING contagem""",
                (cliente, entidade, inicio)).fetchone()[0]
            if contagem < self.p.pico_minimo:
                continue
            historico = [c for (c,) in self.con.execute(
                "SELECT contagem FROM falhas_por_hora WHERE cliente_id = %s AND entidade_id = %s"
                " AND inicio < %s AND inicio >= %s", (cliente, entidade, inicio, inicio - timedelta(days=14))).fetchall()]
            mediana = statistics.median(historico) if historico else 0
            desvio = statistics.median(abs(c - mediana) for c in historico) if historico else 0
            if contagem >= max(self.p.pico_minimo, mediana + 5 * max(desvio, 1)):
                if self._sinal(cliente, entidade, "pico_de_falhas", inicio.isoformat(), momento, evento_id,
                               {"falhas_na_hora": contagem, "mediana_historica": mediana, "ip": ip and str(ip)}):
                    self._atualizar_risco(cliente, entidade, momento)

    def _privilegio(self, cliente, ev):
        evento_id, momento, gerenciador, agente, agente_nome, ip, usuario, bruto = ev[:8]
        chave = chave_do_usuario(usuario)
        if not chave:
            return
        linha = self._entidade(cliente, "usuario", chave, usuario, momento, criar=False)
        if not linha:
            return
        entidade, primeira_vista, sucessos = linha
        destino = ((bruto.get("data") or {}).get("dstuser") if isinstance(bruto, dict) else None) or "-"
        valor = f"{gerenciador}:{agente}:{str(destino)[:64]}"
        if not self._aprendendo(primeira_vista, sucessos, momento) and not self._ja_visto(cliente, entidade, "privilegio", valor):
            self._primeira_vez(cliente, entidade, "primeiro_privilegio", "privilegio", valor, momento, evento_id,
                               {"host": agente_nome, "como": str(destino)[:64]})
        risco = self._atualizar_risco(cliente, entidade, momento)
        if risco < self.p.limite_alerta:
            self._registrar_visto(cliente, entidade, "privilegio", valor, momento)

    def _ativo_e_pessoa(self, cliente, ev, nome, criar):
        """O ativo do evento e, se houver, a pessoa: as duas respondem pelo sinal."""
        momento, gerenciador, agente, agente_nome = ev[1:5]
        alvos = []
        ativo = self._entidade(cliente, "ativo", f"{gerenciador}:{agente}", agente_nome, momento)
        if ativo:
            alvos.append(ativo[0])
        chave = chave_do_usuario(nome)
        linha = self._entidade(cliente, "usuario", chave, nome, momento, criar=criar) if chave else None
        if linha:
            alvos.append(linha[0])
        return alvos

    def _sinal_em_todos(self, cliente, alvos, tipo, valor, momento, evento_id, detalhes):
        for entidade in alvos:
            if self._sinal(cliente, entidade, tipo, valor, momento, evento_id, detalhes):
                self._atualizar_risco(cliente, entidade, momento)

    def _conta_criada(self, cliente, ev, achado):
        evento_id, momento, gerenciador, agente, agente_nome = ev[:5]
        conta, autor = achado
        host = f"{gerenciador}:{agente}"
        detalhes = {"conta": str(conta or "-")[:64], "host": agente_nome}
        chave = chave_do_usuario(autor)
        linha = self._entidade(cliente, "usuario", chave, autor, momento, criar=False) if chave else None
        if not linha:
            # Sem saber quem criou, quem responde é o ativo.
            ativo = self._entidade(cliente, "ativo", host, agente_nome, momento)
            if ativo:
                self._sinal_em_todos(cliente, [ativo[0]], "conta_criada", detalhes["conta"], momento, evento_id, detalhes)
            return
        entidade, primeira_vista, sucessos = linha
        # Quem cria contas ali toda semana está fazendo o trabalho dele.
        if not self._aprendendo(primeira_vista, sucessos, momento) and not self._ja_visto(cliente, entidade, "cria_conta", host):
            self._primeira_vez(cliente, entidade, "conta_criada", "cria_conta", host, momento, evento_id, detalhes)
        if self._atualizar_risco(cliente, entidade, momento) < self.p.limite_alerta:
            self._registrar_visto(cliente, entidade, "cria_conta", host, momento)

    def _grupo_administrativo(self, cliente, ev, achado):
        evento_id, momento, gerenciador, agente, agente_nome = ev[:5]
        membro, grupo, autor = achado
        detalhes = {"membro": str(membro or "-")[:128], "grupo": str(grupo)[:64], "host": agente_nome}
        if autor:
            detalhes["por"] = str(autor)[:64]
        # Só quem administra a máquina escreve este log: o nome não é do atacante de fora, pode criar a pessoa.
        alvos = self._ativo_e_pessoa(cliente, ev, membro, criar=True)
        self._sinal_em_todos(cliente, alvos, "grupo_administrativo", f"{gerenciador}:{agente}:{str(grupo).lower()[:64]}",
                             momento, evento_id, detalhes)

    def _arquivo_sensivel(self, cliente, ev):
        evento_id, momento, bruto = ev[0], ev[1], ev[7]
        syscheck = bruto.get("syscheck") if isinstance(bruto, dict) else None
        if not isinstance(syscheck, dict):
            return
        caminho = syscheck.get("path")
        tecnica = arquivo_sensivel(caminho)
        if not tecnica:
            return
        auditoria = syscheck.get("audit") if isinstance(syscheck.get("audit"), dict) else {}
        # Com whodata, o Wazuh diz quem mexeu: a pessoa que entrou, antes de virar root.
        quem = next((n for n in ((auditoria.get(k) or {}).get("name") for k in ("login_user", "user"))
                     if chave_do_usuario(n)), None)
        detalhes = {"arquivo": str(caminho)[:256], "host": ev[4], "tecnica": tecnica,
                    "mudanca": str(syscheck.get("event") or "")[:16]}
        if quem:
            detalhes["quem"] = str(quem)[:64]
        alvos = self._ativo_e_pessoa(cliente, ev, quem, criar=False)
        self._sinal_em_todos(cliente, alvos, "arquivo_sensivel", caminho, momento, evento_id, detalhes)

    def _ioc(self, cliente, ev):
        evento_id, momento, ip, usuario, bruto = ev[0], ev[1], ev[5], ev[6], ev[7]
        destino = (bruto.get("data") or {}).get("dstip") if isinstance(bruto, dict) else None
        enderecos = [str(e)[:64] for e in (ip, destino) if e]
        if not enderecos:
            return
        indicador = self.con.execute(
            "SELECT valor, descricao FROM intel_indicadores WHERE cliente_id = %s AND tipo = 'ip' AND valor = ANY(%s) LIMIT 1",
            (cliente, enderecos)).fetchone()
        if not indicador:
            return
        detalhes = {"ip": indicador[0], "descricao": (indicador[1] or "")[:200], "host": ev[4]}
        alvos = self._ativo_e_pessoa(cliente, ev, usuario, criar=False)
        self._sinal_em_todos(cliente, alvos, "ioc_tocado", indicador[0], momento, evento_id, detalhes)

    def _taticas_de(self, tecnicas):
        if self._taticas is None:
            self._taticas = {t: list(ts) for t, ts in self.con.execute("SELECT tecnica, taticas FROM tecnicas_attack").fetchall()}
        return sorted({tatica for t in tecnicas for tatica in self._taticas.get(t, self._taticas.get(t.split(".")[0], []))})

    def _regra(self, cliente, ev):
        """Toda regra que dispara soma um pouco no ativo e na pessoa: o risco junta o que cada uma sozinha não diria."""
        evento_id, momento, nivel, regra_id, descricao, mitre = ev[0], ev[1], ev[9], ev[10], ev[11], ev[12] or []
        peso = next((p for minimo, p in PESO_DA_REGRA if nivel >= minimo), None)
        if nivel < self.p.regra_nivel_minimo or peso is None:
            return
        taticas = self._taticas_de(mitre)
        detalhes = {"regra": regra_id, "descricao": (descricao or "")[:200], "nivel": nivel, "host": ev[4]}
        if mitre:
            detalhes["tecnicas"] = list(mitre)[:10]
        if taticas:
            detalhes["taticas"] = taticas
        for entidade in self._ativo_e_pessoa(cliente, ev, ev[6], criar=False):
            if not self._sinal(cliente, entidade, "regra_disparada", regra_id, momento, evento_id, detalhes, peso=peso):
                continue
            vistas = [t for (t,) in self.con.execute(
                """SELECT DISTINCT jsonb_array_elements_text(detalhes->'taticas') FROM sinais
                   WHERE cliente_id = %s AND entidade_id = %s AND tipo = 'regra_disparada'
                     AND ocorrido_em > %s::timestamptz - make_interval(hours => %s) AND ocorrido_em <= %s
                     AND ocorrido_em > coalesce((SELECT risco_desde FROM entidades WHERE id = %s), '-infinity')""",
                (cliente, entidade, momento, self.p.taticas_janela_horas, momento, entidade)).fetchall()]
            if len(vistas) >= self.p.taticas_minimas:
                # Uma vez por dia: a soma das regras já cresce com cada tática nova.
                self._sinal(cliente, entidade, "taticas_em_sequencia", "taticas", momento, evento_id,
                            {"taticas": sorted(vistas), "host": ev[4]})
            self._atualizar_risco(cliente, entidade, momento)

    def processar_cliente(self, cliente, fuso):
        """Processa um lote. Sinais, baseline e cursor avançam juntos, ou nada avança."""
        with self.con.transaction():
            self.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            self.con.execute("INSERT INTO ueba_cursor (cliente_id) VALUES (%s) ON CONFLICT DO NOTHING", (cliente,))
            cursor = self.con.execute("SELECT ultimo_evento_id FROM ueba_cursor WHERE cliente_id = %s",
                                      (cliente,)).fetchone()[0]
            eventos = self.con.execute(
                """SELECT id, ocorrido_em, gerenciador_id, agente_id, agente_nome, ip_origem, usuario, bruto, regra_grupos,
                          nivel, regra_id, regra_descricao, mitre
                   FROM eventos WHERE cliente_id = %s AND id > %s
                     AND recebido_em <= now() - make_interval(secs => %s)
                   ORDER BY id LIMIT %s""",
                (cliente, cursor, self.p.atraso_segundos, self.p.lote)).fetchall()
            self._criticidades = {}
            for ev in eventos:
                self._criticidade = self._criticidade_do_ativo(cliente, ev[2], ev[3])
                grupos = set(ev[8])
                if grupos & GRUPOS_SUCESSO:
                    self._sucesso(cliente, fuso, ev)
                elif grupos & GRUPOS_FALHA:
                    self._falha(cliente, ev)
                if grupos & GRUPOS_PRIVILEGIO:
                    self._privilegio(cliente, ev)
                if grupos & GRUPOS_ARQUIVO:
                    self._arquivo_sensivel(cliente, ev)
                criada = conta_criada(ev[7], grupos)
                if criada:
                    self._conta_criada(cliente, ev, criada)
                admin = grupo_administrativo(ev[7])
                if admin:
                    self._grupo_administrativo(cliente, ev, admin)
                self._ioc(cliente, ev)
                if not grupos & GRUPOS_FORA_DO_RISCO_DAS_REGRAS:
                    self._regra(cliente, ev)
            self._criticidade = "normal"
            if eventos:
                self.con.execute("UPDATE ueba_cursor SET ultimo_evento_id = %s WHERE cliente_id = %s",
                                 (eventos[-1][0], cliente))
        return len(eventos)

    def reavaliar_alertas(self, cliente, agora=None):
        """O risco decai com o tempo: encerra quem caiu abaixo da metade do limite."""
        agora = agora or datetime.now(timezone.utc)
        encerrados = 0
        with self.con.transaction():
            self.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            abertos = self.con.execute(
                "SELECT id, entidade_id FROM alertas_risco WHERE cliente_id = %s AND estado = 'aberto'",
                (cliente,)).fetchall()
            for alerta, entidade in abertos:
                risco = float(self._risco_em(cliente, entidade, agora))
                self.con.execute("UPDATE entidades SET risco = %s, risco_em = %s WHERE id = %s", (risco, agora, entidade))
                if risco < self.p.limite_alerta / 2:
                    self.con.execute("UPDATE alertas_risco SET estado = 'encerrado', encerrado_em = %s WHERE id = %s",
                                     (agora, alerta))
                    encerrados += 1
        return encerrados

    def recalcular_pares(self, cliente, agora=None):
        """Pares são quem mais divide ativos com a pessoa (semelhança de Jaccard). Sem diretório: só o que se vê nos acessos."""
        agora = agora or datetime.now(timezone.utc)
        with self.con.transaction():
            self.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            self.con.execute("INSERT INTO ueba_cursor (cliente_id) VALUES (%s) ON CONFLICT DO NOTHING", (cliente,))
            ultimo = self.con.execute("SELECT pares_em FROM ueba_cursor WHERE cliente_id = %s", (cliente,)).fetchone()[0]
            if ultimo and agora - ultimo < timedelta(hours=self.p.pares_a_cada_horas):
                return None
            self.con.execute("DELETE FROM pares WHERE cliente_id = %s", (cliente,))
            total = self.con.execute(
                """WITH usuarios AS (SELECT id FROM entidades WHERE cliente_id = %(c)s AND tipo = 'usuario' AND sucessos > 0),
                        acessos AS (SELECT v.entidade_id, v.valor FROM vistos v JOIN usuarios u ON u.id = v.entidade_id
                                    WHERE v.cliente_id = %(c)s AND v.dimensao = 'host'),
                        populares AS (SELECT valor FROM acessos GROUP BY valor
                                      HAVING count(*) > greatest(2, %(popular)s * (SELECT count(*) FROM usuarios))),
                        uteis AS (SELECT * FROM acessos WHERE valor NOT IN (SELECT valor FROM populares)),
                        tamanho AS (SELECT entidade_id, count(*) AS n FROM uteis GROUP BY 1),
                        comum AS (SELECT a.entidade_id AS e, b.entidade_id AS p, count(*) AS n FROM uteis a
                                  JOIN uteis b ON a.valor = b.valor AND a.entidade_id <> b.entidade_id GROUP BY 1, 2),
                        semelhanca AS (SELECT c.e, c.p, c.n::double precision / (ta.n + tb.n - c.n) AS s FROM comum c
                                       JOIN tamanho ta ON ta.entidade_id = c.e JOIN tamanho tb ON tb.entidade_id = c.p),
                        ordem AS (SELECT *, row_number() OVER (PARTITION BY e ORDER BY s DESC, p) AS r
                                  FROM semelhanca WHERE s >= %(minima)s)
                   INSERT INTO pares (cliente_id, entidade_id, par_id, semelhanca, calculado_em)
                   SELECT %(c)s, e, p, s, %(agora)s FROM ordem WHERE r <= %(k)s""",
                {"c": cliente, "popular": self.p.pares_ativo_popular, "minima": self.p.pares_semelhanca_minima,
                 "k": self.p.pares_por_entidade, "agora": agora}).rowcount
            self.con.execute("UPDATE ueba_cursor SET pares_em = %s WHERE cliente_id = %s", (agora, cliente))
        return total

    def ciclo(self):
        """Falha em um cliente não impede os outros."""
        total, falhas = 0, {}
        for cliente, fuso in self.clientes():
            try:
                while True:
                    n = self.processar_cliente(cliente, fuso)
                    total += n
                    if n < self.p.lote:
                        break
                self.reavaliar_alertas(cliente)
                self.recalcular_pares(cliente)
            except Exception as erro:
                falhas[cliente] = erro
                log.exception("cliente %s falhou", cliente)
        return total, falhas


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--uma-vez", action="store_true")
    args.add_argument("--intervalo", type=float, default=10.0)
    a = args.parse_args()

    valores = {}
    with open(os.getenv("ROAR_ENV", "/opt/panthera-roar/.env"), encoding="utf-8") as f:
        for linha in f:
            if "=" in linha and not linha.startswith("#"):
                k, v = linha.strip().split("=", 1)
                valores[k] = v
    motor = Motor(f"postgresql://roar_ueba:{valores['ROAR_UEBA_SENHA']}@"
                  f"{os.getenv('ROAR_BANCO_ENDERECO', '127.0.0.1:5433')}/roar")
    while True:
        total, falhas = motor.ciclo()
        if total:
            log.info("ciclo: %d eventos", total)
        if a.uma_vez:
            raise SystemExit(1 if falhas else 0)
        time.sleep(a.intervalo)


if __name__ == "__main__":
    main()
