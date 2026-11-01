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


PESOS = {
    "primeiro_host": 15.0,
    "primeiro_ip": 10.0,
    "host_raro_no_cliente": 10.0,
    "horario_incomum": 15.0,
    "primeiro_privilegio": 30.0,
    "pico_de_falhas": 20.0,
    "viagem_impossivel": 40.0,
    "sucesso_apos_falhas": 50.0,
}


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

    def _risco_em(self, cliente, entidade, momento):
        meia_vida = self.p.meia_vida_horas
        return self.con.execute(
            """SELECT coalesce(sum(peso * power(0.5, greatest(extract(epoch FROM (%s::timestamptz - ocorrido_em)), 0)
                                                   / (3600 * %s::double precision))), 0)
               FROM sinais WHERE cliente_id = %s AND entidade_id = %s
                 AND ocorrido_em > %s::timestamptz - make_interval(hours => %s) AND ocorrido_em <= %s::timestamptz""",
            (momento, meia_vida, cliente, entidade, momento, int(meia_vida * 7), momento)).fetchone()[0]

    def _sinal(self, cliente, entidade, tipo, valor, momento, evento_id, detalhes):
        return self.con.execute(
            """INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id, detalhes)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cliente_id, entidade_id, tipo, valor, dia) DO NOTHING RETURNING id""",
            (cliente, entidade, tipo, str(valor)[:256], momento.astimezone(timezone.utc).date(),
             PESOS[tipo], momento, evento_id, Jsonb(detalhes))).fetchone() is not None

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
                self._sinal(cliente, entidade, "primeiro_host", host, momento, evento_id,
                            {"host": agente_nome, "ip": ip and str(ip)})
                if self._host_raro(cliente, host):
                    self._sinal(cliente, entidade, "host_raro_no_cliente", host, momento, evento_id,
                                {"host": agente_nome})
            if ip and not self._ja_visto(cliente, entidade, "ip", str(ip)):
                self._sinal(cliente, entidade, "primeiro_ip", str(ip), momento, evento_id,
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
            self._sinal(cliente, entidade, "primeiro_privilegio", valor, momento, evento_id,
                        {"host": agente_nome, "como": str(destino)[:64]})
        risco = self._atualizar_risco(cliente, entidade, momento)
        if risco < self.p.limite_alerta:
            self._registrar_visto(cliente, entidade, "privilegio", valor, momento)

    def processar_cliente(self, cliente, fuso):
        """Processa um lote. Sinais, baseline e cursor avançam juntos, ou nada avança."""
        with self.con.transaction():
            self.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            self.con.execute("INSERT INTO ueba_cursor (cliente_id) VALUES (%s) ON CONFLICT DO NOTHING", (cliente,))
            cursor = self.con.execute("SELECT ultimo_evento_id FROM ueba_cursor WHERE cliente_id = %s",
                                      (cliente,)).fetchone()[0]
            eventos = self.con.execute(
                """SELECT id, ocorrido_em, gerenciador_id, agente_id, agente_nome, ip_origem, usuario, bruto, regra_grupos
                   FROM eventos WHERE cliente_id = %s AND id > %s
                     AND recebido_em <= now() - make_interval(secs => %s)
                   ORDER BY id LIMIT %s""",
                (cliente, cursor, self.p.atraso_segundos, self.p.lote)).fetchall()
            for ev in eventos:
                grupos = set(ev[8])
                if grupos & GRUPOS_SUCESSO:
                    self._sucesso(cliente, fuso, ev)
                elif grupos & GRUPOS_FALHA:
                    self._falha(cliente, ev)
                if grupos & GRUPOS_PRIVILEGIO:
                    self._privilegio(cliente, ev)
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
