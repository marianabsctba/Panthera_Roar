"""Fluxos de rede: NetFlow v5 e v9, IPFIX e sFlow, direto ao armazém de eventos (docs/arquitetura.md, "Fluxos de rede").

Quem recebe é o goflow2 (serviço fluxos, infra/docker-compose.yml), um só para a instalação, nas portas padrão 2055
(NetFlow e IPFIX) e 6343 (sFlow). Ele escreve um fluxo por linha, em JSON, num arquivo que o receptor da instalação (o
mesmo do syslog cifrado) lê: cada fluxo vai ao coletor do gerenciador dono do exportador, pela porta de repasse dos
fluxos, com a chave da instalação, e o coletor grava na tabela fluxos do armazém da organização. Os fluxos não passam
pelo gerenciador: é volume demais para ele, e não há regra do Wazuh para fluxo.

Um mesmo exportador não pode mandar para duas organizações: a fonte mais antiga fica com ele. O arquivo do goflow2 gira
de hora em hora (renomeado, e o goflow2 abre outro ao receber o sinal HUP); o receptor continua lendo o renomeado até o
fim, e o que já foi lido sai depois de duas horas.
"""

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import syslog_cifrado

PASTA = Path("/opt/panthera-roar/fluxos")
MODELO = Path(__file__).resolve().parent / "fluxos.yaml"
PORTA_NETFLOW = 2055
PORTA_SFLOW = 6343
# A porta em que o coletor recebe os fluxos repassados pelo receptor (só na rede dos gerenciadores).
PORTA_DO_REPASSE = 5141
# O usuário do goflow2 na imagem: é ele quem escreve na pasta.
USUARIO_DO_GOFLOW = 100
ARQUIVO = "fluxos.log"
SEGUNDOS_POR_ARQUIVO = 3600
SEGUNDOS_GUARDANDO_O_LIDO = 7200


def preparar(raiz=PASTA):
    pasta = raiz / "dados"
    pasta.mkdir(parents=True, exist_ok=True)
    pasta.chmod(0o750)
    os.chown(pasta, USUARIO_DO_GOFLOW, 0)
    return pasta


def configuracao(rotas, chave):
    """A parte do receptor que leva os fluxos. Sem rota, descarta tudo."""
    texto = (MODELO.read_text(encoding="utf-8")
             .replace("__ROTAS__", json.dumps([{"rede": r, "gerenciador": g} for r, g in rotas]))
             .replace("__CHAVE__", chave))
    return texto.replace("\n__SAIDAS__", "\n" + syslog_cifrado.saidas(rotas, "fluxos_rotear", "fluxos_", PORTA_DO_REPASSE))


def gravar_configuracao(texto, raiz=syslog_cifrado.PASTA):
    return syslog_cifrado.gravar_configuracao(texto, raiz, nome="fluxos.yaml")


def girar(raiz=PASTA, agora=None, avisar=None):
    """Troca o arquivo do goflow2 quando ele fica velho, e apaga os já lidos. Devolve True se trocou."""
    agora = agora or time.time()
    pasta = raiz / "dados"
    trocou = False
    atual, marca = pasta / ARQUIVO, raiz / "ultimo_giro"
    # A hora do arquivo muda a cada fluxo escrito: quanto tempo ele tem vem da marca do último giro.
    if not marca.exists():
        marca.write_text(str(agora))
    if atual.exists() and atual.stat().st_size and agora - float(marca.read_text() or 0) >= SEGUNDOS_POR_ARQUIVO:
        atual.rename(pasta / f"fluxos-{datetime.fromtimestamp(agora, timezone.utc):%Y%m%d%H%M%S}.log")
        (avisar or _avisar_o_goflow)()
        marca.write_text(str(agora))
        trocou = True
    for velho in pasta.glob("fluxos-*.log"):
        if agora - velho.stat().st_mtime >= SEGUNDOS_GUARDANDO_O_LIDO:
            velho.unlink(missing_ok=True)
    return trocou


def _avisar_o_goflow():
    """O sinal HUP faz o goflow2 abrir um arquivo novo com o nome de sempre."""
    subprocess.run(["docker", "kill", "--signal", "HUP", "roar-fluxos"], capture_output=True, timeout=30)
