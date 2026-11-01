"""Ações de resposta. O alvo pode ter vindo de um alerta escrito por um atacante.

Por isso nada do alerta vira comando sem validação estrita: o IP precisa ser um IP de verdade
e público, e o endereço do webhook é o que a pessoa configurou no playbook, não o do alerta.
"""

import ipaddress
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

PASTA_GERENCIADORES = Path(os.getenv("ROAR_GERENCIADORES", "/opt/panthera-roar/gerenciadores"))
# Todo bloqueio vence sozinho: um endereço forjado num log não pode ficar bloqueado para sempre.
# Os mesmos prazos estão na configuração do gerenciador, em provisao.SEGUNDOS_DE_BLOQUEIO.
DURACOES_EM_MINUTOS = (60, 1440, 10080)
DURACAO_PADRAO = 60


class AcaoRecusada(Exception):
    """Não adianta tentar de novo: o pedido em si é inválido."""


def _e_publico(ip):
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_global and not ip.is_multicast


def ip_publico(texto):
    try:
        ip = ipaddress.ip_address(str(texto).strip())
    except ValueError:
        raise AcaoRecusada("O alvo não é um endereço IP válido.")
    if not _e_publico(ip):
        raise AcaoRecusada(f"O endereço {ip} não é público: bloquear pode derrubar a própria rede.")
    return str(ip)


def redes_protegidas(lista):
    try:
        return [ipaddress.ip_network(str(item).strip(), strict=False) for item in lista]
    except ValueError:
        raise AcaoRecusada("A lista de endereços protegidos tem um item inválido.")


def validar_acao(acao, parametros):
    """Recusa na criação o que só falharia na hora do incidente."""
    if acao == "webhook":
        _destino_permitido(parametros.get("url"))
    elif acao == "bloquear_ip":
        protegidos = parametros.get("protegidos", [])
        if not isinstance(protegidos, list) or len(protegidos) > 200:
            raise AcaoRecusada("A lista de endereços protegidos é inválida.")
        redes_protegidas(protegidos)
        if parametros.get("duracao_minutos", DURACAO_PADRAO) not in DURACOES_EM_MINUTOS:
            raise AcaoRecusada("O bloqueio dura 1 hora, 1 dia ou 7 dias.")


def recusa_prevista(acao, parametros, alvo):
    """A simulação mostra o que seria recusado, sem chamar nada de fora."""
    if acao != "bloquear_ip":
        return None
    try:
        ip = ip_publico(alvo)
        if any(ipaddress.ip_address(ip) in rede for rede in redes_protegidas(parametros.get("protegidos", []))):
            return "protegido"
    except AcaoRecusada:
        return "sem endereço público"
    return None


def _ler_env(caminho):
    valores = {}
    with open(caminho, encoding="utf-8") as f:
        for linha in f:
            if "=" in linha and not linha.startswith("#"):
                k, v = linha.strip().split("=", 1)
                valores[k] = v
    return valores


def _api_do_gerenciador(gerenciador_id, metodo, rota, **kwargs):
    # Conexão local com a API do contêiner, cujo certificado é autoassinado.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    env = _ler_env(PASTA_GERENCIADORES / gerenciador_id / ".env")
    base = f"https://127.0.0.1:{env['PORTA_API']}"
    token = requests.post(f"{base}/security/user/authenticate?raw=true", auth=("roar", env["API_SENHA"]), verify=False, timeout=30)
    token.raise_for_status()
    r = requests.request(metodo, base + rota, headers={"Authorization": f"Bearer {token.text}"}, verify=False, timeout=60, **kwargs)
    r.raise_for_status()
    return r.json()


def bloquear_ip(gerenciador_id, contexto, parametros):
    """Usa a resposta ativa do Wazuh no ativo onde o alerta aconteceu."""
    alvo = ip_publico(contexto.get("alvo"))
    # O endereço de origem de um log pode ser forjado para derrubar um parceiro ou o próprio cliente.
    if any(ipaddress.ip_address(alvo) in rede for rede in redes_protegidas(parametros.get("protegidos", []))):
        raise AcaoRecusada(f"O endereço {alvo} está na lista de protegidos deste playbook.")
    agente = str(contexto.get("agente_id") or "")
    if not agente.isdigit() or agente == "000":
        raise AcaoRecusada("Sem ativo para aplicar o bloqueio.")
    duracao = parametros.get("duracao_minutos", DURACAO_PADRAO)
    if duracao not in DURACOES_EM_MINUTOS:
        raise AcaoRecusada("O bloqueio dura 1 hora, 1 dia ou 7 dias.")
    resposta = _api_do_gerenciador(
        gerenciador_id, "PUT", "/active-response", params={"agents_list": agente},
        json={"command": f"firewall-drop{duracao * 60}", "alert": {"data": {"srcip": alvo}}},
    )
    if resposta.get("data", {}).get("total_failed_items", 0) or not resposta.get("data", {}).get("total_affected_items"):
        raise RuntimeError(f"O ativo não recebeu o bloqueio: {str(resposta.get('data', {}).get('failed_items'))[:300]}")
    # Isto só diz que o pedido saiu. A confirmação é o alerta do ativo, que a tela procura depois.
    return {"enviado": alvo, "ativo": agente, "expira_em_minutos": duracao}


def _destino_permitido(endereco):
    partes = urlparse(str(endereco))
    if partes.scheme not in ("https", "http") or not partes.hostname:
        raise AcaoRecusada("Endereço de webhook inválido.")
    if partes.username or partes.password:
        raise AcaoRecusada("O endereço do webhook não pode trazer usuário e senha.")
    # Um webhook não pode virar caminho para a rede interna do próprio servidor.
    if os.getenv("ROAR_WEBHOOK_INTERNO") != "1":
        try:
            enderecos = {i[4][0] for i in socket.getaddrinfo(partes.hostname, partes.port or 443)}
        except socket.gaierror:
            raise AcaoRecusada("Não foi possível encontrar o endereço do webhook.")
        for e in enderecos:
            if not _e_publico(ipaddress.ip_address(e)):
                raise AcaoRecusada("O webhook não pode apontar para um endereço interno.")
    return str(endereco)


def webhook(gerenciador_id, contexto, parametros):
    destino = _destino_permitido(parametros.get("url"))
    corpo = {k: contexto.get(k) for k in ("playbook", "alvo", "agente_id", "origem_tipo", "origem_id", "titulo")}
    # O redirecionamento poderia levar a um endereço interno depois da checagem.
    r = requests.post(destino, json=corpo, timeout=15, allow_redirects=False)
    if r.status_code >= 500:
        raise RuntimeError(f"Webhook respondeu {r.status_code}")
    if r.status_code >= 300:
        raise AcaoRecusada(f"Webhook respondeu {r.status_code}")
    return {"status": r.status_code}


def registrar(gerenciador_id, contexto, parametros):
    return {"nota": str(parametros.get("texto", ""))[:1000]}


ACOES = {"bloquear_ip": bloquear_ip, "webhook": webhook, "registrar": registrar}
