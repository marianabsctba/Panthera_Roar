"""Ações de resposta. O alvo pode ter vindo de um alerta escrito por um atacante.

Por isso nada do alerta vira comando sem validação estrita: o IP precisa ser um IP de verdade
e público, e o endereço do webhook é o que a pessoa configurou no playbook, não o do alerta.
"""

import ipaddress
import os
import re
import sys
from pathlib import Path

import requests
import urllib3

# A mesma conexão presa ao IP conferido que a busca de fontes usa.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ingestao"))
from roar_ingestao import rede_externa  # noqa: E402

PASTA_GERENCIADORES = Path(os.getenv("ROAR_GERENCIADORES", "/opt/panthera-roar/gerenciadores"))
# Todo bloqueio vence sozinho: um endereço forjado num log não pode ficar bloqueado para sempre.
# Os mesmos prazos estão na configuração do gerenciador, em provisao.SEGUNDOS_DE_BLOQUEIO.
DURACOES_EM_MINUTOS = (60, 1440, 10080)
DURACAO_PADRAO = 60
METODO_PADRAO = "firewall"
# O mesmo pedido vira um comando diferente em cada sistema. None: não existe nesse sistema.
COMANDOS_DE_BLOQUEIO = {
    "firewall": {"linux": "firewall-drop", "windows": "netsh"},
    "rota": {"linux": "route-null", "windows": "win_route-null"},
    "hosts": {"linux": "host-deny", "windows": None},
}
CONTA_VALIDA = re.compile(r"[A-Za-z_][A-Za-z0-9._-]{0,63}")
# Desativar qualquer uma destas derruba o ativo ou tira o acesso de quem responderia ao incidente.
CONTAS_NUNCA_DESATIVADAS = {"root", "administrator", "administrador", "admin", "system", "wazuh", "ossec", "daemon", "bin", "sshd", "nobody"}


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
        if parametros.get("metodo", METODO_PADRAO) not in COMANDOS_DE_BLOQUEIO:
            raise AcaoRecusada("Forma de bloqueio desconhecida.")
    elif acao == "desativar_conta":
        protegidas = parametros.get("protegidas", [])
        if not isinstance(protegidas, list) or len(protegidas) > 200:
            raise AcaoRecusada("A lista de contas protegidas é inválida.")
        if parametros.get("duracao_minutos", DURACAO_PADRAO) not in DURACOES_EM_MINUTOS:
            raise AcaoRecusada("A conta volta em 1 hora, 1 dia ou 7 dias.")


def recusa_prevista(acao, parametros, alvo, usuario=None):
    """A simulação mostra o que seria recusado, sem chamar nada de fora."""
    if acao == "desativar_conta":
        try:
            conta_permitida(usuario, parametros.get("protegidas", []))
        except AcaoRecusada:
            return "conta protegida ou sem conta"
        return None
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
    try:
        env = _ler_env(PASTA_GERENCIADORES / gerenciador_id / ".env")
    except FileNotFoundError:
        raise AcaoRecusada("Este alerta veio de um gerenciador que não está conectado.")
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
    agente = _agente_do_contexto(contexto)
    duracao = _duracao(parametros)
    metodo = parametros.get("metodo", METODO_PADRAO)
    if metodo not in COMANDOS_DE_BLOQUEIO:
        raise AcaoRecusada("Forma de bloqueio desconhecida.")
    comando = COMANDOS_DE_BLOQUEIO[metodo][_plataforma(gerenciador_id, agente)]
    if not comando:
        raise AcaoRecusada(f"A forma de bloqueio {metodo} não existe no sistema deste ativo.")
    _resposta_ativa(gerenciador_id, agente, f"{comando}{duracao * 60}", {"srcip": alvo})
    # Isto só diz que o pedido saiu. A confirmação é o alerta do ativo, que a tela procura depois.
    return {"enviado": alvo, "ativo": agente, "expira_em_minutos": duracao, "comando": comando}


def conta_permitida(texto, protegidas=()):
    """O nome vem de um alerta e vira argumento de um script no ativo: só passa o que é claramente um nome."""
    conta = str(texto or "").strip()
    if not CONTA_VALIDA.fullmatch(conta):
        raise AcaoRecusada("O alerta não trouxe um nome de conta válido.")
    if conta.lower() in CONTAS_NUNCA_DESATIVADAS or conta.lower() in {str(p).strip().lower() for p in protegidas}:
        raise AcaoRecusada(f"A conta {conta} é protegida e não pode ser desativada.")
    return conta


def desativar_conta(gerenciador_id, contexto, parametros):
    """Vale para o ativo do alerta, e a conta volta sozinha ao fim do prazo. Em Windows o script não existe."""
    conta = conta_permitida(contexto.get("usuario"), parametros.get("protegidas", []))
    agente = _agente_do_contexto(contexto)
    duracao = _duracao(parametros)
    if _plataforma(gerenciador_id, agente) == "windows":
        raise AcaoRecusada("Desativar conta ainda não existe para ativos Windows.")
    _resposta_ativa(gerenciador_id, agente, f"disable-account{duracao * 60}", {"dstuser": conta})
    return {"enviado": conta, "ativo": agente, "expira_em_minutos": duracao, "comando": "disable-account"}


def _agente_do_contexto(contexto):
    agente = str(contexto.get("agente_id") or "")
    if not agente.isdigit() or agente == "000":
        raise AcaoRecusada("Sem ativo para aplicar a resposta.")
    return agente


def _duracao(parametros):
    duracao = parametros.get("duracao_minutos", DURACAO_PADRAO)
    if duracao not in DURACOES_EM_MINUTOS:
        raise AcaoRecusada("A resposta dura 1 hora, 1 dia ou 7 dias.")
    return duracao


def _plataforma(gerenciador_id, agente):
    resposta = _api_do_gerenciador(gerenciador_id, "GET", "/agents", params={"agents_list": agente, "select": "os.platform"})
    itens = resposta.get("data", {}).get("affected_items") or []
    if not itens:
        raise AcaoRecusada("Este ativo não existe no gerenciador.")
    return "windows" if itens[0].get("os", {}).get("platform") == "windows" else "linux"


def _resposta_ativa(gerenciador_id, agente, comando, dados):
    resposta = _api_do_gerenciador(gerenciador_id, "PUT", "/active-response", params={"agents_list": agente},
                                   json={"command": comando, "alert": {"data": dados}})
    if resposta.get("data", {}).get("total_failed_items", 0) or not resposta.get("data", {}).get("total_affected_items"):
        raise RuntimeError(f"O ativo não recebeu a resposta: {str(resposta.get('data', {}).get('failed_items'))[:300]}")


def _destino_permitido(endereco):
    try:
        rede_externa.resolver(endereco)
    except rede_externa.DestinoRecusado as erro:
        raise AcaoRecusada(str(erro))
    return str(endereco)


def webhook(gerenciador_id, contexto, parametros):
    destino = _destino_permitido(parametros.get("url"))
    corpo = {k: contexto.get(k) for k in ("playbook", "alvo", "agente_id", "origem_tipo", "origem_id", "titulo")}
    try:
        r, _ = rede_externa.chamar("POST", destino, json=corpo)
    except rede_externa.DestinoRecusado as erro:
        raise AcaoRecusada(str(erro))
    if r.status_code >= 500:
        raise RuntimeError(f"Webhook respondeu {r.status_code}")
    if r.status_code >= 300:
        raise AcaoRecusada(f"Webhook respondeu {r.status_code}")
    return {"status": r.status_code}


def registrar(gerenciador_id, contexto, parametros):
    return {"nota": str(parametros.get("texto", ""))[:1000]}


ACOES = {"bloquear_ip": bloquear_ip, "desativar_conta": desativar_conta, "webhook": webhook, "registrar": registrar}
