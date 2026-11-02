"""Chamadas a endereços que o cliente informou, sem virar um caminho para a rede interna do servidor.

Conferir o nome e deixar a biblioteca resolver de novo não basta: um DNS pode responder um endereço
público na checagem e um interno na conexão. Aqui a conexão vai para o IP já conferido, e o certificado
continua sendo validado pelo nome original.
"""

import ipaddress
import os
import socket
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter

TEMPO_LIMITE = 15


class DestinoRecusado(Exception):
    """A mensagem aparece na tela, então precisa explicar o que corrigir."""


def _rede_interna_liberada():
    # Para instalações cujo sistema de destino está de propósito na rede interna, e para os testes.
    return os.getenv("ROAR_DESTINO_INTERNO") == "1"


def e_publico(ip):
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_global and not ip.is_multicast


def resolver(endereco):
    """Devolve as partes do endereço e o IP conferido em que a conexão deve ser feita."""
    partes = urlsplit(str(endereco))
    if partes.scheme not in ("https", "http") or not partes.hostname:
        raise DestinoRecusado("Endereço inválido: use um endereço web completo.")
    if partes.username or partes.password:
        raise DestinoRecusado("O endereço não pode trazer usuário e senha.")
    try:
        porta = partes.port
    except ValueError:
        raise DestinoRecusado("A porta do endereço é inválida.")
    try:
        encontrados = {i[4][0] for i in socket.getaddrinfo(partes.hostname, porta or (443 if partes.scheme == "https" else 80), type=socket.SOCK_STREAM)}
    except (socket.gaierror, UnicodeError):
        raise DestinoRecusado("Não foi possível encontrar este endereço.")
    ips = [ipaddress.ip_address(e.split("%")[0]) for e in encontrados]
    if not _rede_interna_liberada() and not all(e_publico(ip) for ip in ips):
        raise DestinoRecusado("O endereço não pode apontar para uma rede interna.")
    return partes, str(ips[0])


class _PresoAoIp(HTTPAdapter):
    """Conecta no IP conferido e valida o TLS pelo nome que a pessoa informou."""

    def __init__(self, nome, **kwargs):
        self.nome = nome
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["server_hostname"] = self.nome
        kwargs["assert_hostname"] = self.nome
        super().init_poolmanager(*args, **kwargs)


def chamar(metodo, endereco, cabecalhos=None, limite_de_bytes=None, **kwargs):
    """Sem redirecionamento: ele levaria a um endereço que nunca foi conferido."""
    partes, ip = resolver(endereco)
    hospedeiro = f"[{ip}]" if ":" in ip else ip
    if partes.port:
        hospedeiro += f":{partes.port}"
    direto = urlunsplit((partes.scheme, hospedeiro, partes.path or "/", partes.query, ""))
    with requests.Session() as sessao:
        sessao.trust_env = False
        sessao.mount(f"https://{hospedeiro}", _PresoAoIp(partes.hostname))
        resposta = sessao.request(metodo, direto, headers={**(cabecalhos or {}), "Host": partes.netloc}, timeout=TEMPO_LIMITE,
                                  allow_redirects=False, stream=limite_de_bytes is not None, **kwargs)
        if limite_de_bytes is None:
            return resposta, resposta.content
        corpo = bytearray()
        for pedaco in resposta.iter_content(65536):
            corpo += pedaco
            if len(corpo) > limite_de_bytes:
                resposta.close()
                raise DestinoRecusado("A resposta é grande demais.")
        return resposta, bytes(corpo)
