"""Confere cada item de uma lista de observação conforme o tipo, e diz como uma regra em XML consulta a lista."""

import ipaddress
import re

TIPOS = {"ip": "Endereços IP", "usuario": "Usuários", "dominio": "Domínios", "hash": "Hashes de arquivo", "texto": "Texto livre"}
ITENS_POR_LISTA = 50000
ITENS_POR_VEZ = 10000
# O campo do evento que cada tipo costuma consultar, e como o Wazuh compara.
CONSULTA = {
    "ip": ("srcip", "address_match_key"),
    "usuario": ("dstuser", "match_key"),
    "dominio": ("url", "match_key"),
    "hash": ("sha256_after", "match_key"),
    "texto": ("data", "match_key"),
}
_DOMINIO = re.compile(r"(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}")
_HASH = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")


class ItemInvalido(ValueError):
    pass


def normalizar(tipo, valor):
    """O item como vai para o arquivo. Rede vira prefixo, que é como o Wazuh compara endereços."""
    valor = valor.strip()
    if not valor or len(valor) > 255 or any(c in valor for c in '"\r\n\0'):
        raise ItemInvalido("Item vazio, longo demais ou com aspas.")
    if tipo == "ip":
        try:
            rede = ipaddress.ip_network(valor, strict=False)
        except ValueError:
            raise ItemInvalido(f"{valor} não é um endereço IP nem uma rede.") from None
        if rede.num_addresses == 1:
            return str(rede.network_address)
        if rede.version == 4 and rede.prefixlen in (8, 16, 24):
            return ".".join(str(rede.network_address).split(".")[:rede.prefixlen // 8]) + "."
        raise ItemInvalido(f"{valor}: a lista aceita endereços sozinhos ou redes /8, /16 e /24.")
    if tipo == "dominio":
        valor = valor.lower().rstrip(".")
        if not _DOMINIO.fullmatch(valor):
            raise ItemInvalido(f"{valor} não é um domínio.")
        return valor
    if tipo == "hash":
        valor = valor.lower()
        if not _HASH.fullmatch(valor):
            raise ItemInvalido(f"{valor} não é um hash MD5, SHA-1 ou SHA-256.")
        return valor
    return valor


def exemplo_de_regra(nome, tipo, titulo):
    """Uma regra em XML, sem o grupo: o editor de regras põe o grupo e ajusta o número na hora de instalar."""
    campo, comparacao = CONSULTA[tipo]
    return (f'<rule id="100000" level="10">\n'
            f'  <list field="{campo}" lookup="{comparacao}">etc/lists/roar/{nome}</list>\n'
            f'  <description>Item da lista {titulo.replace("<", "").replace(">", "").replace("&", "e")} visto</description>\n'
            f'</rule>\n')
