"""Segundo fator por aplicativo autenticador (TOTP).

O segredo precisa ser lido para conferir o código, então não dá para guardar só um hash: fica cifrado com
uma chave fora do banco, e amarrado à pessoa, para um valor copiado para outra conta não abrir.
"""

import hashlib
import hmac
import io
import os
import secrets
import time

import pyotp
import segno
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PASSO = 30
JANELA = 1
CODIGOS_DE_RECUPERACAO = 10
EMISSOR = "Panthera Roar"
NONCE = 12


class SegredoInvalido(Exception):
    pass


def _chave(mestra):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"roar-mfa-v1").derive(mestra.encode())


def selar(mestra, usuario, segredo):
    nonce = os.urandom(NONCE)
    return nonce + AESGCM(_chave(mestra)).encrypt(nonce, segredo.encode(), str(usuario).encode())


def abrir(mestra, usuario, selado):
    selado = bytes(selado)
    try:
        return AESGCM(_chave(mestra)).decrypt(selado[:NONCE], selado[NONCE:], str(usuario).encode()).decode()
    except (InvalidTag, ValueError):
        raise SegredoInvalido()


def novo_segredo():
    return pyotp.random_base32()


def endereco(segredo, conta):
    return pyotp.TOTP(segredo, interval=PASSO).provisioning_uri(name=conta, issuer_name=EMISSOR)


def qr_em_svg(uri):
    """O QR sai daqui, sem serviço de fora: quem gerasse a imagem veria o segredo."""
    saida = io.BytesIO()
    segno.make(uri, error="m").save(saida, kind="svg", scale=5, border=2, dark="#000", light="#fff", xmldecl=False, svgns=True, omitsize=False)
    return saida.getvalue().decode()


def passo_do_codigo(segredo, codigo, agora=None):
    """Devolve o passo de tempo em que o código vale, ou None. Quem usa precisa gravar o passo para não aceitar de novo."""
    codigo = str(codigo).strip().replace(" ", "")
    if not (len(codigo) == 6 and codigo.isascii() and codigo.isdigit()):
        return None
    agora = int(agora if agora is not None else time.time())
    totp = pyotp.TOTP(segredo, interval=PASSO)
    achado = None
    # Sem sair no primeiro acerto: o tempo de resposta não pode dizer em qual janela o código caiu.
    for deslocamento in range(-JANELA, JANELA + 1):
        momento = agora + deslocamento * PASSO
        if hmac.compare_digest(totp.at(momento), codigo):
            achado = momento // PASSO
    return achado


def novos_codigos_de_recuperacao():
    return [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(CODIGOS_DE_RECUPERACAO)]


def hash_do_codigo(usuario, codigo):
    return hashlib.sha256(f"{usuario}:{str(codigo).strip().lower()}".encode()).hexdigest()
