"""Guarda credenciais de cada cliente sem que a API consiga lê-las de volta.

    python -m roar_ingestao.cofre gerar

A API só tem a chave pública: fecha o segredo e não abre. Quem abre é o serviço que configura o
gerenciador, com a chave privada, que nunca vai ao banco. O cliente e o nome entram na autenticação,
então copiar um valor cifrado para outro cliente ou outra credencial faz a abertura falhar.
"""

import argparse
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PASTA = Path(os.getenv("ROAR_COFRE", "/opt/panthera-roar/cofre"))
TAMANHO_DA_CHAVE = 32
TAMANHO_DO_NONCE = 12
RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class SegredoInvalido(Exception):
    """Valor adulterado, de outro cliente ou aberto com a chave errada."""


def _chave_de_sessao(compartilhado, publica_efemera, publica_destino):
    # As duas chaves públicas entram na derivação, como o RFC 9180 recomenda para este tipo de troca.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"roar-cofre-v1" + publica_efemera + publica_destino).derive(compartilhado)


def _contexto(cliente, nome):
    # Com o tamanho de cada campo na frente, dois pares diferentes nunca viram o mesmo texto.
    cliente, nome = str(cliente).encode(), nome.encode()
    return b"%d:%s%d:%s" % (len(cliente), cliente, len(nome), nome)


def selar(publica, cliente, nome, texto):
    destino = X25519PublicKey.from_public_bytes(publica)
    efemera = X25519PrivateKey.generate()
    publica_efemera = efemera.public_key().public_bytes(*RAW)
    chave = _chave_de_sessao(efemera.exchange(destino), publica_efemera, publica)
    nonce = os.urandom(TAMANHO_DO_NONCE)
    return publica_efemera + nonce + AESGCM(chave).encrypt(nonce, texto.encode(), _contexto(cliente, nome))


def abrir(privada, cliente, nome, selado):
    selado = bytes(selado)
    if len(selado) <= TAMANHO_DA_CHAVE + TAMANHO_DO_NONCE:
        raise SegredoInvalido("valor curto demais")
    publica_efemera = selado[:TAMANHO_DA_CHAVE]
    nonce = selado[TAMANHO_DA_CHAVE:TAMANHO_DA_CHAVE + TAMANHO_DO_NONCE]
    minha = X25519PrivateKey.from_private_bytes(privada)
    chave = _chave_de_sessao(minha.exchange(X25519PublicKey.from_public_bytes(publica_efemera)), publica_efemera,
                             minha.public_key().public_bytes(*RAW))
    try:
        return AESGCM(chave).decrypt(nonce, selado[TAMANHO_DA_CHAVE + TAMANHO_DO_NONCE:], _contexto(cliente, nome)).decode()
    except InvalidTag:
        raise SegredoInvalido("autenticação falhou")


def ler_publica(pasta=PASTA):
    return (pasta / "publica").read_bytes()


def ler_privada(pasta=PASTA):
    return (pasta / "privada").read_bytes()


def gerar(pasta=PASTA):
    """Nunca sobrescreve: trocar a chave perderia todas as credenciais guardadas."""
    privada = pasta / "privada"
    if privada.exists():
        return False
    pasta.mkdir(parents=True, exist_ok=True, mode=0o711)
    chave = X25519PrivateKey.generate()
    descritor = os.open(privada, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descritor, "wb") as f:
        f.write(chave.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    (pasta / "publica").write_bytes(chave.public_key().public_bytes(*RAW))
    (pasta / "publica").chmod(0o644)
    return True


def main():
    args = argparse.ArgumentParser()
    comandos = args.add_subparsers(dest="comando", required=True)
    comandos.add_parser("gerar")
    args.parse_args()
    print("Chaves criadas." if gerar() else "As chaves já existem: nada mudou.")


if __name__ == "__main__":
    main()
