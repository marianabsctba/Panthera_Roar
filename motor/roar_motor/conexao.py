"""Conexão com o Temporal, sempre com o certificado de cliente.

O servidor recusa quem não apresenta certificado da autoridade do Roar. A chave só é lida por quem roda a automação.
"""

import os
from pathlib import Path

from temporalio.client import Client
from temporalio.service import TLSConfig

PASTA = Path(os.getenv("ROAR_TEMPORAL_TLS", "/opt/panthera-roar/temporal-tls/cliente"))


def tls():
    if not (PASTA / "cliente.pem").exists():
        # Instalação anterior aos certificados: o instalador cria na próxima atualização.
        return False
    return TLSConfig(server_root_ca_cert=(PASTA / "ca.pem").read_bytes(), client_cert=(PASTA / "cliente.pem").read_bytes(),
                     client_private_key=(PASTA / "cliente.key").read_bytes(), domain="temporal")


async def conectar():
    return await Client.connect(os.getenv("ROAR_TEMPORAL", "127.0.0.1:7233"), namespace="roar", tls=tls())
