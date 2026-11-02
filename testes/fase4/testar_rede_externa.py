#!/usr/bin/env python3
"""Conexões a endereços informados pelo cliente: o que não pode alcançar a rede interna.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_rede_externa.py

Cria um servidor local, que representa um serviço interno, e tenta alcançá-lo por vários caminhos.
"""

import os
import socket
import ssl
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ / "ingestao"))

from roar_ingestao import rede_externa as rede  # noqa: E402

RESULTADOS = []
ALCANCADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


class Interno(BaseHTTPRequestHandler):
    def do_GET(self):
        ALCANCADOS.append((self.path, self.headers.get("Host")))
        if self.path == "/redireciona":
            self.send_response(302)
            self.send_header("Location", "/segredo")
            self.end_headers()
        elif self.path == "/grande":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * 300_000)
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def recusado(endereco):
    try:
        rede.chamar("GET", endereco)
        return False
    except rede.DestinoRecusado:
        return True


def certificado_para(pasta, nome):
    chave = ec.generate_private_key(ec.SECP256R1())
    sujeito = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome)])
    agora = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(sujeito).issuer_name(sujeito).public_key(chave.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(agora - timedelta(minutes=5)).not_valid_after(agora + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(nome)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(chave, hashes.SHA256()))
    caminho_cert, caminho_chave = pasta / "cert.pem", pasta / "chave.pem"
    caminho_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    caminho_chave.write_bytes(chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return caminho_cert, caminho_chave


def testar_https():
    print("\n== HTTPS preso ao IP", flush=True)
    nome = "api.exemplo.test"
    cert, chave = certificado_para(Path(tempfile.mkdtemp(prefix="roar-tls-")), nome)
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.load_cert_chain(cert, chave)
    servidor = HTTPServer(("127.0.0.1", 0), Interno)
    servidor.socket = contexto.wrap_socket(servidor.socket, server_side=True)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    porta = servidor.server_address[1]
    original = socket.getaddrinfo

    def falso(host, *args, **kwargs):
        if host.endswith(".exemplo.test"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", porta))]
        return original(host, *args, **kwargs)

    with mock.patch("socket.getaddrinfo", falso):
        ALCANCADOS.clear()
        resposta, corpo = rede.chamar("GET", f"https://{nome}:{porta}/ok", verify=str(cert))
        registrar("certificado válido para o nome passa", resposta.status_code == 200 and corpo == b"ok")
        registrar("o sistema de destino recebe o nome no Host", ALCANCADOS and ALCANCADOS[-1][1] == f"{nome}:{porta}", str(ALCANCADOS[-1:]))
        try:
            rede.chamar("GET", f"https://outro.exemplo.test:{porta}/ok", verify=str(cert))
            registrar("certificado de outro nome é recusado", False)
        except requests.exceptions.SSLError:
            registrar("certificado de outro nome é recusado", True)
        try:
            rede.chamar("GET", f"https://{nome}:{porta}/ok")
            registrar("certificado sem autoridade conhecida é recusado", False)
        except requests.exceptions.SSLError:
            registrar("certificado sem autoridade conhecida é recusado", True)
    servidor.shutdown()
    os.environ.pop("ROAR_DESTINO_INTERNO", None)
    # Um site público de verdade, com certificado real, sem nada de cliente na chamada.
    resposta, _ = rede.chamar("GET", "https://documentation.wazuh.com/")
    registrar("site público de verdade funciona", resposta.status_code in (200, 301, 302), str(resposta.status_code))


def main():
    servidor = HTTPServer(("127.0.0.1", 0), Interno)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    porta = servidor.server_address[1]
    os.environ.pop("ROAR_DESTINO_INTERNO", None)

    print("== Endereços internos", flush=True)
    for nome, endereco in (("IP local", f"http://127.0.0.1:{porta}/"), ("nome local", f"http://localhost:{porta}/"),
                           ("IP local em decimal", f"http://2130706433:{porta}/"), ("IP local em hexadecimal", f"http://0x7f.0.0.1:{porta}/"),
                           ("zero", f"http://0.0.0.0:{porta}/"), ("IPv6 local", f"http://[::1]:{porta}/"),
                           ("IPv4 dentro de IPv6", f"http://[::ffff:127.0.0.1]:{porta}/"),
                           ("metadados de nuvem", "http://169.254.169.254/latest/meta-data/"),
                           ("rede privada", "http://10.0.0.1/"), ("rede privada 172", "http://172.17.0.1/"), ("rede privada 192", "http://192.168.0.1/"),
                           ("CGNAT", "http://100.64.0.1/"), ("multicast", "http://224.0.0.1/"),
                           ("com senha", "https://a:b@exemplo.com/"), ("outro protocolo", "file:///etc/passwd"), ("gopher", "gopher://127.0.0.1/"),
                           ("sem endereço", ""), ("porta inválida", "https://exemplo.com:99999/")):
        registrar(f"recusado: {nome}", recusado(endereco))
    registrar("nada alcançou o serviço interno", not ALCANCADOS, str(ALCANCADOS))

    print("\n== DNS que muda de resposta", flush=True)
    original = socket.getaddrinfo
    respostas = []

    def falso(host, *args, **kwargs):
        if host != "rebind.exemplo.test":
            return original(host, *args, **kwargs)
        respostas.append(host)
        # Primeira consulta: público, para passar na checagem. Depois: o serviço interno.
        ip = "1.1.1.1" if len(respostas) == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, kwargs.get("port", 80)))]

    with mock.patch("socket.getaddrinfo", falso):
        _, ip = rede.resolver(f"http://rebind.exemplo.test:{porta}/")
        registrar("a checagem vê o endereço público", ip == "1.1.1.1", ip)
        try:
            # A conexão precisa ir ao 1.1.1.1 conferido, sem consultar o nome de novo.
            with mock.patch.object(rede, "resolver", lambda e: (rede.urlsplit(e), "1.1.1.1")):
                rede.TEMPO_LIMITE, antes = 2, rede.TEMPO_LIMITE
                rede.chamar("GET", f"http://rebind.exemplo.test:{porta}/segredo")
                rede.TEMPO_LIMITE = antes
        except Exception as erro:
            rede.TEMPO_LIMITE = antes
            print(f"   conexão ao endereço conferido não completou: {type(erro).__name__}")
        registrar("a conexão não consulta o nome de novo", len(respostas) == 1, f"{len(respostas)} consulta")
        registrar("o serviço interno não foi alcançado", not ALCANCADOS, str(ALCANCADOS))
    with mock.patch("socket.getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 80)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]):
        registrar("nome com um endereço público e um interno é recusado", recusado("http://misto.exemplo.test/"))

    print("\n== Com a rede interna liberada", flush=True)
    os.environ["ROAR_DESTINO_INTERNO"] = "1"
    resposta, corpo = rede.chamar("GET", f"http://127.0.0.1:{porta}/ok")
    registrar("chega ao destino", resposta.status_code == 200 and corpo == b"ok")
    registrar("o Host é o informado", ALCANCADOS[-1][1] == f"127.0.0.1:{porta}", str(ALCANCADOS[-1]))
    ALCANCADOS.clear()
    resposta, _ = rede.chamar("GET", f"http://127.0.0.1:{porta}/redireciona")
    registrar("não segue redirecionamento", resposta.status_code == 302 and [a[0] for a in ALCANCADOS] == ["/redireciona"], str(ALCANCADOS))
    try:
        rede.chamar("GET", f"http://127.0.0.1:{porta}/grande", limite_de_bytes=100_000)
        registrar("resposta grande demais é recusada", False)
    except rede.DestinoRecusado:
        registrar("resposta grande demais é recusada", True)
    servidor.shutdown()
    testar_https()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
