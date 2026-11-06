#!/usr/bin/env python3
"""Avisos por e-mail: conexão segura com servidor de e-mail de verdade (local, com certificado próprio) e a volta do serviço
com banco real.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_avisos.py
"""

import datetime
import os
import socket
import ssl
import sys
import tempfile
import threading
import uuid
from pathlib import Path

import psycopg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao")]

from roar_ingestao import avisos, rede_externa  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def certificado(pasta):
    """Certificado para localhost, assinado por ele mesmo: o cliente confia só nele."""
    chave = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    agora = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome).public_key(chave.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(agora - datetime.timedelta(minutes=5)).not_valid_after(agora + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(chave, hashes.SHA256()))
    (pasta / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (pasta / "chave.pem").write_bytes(chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return pasta / "cert.pem", pasta / "chave.pem"


class ServidorDeEmail:
    """SMTP mínimo sobre TLS direto: o bastante para o smtplib entrar, autenticar e mandar."""

    def __init__(self, cert, chave, senha="certa"):
        self.contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.contexto.load_cert_chain(cert, chave)
        self.senha, self.recebidos = senha, []
        self.ouvinte = socket.create_server(("127.0.0.1", 0))
        self.porta = self.ouvinte.getsockname()[1]
        threading.Thread(target=self._aceitar, daemon=True).start()

    def _aceitar(self):
        while True:
            try:
                bruto, _ = self.ouvinte.accept()
            except OSError:
                return
            threading.Thread(target=self._atender, args=(bruto,), daemon=True).start()

    def _atender(self, bruto):
        try:
            con = self.contexto.wrap_socket(bruto, server_side=True)
        except (ssl.SSLError, OSError):
            return
        arquivo = con.makefile("rb")
        def dizer(t):
            con.sendall(t.encode() + b"\r\n")
        dizer("220 teste")
        dados, lendo = [], False
        for linha in arquivo:
            texto = linha.decode(errors="replace").rstrip("\r\n")
            if lendo:
                if texto == ".":
                    lendo = False
                    self.recebidos.append("\n".join(dados))
                    dados = []
                    dizer("250 ok")
                else:
                    dados.append(texto)
                continue
            comando = texto.split(" ")[0].upper()
            if comando == "EHLO":
                dizer("250-teste")
                dizer("250 AUTH PLAIN")
            elif comando == "AUTH":
                import base64
                partes = base64.b64decode(texto.split(" ")[2]).split(b"\0")
                dizer("235 ok" if partes[-1].decode() == self.senha else "535 senha errada")
            elif comando in ("MAIL", "RCPT"):
                dizer("250 ok")
            elif comando == "DATA":
                lendo = True
                dizer("354 manda")
            elif comando == "QUIT":
                dizer("221 tchau")
                break
            else:
                dizer("250 ok")
        con.close()


def main():
    pasta = Path(tempfile.mkdtemp(prefix="roar-email-"))
    cert, chave = certificado(pasta)
    servidor = ServidorDeEmail(cert, chave)
    confia = ssl.create_default_context(cafile=str(cert))
    config = {"servidor": "localhost", "porta": servidor.porta, "seguranca": "ssl", "usuario": "roar", "remetente": "roar@exemplo.test",
              "destinatarios": ["soc@exemplo.test"]}

    print("== Servidor de e-mail", flush=True)
    os.environ.pop("ROAR_DESTINO_INTERNO", None)
    try:
        avisos.conectar(config, "certa", confia)
        registrar("servidor na rede interna é recusado", False)
    except avisos.EnvioFalhou as erro:
        registrar("servidor na rede interna é recusado", "rede interna" in str(erro), str(erro))
    os.environ["ROAR_DESTINO_INTERNO"] = "1"
    smtp = avisos.conectar(config, "certa", confia)
    msg = avisos.mensagem(config, "Org <b>", "Panthera Roar: 2 avisos novos", [("Busca agendada", "Admin <script>", "06/11/2026 10:00 UTC", 3)])
    smtp.send_message(msg)
    smtp.quit()
    recebido = servidor.recebidos[-1] if servidor.recebidos else ""
    registrar("entra com TLS e senha e manda a mensagem", "Subject: Panthera Roar: 2 avisos novos" in recebido and "soc@exemplo.test" in recebido, recebido[:120])
    registrar("o HTML do e-mail não leva marcação vinda do alerta", "&lt;script&gt;" in recebido and "<script>" not in recebido.split("text/html", 1)[-1])
    registrar("o aviso repetido diz quantas vezes", "(3 vezes)" in recebido)
    try:
        avisos.conectar(config, "errada", confia)
        registrar("senha errada vira motivo claro", False)
    except avisos.EnvioFalhou as erro:
        registrar("senha errada vira motivo claro", "usuário ou a senha" in str(erro), str(erro))
    try:
        avisos.conectar({**config, "servidor": "127.0.0.1"}, "certa", confia)
        registrar("certificado de outro nome é recusado", False)
    except avisos.EnvioFalhou as erro:
        registrar("certificado de outro nome é recusado", "certificado" in str(erro), str(erro))
    try:
        avisos.conectar({**config, "porta": 9}, "certa", confia)
        registrar("porta sem servidor vira motivo claro", False)
    except avisos.EnvioFalhou as erro:
        registrar("porta sem servidor vira motivo claro", "Não foi possível falar" in str(erro) and "127.0.0.1" not in str(erro), str(erro))
    os.environ.pop("ROAR_DESTINO_INTERNO", None)
    _ = rede_externa

    print("\n== Volta do serviço", flush=True)
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"email-{uuid.uuid4().hex[:8]}",)).fetchone()[0])
    mandados, falhar = [], [False]

    def enviar(config_, senha, mensagem):
        if falhar[0]:
            raise avisos.EnvioFalhou("O servidor de e-mail recusou a mensagem.")
        mandados.append((config_, senha, mensagem))

    def aviso(tipo, alvo, contagem=1):
        return admin.execute("INSERT INTO notificacoes (cliente_id, tipo, alvo, contagem) VALUES (%s, %s, %s, %s) RETURNING id", (cliente, tipo, alvo, contagem)).fetchone()[0]

    try:
        antigo = aviso("busca_agendada", "do passado")
        admin.execute("""INSERT INTO email_config (cliente_id, servidor, porta, seguranca, remetente, destinatarios, tipos, ultima_notificacao)
                         VALUES (%s, 'smtp.exemplo.test', 587, 'starttls', 'roar@exemplo.test', '{soc@exemplo.test}', '{busca_agendada,indicador_encontrado}', %s)""", (cliente, antigo))
        avisos.volta(banco, enviar)
        registrar("sem aviso novo, nada sai", not [m for m in mandados if cliente in str(m)] and not mandados)
        aviso("busca_agendada", "Admin fora do horário", 2)
        aviso("indicador_encontrado", "203.0.113.9")
        aviso("logon_recusado", "fora da lista")
        avisos.volta(banco, enviar)
        registrar("os avisos novos vão juntos num e-mail só", len(mandados) == 1, str(len(mandados)))
        corpo = mandados[-1][2].get_body(("plain",)).get_content() if mandados else ""
        registrar("só os tipos escolhidos, com o nome em português", "Busca agendada encontrou" in corpo and "203.0.113.9" in corpo and "fora da lista" not in corpo and "do passado" not in corpo, corpo[:200])
        registrar("o assunto diz quantos e de qual organização", mandados and mandados[-1][2]["Subject"].startswith("Panthera Roar: 2 avisos novos em email-"))
        avisos.volta(banco, enviar)
        registrar("o mesmo aviso não sai duas vezes", len(mandados) == 1)
        falhar[0] = True
        aviso("busca_agendada", "Segunda vez")
        avisos.volta(banco, enviar)
        erro = admin.execute("SELECT ultimo_erro FROM email_config WHERE cliente_id = %s", (cliente,)).fetchone()[0]
        registrar("falha no envio fica na tela e o aviso espera", erro == "O servidor de e-mail recusou a mensagem.", str(erro))
        falhar[0] = False
        avisos.volta(banco, enviar)
        registrar("na volta seguinte o aviso que esperou sai", len(mandados) == 2 and "Segunda vez" in mandados[-1][2].get_body(("plain",)).get_content())
        registrar("e o erro some", admin.execute("SELECT ultimo_erro FROM email_config WHERE cliente_id = %s", (cliente,)).fetchone()[0] is None)
        admin.execute("UPDATE email_config SET teste_pedido_em = now(), ativo = false WHERE cliente_id = %s", (cliente,))
        avisos.volta(banco, enviar)
        teste = admin.execute("SELECT teste_pedido_em, teste_resultado FROM email_config WHERE cliente_id = %s", (cliente,)).fetchone()
        registrar("o e-mail de teste sai mesmo desligado, e responde ok", teste == (None, "ok") and mandados[-1][2]["Subject"] == "Panthera Roar: e-mail de teste", str(teste))
    finally:
        for tabela in ("email_config", "notificacoes"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
