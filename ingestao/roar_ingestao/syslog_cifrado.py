"""Syslog cifrado (TLS): um receptor só para a instalação, na porta 6514, para equipamentos que mandam log pela internet.

O Wazuh não recebe syslog com TLS. Quem recebe é um Vector (serviço recepcao, infra/docker-compose.yml) com o certificado
de uma autoridade própria da instalação, que o cliente importa no equipamento. O receptor só aceita os endereços
cadastrados em fontes de syslog cifrado e repassa cada linha, sem a prioridade do começo, ao coletor do gerenciador dono
daquele endereço, pela porta de repasse na rede dos gerenciadores (coletor_syslog.PORTA_DO_REPASSE), com a chave da
instalação e o endereço do equipamento na frente. Dali em diante é igual ao syslog comum: o coletor entrega ao analisador
do gerenciador com o endereço do equipamento como origem.

Um mesmo endereço não pode ir para duas organizações: a fonte mais antiga fica com ele, e a outra é recusada com o motivo.
"""

import ipaddress
import json
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("roar.syslog_cifrado")
PASTA = Path("/opt/panthera-roar/syslog-cifrado")
MODELO = Path(__file__).resolve().parent / "syslog_cifrado.yaml"
PORTA = 6514
NOME_DE_GERENCIADOR = re.compile(r"[a-z0-9]{6,32}")


def chave_do_repasse(raiz=PASTA):
    """A chave que o receptor põe na frente de cada linha repassada, e que o coletor confere. Criada na primeira vez."""
    arquivo = raiz / "autoridade" / "repasse"
    if not arquivo.exists():
        arquivo.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        arquivo.touch(mode=0o600)
        arquivo.chmod(0o600)
        arquivo.write_text(secrets.token_hex(32))
    return arquivo.read_text().strip()


def preparar(dominio, raiz=PASTA):
    """Pastas e certificados. Pode rodar de novo: a autoridade não muda, e o certificado do servidor só é refeito quando o
    domínio muda ou está para vencer (o equipamento confia na autoridade, não no certificado do servidor)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    # A chave da autoridade fica fora do que o receptor monta: ele só precisa do certificado do servidor.
    certificados, autoridade = raiz / "certificados", raiz / "autoridade"
    for pasta, modo in ((raiz, 0o755), (certificados, 0o755), (autoridade, 0o700), (raiz / "configuracao", 0o700)):
        pasta.mkdir(parents=True, exist_ok=True)
        pasta.chmod(modo)
    agora = datetime.now(timezone.utc)

    def gravar_chave(chave, arquivo):
        arquivo.touch(mode=0o600)
        arquivo.chmod(0o600)
        arquivo.write_bytes(chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    ca_pem, ca_chave_pem = certificados / "autoridade.pem", autoridade / "autoridade-chave.pem"
    if not ca_pem.exists():
        chave = ec.generate_private_key(ec.SECP256R1())
        nome = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Panthera Roar"),
                          x509.NameAttribute(NameOID.COMMON_NAME, f"Autoridade do syslog cifrado ({dominio})")])
        ca = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome).public_key(chave.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(agora - timedelta(minutes=5)).not_valid_after(agora + timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False,
                                           data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
              .sign(chave, hashes.SHA256()))
        gravar_chave(chave, ca_chave_pem)
        ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        ca_pem.chmod(0o644)
    ca = x509.load_pem_x509_certificate(ca_pem.read_bytes())
    ca_chave = serialization.load_pem_private_key(ca_chave_pem.read_bytes(), password=None)

    servidor_pem, servidor_chave_pem = certificados / "servidor.pem", certificados / "servidor-chave.pem"
    try:
        nome = ipaddress.ip_address(dominio)
        alternativo = x509.IPAddress(nome)
    except ValueError:
        alternativo = x509.DNSName(dominio)
    if servidor_pem.exists():
        atual = x509.load_pem_x509_certificate(servidor_pem.read_bytes())
        nomes = atual.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if alternativo in nomes and atual.not_valid_after_utc - agora > timedelta(days=30):
            return False
    chave = ec.generate_private_key(ec.SECP256R1())
    servidor = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dominio)])).issuer_name(ca.subject)
                .public_key(chave.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(agora - timedelta(minutes=5)).not_valid_after(agora + timedelta(days=397))
                .add_extension(x509.SubjectAlternativeName([alternativo]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_chave, hashes.SHA256()))
    gravar_chave(chave, servidor_chave_pem)
    servidor_pem.write_bytes(servidor.public_bytes(serialization.Encoding.PEM) + ca_pem.read_bytes())
    servidor_pem.chmod(0o644)
    return True


def distribuir(fontes, motivo="O endereço {} já envia syslog cifrado para outra organização desta instalação."):
    """fontes: [{"id", "gerenciador", "origens", "criada_em"}] de todas as organizações. Devolve (rotas, recusadas):
    rotas é [(rede, gerenciador)], e recusadas, {id da fonte: motivo}. A mais antiga fica com a rede."""
    rotas, recusadas = [], {}
    for fonte in sorted(fontes, key=lambda f: (f["criada_em"], f["id"])):
        redes = [ipaddress.ip_network(r) for r in fonte["origens"]]
        conflito = next((r for r in redes for tomada, dono in rotas if dono != fonte["gerenciador"] and r.overlaps(tomada)), None)
        if conflito:
            recusadas[fonte["id"]] = motivo.format(conflito)
            continue
        rotas += [(r, fonte["gerenciador"]) for r in redes if (r, fonte["gerenciador"]) not in rotas]
    return [(str(r), g) for r, g in rotas], recusadas


def saidas(rotas, entrada, prefixo, porta):
    """O roteador e uma saída por gerenciador, para o coletor dele, no fim de uma configuração do receptor. Sem rota, uma
    saída que descarta (o Vector exige ao menos uma). Serve ao syslog cifrado e aos fluxos (fluxos.py)."""
    gerenciadores = sorted({g for _, g in rotas})
    for g in gerenciadores:
        if not NOME_DE_GERENCIADOR.fullmatch(g):
            raise ValueError("gerenciador inválido")
    if not gerenciadores:
        return f"sinks:\n  {prefixo}nenhum:\n    type: blackhole\n    inputs: [{entrada}]\n    print_interval_secs: 0"
    destinos = "".join(f"      g{g}: .gerenciador == \"{g}\"\n" for g in gerenciadores)
    roteador = f"""  {prefixo}destino:
    type: route
    inputs: [{entrada}]
    route:
{destinos}"""
    envios = "".join(f"""  {prefixo}coletor_{g}:
    type: socket
    inputs: [{prefixo}destino.g{g}]
    mode: tcp
    address: roar-ger-{g}-coletor-1:{porta}
    framing:
      method: newline_delimited
    encoding:
      codec: text
    buffer:
      type: memory
      max_events: 50000
      when_full: block
""" for g in gerenciadores)
    # O roteador é uma transformação: entra no fim da lista de transformações do modelo.
    return roteador + "\nsinks:\n" + envios.rstrip("\n")


def configuracao(rotas, chave):
    """A configuração do receptor: as rotas e uma saída por gerenciador, para o coletor dele. Sem rota, recusa tudo."""
    from .coletor_syslog import PORTA_DO_REPASSE

    texto = (MODELO.read_text(encoding="utf-8")
             .replace("__ROTAS__", json.dumps([{"rede": r, "gerenciador": g} for r, g in rotas]))
             .replace("__CHAVE__", chave))
    return texto.replace("\n__SAIDAS__", "\n" + saidas(rotas, "rotear", "", PORTA_DO_REPASSE))


def gravar_configuracao(texto, raiz=PASTA, nome="recepcao.yaml"):
    """Troca o arquivo de uma vez só: o receptor relê a pasta sozinho quando ela muda. Só o root lê: tem a chave do
    repasse. Devolve True se mudou."""
    destino = raiz / "configuracao" / nome
    if destino.exists() and destino.read_text(encoding="utf-8") == texto:
        return False
    provisorio = destino.with_suffix(".novo")
    provisorio.touch(mode=0o600)
    provisorio.chmod(0o600)
    provisorio.write_text(texto, encoding="utf-8")
    provisorio.replace(destino)
    return True


def main():
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser(description="Prepara o receptor de syslog cifrado.")
    args.add_argument("--dominio", required=True)
    a = args.parse_args()
    print("certificado do servidor refeito" if preparar(a.dominio) else "certificados em dia")
    if not (PASTA / "configuracao" / "recepcao.yaml").exists():
        gravar_configuracao(configuracao([], chave_do_repasse()), PASTA)


if __name__ == "__main__":
    main()
