"""Syslog cifrado (TLS): um receptor só para a instalação, na porta 6514, para equipamentos que mandam log pela internet.

O Wazuh não recebe syslog com TLS. Quem recebe é um Vector (serviço recepcao, infra/docker-compose.yml) com o certificado
de uma autoridade própria da instalação, que o cliente importa no equipamento. O receptor só aceita os endereços
cadastrados em fontes de syslog cifrado e grava cada linha, sem o cabeçalho de prioridade, num arquivo por dia e por
endereço (<endereço>-AAAA-MM-DD.log), na pasta do gerenciador dono daquele endereço. O gerenciador lê a pasta dele como lê qualquer arquivo de log:
mesmas regras, mesmos decodificadores, o coletor leva ao armazém, e o endereço do equipamento continua no nome do arquivo,
que é o que a saúde da fonte usa (api/roar_api/saude_das_fontes.py).

Um mesmo endereço não pode ir para duas organizações: a fonte mais antiga fica com ele, e a outra é recusada com o motivo.
"""

import ipaddress
import json
import logging
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("roar.syslog_cifrado")
PASTA = Path("/opt/panthera-roar/syslog-cifrado")
MODELO = Path(__file__).resolve().parent / "syslog_cifrado.yaml"
PORTA = 6514
# Onde o gerenciador vê a pasta dele, e o que a configuração do Wazuh lê dela.
PASTA_NO_GERENCIADOR = "/var/ossec/roar-cifrado"
# Só curinga: o Wazuh não expande curinga e data juntos no mesmo caminho, e um caminho assim nunca é lido.
ARQUIVOS_NO_GERENCIADOR = f"{PASTA_NO_GERENCIADOR}/*.log"
# A origem de um evento cifrado: o caminho do arquivo, com o endereço do equipamento no nome.
ORIGEM_CIFRADA = re.compile(re.escape(PASTA_NO_GERENCIADOR) + r"/(\d{1,3}(?:\.\d{1,3}){3})-\d{4}-\d{2}-\d{2}\.log")
DIAS_GUARDADOS = 2
NOME_DE_GERENCIADOR = re.compile(r"[a-z0-9]{6,32}")


def endereco_da_origem(local):
    """O endereço do equipamento de uma origem de syslog: o próprio local no syslog comum, o nome do arquivo no cifrado."""
    achado = ORIGEM_CIFRADA.fullmatch(local or "")
    return achado.group(1) if achado else local


def pasta_do_gerenciador(gerenciador_id, raiz=PASTA):
    if not NOME_DE_GERENCIADOR.fullmatch(gerenciador_id):
        raise ValueError("gerenciador inválido")
    return raiz / "dados" / gerenciador_id


def preparar(dominio, raiz=PASTA):
    """Pastas e certificados. Pode rodar de novo: a autoridade não muda, e o certificado do servidor só é refeito quando o
    domínio muda ou está para vencer (o equipamento confia na autoridade, não no certificado do servidor)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    # A chave da autoridade fica fora do que o receptor monta: ele só precisa do certificado do servidor.
    certificados, autoridade = raiz / "certificados", raiz / "autoridade"
    for pasta, modo in ((raiz, 0o755), (certificados, 0o755), (autoridade, 0o700), (raiz / "dados", 0o755), (raiz / "configuracao", 0o755)):
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


def distribuir(fontes):
    """fontes: [{"id", "gerenciador", "origens", "criada_em"}] de todas as organizações. Devolve (rotas, recusadas):
    rotas é [(rede, gerenciador)], e recusadas, {id da fonte: motivo}. A mais antiga fica com a rede."""
    rotas, recusadas = [], {}
    for fonte in sorted(fontes, key=lambda f: (f["criada_em"], f["id"])):
        redes = [ipaddress.ip_network(r) for r in fonte["origens"]]
        conflito = next((r for r in redes for tomada, dono in rotas if dono != fonte["gerenciador"] and r.overlaps(tomada)), None)
        if conflito:
            recusadas[fonte["id"]] = f"O endereço {conflito} já envia syslog cifrado para outra organização desta instalação."
            continue
        rotas += [(r, fonte["gerenciador"]) for r in redes if (r, fonte["gerenciador"]) not in rotas]
    return [(str(r), g) for r, g in rotas], recusadas


def configuracao(rotas):
    """A configuração do receptor, com as rotas dentro. Sem rota nenhuma, o receptor recusa tudo."""
    lista = json.dumps([{"rede": r, "gerenciador": g} for r, g in rotas])
    return MODELO.read_text(encoding="utf-8").replace("__ROTAS__", lista)


def gravar_configuracao(texto, raiz=PASTA):
    """Troca o arquivo de uma vez só: o receptor relê a pasta sozinho quando ela muda. Devolve True se mudou."""
    destino = raiz / "configuracao" / "recepcao.yaml"
    if destino.exists() and destino.read_text(encoding="utf-8") == texto:
        return False
    provisorio = destino.with_suffix(".novo")
    provisorio.write_text(texto, encoding="utf-8")
    provisorio.chmod(0o644)
    provisorio.replace(destino)
    return True


def vencer(raiz=PASTA, hoje=None):
    """Apaga os dias já lidos: o gerenciador lê o arquivo enquanto ele é escrito, e o coletor leva ao armazém."""
    hoje = hoje or datetime.now(timezone.utc).date()
    apagados = 0
    for arquivo in (raiz / "dados").glob("*/*"):
        achado = re.fullmatch(r".+-(\d{4}-\d{2}-\d{2})\.log", arquivo.name)
        if not achado:
            # Pasta de dia do desenho anterior, que o Wazuh não lia.
            if arquivo.is_dir():
                shutil.rmtree(arquivo, ignore_errors=True)
            continue
        if (hoje - datetime.strptime(achado.group(1), "%Y-%m-%d").date()).days > DIAS_GUARDADOS:
            arquivo.unlink(missing_ok=True)
            apagados += 1
    return apagados


def main():
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser(description="Prepara o receptor de syslog cifrado.")
    args.add_argument("--dominio", required=True)
    a = args.parse_args()
    print("certificado do servidor refeito" if preparar(a.dominio) else "certificados em dia")
    gravar_configuracao(configuracao([]), PASTA) if not (PASTA / "configuracao" / "recepcao.yaml").exists() else None


if __name__ == "__main__":
    main()
