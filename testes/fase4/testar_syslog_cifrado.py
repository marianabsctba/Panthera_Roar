#!/usr/bin/env python3
"""Syslog cifrado (ingestao/roar_ingestao/syslog_cifrado.py) e syslog no coletor (coletor_syslog.py): rotas entre
organizações, o repasse ao coletor de cada gerenciador com a chave da instalação, o gerenciador que não abre porta nem lê
arquivo, e o receptor de verdade: TLS 1.2, versões velhas e texto puro recusados, e certificado que só vale com a
autoridade da instalação.

    sudo bash testes/rodar.sh testes/fase4/testar_syslog_cifrado.py
"""

import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_ingestao import coletor_syslog, fontes, syslog_cifrado as sc  # noqa: E402

RESULTADOS = []
ANTIGA, NOVA = datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 6, 1, tzinfo=timezone.utc)


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def regras():
    print("== Rotas entre organizações", flush=True)
    fontes_ = [{"id": 2, "gerenciador": "gerb00001", "origens": ["10.0.0.0/24"], "criada_em": NOVA},
               {"id": 1, "gerenciador": "gera00001", "origens": ["10.0.0.7/32", "192.0.2.0/24"], "criada_em": ANTIGA},
               {"id": 3, "gerenciador": "gera00001", "origens": ["10.0.0.7/32"], "criada_em": NOVA}]
    rotas, recusadas = sc.distribuir(fontes_)
    registrar("a fonte mais antiga fica com o endereço; a da outra organização é recusada", list(recusadas) == [2] and "outra organização" in recusadas[2], str(recusadas))
    registrar("duas fontes da mesma organização podem dividir o endereço", 3 not in recusadas and rotas.count(("10.0.0.7/32", "gera00001")) == 1, str(rotas))
    texto = sc.configuracao(rotas, "chave-de-teste")
    registrar("as rotas entram no receptor, com uma saída para o coletor de cada gerenciador", '"rede": "192.0.2.0/24", "gerenciador": "gera00001"' in texto
              and "address: roar-ger-gera00001-coletor-1:5140" in texto and "__ROTAS__" not in texto and "__SAIDAS__" not in texto)
    registrar("o repasse leva a chave da instalação e o endereço do equipamento", '"ROAR chave-de-teste " + ip + " " + linha' in texto)
    import yaml
    for nome, gerada in (("receptor com rota", texto), ("receptor sem rota", sc.configuracao([], "chave-de-teste")),
                         ("coletor", coletor_syslog.configuracao(["10.0.0.0/8"], True, "chave-de-teste"))):
        try:
            yaml.safe_load(gerada)
            registrar(f"{nome}: YAML válido, com a chave uma vez só", gerada.count("chave-de-teste") == 1, str(gerada.count("chave-de-teste")))
        except yaml.YAMLError as erro:
            registrar(f"{nome}: YAML válido, com a chave uma vez só", False, str(erro)[:200])
    vazio = sc.configuracao([], "k")
    registrar("sem fonte nenhuma, o receptor não tem rota nem destino", "parse_json(s'[]')" in vazio and "type: blackhole" in vazio and "coletor-1" not in vazio)
    try:
        sc.configuracao([("10.0.0.0/8", "../x")], "k")
        registrar("nome de gerenciador estranho não entra na configuração", False)
    except ValueError:
        registrar("nome de gerenciador estranho não entra na configuração", True)

    print("\n== Coletor e gerenciador", flush=True)
    fontes_ = [{"id": 1, "tipo": "syslog", "config": {"protocolo": "tls", "origens": ["10.0.0.7"]}},
               {"id": 2, "tipo": "syslog", "config": {"protocolo": "udp", "origens": ["10.0.1.0/24"]}}]
    registrar("o coletor aceita os endereços comuns e os cifrados", fontes.redes_de_syslog(fontes_) == ["10.0.0.7/32", "10.0.1.0/24"])
    coletor = coletor_syslog.configuracao(fontes.redes_de_syslog(fontes_), True, "chave-de-teste")
    registrar("o coletor confere a chave do repasse e entrega ao socket do analisador", 'partes.chave != "chave-de-teste"' in coletor
              and "/var/ossec/queue/sockets/queue" in coletor and "if true {" in coletor and "__" not in coletor.replace("_unmatched", ""))
    xml = fontes.fragmento_de_configuracao(fontes_)
    registrar("o gerenciador não abre porta de syslog nem lê arquivo", "<remote>" not in xml and "<localfile>" not in xml, xml[:200])
    registrar("protocolo TLS é aceito; outro qualquer, não", fontes.validar_syslog("tls", ["10.0.0.7"]) == ["10.0.0.7/32"])
    try:
        fontes.validar_syslog("ssl", ["10.0.0.7"])
        registrar("protocolo desconhecido é recusado", False)
    except fontes.FonteInvalida:
        registrar("protocolo desconhecido é recusado", True)


def receptor():
    print("\n== Receptor", flush=True)
    autoridade = sc.PASTA / "certificados" / "autoridade.pem"
    if not autoridade.exists():
        registrar("o receptor está preparado (infra/servicos.sh)", False)
        return

    def conectar(versao=None, contexto=None):
        c = contexto or ssl.create_default_context(cafile=str(autoridade))
        if versao:
            c.minimum_version = c.maximum_version = versao
            c.set_ciphers("ALL:@SECLEVEL=0")
        with socket.create_connection(("127.0.0.1", 6514), timeout=5) as b, c.wrap_socket(b, server_hostname="localhost") as t:
            return t.version()

    try:
        registrar("TLS 1.2 com a autoridade da instalação", conectar(ssl.TLSVersion.TLSv1_2) == "TLSv1.2")
    except (OSError, ssl.SSLError) as erro:
        registrar("TLS 1.2 com a autoridade da instalação", False, str(erro))
    for versao in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            conectar(versao)
            registrar(f"{versao.name} é recusado", False)
        except (OSError, ssl.SSLError):
            registrar(f"{versao.name} é recusado", True)
    try:
        conectar(contexto=ssl.create_default_context())
        registrar("sem a autoridade, o certificado não vale", False)
    except ssl.SSLError:
        registrar("sem a autoridade, o certificado não vale", True)


def main():
    regras()
    receptor()
    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
