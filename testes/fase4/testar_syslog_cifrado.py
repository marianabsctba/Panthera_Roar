#!/usr/bin/env python3
"""Syslog cifrado (ingestao/roar_ingestao/syslog_cifrado.py): rotas entre organizações, configuração do gerenciador, a
origem que a saúde usa, a limpeza dos dias, e o receptor de verdade: TLS 1.2, versões velhas e texto puro recusados,
certificado que só vale com a autoridade da instalação, e nada gravado de endereço sem rota.

    sudo bash testes/rodar.sh testes/fase4/testar_syslog_cifrado.py
"""

import socket
import ssl
import sys
import tempfile
import time
from datetime import date, datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_api import saude_das_fontes as saude  # noqa: E402
from roar_ingestao import fontes, syslog_cifrado as sc  # noqa: E402

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
    texto = sc.configuracao(rotas)
    registrar("as rotas entram na configuração do receptor", '"rede": "192.0.2.0/24", "gerenciador": "gera00001"' in texto and "__ROTAS__" not in texto)
    registrar("sem fonte nenhuma, o receptor não tem rota", "parse_json(s'[]')" in sc.configuracao([]))

    print("\n== Gerenciador", flush=True)
    xml = fontes.fragmento_de_configuracao([{"id": 1, "tipo": "syslog", "config": {"protocolo": "tls", "origens": ["10.0.0.7"]}},
                                            {"id": 2, "tipo": "syslog", "config": {"protocolo": "udp", "origens": ["10.0.1.0/24"]}}])
    registrar("fonte cifrada não abre porta no gerenciador; ele lê a pasta", "<protocol>tls</protocol>" not in xml and "<protocol>udp</protocol>" in xml
              and f"<location>{sc.ARQUIVOS_NO_GERENCIADOR}</location>" in xml and "%" not in sc.ARQUIVOS_NO_GERENCIADOR, xml[:300])
    registrar("protocolo TLS é aceito; outro qualquer, não", fontes.validar_syslog("tls", ["10.0.0.7"]) == ["10.0.0.7/32"])
    try:
        fontes.validar_syslog("ssl", ["10.0.0.7"])
        registrar("protocolo desconhecido é recusado", False)
    except fontes.FonteInvalida:
        registrar("protocolo desconhecido é recusado", True)

    print("\n== Origem e saúde", flush=True)
    registrar("a origem cifrada vira o endereço do equipamento", sc.endereco_da_origem("/var/ossec/roar-cifrado/203.0.113.9-2026-11-06.log") == "203.0.113.9"
              and sc.endereco_da_origem("203.0.113.9") == "203.0.113.9" and sc.endereco_da_origem("/var/log/auth.log") == "/var/log/auth.log")
    h = int(datetime(2026, 11, 6, 10, tzinfo=timezone.utc).timestamp())
    origens = {"/var/ossec/roar-cifrado/203.0.113.9-2026-11-05.log": {"ultimo": 1.0, "horas": {h - 86400: (10, 10)}, "primeira": h - 86400},
               "/var/ossec/roar-cifrado/203.0.113.9-2026-11-06.log": {"ultimo": 2.0, "horas": {h: (5, 4)}, "primeira": h}}
    achadas = saude.origens_da_fonte({"tipo": "syslog", "config": {"origens": ["203.0.113.0/24"]}}, origens)
    registrar("os arquivos de cada dia se juntam no mesmo equipamento", list(achadas) == ["203.0.113.9"] and achadas["203.0.113.9"]["horas"][h] == (5, 4)
              and achadas["203.0.113.9"]["primeira"] == h - 86400, str(achadas))

    print("\n== Limpeza", flush=True)
    with tempfile.TemporaryDirectory() as pasta:
        raiz = Path(pasta)
        dados = raiz / "dados" / "gera00001"
        dados.mkdir(parents=True)
        for dia in ("2026-11-01", "2026-11-04", "2026-11-06"):
            (dados / f"10.0.0.7-{dia}.log").write_text("x\n")
        (dados / "2026-11-01").mkdir()
        apagados = sc.vencer(raiz, hoje=date(2026, 11, 6))
        sobraram = sorted(p.name for p in dados.iterdir())
        registrar("os dias velhos saem e os dois últimos ficam", apagados == 1 and sobraram == ["10.0.0.7-2026-11-04.log", "10.0.0.7-2026-11-06.log"], str(sobraram))


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

    # O endereço de quem testa aqui não tem rota (nenhuma fonte cifrada de teste): nada pode ser gravado.
    antes = {p: p.stat().st_size for p in (sc.PASTA / "dados").glob("*/*.log")}
    rotas = (sc.PASTA / "configuracao" / "recepcao.yaml").read_text()
    sem_rota = "172.19.0.0" not in rotas and "172.16.0.0" not in rotas
    with socket.create_connection(("127.0.0.1", 6514), timeout=5) as b, ssl.create_default_context(cafile=str(autoridade)).wrap_socket(b, server_hostname="localhost") as t:
        t.sendall(b"<38>Nov  6 10:00:00 teste sshd[1]: linha sem rota\n")
    with socket.create_connection(("127.0.0.1", 6514), timeout=5) as s:
        try:
            s.sendall(b"<38>Nov  6 10:00:00 teste sshd[1]: linha sem tls\n")
        except OSError:
            pass
    time.sleep(3)
    depois = {p: p.stat().st_size for p in (sc.PASTA / "dados").glob("*/*.log")}
    registrar("sem rota e sem TLS, nada é gravado", (not sem_rota) or antes == depois, f"rotas de teste ativas: {not sem_rota}")


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
