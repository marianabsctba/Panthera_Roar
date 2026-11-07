#!/usr/bin/env python3
"""Fluxos de rede de exemplo na organização Demonstração, para a tela Fluxos de rede não ficar vazia.

    sudo /opt/panthera-roar/venv/bin/python infra/demo/semear_fluxos.py

A Demonstração não tem roteador mandando NetFlow: sem isto, os fluxos saem da janela da tela em um dia. Grava os
últimos 7 dias, hora a hora, com mais tráfego no horário comercial, dois roteadores (matriz e filial), a navegação de
sempre, consultas de DNS, uma cópia noturna para a nuvem e um varredor de fora batendo em SSH e RDP de madrugada.
Rodar de novo apaga o que ele mesmo gravou e grava de novo, terminando na hora atual. Só mexe no armazém da Demonstração.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao")]

from roar_ingestao import armazem  # noqa: E402

ENV = dict(l.strip().split("=", 1) for l in Path("/opt/panthera-roar/.env").read_text().splitlines() if "=" in l and not l.startswith("#"))
NOME = "Demonstração"
ROTEADORES = ("10.0.0.1", "10.20.0.1")
DIAS = 7
FLUXOS_POR_HORA = 900
FUSO = timedelta(hours=-3)
# Serviços de fora: endereço, país, operadora e ASN, como o coletor anota.
SERVICOS = [
    ("142.250.78.14", "United States", "Google LLC", "15169"), ("13.107.42.14", "United States", "Microsoft Corporation", "8075"),
    ("104.16.132.229", "United States", "Cloudflare, Inc.", "13335"), ("200.147.3.157", "Brazil", "UOL", "7162"),
    ("52.67.31.210", "Brazil", "Amazon.com, Inc.", "16509"), ("31.13.85.36", "Ireland", "Meta Platforms, Inc.", "32934"),
    ("151.101.1.140", "United States", "Fastly, Inc.", "54113"), ("189.40.201.19", "Brazil", "Claro S.A.", "28573"),
]
# Não o 8.8.8.8: a lista do MISP da Demonstração o traz como indicador, e cada consulta viraria aviso.
DNS = ("9.9.9.9", "Switzerland", "Quad9", "19281")
COPIA = ("52.217.110.68", "United States", "Amazon.com, Inc.", "16509")
VARREDOR = ("185.220.101.45", "Germany", "Stiftung Erneuerbare Freiheit", "60729")


def lista(valores):
    return "[" + ", ".join(f"'{v}'" for v in valores) + "]"


def peso_da_hora(hora_local):
    """Horário comercial cheio, almoço um pouco menor, madrugada quase parada."""
    if 8 <= hora_local < 18:
        return 0.8 if hora_local == 12 else 1.0
    if 18 <= hora_local < 22 or hora_local == 7:
        return 0.35
    return 0.08


def main():
    with psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar") as admin:
        linha = admin.execute("SELECT c.id, g.id FROM clientes c JOIN gerenciadores g ON g.cliente_id = c.id WHERE c.nome = %s ORDER BY g.criado_em LIMIT 1",
                              (NOME,)).fetchone()
        if not linha:
            print("sem organização de demonstração")
            return
        # Um serviço de exemplo que esteja nas listas de ameaça da Demonstração encheria o sino de avisos falsos.
        enderecos = [s[0] for s in (*SERVICOS, DNS, COPIA)]
        marcados = [r[0] for r in admin.execute("SELECT DISTINCT valor FROM intel_indicadores WHERE cliente_id = %s AND valor = ANY(%s)",
                                                 (linha[0], enderecos)).fetchall()]
    if marcados:
        print("estes endereços de exemplo estão nas listas de ameaça; troque-os:", ", ".join(marcados))
        return
    cliente, gerenciador = linha
    a = armazem.admin(ENV)
    banco = armazem.banco_do(cliente)
    a.executar(f"DELETE FROM {banco}.fluxos WHERE exportador IN {tuple(ROTEADORES)}")

    ips, paises, operadoras, asns = (lista(s[i] for s in SERVICOS) for i in range(4))
    agora = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    total = 0
    for h in range(DIAS * 24, -1, -1):
        inicio = agora - timedelta(hours=h)
        hora_local = (inicio + FUSO).hour
        n = int(FLUXOS_POR_HORA * peso_da_hora(hora_local))
        # A hora atual vai só até agora.
        segundos = 3600 if h else max(60, int((datetime.now(timezone.utc) - inicio).total_seconds()))
        base = f"toDateTime64('{inicio:%Y-%m-%d %H:%M:%S}', 3, 'UTC') + toIntervalSecond(cityHash64(number, 's{h}') % {segundos})"
        # Navegação e DNS: de dentro para fora, e a resposta de volta. Um quarto passa pelo roteador da filial.
        a.executar(f"""
            INSERT INTO {banco}.fluxos (ocorrido_em, gerenciador, exportador, tipo, origem, destino, porta_origem, porta_destino, protocolo, bytes, pacotes, amostragem, pais, operadora, asn)
            SELECT {base}, '{gerenciador}', roteador, if(filial, 'NETFLOW_V9', 'IPFIX'),
                   if(volta, servico, maquina), if(volta, maquina, servico), if(volta, porta, efemera), if(volta, efemera, porta),
                   if(dns, 'udp', 'tcp'), bytes_, greatest(1, intDiv(bytes_, 1200)), 1, pais_, operadora_, asn_
            FROM (SELECT number, cityHash64(number, 'r{h}') % 4 = 0 AS filial, if(filial, '{ROTEADORES[1]}', '{ROTEADORES[0]}') AS roteador,
                         concat(if(filial, '10.20.0.', '10.0.0.'), toString(10 + cityHash64(number, 'i{h}') % 50)) AS maquina,
                         cityHash64(number, 'd{h}') % 100 < 20 AS dns, cityHash64(number, 'v{h}') % 2 = 1 AS volta,
                         cityHash64(number, 'e{h}') % {len(SERVICOS)} + 1 AS k,
                         if(dns, '{DNS[0]}', {ips}[k]) AS servico, if(dns, '{DNS[1]}', {paises}[k]) AS pais_,
                         if(dns, '{DNS[2]}', {operadoras}[k]) AS operadora_, if(dns, '{DNS[3]}', {asns}[k]) AS asn_,
                         if(dns, 53, if(cityHash64(number, 'h{h}') % 10 = 0, 80, 443)) AS porta, 49152 + cityHash64(number, 'p{h}') % 16000 AS efemera,
                         if(dns, 80 + cityHash64(number, 'b{h}') % 300,
                            if(volta, 2000 + cityHash64(number, 'b{h}') % 900000, 400 + cityHash64(number, 'b{h}') % 20000)) AS bytes_
                  FROM numbers({n}))""")
        total += n
        if hora_local == 2:
            # A cópia noturna do servidor de arquivos para a nuvem: poucos fluxos, muitos bytes.
            a.executar(f"""
                INSERT INTO {banco}.fluxos (ocorrido_em, gerenciador, exportador, tipo, origem, destino, porta_origem, porta_destino, protocolo, bytes, pacotes, amostragem, pais, operadora, asn)
                SELECT {base}, '{gerenciador}', '{ROTEADORES[0]}', 'IPFIX', '10.0.0.40', '{COPIA[0]}', 50000 + number, 443, 'tcp',
                       30000000 + cityHash64(number, 'c{h}') % 50000000, 40000, 1, '{COPIA[1]}', '{COPIA[2]}', '{COPIA[3]}' FROM numbers(6)""")
            total += 6
        if hora_local in (3, 4):
            # Um varredor de fora tentando SSH e RDP nas máquinas da matriz: muitos fluxos curtos, sem resposta.
            a.executar(f"""
                INSERT INTO {banco}.fluxos (ocorrido_em, gerenciador, exportador, tipo, origem, destino, porta_origem, porta_destino, protocolo, bytes, pacotes, amostragem, pais, operadora, asn, tcp_flags)
                SELECT {base}, '{gerenciador}', '{ROTEADORES[0]}', 'IPFIX', '{VARREDOR[0]}', concat('10.0.0.', toString(10 + number % 50)),
                       40000 + number % 20000, if(number % 3 = 0, 3389, 22), 'tcp', 60, 1, 1, '{VARREDOR[1]}', '{VARREDOR[2]}', '{VARREDOR[3]}', 2 FROM numbers(150)""")
            total += 150
    print(f"{total} fluxos gravados nos últimos {DIAS} dias")


if __name__ == "__main__":
    main()
