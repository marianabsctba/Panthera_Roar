#!/usr/bin/env python3
"""Firewalls por fabricante (web/src/telas/Fontes.tsx, ingestao/roar_ingestao/fabricantes): cada linha de exemplo do
catálogo passa pelo teste do gerenciador de verdade e precisa sair com o decodificador certo e os campos que o Roar usa;
o parser do MikroTik e as regras dele; e os nomes de campo dos firewalls na ingestão.

    sudo bash testes/rodar.sh testes/fase4/testar_fabricantes.py
"""

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_ingestao import fabricantes, provisao  # noqa: E402
from roar_ingestao.normalizar import CAMPOS_DE_IP_DE_DESTINO, CAMPOS_DE_IP_DE_ORIGEM, normalizar, primeiro_campo  # noqa: E402

RESULTADOS = []
# O que cada cartão precisa entregar: o decodificador e os campos que a tela mostra como aproveitados.
ESPERADO = {
    "fortigate": ("fortigate-firewall-v5", {"origem": "198.51.100.7", "usuario": "admin"}),
    "pfsense": ("pf", {"origem": "198.51.100.7", "destino": "10.0.10.5"}),
    "opnsense": ("pf", {"origem": "198.51.100.7", "destino": "10.0.10.5"}),
    "paloalto": ("paloalto", {"origem": "198.51.100.7", "destino": "10.0.10.5"}),
    "sophos": ("sophos-fw", {"origem": "198.51.100.7", "destino": "10.0.10.5"}),
    "ciscoasa": ("cisco-asa", {"origem": "198.51.100.7", "destino": "10.0.10.5"}),
    "mikrotik": ("roar-mikrotik", {"origem": "198.51.100.7", "usuario": "admin"}),
}
USUARIO = ("srcuser", "dstuser", "user_name", "source_user", "username", "user")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def amostras_da_tela():
    """{id do cartão: linha de exemplo}, lidas do catálogo da tela."""
    texto = (RAIZ / "web/src/telas/Fontes.tsx").read_text(encoding="utf-8")
    achadas = {}
    for bloco in re.finditer(r'\{ id: "(\w+)",((?:(?!\{ id:).)*?)amostra: ("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\') \}', texto, re.S):
        achadas[bloco.group(1)] = bloco.group(3)[1:-1].replace('\\"', '"').replace("\\'", "'")
    return achadas


def gerenciador_de_teste():
    with provisao.banco_admin(provisao.ler_env(provisao.DESTINO / ".env")) as b:
        for (g,) in b.execute("SELECT id FROM gerenciadores ORDER BY criado_em").fetchall():
            if (provisao.DESTINO / "gerenciadores" / g).is_dir():
                return g
    return None


def main():
    print("== Arquivos do produto", flush=True)
    decodificadores, regras = fabricantes.conteudo()
    try:
        ET.fromstring(f"<raiz>{decodificadores}</raiz>")
        ET.fromstring(f"<raiz>{regras}</raiz>")
        registrar("decodificadores e regras são XML válido", True)
    except ET.ParseError as erro:
        registrar("decodificadores e regras são XML válido", False, str(erro))
    ids = [int(i) for i in re.findall(r'<rule id="(\d+)"', regras)]
    registrar("as regras ficam na faixa reservada (100910 a 100949)", ids and all(100910 <= i <= 100949 for i in ids), str(ids))

    print("\n== Nomes de campo dos firewalls na ingestão", flush=True)
    registrar("Palo Alto: o endereço sai de source_address", primeiro_campo({"source_address": "198.51.100.7"}, CAMPOS_DE_IP_DE_ORIGEM) == "198.51.100.7")
    registrar("Sophos: o destino sai de dst_ip", primeiro_campo({"dst_ip": "10.0.10.5"}, CAMPOS_DE_IP_DE_DESTINO) == "10.0.10.5")
    registrar("srcip continua valendo primeiro", primeiro_campo({"srcip": "1.1.1.1", "src_ip": "2.2.2.2"}, CAMPOS_DE_IP_DE_ORIGEM) == "1.1.1.1")
    alerta = {"id": "1.2", "timestamp": "2026-11-06T10:15:02.000+0000", "agent": {"id": "000", "name": "g"}, "rule": {"id": "70021", "level": 5},
              "data": {"src_ip": "198.51.100.7", "user_name": "maria"}}
    evento = normalizar("1.2", alerta)
    registrar("o evento do Sophos chega com origem e usuário", evento.ip_origem == "198.51.100.7" and evento.usuario == "maria", f"{evento.ip_origem} {evento.usuario}")

    print("\n== Cada exemplo do catálogo no gerenciador", flush=True)
    gerenciador = gerenciador_de_teste()
    if not gerenciador:
        registrar("há um gerenciador para testar", False)
        return 1
    fabricantes.aplicar(gerenciador)
    amostras = amostras_da_tela()
    registrar("todo cartão de firewall tem exemplo", set(amostras) == set(ESPERADO), str(sorted(amostras)))
    for cartao, (decodificador, campos) in ESPERADO.items():
        if cartao not in amostras:
            continue
        saida = provisao.testar_log(gerenciador, amostras[cartao])["saida"]
        dados = saida.get("data") or {}
        lido = {"origem": primeiro_campo(dados, CAMPOS_DE_IP_DE_ORIGEM), "destino": primeiro_campo(dados, CAMPOS_DE_IP_DE_DESTINO), "usuario": primeiro_campo(dados, USUARIO)}
        nome = (saida.get("decoder") or {}).get("parent") or (saida.get("decoder") or {}).get("name")
        registrar(f"{cartao}: lido como {decodificador}, com {', '.join(campos)}", nome == decodificador and all(lido[k] == v for k, v in campos.items()),
                  f"{nome} {lido}")

    print("\n== MikroTik", flush=True)
    casos = [
        ("firewall,info input: in:ether1 out:(unknown 0), src-mac 00:1a:2b:3c:4d:5e, proto TCP (SYN), 198.51.100.7:51544->10.0.10.1:22, len 60", "100910", "198.51.100.7"),
        ("Nov  6 10:15:03 MikroTik firewall,info saida forward: in:bridge out:ether1, src-mac 00:1a:2b:3c:4d:5e, proto ICMP (type 8, code 0), 10.0.10.5->203.0.113.80, len 84", "100910", "10.0.10.5"),
        ("system,info,account user admin logged in from 198.51.100.7 via ssh", "100912", "198.51.100.7"),
        ("Nov  6 10:16:40 MikroTik system,error,critical login failure for user admin from 198.51.100.7 via winbox", "100911", "198.51.100.7"),
    ]
    for linha, regra, origem in casos:
        saida = provisao.testar_log(gerenciador, linha)["saida"]
        registrar(f"MikroTik: {linha[linha.index(',') - 8:][:40]}... dispara a {regra}", (saida.get("rule") or {}).get("id") == regra
                  and (saida.get("data") or {}).get("srcip") == origem, f"{(saida.get('rule') or {}).get('id')} {saida.get('data')}")
    saida = provisao.testar_log(gerenciador, "Nov  6 10:16:41 servidor sshd[1201]: Failed password for invalid user teste from 198.51.100.7 port 22 ssh2")["saida"]
    registrar("o parser do MikroTik não pega o log de outros", (saida.get("decoder") or {}).get("name") == "sshd", str(saida.get("decoder")))

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
