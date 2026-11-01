"""Aplica no gerenciador as fontes de dados pedidas na tela.

    python -m roar_ingestao.fontes

O dono de um log de syslog é o gerenciador cuja porta recebeu o log, nunca o conteúdo da mensagem.
"""

import argparse
import hashlib
import ipaddress
import logging
import re
import time
from pathlib import Path

log = logging.getLogger("roar.fontes")
PASTA_GERENCIADORES = Path("/opt/panthera-roar/gerenciadores")
PROTOCOLOS = ("tcp", "udp")
ORIGENS_MAXIMAS = 200
# Mais aberto que isso, qualquer um na internet escreveria nos logs do cliente.
MENOR_PREFIXO_IPV4 = 8


class FonteInvalida(Exception):
    """A mensagem aparece na tela, então precisa explicar o que corrigir."""


def validar_syslog(protocolo, origens):
    """Devolve as redes normalizadas: só isso chega ao XML, nunca o texto que a pessoa digitou."""
    if protocolo not in PROTOCOLOS:
        raise FonteInvalida("O protocolo precisa ser TCP ou UDP.")
    if not isinstance(origens, list) or not 1 <= len(origens) <= ORIGENS_MAXIMAS:
        raise FonteInvalida(f"Informe de 1 a {ORIGENS_MAXIMAS} endereços ou redes de origem.")
    redes = []
    for origem in origens:
        try:
            rede = ipaddress.ip_network(str(origem).strip(), strict=False)
        except ValueError:
            raise FonteInvalida(f"Endereço ou rede inválida: {str(origem)[:60]}")
        if rede.version != 4:
            raise FonteInvalida("Por enquanto, o syslog aceita só endereços IPv4.")
        if rede.prefixlen < MENOR_PREFIXO_IPV4:
            raise FonteInvalida(f"A rede {rede} é aberta demais: use /{MENOR_PREFIXO_IPV4} ou menor.")
        redes.append(str(rede))
    return sorted(set(redes))


def fragmento_de_configuracao(fontes):
    """Uma entrada por protocolo, porque a porta interna é a mesma para todas as fontes do cliente."""
    por_protocolo = {}
    for fonte in fontes:
        if fonte["tipo"] != "syslog":
            continue
        config = fonte["config"]
        por_protocolo.setdefault(config["protocolo"], set()).update(validar_syslog(config["protocolo"], config["origens"]))
    if not por_protocolo:
        return ""
    blocos = []
    for protocolo in sorted(por_protocolo):
        permitidos = "".join(f"    <allowed-ips>{rede}</allowed-ips>\n" for rede in sorted(por_protocolo[protocolo]))
        blocos.append(f"  <remote>\n    <connection>syslog</connection>\n    <port>514</port>\n    <protocol>{protocolo}</protocol>\n{permitidos}  </remote>\n")
    return "\n<ossec_config>\n" + "".join(blocos) + "</ossec_config>\n"


def aplicar_fontes(banco, gerenciador_id, cliente):
    """Só reinicia o gerenciador se a configuração mudou. Reprovou: volta ao anterior e avisa na tela."""
    from . import provisao

    def com_cliente(sql, *args):
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        return banco.con.execute(sql, args)

    with banco.con.transaction():
        linhas = com_cliente(
            "SELECT id, tipo, config, estado FROM fontes WHERE gerenciador_id = %s AND estado IN ('pendente', 'ativa', 'desativada')",
            gerenciador_id).fetchall()
    pendentes = [l[0] for l in linhas if l[3] == "pendente"]
    em_uso = [{"id": l[0], "tipo": l[1], "config": l[2]} for l in linhas if l[3] != "desativada"]
    pasta = PASTA_GERENCIADORES / gerenciador_id
    marca = pasta / "fontes.aplicadas"
    fragmento = fragmento_de_configuracao(em_uso)
    resumo = hashlib.sha256(fragmento.encode()).hexdigest()
    anterior = marca.read_text() if marca.exists() else hashlib.sha256(b"").hexdigest()
    if resumo == anterior and not pendentes:
        return 0
    ok, detalhe = (True, {}) if resumo == anterior else provisao.aplicar_configuracao(gerenciador_id, fragmento)
    if ok:
        marca.write_text(resumo)
    with banco.con.transaction():
        for fonte in pendentes:
            if ok:
                com_cliente("UPDATE fontes SET estado = 'ativa', mensagem = NULL, aplicada_em = now() WHERE id = %s", fonte)
            else:
                # O motivo vem do validador e pode citar caminhos internos: a tela recebe só o aviso.
                log.error("gerenciador %s recusou a configuração: %s", gerenciador_id, re.sub(r"\s+", " ", str(detalhe))[:400])
                com_cliente("UPDATE fontes SET estado = 'recusada', mensagem = %s WHERE id = %s",
                            "O gerenciador recusou esta configuração. Nada mudou.", fonte)
    return len(pendentes)


def ciclo(banco):
    from .regras import aplicar_regras_proprias

    for gerenciador_id, cliente in banco.gerenciadores():
        if not (PASTA_GERENCIADORES / gerenciador_id).is_dir():
            continue
        try:
            aplicar_fontes(banco, gerenciador_id, cliente)
            # No mesmo ciclo curto: regra criada ou editada na tela não pode esperar a sincronização de hora em hora.
            aplicar_regras_proprias(banco, gerenciador_id, cliente)
        except Exception:  # Um gerenciador com problema não pode travar a configuração dos outros.
            log.exception("fontes do gerenciador %s falharam", gerenciador_id)


def main():
    from .ciclo import conexoes

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--intervalo", type=float, default=15.0)
    a = args.parse_args()
    _, banco, _ = conexoes()
    while True:
        ciclo(banco)
        time.sleep(a.intervalo)


if __name__ == "__main__":
    main()
