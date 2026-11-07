#!/usr/bin/env python3
"""Fluxos de rede (ingestao/roar_ingestao/fluxos.py): a parte do receptor e do coletor que leva os fluxos, o arquivo do
goflow2 que gira sem perder nada, e o caminho de verdade: NetFlow v5 mandado à porta da instalação chega à tabela fluxos
do armazém da organização dona do exportador, com o país do lado de fora, e conta na saúde da fonte.

    sudo bash testes/rodar.sh testes/fase4/testar_fluxos.py
"""

import socket
import struct
import sys
import tempfile
import time
import uuid
from pathlib import Path

import psycopg
import yaml

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_api import leitor_armazem, saude_das_fontes  # noqa: E402
from roar_ingestao import armazem, coletor_syslog, fluxos, fontes, inteligencia, provisao  # noqa: E402
from roar_ingestao.armazenamento import Armazenamento  # noqa: E402
from roar_ingestao.ciclo import ler_env  # noqa: E402

RESULTADOS = []
ENV = ler_env(provisao.DESTINO / ".env")


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def netflow_v5(destino, n, sequencia):
    """Um pacote NetFlow v5 com n fluxos de 10.0.10.x para o destino, porta 443."""
    agora = int(time.time())
    pacote = struct.pack("!HHIIIIBBH", 5, n, 100000, agora, 0, sequencia, 0, 0, 0)
    for i in range(n):
        pacote += struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", socket.inet_aton(f"10.0.10.{i + 1}"), socket.inet_aton(destino), socket.inet_aton("0.0.0.0"),
                              1, 2, 10, 1500, 99000, 99900, 40000 + i, 443, 0, 0x18, 6, 0, 0, 0, 24, 24, 0)
    return pacote


def contas():
    print("== Configurações geradas", flush=True)
    vazio = fluxos.configuracao([], "chave-de-teste")
    com_rota = fluxos.configuracao([("172.16.0.0/12", "abcdef123456")], "chave-de-teste")
    for nome, texto in (("receptor sem rota", vazio), ("receptor com rota", com_rota),
                        ("coletor", coletor_syslog.configuracao(["10.0.0.0/8"], False, "chave-de-teste"))):
        try:
            yaml.safe_load(texto)
            registrar(f"{nome}: YAML válido, sem marcador sobrando", "__" not in texto.replace("_unmatched", ""))
        except yaml.YAMLError as erro:
            registrar(f"{nome}: YAML válido, sem marcador sobrando", False, str(erro)[:200])
    registrar("o receptor manda cada fluxo ao coletor do gerenciador dono, pela porta dos fluxos",
              f"address: roar-ger-abcdef123456-coletor-1:{fluxos.PORTA_DO_REPASSE}" in com_rota and "fluxos_destino" in com_rota and "type: blackhole" in vazio)
    registrar("o exportador segue as regras de endereço do syslog", fontes.validar_fluxo(["10.0.0.1"]) == ["10.0.0.1/32"])

    print("\n== O arquivo do goflow2 gira", flush=True)
    with tempfile.TemporaryDirectory() as pasta:
        raiz = Path(pasta)
        (raiz / "dados").mkdir()
        atual = raiz / "dados" / fluxos.ARQUIVO
        atual.write_text("{}\n")
        avisos = []
        registrar("o primeiro giro só marca a hora", not fluxos.girar(raiz, agora=1000, avisar=lambda: avisos.append(1)) and not avisos)
        registrar("antes de uma hora, não gira", not fluxos.girar(raiz, agora=1000 + 1800, avisar=lambda: avisos.append(1)))
        registrar("depois de uma hora, renomeia e avisa o goflow2", fluxos.girar(raiz, agora=1000 + 3700, avisar=lambda: avisos.append(1)) and avisos == [1]
                  and not atual.exists() and len(list((raiz / "dados").glob("fluxos-*.log"))) == 1)
        velho = next((raiz / "dados").glob("fluxos-*.log"))
        import os
        os.utime(velho, (1000, 1000))
        fluxos.girar(raiz, agora=1000 + 3700 + fluxos.SEGUNDOS_GUARDANDO_O_LIDO + 10, avisar=lambda: None)
        registrar("o arquivo já lido sai depois de duas horas", not velho.exists())


def caminho():
    print("\n== De ponta a ponta", flush=True)
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    banco = Armazenamento(f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@127.0.0.1:5433/roar")
    gerenciador, cliente = next(((g, c) for g, c in admin.execute("SELECT id, cliente_id FROM gerenciadores ORDER BY criado_em").fetchall()
                                 if (provisao.DESTINO / "gerenciadores" / g).is_dir()), (None, None))
    if not gerenciador:
        registrar("há um gerenciador com coletor", False)
        return
    usuario = admin.execute("SELECT id FROM usuarios WHERE cliente_id = %s LIMIT 1", (cliente,)).fetchone()
    fonte = admin.execute("""INSERT INTO fontes (cliente_id, gerenciador_id, tipo, nome, config, estado, criada_por)
                             VALUES (%s, %s, 'fluxo', 'Teste dos fluxos', '{"origens": ["172.16.0.0/12"]}', 'ativa', %s) RETURNING id""",
                          (cliente, gerenciador, usuario[0] if usuario else uuid.uuid4())).fetchone()[0]
    leitor = armazem.leitor(ENV)
    nome_do_banco = armazem.banco_do(cliente)
    try:
        fontes.aplicar_recepcao(banco)
        time.sleep(8)  # O receptor relê a configuração sozinho.
        destino = f"192.0.2.{100 + int(time.time()) % 100}"
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(netflow_v5(destino, 4, int(time.time()) % 100000), ("127.0.0.1", fluxos.PORTA_NETFLOW))
        linhas = []
        for _ in range(15):
            time.sleep(3)
            linhas = leitor.linhas(f"SELECT exportador, origem, porta_destino, protocolo, bytes FROM {nome_do_banco}.fluxos WHERE destino = {{d:String}}", {"d": destino})
            if len(linhas) >= 4:
                break
        registrar("o NetFlow chega à tabela fluxos da organização dona do exportador", len(linhas) == 4 and all(l["porta_destino"] in (443, "443") for l in linhas),
                  str(linhas[:1]))
        visao = leitor_armazem.fluxos(leitor, nome_do_banco, 1, destino)
        registrar("a consulta da tela acha os fluxos pelo endereço", visao["total"]["fluxos"] == 4 and visao["destinos"][0]["valor"] == destino, str(visao["total"]))
        resumo = saude_das_fontes.ler(leitor, nome_do_banco, gerenciador)
        conta = saude_das_fontes.da_fonte({"tipo": "fluxo", "config": {"origens": ["172.16.0.0/12"]}}, resumo)
        registrar("os fluxos contam na saúde da fonte, por exportador", conta["eventos_24h"] >= 4 and conta["equipamentos"]
                  and not any(e["endereco"].startswith("fluxo:") for e in conta["equipamentos"]), str(conta.get("equipamentos"))[:200])

        print("\n== Indicadores de ameaça nos fluxos", flush=True)
        indicadores_nos_fluxos(admin, banco, leitor, cliente, usuario[0] if usuario else uuid.uuid4())
    finally:
        admin.execute("DELETE FROM fontes WHERE id = %s", (fonte,))
        fontes.aplicar_recepcao(banco)
        banco.fechar()


def mandar_e_esperar(leitor, nome_do_banco, destino, n):
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(netflow_v5(destino, n, int(time.time()) % 100000), ("127.0.0.1", fluxos.PORTA_NETFLOW))
    for _ in range(15):
        time.sleep(3)
        if int(leitor.linhas(f"SELECT count() AS n FROM {nome_do_banco}.fluxos WHERE destino = {{d:String}}", {"d": destino})[0]["n"]) >= n:
            return True
    return False


def indicadores_nos_fluxos(admin, banco, leitor, cliente, usuario):
    nome_do_banco = armazem.banco_do(cliente)
    fonte = admin.execute("SELECT id FROM intel_fontes WHERE cliente_id = %s AND tipo = 'manual'", (cliente,)).fetchone()
    criada = fonte is None
    if criada:
        fonte = admin.execute("""INSERT INTO intel_fontes (cliente_id, nome, tipo, endereco, criado_por) VALUES (%s, 'Lista manual de teste', 'manual', '', %s) RETURNING id""",
                              (cliente, usuario)).fetchone()
    mau, outro = f"198.51.100.{10 + int(time.time()) % 80}", f"198.51.100.{100 + int(time.time()) % 80}"
    ids = []
    try:
        ids.append(admin.execute("INSERT INTO intel_indicadores (cliente_id, fonte_id, tipo, valor, descricao) VALUES (%s, %s, 'ip', %s, 'teste') RETURNING id",
                                 (cliente, fonte[0], mau)).fetchone()[0])
        inteligencia.buscar_nos_fluxos(banco, leitor, cliente)  # Marca a posição antes dos fluxos de teste.
        avisos_antes = admin.execute("SELECT coalesce(sum(contagem), 0) FROM notificacoes WHERE cliente_id = %s AND tipo = 'indicador_encontrado'", (cliente,)).fetchone()[0]
        registrar("os fluxos para o IP malicioso chegam ao armazém", mandar_e_esperar(leitor, nome_do_banco, mau, 3))
        time.sleep(16)  # A folga da conferência.
        achados = inteligencia.buscar_nos_fluxos(banco, leitor, cliente)
        linha = admin.execute("SELECT fluxos, sentido, interno FROM intel_fluxos WHERE indicador_id = %s", (ids[0],)).fetchall()
        registrar("a conversa da rede com o indicador vira um achado, por endereço da rede", achados == 3 and len(linha) == 3
                  and all(l[1] == "saida" and l[0] == 1 for l in linha), str(linha))
        avisos = admin.execute("SELECT coalesce(sum(contagem), 0) FROM notificacoes WHERE cliente_id = %s AND tipo = 'indicador_encontrado'", (cliente,)).fetchone()[0]
        registrar("o sino avisa", avisos > avisos_antes, f"{avisos_antes} -> {avisos}")
        registrar("a volta seguinte não conta de novo", inteligencia.buscar_nos_fluxos(banco, leitor, cliente) == 0
                  and admin.execute("SELECT sum(fluxos) FROM intel_fluxos WHERE indicador_id = %s", (ids[0],)).fetchone()[0] == 3)

        # Indicador que chega depois: os fluxos já conferidos são procurados de novo.
        registrar("fluxos para outro IP chegam antes de ele virar indicador", mandar_e_esperar(leitor, nome_do_banco, outro, 2))
        time.sleep(16)
        inteligencia.buscar_nos_fluxos(banco, leitor, cliente)
        ids.append(admin.execute("INSERT INTO intel_indicadores (cliente_id, fonte_id, tipo, valor, descricao) VALUES (%s, %s, 'ip', %s, 'teste') RETURNING id",
                                 (cliente, fonte[0], outro)).fetchone()[0])
        passado = inteligencia.buscar_nos_fluxos_do_passado(banco, leitor, cliente, [{"id": ids[1], "tipo": "ip", "valor": outro}])
        registrar("o indicador novo acha os fluxos que já tinham passado, marcados como do passado", passado == 2
                  and admin.execute("SELECT bool_and(no_passado) FROM intel_fluxos WHERE indicador_id = %s", (ids[1],)).fetchone()[0], str(passado))
    finally:
        admin.execute("DELETE FROM intel_fluxos WHERE indicador_id = ANY(%s)", (ids,))
        admin.execute("DELETE FROM intel_indicadores WHERE id = ANY(%s)", (ids,))
        if criada:
            admin.execute("DELETE FROM intel_fontes WHERE id = %s", (fonte[0],))


def main():
    contas()
    caminho()
    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
