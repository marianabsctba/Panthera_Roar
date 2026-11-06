"""Buscas agendadas: roda as que venceram, guarda o resultado e avisa no sino quando a condição vale.

    python -m roar_ingestao.buscas

Conta do mesmo jeito que o bloco de número de um painel (api/roar_api/buscas.py).
"""

import logging
import time

from roar_api import buscas as montagem

from . import fontes_quietas
from .armazem import banco_do as banco_do_armazem, leitor
from .ciclo import conexoes
from .regras import PASTA_GERENCIADORES

log = logging.getLogger("roar.buscas")

SEGUNDOS_ENTRE_VOLTAS = 30
SEGUNDOS_ENTRE_FONTES_QUIETAS = 600
EXECUCOES_GUARDADAS = 200


def disparou(condicao, limite, total):
    if condicao == "nenhum":
        return total == 0
    if condicao == "mais_de":
        return total > limite
    return total > 0


def _com_cliente(banco, cliente, sql, *args):
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        cursor = banco.con.execute(sql, args)
        return cursor.fetchall() if cursor.description else None


def rodar_vencidas(banco, post, url, armazem=None):
    """Uma organização com problema não para as outras, e uma busca com problema não para as outras da mesma."""
    por_cliente = {}
    for gerenciador_id, cliente in banco.gerenciadores():
        # Só gerenciador instalado aqui: registro sem pasta é de teste ou de remoção pela metade.
        if (PASTA_GERENCIADORES / gerenciador_id).is_dir():
            por_cliente.setdefault(cliente, []).append(gerenciador_id)
    rodadas = 0
    for cliente, gerenciadores in por_cliente.items():
        vencidas = _com_cliente(banco, cliente, """SELECT id, nome, texto, janela_minutos, a_cada_minutos, condicao, limite FROM buscas_salvas
                                                   WHERE ativa AND a_cada_minutos IS NOT NULL AND (proxima_em IS NULL OR proxima_em <= now())
                                                   ORDER BY proxima_em NULLS FIRST LIMIT 20""")
        # A organização escolhe de onde ler durante a migração para o armazém de eventos (docs/clickhouse.md).
        ler_do_armazem = armazem is not None and bool(vencidas) and _com_cliente(banco, cliente, "SELECT ler_do_armazem FROM clientes WHERE id = %s", cliente)[0][0]
        onde = {"armazem": armazem, "banco": banco_do_armazem(cliente)} if ler_do_armazem else {}
        for busca_id, nome, texto, janela, intervalo, condicao, limite in vencidas or []:
            total, erro = None, None
            try:
                total = montagem.executar(post, url, gerenciadores, texto, "numero", janela, **onde)["total"]
            except montagem.BuscaInvalida as e:
                erro = str(e)
            except Exception as e:  # O índice pode citar endereços internos: a tela recebe só o aviso.
                log.warning("busca %s de %s falhou: %s", busca_id, cliente, type(e).__name__)
                erro = "Não foi possível consultar os logs. A busca roda de novo no próximo horário."
            vale = total is not None and disparou(condicao, limite, total)
            _com_cliente(banco, cliente, """UPDATE buscas_salvas SET ultima_em = now(), ultimo_total = %s, ultimo_erro = %s,
                                            proxima_em = now() + make_interval(mins => %s) WHERE id = %s""", total, erro, intervalo, busca_id)
            _com_cliente(banco, cliente, "INSERT INTO buscas_execucoes (cliente_id, busca_id, total, disparou, erro) VALUES (%s, %s, %s, %s, %s)",
                         cliente, busca_id, total, vale, erro)
            _com_cliente(banco, cliente, """DELETE FROM buscas_execucoes WHERE busca_id = %s AND id NOT IN
                                            (SELECT id FROM buscas_execucoes WHERE busca_id = %s ORDER BY id DESC LIMIT %s)""", busca_id, busca_id, EXECUCOES_GUARDADAS)
            if vale:
                _com_cliente(banco, cliente, "SELECT roar_avisar(%s, 'busca_agendada', %s)", cliente, nome)
            rodadas += 1
    return rodadas


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    indexer, banco, env = conexoes()
    armazem = leitor(env)
    proxima_conferencia = 0.0
    while True:
        try:
            rodar_vencidas(banco, indexer.sessao.post, indexer.url, armazem)
        except Exception:
            log.exception("volta das buscas agendadas falhou")
        if time.monotonic() >= proxima_conferencia:
            try:
                # Fonte que ficou quieta: lê do mesmo armazém que as buscas, a cada dez minutos.
                fontes_quietas.conferir(banco, armazem)
            except Exception:
                log.exception("conferência das fontes quietas falhou")
            proxima_conferencia = time.monotonic() + SEGUNDOS_ENTRE_FONTES_QUIETAS
        time.sleep(SEGUNDOS_ENTRE_VOLTAS)


if __name__ == "__main__":
    main()
