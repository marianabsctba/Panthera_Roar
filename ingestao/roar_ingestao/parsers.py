"""Parsers próprios no gerenciador: atende os testes pedidos na console e instala os parsers de cada organização.

    python -m roar_ingestao.parsers

Os testes rodam aqui porque só a ingestão fala com o gerenciador. A instalação roda no ciclo das fontes (fontes.ciclo).
"""

import hashlib
import logging
import time

from psycopg.types.json import Jsonb

from .ciclo import conexoes
from .regras import PASTA_GERENCIADORES

log = logging.getLogger("roar.parsers")

ARQUIVO = "roar_parsers.xml"
SEGUNDOS_ENTRE_VOLTAS = 1
TESTES_POR_VOLTA = 5
HORAS_GUARDANDO_TESTES = 24


def _com_cliente(banco, cliente, sql, *args):
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        cursor = banco.con.execute(sql, args)
        return cursor.fetchall() if cursor.description else None


def _resumo_da_saida(saida):
    """Só o que a tela mostra: quem decodificou, os campos e a regra que disparou."""
    regra = saida.get("rule") or {}
    return {"decodificador": (saida.get("decoder") or {}).get("name"), "pai": (saida.get("decoder") or {}).get("parent"),
            "campos": saida.get("data") or {}, "previo": saida.get("predecoder") or {},
            "regra": {"id": regra.get("id"), "nivel": regra.get("level"), "descricao": regra.get("description")} if regra else None}


def atender_testes(banco, testar):
    """Cada teste roda duas vezes: como o gerenciador lê hoje e com o parser novo."""
    feitos = 0
    for gerenciador_id, cliente in banco.gerenciadores():
        if not (PASTA_GERENCIADORES / gerenciador_id).is_dir():
            continue
        pedidos = _com_cliente(banco, cliente, "SELECT id, log, xml FROM parser_testes WHERE gerenciador_id = %s AND estado = 'pendente' ORDER BY id LIMIT %s",
                               gerenciador_id, TESTES_POR_VOLTA)
        for teste_id, texto, xml in pedidos or []:
            try:
                hoje = testar(gerenciador_id, texto)
                novo = testar(gerenciador_id, texto, xml) if xml else None
                resultado = {"hoje": _resumo_da_saida(hoje["saida"]), "novo": _resumo_da_saida(novo["saida"]) if novo else None,
                             "avisos": (novo or hoje)["mensagens"]}
                estado = "pronto"
            except Exception as erro:  # O motivo pode citar endereços internos: a tela recebe só o aviso.
                log.warning("teste de parser %s falhou: %s", teste_id, type(erro).__name__)
                resultado, estado = {"erro": "O servidor não respondeu ao teste. Tente de novo em instantes."}, "erro"
            _com_cliente(banco, cliente, "UPDATE parser_testes SET estado = %s, resultado = %s WHERE id = %s", estado, Jsonb(resultado), teste_id)
            feitos += 1
    return feitos


def limpar_testes(banco):
    for _, cliente in banco.gerenciadores():
        _com_cliente(banco, cliente, "DELETE FROM parser_testes WHERE criado_em < now() - make_interval(hours => %s)", HORAS_GUARDANDO_TESTES)


def aplicar(banco, gerenciador_id, cliente, provisao=None):
    """Instala os parsers ativos. Se o conjunto reprovar, os novos ficam recusados e os que já valiam continuam."""
    if provisao is None:
        from . import provisao
    linhas = _com_cliente(banco, cliente, "SELECT id, xml, estado FROM parsers WHERE ativo ORDER BY id")
    pendentes = [i for i, _, estado in linhas if estado == "pendente"]
    desejado = "".join(x for _, x, _ in linhas)
    resumo = hashlib.sha256(desejado.encode()).hexdigest()
    marca = PASTA_GERENCIADORES / gerenciador_id / "parsers.aplicado"
    if marca.exists() and marca.read_text() == resumo and not pendentes:
        return 0
    if desejado:
        ok, detalhe = provisao.aplicar_regras(gerenciador_id, ARQUIVO, desejado, tipo="decoders")
    else:
        ok, detalhe = provisao.remover_regras(gerenciador_id, ARQUIVO, tipo="decoders")
    if not ok and pendentes:
        log.error("parsers de %s reprovaram: %s", gerenciador_id, str(detalhe)[:400])
        # Volta ao que já valia, sem os novos.
        valiam = "".join(x for _, x, estado in linhas if estado == "aplicado")
        if valiam:
            provisao.aplicar_regras(gerenciador_id, ARQUIVO, valiam, tipo="decoders")
        for i in pendentes:
            _com_cliente(banco, cliente, "UPDATE parsers SET estado = 'recusado', mensagem = %s WHERE id = %s",
                         "O servidor recusou este parser. Os outros continuam valendo.", i)
        marca.write_text(hashlib.sha256(valiam.encode()).hexdigest())
        return 0
    if ok:
        marca.write_text(resumo)
        for i in pendentes:
            _com_cliente(banco, cliente, "UPDATE parsers SET estado = 'aplicado', mensagem = NULL, aplicado_em = now() WHERE id = %s", i)
    return len(pendentes)


def main():
    from . import provisao

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    _, banco, _ = conexoes()
    ultima_limpeza = 0.0
    while True:
        try:
            atender_testes(banco, provisao.testar_log)
            if time.time() - ultima_limpeza > 3600:
                limpar_testes(banco)
                ultima_limpeza = time.time()
        except Exception:
            log.exception("volta dos testes de parser falhou")
        time.sleep(SEGUNDOS_ENTRE_VOLTAS)


if __name__ == "__main__":
    main()
