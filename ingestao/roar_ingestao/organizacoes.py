"""Cria e remove organizações a pedido da tela.

A API não tem acesso ao Docker: quem invade a tela não sobe contêiner. Ela só registra o pedido, e este serviço executa.
Remover apaga os dados de operação, mas os selos ficam: são prova, e só recebem acréscimos.
"""

import argparse
import logging
import time

from . import copia_fria, provisao

log = logging.getLogger("roar.organizacoes")
SEGUNDOS_ENTRE_CICLOS = 10
TABELAS_SEM_LIGACAO = ("intel_ocorrencias", "intel_indicadores", "intel_fontes", "intel_cursor", "notificacoes", "yara_regras", "yara_assinatura")


def _so_vulnerabilidades():
    arquivo = provisao.DESTINO / "perfil"
    return arquivo.is_file() and arquivo.read_text().strip() == "vulnerabilidades"


def _desfazer(env, nome):
    """Organização pela metade não tem quem entre nela, e ainda prende o nome. Quem pediu pode tentar de novo."""
    with provisao.banco_admin(env) as b:
        linha = b.execute("SELECT id FROM clientes c WHERE nome = %s AND NOT EXISTS (SELECT 1 FROM usuarios u WHERE u.cliente_id = c.id)", (nome,)).fetchone()
        if not linha:
            return
        gerenciadores = [l[0] for l in b.execute("SELECT id FROM gerenciadores WHERE cliente_id = %s", (linha[0],)).fetchall()]
    for gerenciador in gerenciadores:
        provisao.remover(gerenciador)
    with provisao.banco_admin(env) as b:
        b.execute("DELETE FROM clientes WHERE id = %s", (linha[0],))


def criar(env, pedido):
    try:
        if _so_vulnerabilidades():
            with provisao.banco_admin(env) as b:
                cliente = b.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (pedido["nome"],)).fetchone()[0]
        else:
            cliente = provisao.criar(pedido["nome"])["cliente"]
        with provisao.banco_admin(env) as b:
            b.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil, trocar_senha) VALUES (%s, %s, 'Administração', %s, 'administrador', true)",
                      (cliente, pedido["email"], pedido["senha_hash"]))
    except Exception:
        try:
            _desfazer(env, pedido["nome"])
        except Exception:
            log.exception("não deu para desfazer a organização %s", pedido["nome"])
        raise
    return cliente


def remover(env, cliente):
    with provisao.banco_admin(env) as b:
        gerenciadores = [l[0] for l in b.execute("SELECT id FROM gerenciadores WHERE cliente_id = %s", (cliente,)).fetchall()]
        # Sessões e códigos de recuperação saem junto com a pessoa.
        b.execute("DELETE FROM usuarios WHERE cliente_id = %s", (cliente,))
        for tabela in TABELAS_SEM_LIGACAO:
            b.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
    for gerenciador in gerenciadores:
        provisao.remover(gerenciador)
    with provisao.banco_admin(env) as b:
        for tabela in ("vuln_historico", "vuln_achados", "vuln_ativos", "vuln_varreduras", "vuln_alvos", "vuln_modelos", "auditoria"):
            b.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
        b.execute("DELETE FROM clientes WHERE id = %s", (cliente,))


def processar_um(env):
    with provisao.banco_admin(env) as b:
        linha = b.execute(
            """UPDATE organizacoes_pedidos SET estado = 'em_andamento' WHERE id = (
                 SELECT id FROM organizacoes_pedidos WHERE estado = 'pendente' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
               RETURNING id, acao, nome, email, senha_hash, cliente_id""").fetchone()
    if not linha:
        return False
    pedido = dict(zip(("id", "acao", "nome", "email", "senha_hash", "cliente_id"), linha))
    estado, mensagem = "pronto", None
    try:
        if pedido["acao"] == "criar":
            criar(env, pedido)
        else:
            remover(env, pedido["cliente_id"])
    except Exception:
        log.exception("pedido %s", pedido["id"])
        estado, mensagem = "falhou", "Não foi possível concluir. Veja o registro do serviço de organizações."
    with provisao.banco_admin(env) as b:
        # A senha temporária só existe até a conta nascer.
        b.execute("UPDATE organizacoes_pedidos SET estado = %s, mensagem = %s, senha_hash = NULL, concluido_em = now() WHERE id = %s", (estado, mensagem, pedido["id"]))
    return True


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--uma-vez", action="store_true")
    a = args.parse_args()
    env = provisao.ler_env(provisao.DESTINO / ".env")
    # Pedido que ficou pela metade numa queda não pode prender a fila nem repetir sozinho.
    with provisao.banco_admin(env) as b:
        b.execute("UPDATE organizacoes_pedidos SET estado = 'falhou', senha_hash = NULL, mensagem = 'O serviço reiniciou no meio. Confira a organização e peça de novo.' WHERE estado = 'em_andamento'")
    while True:
        feito = processar_um(env)
        try:
            # Também precisa do indexador como administrador, que a API não tem.
            feito = copia_fria.processar(env) or feito
        except Exception:
            log.exception("cópia fria")
        if a.uma_vez:
            return
        if not feito:
            time.sleep(SEGUNDOS_ENTRE_CICLOS)


if __name__ == "__main__":
    main()
