"""Listas de observação no gerenciador: cada lista vira um arquivo chave:valor em etc/lists/roar, declarado na configuração.

O gerenciador compila as listas ao reiniciar. A declaração entra no bloco <ruleset> que a configuração já tem: um
segundo bloco <ruleset> faz o analisador deixar de carregar todas as listas, inclusive as que vêm com ele.
O resumo do conteúdo entra no resumo da configuração (fontes.aplicar_fontes): mudar um item troca a configuração,
que é validada, reinicia o gerenciador e volta à anterior se reprovar.
"""

import hashlib

CAMINHO = "etc/lists/roar"


def chave(valor):
    """Na lista do Wazuh, dois pontos separam chave e valor: chave com dois pontos, como IPv6, vai entre aspas."""
    return f'"{valor}"' if ":" in valor else valor


def arquivos(banco, cliente):
    """{nome: conteúdo} de todas as listas da organização, com as aspas e quebras de linha já fora."""
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        linhas = banco.con.execute(
            """SELECT l.nome, i.valor, i.nota FROM listas l LEFT JOIN listas_itens i ON i.lista_id = l.id
               ORDER BY l.nome, i.valor""").fetchall()
    saida = {}
    for nome, valor, nota in linhas:
        texto = saida.setdefault(nome, [])
        # A API já recusa aspas; isto é a segunda trava, para nenhum item quebrar o arquivo inteiro.
        if valor and '"' not in valor:
            texto.append(f"{chave(valor)}:{(nota or '').replace(':', ' ')}")
    # O gerenciador recusa lista vazia: ela fica com uma linha que nenhum evento traz.
    return {nome: "\n".join(itens or ["roar-lista-vazia:"]) + "\n" for nome, itens in saida.items()}


def resumo(conteudos):
    return hashlib.sha256("".join(f"{n}\0{c}" for n, c in sorted(conteudos.items())).encode()).hexdigest() if conteudos else ""


def declaracoes(conteudos):
    """As linhas <list> que entram no <ruleset> da configuração."""
    return "".join(f"    <list>{CAMINHO}/{nome}</list>\n" for nome in sorted(conteudos))
