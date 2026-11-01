"""Reduz as variações de um nome de usuário a uma chave só.

Sem AD ou IAM, `EMPRESA\\maria` e `OUTRA\\maria` viram a mesma entidade. É o preço de juntar
`maria`, `MARIA` e `maria@empresa.com`, e dentro de um cliente é o erro menos provável.
"""

import re

CONTAS_DE_SISTEMA = {
    "-", "system", "local service", "network service", "anonymous logon", "anonymous",
    "nobody", "dwm", "umfd", "font driver host", "window manager",
}
CONTA_DE_MAQUINA = re.compile(r".*\$$")
LIMITE = 128


def chave_do_usuario(nome):
    """Devolve a chave, ou None se não for uma pessoa nem uma conta que valha acompanhar."""
    if not isinstance(nome, str):
        return None
    chave = nome.strip().lower()
    if "\\" in chave:
        chave = chave.rsplit("\\", 1)[1]
    if "@" in chave:
        chave = chave.split("@", 1)[0]
    chave = chave.strip()
    if not chave or len(chave) > LIMITE or chave in CONTAS_DE_SISTEMA or CONTA_DE_MAQUINA.fullmatch(chave):
        return None
    # Nome com caractere de controle ou espaço não veio de um sistema de contas.
    if any(c.isspace() or not c.isprintable() for c in chave):
        return None
    return chave
