#!/usr/bin/env python3
"""Guarda de credenciais: o que a API consegue fazer, o que não consegue e o que cada cliente alcança.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_cofre.py
"""

import os
import secrets
import stat
import sys
import tempfile
import uuid
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ / "ingestao"))

from roar_ingestao import cofre  # noqa: E402

RESULTADOS = []
ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
ENDERECO = "127.0.0.1:5433/roar"


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def invalido(funcao):
    try:
        funcao()
        return False
    except cofre.SegredoInvalido:
        return True


def negado(funcao):
    try:
        funcao()
        return False
    except psycopg.errors.InsufficientPrivilege:
        return True


def testar_cifra():
    print("== Cifra", flush=True)
    pasta = Path(tempfile.mkdtemp(prefix="roar-cofre-"))
    registrar("gera as chaves", cofre.gerar(pasta))
    privada_antes = cofre.ler_privada(pasta)
    registrar("não sobrescreve chave existente", not cofre.gerar(pasta) and cofre.ler_privada(pasta) == privada_antes)
    registrar("só o dono lê a chave privada", stat.S_IMODE(os.stat(pasta / "privada").st_mode) == 0o600)
    publica, privada = cofre.ler_publica(pasta), cofre.ler_privada(pasta)
    segredo = "chave-secreta-áé-123"
    selado = cofre.selar(publica, "a", "aws", segredo)
    registrar("abre com a chave certa", cofre.abrir(privada, "a", "aws", selado) == segredo)
    registrar("o valor não aparece no cifrado", segredo.encode() not in selado)
    registrar("cifrar de novo dá outro resultado", cofre.selar(publica, "a", "aws", segredo) != selado)
    registrar("não abre como se fosse de outro cliente", invalido(lambda: cofre.abrir(privada, "b", "aws", selado)))
    registrar("não abre como se fosse outra credencial", invalido(lambda: cofre.abrir(privada, "a", "azure", selado)))
    adulterado = bytearray(selado)
    adulterado[-1] ^= 1
    registrar("valor adulterado não abre", invalido(lambda: cofre.abrir(privada, "a", "aws", bytes(adulterado))))
    registrar("valor curto não abre", invalido(lambda: cofre.abrir(privada, "a", "aws", b"123")))
    outra = Path(tempfile.mkdtemp(prefix="roar-cofre-"))
    cofre.gerar(outra)
    registrar("outra chave não abre", invalido(lambda: cofre.abrir(cofre.ler_privada(outra), "a", "aws", selado)))
    # Separador no nome não pode fazer dois contextos diferentes parecerem iguais.
    registrar("cliente e nome não se confundem", invalido(lambda: cofre.abrir(privada, "a\x00aws", "", cofre.selar(publica, "a", "aws\x00", "x"))))
    return publica, privada


def testar_banco(publica, privada):
    print("\n== Banco", flush=True)
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@{ENDERECO}", autocommit=True)
    sufixo = uuid.uuid4().hex[:8]
    a = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"cofre-a-{sufixo}",)).fetchone()[0])
    b = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"cofre-b-{sufixo}",)).fetchone()[0])
    usuario = uuid.uuid4()
    url_api = f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@{ENDERECO}"
    url_ingestao = f"postgresql://roar_ingestao:{ENV['ROAR_INGESTAO_SENHA']}@{ENDERECO}"
    segredo = secrets.token_urlsafe(24)

    def como(url, cliente, sql, *args):
        with psycopg.connect(url) as con:
            if cliente:
                con.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
            cursor = con.execute(sql, args)
            return cursor.fetchall() if cursor.description else None

    try:
        selado = cofre.selar(publica, a, "aws", segredo)
        como(url_api, a, "INSERT INTO segredos (cliente_id, nome, selado, criado_por) VALUES (%s, 'aws', %s, %s)", a, selado, usuario)
        registrar("API grava a credencial", admin.execute("SELECT count(*) FROM segredos WHERE cliente_id = %s", (a,)).fetchone()[0] == 1)
        registrar("API vê que a credencial existe", como(url_api, a, "SELECT nome FROM segredos")[0][0] == "aws")
        registrar("API não lê o valor cifrado", negado(lambda: como(url_api, a, "SELECT selado FROM segredos")))
        registrar("API não lê com SELECT *", negado(lambda: como(url_api, a, "SELECT * FROM segredos")))
        registrar("API não grava para outro cliente", negado(lambda: como(
            url_api, a, "INSERT INTO segredos (cliente_id, nome, selado, criado_por) VALUES (%s, 'x', 'x', %s)", b, usuario)))
        registrar("sem cliente definido, a API não vê nada", como(url_api, None, "SELECT nome FROM segredos") == [])
        registrar("outro cliente não vê", como(url_api, b, "SELECT nome FROM segredos") == [])
        como(url_api, b, "UPDATE segredos SET selado = 'x' WHERE nome = 'aws'")
        registrar("outro cliente não troca", bytes(admin.execute("SELECT selado FROM segredos WHERE cliente_id = %s", (a,)).fetchone()[0]) == selado)
        como(url_api, b, "DELETE FROM segredos WHERE nome = 'aws'")
        registrar("outro cliente não apaga", admin.execute("SELECT count(*) FROM segredos WHERE cliente_id = %s", (a,)).fetchone()[0] == 1)
        lido = como(url_ingestao, a, "SELECT selado FROM segredos WHERE nome = 'aws'")
        registrar("serviço de configuração lê e abre", cofre.abrir(privada, a, "aws", lido[0][0]) == segredo)
        registrar("serviço só vê o cliente da transação", como(url_ingestao, b, "SELECT selado FROM segredos") == [])
        registrar("serviço não altera", negado(lambda: como(url_ingestao, a, "UPDATE segredos SET selado = 'x'")))
        registrar("o valor não está em texto no banco", segredo.encode() not in bytes(admin.execute("SELECT selado FROM segredos WHERE cliente_id = %s", (a,)).fetchone()[0]))
        admin.execute("UPDATE segredos SET cliente_id = %s WHERE cliente_id = %s", (b, a))
        copiado = como(url_ingestao, b, "SELECT selado FROM segredos WHERE nome = 'aws'")[0][0]
        registrar("valor movido no banco para outro cliente não abre", invalido(lambda: cofre.abrir(privada, b, "aws", copiado)))
    finally:
        admin.execute("DELETE FROM segredos WHERE cliente_id = ANY(%s)", ([a, b],))
        admin.execute("DELETE FROM clientes WHERE id = ANY(%s)", ([a, b],))
        admin.close()


def main():
    publica, privada = testar_cifra()
    testar_banco(publica, privada)
    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
