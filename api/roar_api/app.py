"""API e tela do Roar. Por enquanto só leitura: fila de alertas e detalhe com as evidências.

    ROAR_API_ENDERECO=127.0.0.1:5433 uvicorn roar_api.app:app --port 8600

O cliente de cada consulta vem da sessão e vira a definição do RLS da transação. Nenhuma rota
aceita cliente vindo do navegador, então um id de outro cliente simplesmente não é encontrado.
"""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import sys
import time
import uuid
from collections import Counter, defaultdict
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import requests
import yaml
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field
from requests.adapters import HTTPAdapter

# O mesmo conversor que a instalação das regras usa.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ingestao"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))
from roar_api import consulta as linguagem_de_consulta  # noqa: E402
from roar_api import mfa, permissoes, relatorios  # noqa: E402
from roar_ingestao import cofre, fim  # noqa: E402
from roar_ingestao import fontes as fontes_de_dados  # noqa: E402
from roar_ingestao import sigma, xml_proprio  # noqa: E402
from roar_motor import acoes, blocos, fatos  # noqa: E402

INDEXER_URL = os.getenv("ROAR_INDEXER_URL", "https://127.0.0.1:9200")
ESTATICO = Path(__file__).parent / "estatico"
COOKIE = "roar_sessao"
HORAS_DE_SESSAO = 12
SENHA_MINIMA = 12
MINUTOS_PARA_O_CODIGO = 10
TENTATIVAS = 5
JANELA_TENTATIVAS = 900
# Abaixo disso são acontecimentos normais, como login: alimentam o UEBA, mas não pedem atenção.
NIVEL_MINIMO_NA_FILA = 5
TAMANHO_DA_PAGINA = 100
DIAS_DE_SIMULACAO = 7
REGRA_DE_BLOQUEIO_CONFIRMADO = "651"
DIAS_DE_SAUDE = 7
EVENTOS_POR_ENVIO = 100
TAMANHO_MAXIMO_DO_EVENTO = 60_000
TAMANHO_MAXIMO_DO_ENVIO = 1_000_000
LIMITE_DA_FILA_DO_WEBHOOK = 10_000
MINUTOS_ATE_PARADA = 15
DESLOCAMENTO_SYSLOG = 3
VERSAO_DO_AGENTE = "4.14.9"
# Endereço que os ativos e equipamentos do cliente usam para chegar a este servidor.
ENDERECO_PUBLICO = os.getenv("ROAR_ENDERECO_PUBLICO", "ENDERECO_DESTE_SERVIDOR")
LIMITE_DE_SIMULACAO = 5000
# Os mesmos pesos do UEBA; o teste confere que não divergem.
REGRAS_DE_COMPORTAMENTO = [
    {"tipo": "sucesso_apos_falhas", "peso": 50.0},
    {"tipo": "viagem_impossivel", "peso": 40.0},
    {"tipo": "primeiro_privilegio", "peso": 30.0},
    {"tipo": "pico_de_falhas", "peso": 20.0},
    {"tipo": "primeiro_host", "peso": 15.0},
    {"tipo": "horario_incomum", "peso": 15.0},
    {"tipo": "primeiro_ip", "peso": 10.0},
    {"tipo": "host_raro_no_cliente", "peso": 10.0},
]
SEGURANCA = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}

hasher = PasswordHasher()
HASH_FICTICIO = hasher.hash(secrets.token_hex(16))
falhas_de_login = defaultdict(list)


def _ler_env():
    valores = {}
    with open(os.getenv("ROAR_ENV", "/opt/panthera-roar/.env"), encoding="utf-8") as f:
        for linha in f:
            if "=" in linha and not linha.startswith("#"):
                k, v = linha.strip().split("=", 1)
                valores[k] = v
    return valores


class _NomeDoCertificado(HTTPAdapter):
    """Conecta em 127.0.0.1 e valida o certificado do indexer pelo nome do serviço."""

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_hostname"] = "wazuh.indexer"
        super().init_poolmanager(*args, **kwargs)


def _sessao_do_indexer(valores):
    sessao = requests.Session()
    sessao.auth = ("roar_leitor", valores["ROAR_LEITOR_SENHA"])
    sessao.verify = os.getenv("ROAR_INDEXER_CA", "/opt/panthera-roar/wazuh/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem")
    sessao.mount("https://", _NomeDoCertificado())
    return sessao


@asynccontextmanager
async def ciclo_de_vida(app):
    valores = _ler_env()
    url = (f"postgresql://roar_api:{valores['ROAR_API_SENHA']}@"
           f"{os.getenv('ROAR_BANCO_ENDERECO', '127.0.0.1:5433')}/roar")
    app.state.banco = ConnectionPool(url, min_size=1, max_size=10, open=True, kwargs={"row_factory": dict_row})
    app.state.indexer = _sessao_do_indexer(valores)
    yield
    app.state.banco.close()


app = FastAPI(title="Panthera Roar", lifespan=ciclo_de_vida, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def cabecalhos(request: Request, chamada):
    # Sem cabeçalho Origin é requisição fora do navegador; com ele, precisa ser a própria tela.
    origem = request.headers.get("origin")
    if request.method not in ("GET", "HEAD") and origem and origem.split("://")[-1] != request.headers.get("host"):
        return Response(status_code=403)
    resposta = await chamada(request)
    resposta.headers.update(SEGURANCA)
    # Dado de alerta nunca fica guardado; a tela sempre confere se há versão nova.
    resposta.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    return resposta


def _hash_do_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def sessao_atual(request: Request):
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(status_code=401)
    with request.app.state.banco.connection() as con:
        linha = con.execute("SELECT * FROM roar_sessao(%s)", (_hash_do_token(token),)).fetchone()
    if not linha:
        raise HTTPException(status_code=401)
    return linha


def _sessao_liberada(sessao):
    """Passou da senha não basta: nada de dado até confirmar o segundo fator e cumprir o que a organização exige."""
    if sessao["mfa_pendente"]:
        raise HTTPException(status_code=403, detail="Confirme o código do autenticador para continuar.")
    # Senha gerada por outra pessoa é temporária: até trocar, ela só serve para trocar.
    if sessao["trocar_senha"]:
        raise HTTPException(status_code=403, detail="Troque a senha temporária para continuar.")
    if sessao["mfa_obrigatorio"] and not sessao["mfa_ativo"]:
        raise HTTPException(status_code=403, detail="Sua organização exige o autenticador: configure-o para continuar.")


def exige(permissao):
    """Toda rota com dado declara o que pede. O teste de perfis confere cada uma contra a tabela esperada."""
    def verificar(sessao=Depends(sessao_atual)):
        _sessao_liberada(sessao)
        if not permissoes.pode(sessao["perfil"], permissao):
            raise HTTPException(status_code=403, detail="Seu perfil não permite esta ação.")
        return sessao
    verificar.permissao = permissao
    return verificar


@contextmanager
def do_cliente(request: Request, sessao):
    """Transação sob o RLS do cliente da sessão. A definição morre com a transação."""
    with request.app.state.banco.connection() as con:
        with con.transaction():
            con.execute("SELECT set_config('roar.cliente', %s, true)", (str(sessao["cliente_id"]),))
            yield con


class Entrada(BaseModel):
    email: str = Field(max_length=254)
    senha: str = Field(max_length=256)


def _bloqueado(chave):
    agora = time.monotonic()
    falhas_de_login[chave] = [t for t in falhas_de_login[chave] if agora - t < JANELA_TENTATIVAS]
    return len(falhas_de_login[chave]) >= TENTATIVAS


@app.post("/api/entrar", status_code=204, response_model=None)
def entrar(dados: Entrada, request: Request):
    email = dados.email.strip().lower()
    if _bloqueado(email):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde alguns minutos.")
    with request.app.state.banco.connection() as con:
        usuario = con.execute("SELECT * FROM roar_usuario_para_login(%s)", (email,)).fetchone()
    # Verifica mesmo sem usuário: o tempo de resposta não revela quem existe.
    try:
        hasher.verify(usuario["senha_hash"] if usuario else HASH_FICTICIO, dados.senha)
        valido = usuario is not None
    except (VerificationError, InvalidHashError):
        valido = False
    if not valido:
        falhas_de_login[email].append(time.monotonic())
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.")

    falhas_de_login.pop(email, None)
    token = secrets.token_urlsafe(32)
    with request.app.state.banco.connection() as con:
        precisa_de_codigo = con.execute("SELECT roar_mfa_ativo(%s) AS a", (usuario["id"],)).fetchone()["a"]
        if precisa_de_codigo:
            con.execute("SELECT roar_criar_sessao_mfa(%s, %s, %s)", (_hash_do_token(token), usuario["id"], MINUTOS_PARA_O_CODIGO))
        else:
            con.execute("SELECT roar_criar_sessao(%s, %s, %s)", (_hash_do_token(token), usuario["id"], HORAS_DE_SESSAO))
    saida = JSONResponse({"mfa": True}) if precisa_de_codigo else Response(status_code=204)
    saida.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/", secure=os.getenv("ROAR_COOKIE_SEGURO", "1") == "1",
                     max_age=MINUTOS_PARA_O_CODIGO * 60 if precisa_de_codigo else HORAS_DE_SESSAO * 3600)
    return saida


@app.post("/api/sair", status_code=204)
def sair(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        with request.app.state.banco.connection() as con:
            con.execute("SELECT roar_encerrar_sessao(%s)", (_hash_do_token(token),))
    response.delete_cookie(COOKIE, path="/")


@app.get("/api/eu")
def eu(request: Request, sessao=Depends(sessao_atual)):
    restantes = 0
    if sessao["mfa_ativo"] and not sessao["mfa_pendente"]:
        with request.app.state.banco.connection() as con:
            restantes = con.execute("SELECT roar_mfa_codigos_restantes(%s) AS n", (sessao["usuario_id"],)).fetchone()["n"]
    return {"nome": sessao["nome"], "cliente": sessao["cliente_nome"], "fuso": sessao["fuso"], "perfil": sessao["perfil"],
            "trocar_senha": sessao["trocar_senha"], "permissoes": sorted(permissoes.PERFIS.get(sessao["perfil"], ())),
            "mfa_pendente": sessao["mfa_pendente"], "mfa_ativo": sessao["mfa_ativo"], "mfa_obrigatorio": sessao["mfa_obrigatorio"],
            "mfa_codigos_restantes": restantes}


class CodigoDeMfa(BaseModel):
    codigo: str = Field(max_length=32)


class SenhaAtual(BaseModel):
    senha: str = Field(max_length=256)


class DesligarMfa(BaseModel):
    senha: str = Field(max_length=256)
    codigo: str = Field(max_length=32)


class PoliticaDeMfa(BaseModel):
    obrigatorio: bool


def _chave_de_mfa():
    return _ler_env()["ROAR_MFA_CHAVE"]


def _codigo_confere(con, usuario, codigo):
    """Aceita o código do aplicativo, uma vez por janela de tempo."""
    selado = con.execute("SELECT roar_mfa_segredo(%s) AS s", (usuario,)).fetchone()["s"]
    if not selado:
        return False
    try:
        segredo = mfa.abrir(_chave_de_mfa(), usuario, selado)
    except mfa.SegredoInvalido:
        return False
    passo = mfa.passo_do_codigo(segredo, codigo)
    return passo is not None and con.execute("SELECT roar_mfa_usar_passo(%s, %s) AS ok", (usuario, passo)).fetchone()["ok"]


@app.post("/api/mfa/verificar", status_code=204)
def verificar_mfa(dados: CodigoDeMfa, request: Request, sessao=Depends(sessao_atual)):
    """Depois da senha. Errar demais derruba esta sessão, e a pessoa volta a provar a senha."""
    if not sessao["mfa_pendente"]:
        raise HTTPException(status_code=409, detail="Esta sessão já está confirmada.")
    chave = f"mfa:{sessao['usuario_id']}"
    token = _hash_do_token(request.cookies[COOKIE])
    if _bloqueado(chave):
        # Em bloco próprio: um erro levantado dentro da conexão desfaria o encerramento.
        with request.app.state.banco.connection() as con:
            con.execute("SELECT roar_encerrar_sessao(%s)", (token,))
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde alguns minutos.")
    with request.app.state.banco.connection() as con:
        valido = _codigo_confere(con, sessao["usuario_id"], dados.codigo)
        recuperacao = False
        if not valido:
            valido = recuperacao = con.execute("SELECT roar_mfa_usar_recuperacao(%s, %s) AS ok",
                                               (sessao["usuario_id"], mfa.hash_do_codigo(sessao["usuario_id"], dados.codigo))).fetchone()["ok"]
        if not valido:
            falhas_de_login[chave].append(time.monotonic())
            raise HTTPException(status_code=422, detail="Código incorreto.")
        falhas_de_login.pop(chave, None)
        con.execute("SELECT roar_concluir_mfa(%s, %s)", (token, HORAS_DE_SESSAO))
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, %s, '')",
                    (sessao["cliente_id"], sessao["usuario_id"], "entrar_com_codigo_de_recuperacao" if recuperacao else "entrar_com_mfa"))


def _senha_confere(request, usuario, senha):
    with request.app.state.banco.connection() as con:
        guardado = con.execute("SELECT roar_hash_da_senha(%s) AS h", (usuario,)).fetchone()["h"]
    try:
        hasher.verify(guardado, senha)
        return True
    except (VerificationError, InvalidHashError):
        return False


def _antes_de_mexer_no_mfa(sessao):
    if sessao["mfa_pendente"]:
        raise HTTPException(status_code=403, detail="Confirme o código do autenticador para continuar.")
    if sessao["trocar_senha"]:
        raise HTTPException(status_code=403, detail="Troque a senha temporária para continuar.")


@app.post("/api/mfa/iniciar")
def iniciar_mfa(dados: SenhaAtual, request: Request, sessao=Depends(sessao_atual)):
    """Pede a senha: uma sessão esquecida aberta não pode trocar o segundo fator de ninguém."""
    _antes_de_mexer_no_mfa(sessao)
    chave = f"senha:{sessao['usuario_id']}"
    if _bloqueado(chave):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde alguns minutos.")
    if not _senha_confere(request, sessao["usuario_id"], dados.senha):
        falhas_de_login[chave].append(time.monotonic())
        raise HTTPException(status_code=403, detail="A senha não confere.")
    falhas_de_login.pop(chave, None)
    segredo = mfa.novo_segredo()
    with request.app.state.banco.connection() as con:
        if not con.execute("SELECT roar_mfa_guardar(%s, %s) AS ok", (sessao["usuario_id"], mfa.selar(_chave_de_mfa(), sessao["usuario_id"], segredo))).fetchone()["ok"]:
            raise HTTPException(status_code=409, detail="O autenticador já está ligado.")
    endereco = mfa.endereco(segredo, sessao["nome"])
    return {"segredo": segredo, "qr": mfa.qr_em_svg(endereco)}


@app.post("/api/mfa/confirmar")
def confirmar_mfa(dados: CodigoDeMfa, request: Request, sessao=Depends(sessao_atual)):
    """Só liga depois de um código certo: ninguém fica trancado por um QR que não leu. Os códigos de recuperação saem uma vez."""
    _antes_de_mexer_no_mfa(sessao)
    if sessao["mfa_ativo"]:
        raise HTTPException(status_code=409, detail="O autenticador já está ligado.")
    codigos = mfa.novos_codigos_de_recuperacao()
    with request.app.state.banco.connection() as con:
        if not _codigo_confere(con, sessao["usuario_id"], dados.codigo):
            raise HTTPException(status_code=422, detail="Código incorreto. Confira o horário do celular e tente de novo.")
        con.execute("SELECT roar_mfa_ativar(%s, %s)", (sessao["usuario_id"], [mfa.hash_do_codigo(sessao["usuario_id"], c) for c in codigos]))
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'ligar_mfa', '')", (sessao["cliente_id"], sessao["usuario_id"]))
    return {"codigos_de_recuperacao": codigos}


def _provar_senha_e_codigo(request, sessao, dados):
    chave = f"senha:{sessao['usuario_id']}"
    if _bloqueado(chave):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde alguns minutos.")
    with request.app.state.banco.connection() as con:
        confere = _senha_confere(request, sessao["usuario_id"], dados.senha) and _codigo_confere(con, sessao["usuario_id"], dados.codigo)
    if not confere:
        falhas_de_login[chave].append(time.monotonic())
        raise HTTPException(status_code=403, detail="A senha ou o código não confere.")
    falhas_de_login.pop(chave, None)


@app.post("/api/mfa/novos-codigos")
def novos_codigos_de_mfa(dados: DesligarMfa, request: Request, sessao=Depends(sessao_atual)):
    """Os antigos deixam de valer. Sem isto, quem gastou os códigos numa organização que exige ficaria sem saída."""
    _antes_de_mexer_no_mfa(sessao)
    if not sessao["mfa_ativo"]:
        raise HTTPException(status_code=409, detail="O autenticador não está ligado.")
    _provar_senha_e_codigo(request, sessao, dados)
    codigos = mfa.novos_codigos_de_recuperacao()
    with request.app.state.banco.connection() as con:
        con.execute("SELECT roar_mfa_ativar(%s, %s)", (sessao["usuario_id"], [mfa.hash_do_codigo(sessao["usuario_id"], c) for c in codigos]))
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'gerar_codigos_de_recuperacao', '')", (sessao["cliente_id"], sessao["usuario_id"]))
    return {"codigos_de_recuperacao": codigos}


@app.post("/api/mfa/desligar", status_code=204)
def desligar_mfa(dados: DesligarMfa, request: Request, sessao=Depends(sessao_atual)):
    _antes_de_mexer_no_mfa(sessao)
    if sessao["mfa_obrigatorio"]:
        raise HTTPException(status_code=409, detail="Sua organização exige o autenticador.")
    _provar_senha_e_codigo(request, sessao, dados)
    with request.app.state.banco.connection() as con:
        con.execute("SELECT roar_mfa_desligar(%s)", (sessao["usuario_id"],))
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'desligar_mfa', '')", (sessao["cliente_id"], sessao["usuario_id"]))


class TrocaDeSenha(BaseModel):
    atual: str = Field(max_length=256)
    nova: str = Field(min_length=SENHA_MINIMA, max_length=256)


@app.post("/api/minha-senha", status_code=204)
def trocar_minha_senha(dados: TrocaDeSenha, request: Request, sessao=Depends(sessao_atual)):
    """Exige a senha atual: uma sessão esquecida aberta não pode virar posse da conta."""
    if sessao["mfa_pendente"]:
        raise HTTPException(status_code=403, detail="Confirme o código do autenticador para continuar.")
    chave = f"senha:{sessao['usuario_id']}"
    if _bloqueado(chave):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde alguns minutos.")
    with request.app.state.banco.connection() as con:
        guardado = con.execute("SELECT roar_hash_da_senha(%s) AS h", (sessao["usuario_id"],)).fetchone()["h"]
    try:
        hasher.verify(guardado, dados.atual)
    except (VerificationError, InvalidHashError):
        falhas_de_login[chave].append(time.monotonic())
        raise HTTPException(status_code=403, detail="A senha atual não confere.")
    if dados.nova == dados.atual:
        raise HTTPException(status_code=422, detail="Escolha uma senha diferente da atual.")
    falhas_de_login.pop(chave, None)
    with do_cliente(request, sessao) as con:
        con.execute("SELECT roar_trocar_minha_senha(%s, %s, %s)",
                    (sessao["usuario_id"], hasher.hash(dados.nova), _hash_do_token(request.cookies[COOKIE])))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'trocar_senha', '')",
                    (sessao["cliente_id"], sessao["usuario_id"]))


class UsuarioNovo(BaseModel):
    email: str = Field(max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    nome: str = Field(min_length=1, max_length=120)
    perfil: str


class UsuarioAlterado(BaseModel):
    perfil: str
    ativo: bool


def _perfil_valido(perfil):
    if perfil not in permissoes.PERFIS:
        raise HTTPException(status_code=422, detail="Perfil desconhecido.")


@app.get("/api/usuarios")
def listar_usuarios(request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    with do_cliente(request, sessao) as con:
        return {"usuarios": con.execute("SELECT * FROM roar_listar_usuarios()").fetchall(), "eu": str(sessao["usuario_id"])}


@app.post("/api/usuarios", status_code=201)
def criar_usuario(dados: UsuarioNovo, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    """A senha temporária aparece só nesta resposta, e no primeiro acesso a pessoa precisa trocar."""
    _perfil_valido(dados.perfil)
    temporaria = secrets.token_urlsafe(18)
    try:
        with do_cliente(request, sessao) as con:
            novo = con.execute("SELECT roar_criar_usuario(%s, %s, %s, %s) AS id",
                               (dados.email.strip(), dados.nome.strip(), hasher.hash(temporaria), dados.perfil)).fetchone()["id"]
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_usuario', %s)",
                        (sessao["cliente_id"], sessao["usuario_id"], f"{novo} {dados.perfil}"))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Não foi possível usar este e-mail.")
    return {"id": novo, "senha_temporaria": temporaria}


@app.put("/api/usuarios/{identificador}", status_code=204)
def alterar_usuario(identificador: uuid.UUID, dados: UsuarioAlterado, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    _perfil_valido(dados.perfil)
    with do_cliente(request, sessao) as con:
        resultado = con.execute("SELECT roar_alterar_usuario(%s, %s, %s) AS r", (identificador, dados.perfil, dados.ativo)).fetchone()["r"]
        if resultado == "desconhecido":
            raise HTTPException(status_code=404)
        if resultado == "ultimo_administrador":
            raise HTTPException(status_code=409, detail="Esta é a última pessoa administradora: defina outra antes.")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'alterar_usuario', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{identificador} {dados.perfil} {'ativo' if dados.ativo else 'inativo'}"))


@app.post("/api/usuarios/{identificador}/mfa/remover", status_code=204)
def remover_mfa_de_usuario(identificador: uuid.UUID, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    """Para quem perdeu o celular e os códigos. É a porta dos fundos do segundo fator, então a auditoria diz quem usou."""
    # Na própria conta não: quem roubou uma sessão de administrador tiraria o segundo fator sem provar nada.
    if str(identificador) == str(sessao["usuario_id"]):
        raise HTTPException(status_code=409, detail="Para a sua conta, use a janela Autenticador.")
    with do_cliente(request, sessao) as con:
        if not con.execute("SELECT roar_mfa_remover_de(%s) AS ok", (identificador,)).fetchone()["ok"]:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'remover_mfa_de_usuario', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))


@app.put("/api/organizacao/mfa", status_code=204)
def definir_politica_de_mfa(dados: PoliticaDeMfa, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    # Quem liga a exigência precisa já usar: senão se tranca para fora na mesma hora.
    if dados.obrigatorio and not sessao["mfa_ativo"]:
        raise HTTPException(status_code=409, detail="Ligue o autenticador na sua conta antes de exigir de todos.")
    with do_cliente(request, sessao) as con:
        con.execute("SELECT roar_definir_mfa_obrigatorio(%s)", (dados.obrigatorio,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'definir_mfa_obrigatorio', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(dados.obrigatorio)))


@app.post("/api/usuarios/{identificador}/nova-senha")
def redefinir_senha(identificador: uuid.UUID, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    temporaria = secrets.token_urlsafe(18)
    with do_cliente(request, sessao) as con:
        if not con.execute("SELECT roar_redefinir_senha(%s, %s) AS ok", (identificador, hasher.hash(temporaria))).fetchone()["ok"]:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'redefinir_senha', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))
    return {"senha_temporaria": temporaria}


@app.get("/api/fila")
def fila(request: Request, sessao=Depends(exige(permissoes.VER)), limite: int = 200):
    limite = max(1, min(limite, 500))
    with do_cliente(request, sessao) as con:
        riscos = con.execute(
            """SELECT a.id, a.severidade, a.risco_maximo, a.aberto_em AS quando, a.estado,
                      e.tipo AS entidade_tipo, coalesce(e.nome, e.chave) AS entidade, e.risco AS risco_atual,
                      (SELECT array_agg(DISTINCT s.tipo) FROM sinais s
                        WHERE s.cliente_id = a.cliente_id AND s.entidade_id = a.entidade_id
                          AND s.ocorrido_em >= a.aberto_em - interval '48 hours') AS sinais
               FROM alertas_risco a JOIN entidades e ON e.id = a.entidade_id
               WHERE a.estado = 'aberto' ORDER BY a.risco_maximo DESC, a.aberto_em DESC LIMIT %s""",
            (limite,)).fetchall()
        grupos = con.execute(
            """SELECT g.id, g.severidade, g.nivel, g.total, g.regras, g.ultima_em AS quando, g.primeira_em,
                      host(g.ip_origem) AS ip_origem, g.agente_id,
                      (SELECT v.agente_nome FROM eventos v WHERE v.cliente_id = g.cliente_id AND v.grupo_id = g.id
                        ORDER BY v.id DESC LIMIT 1) AS ativo,
                      (SELECT v.regra_descricao FROM eventos v WHERE v.cliente_id = g.cliente_id AND v.grupo_id = g.id
                        ORDER BY v.nivel DESC, v.id DESC LIMIT 1) AS descricao
               FROM grupos_alerta g WHERE g.nivel >= %s ORDER BY g.nivel DESC, g.ultima_em DESC LIMIT %s""",
            (NIVEL_MINIMO_NA_FILA, limite)).fetchall()
    return {"riscos": riscos, "grupos": grupos}


@app.get("/api/panorama")
def panorama(request: Request, sessao=Depends(exige(permissoes.VER)), dias: int = 30):
    dias = max(1, min(dias, 90))
    fuso = sessao["fuso"]
    with do_cliente(request, sessao) as con:
        por_dia = con.execute(
            """WITH dias AS (
                 SELECT generate_series((now() AT TIME ZONE %(fuso)s)::date - (%(dias)s - 1),
                                        (now() AT TIME ZONE %(fuso)s)::date, interval '1 day')::date AS dia)
               SELECT d.dia, count(*) FILTER (WHERE e.severidade = 'baixa') AS baixa,
                      count(*) FILTER (WHERE e.severidade = 'media') AS media,
                      count(*) FILTER (WHERE e.severidade = 'alta') AS alta,
                      count(*) FILTER (WHERE e.severidade = 'critica') AS critica
               FROM dias d LEFT JOIN eventos e
                 ON (e.ocorrido_em AT TIME ZONE %(fuso)s)::date = d.dia AND e.nivel >= %(nivel)s
               GROUP BY d.dia ORDER BY d.dia""",
            {"fuso": fuso, "dias": dias, "nivel": NIVEL_MINIMO_NA_FILA}).fetchall()
        desde = "now() - make_interval(days => %s)"
        sinais = con.execute(
            f"SELECT tipo, count(*) AS total FROM sinais WHERE ocorrido_em >= {desde}"
            " GROUP BY tipo ORDER BY total DESC, tipo", (dias,)).fetchall()
        origens = con.execute(
            f"""SELECT host(ip_origem) AS origem, count(*) AS total FROM eventos
                WHERE ip_origem IS NOT NULL AND nivel >= %s AND ocorrido_em >= {desde}
                GROUP BY ip_origem ORDER BY total DESC, origem LIMIT 8""",
            (NIVEL_MINIMO_NA_FILA, dias)).fetchall()
        # O risco guardado é o do último evento; aqui vale o de agora, já com o decaimento.
        riscos = con.execute(
            """SELECT coalesce(nome, chave) AS entidade, tipo,
                      risco * power(0.5, greatest(extract(epoch FROM now() - risco_em), 0) / 86400) AS risco
               FROM entidades WHERE risco > 0 AND risco_em IS NOT NULL ORDER BY 3 DESC LIMIT 8""").fetchall()
    return {"por_dia": por_dia, "sinais": sinais, "origens": origens,
            "riscos": [r for r in riscos if r["risco"] >= 1]}


def _sem_curinga(texto):
    return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@app.get("/api/eventos")
def eventos(request: Request, sessao=Depends(exige(permissoes.VER)), busca: str = "", severidade: str = "",
            dias: int = 30, antes_de: int = 0):
    """Todos os eventos, inclusive os normais, em páginas do mais novo para o mais antigo."""
    dias = max(1, min(dias, 90))
    condicoes = ["ocorrido_em >= now() - make_interval(days => %s)"]
    parametros = [dias]
    busca = busca.strip()[:200]
    if busca:
        condicoes.append("(usuario ILIKE %s OR regra_descricao ILIKE %s OR regra_id = %s"
                         " OR agente_nome ILIKE %s OR host(ip_origem) ILIKE %s)")
        termo = f"%{_sem_curinga(busca)}%"
        parametros += [termo, termo, busca, termo, termo]
    if severidade in ("baixa", "media", "alta", "critica"):
        condicoes.append("severidade = %s")
        parametros.append(severidade)
    if 0 < antes_de < 2**63:
        condicoes.append("id < %s")
        parametros.append(antes_de)
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            f"""SELECT id, ocorrido_em, severidade, nivel, regra_id, regra_descricao, agente_nome AS ativo,
                       host(ip_origem) AS ip_origem, usuario
                FROM eventos WHERE {' AND '.join(condicoes)} ORDER BY id DESC LIMIT %s""",
            (*parametros, TAMANHO_DA_PAGINA + 1)).fetchall()
    return {"eventos": linhas[:TAMANHO_DA_PAGINA], "ha_mais": len(linhas) > TAMANHO_DA_PAGINA}


@app.get("/api/eventos/{identificador}/bruto")
def evento_bruto(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO))):
    """O alerta como chegou. Pode ter dado pessoal, então cada acesso fica registrado."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute(
            "SELECT id, origem_id, origem, ocorrido_em, recebido_em, bruto FROM eventos WHERE id = %s",
            (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'ver_bruto', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))
    return linha


CAMPOS_DE_LOG = ("agent.name", "location", "decoder.name", "data.srcip", "data.srcuser", "data.dstuser", "data.protocol", "predecoder.program_name")


def _filtros_de_campo(texto):
    """Filtros clicados na tela: [{"campo", "valor", "negar"}]. Só viram comparação exata de campo."""
    if not texto:
        return [], []
    try:
        filtros = json.loads(texto)
    except ValueError:
        raise HTTPException(status_code=422)
    if not isinstance(filtros, list) or len(filtros) > 20:
        raise HTTPException(status_code=422)
    condicoes, exclusoes = [], []
    for f in filtros:
        campo = f.get("campo") if isinstance(f, dict) else None
        valor = f.get("valor") if isinstance(f, dict) else None
        if (not isinstance(campo, str) or not re.fullmatch(r"[A-Za-z0-9_@][A-Za-z0-9_.@-]{0,120}", campo)
                or not isinstance(valor, (str, int, float)) or isinstance(valor, bool) or len(str(valor)) > 1000):
            raise HTTPException(status_code=422)
        (exclusoes if f.get("negar") is True else condicoes).append({"term": {campo: valor}})
    return condicoes, exclusoes


@app.get("/api/logs")
def logs(request: Request, sessao=Depends(exige(permissoes.VER_BRUTO)), busca: str = "", dias: int = 7, depois_de: str = "", filtros: str = ""):
    """Logs como chegaram, inclusive os que não viraram alerta. Cada busca fica registrada."""
    dias = max(1, min(dias, 90))
    busca = busca.strip()
    try:
        pedido = linguagem_de_consulta.analisar(busca)
    except linguagem_de_consulta.ConsultaInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    condicoes, exclusoes = _filtros_de_campo(filtros)
    with do_cliente(request, sessao) as con:
        gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'buscar_logs', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], (busca or "*")[:800] + (f" {filtros[:400]}" if filtros else "")))
    if not gerenciadores:
        return {"logs": [], "proximo": None, "total": 0, "linha_do_tempo": [], "campos": {}, "colunas": pedido.colunas, "contagem": None}

    condicoes.append({"range": {"timestamp": {"gte": f"now-{dias}d"}}})
    condicoes.append(pedido.filtro)
    ordem = [{pedido.ordem[0]: {"order": pedido.ordem[1], "unmapped_type": "keyword"}}] if pedido.ordem else []
    tamanho = min(pedido.limite, TAMANHO_DA_PAGINA) if pedido.limite else TAMANHO_DA_PAGINA
    consulta = {
        "size": 0 if pedido.contar else tamanho,
        "sort": [*ordem, {"timestamp": "desc"}, {"_id": "desc"}],
        "query": {"bool": {"filter": condicoes, "must_not": exclusoes}},
        "track_total_hits": 100000,
    }
    if pedido.contar_por:
        consulta["aggs"] = {"contagem": {"terms": {"field": pedido.contar_por, "size": min(pedido.limite or 20, linguagem_de_consulta.LIMITE_DE_GRUPOS)}}}
    elif not depois_de and not pedido.contar:
        # Contagens e linha do tempo só na primeira página: as seguintes pedem só mais linhas.
        consulta["aggs"] = {
            "linha_do_tempo": {"auto_date_histogram": {"field": "timestamp", "buckets": 48}},
            **{f"campo_{i}": {"terms": {"field": campo, "size": 8}} for i, campo in enumerate(CAMPOS_DE_LOG)},
        }
    if depois_de:
        try:
            cursor = json.loads(depois_de)
        except ValueError:
            raise HTTPException(status_code=422)
        if not (isinstance(cursor, list) and len(cursor) == 2 and all(isinstance(c, (int, str)) for c in cursor)):
            raise HTTPException(status_code=422)
        consulta["search_after"] = cursor
    # O índice vem do banco, sob o RLS do cliente da sessão, nunca da requisição.
    indices = ",".join(f"wazuh-archives-4.x-{g}-*" for g in gerenciadores)
    resposta = request.app.state.indexer.post(f"{INDEXER_URL}/{indices}/_search?allow_no_indices=true&ignore_unavailable=true",
                                              json=consulta, timeout=30)
    if resposta.status_code == 400:
        # Pedido bem formado que o tipo do campo não aceita, como contar por um texto longo.
        raise HTTPException(status_code=422, detail="Este campo não aceita essa operação. Tente outro campo.")
    if not resposta.ok:
        raise HTTPException(status_code=502, detail="Não foi possível consultar os logs.")
    corpo = resposta.json()
    achados = corpo["hits"]["hits"]
    agregados = corpo.get("aggregations", {})
    contagem = None
    if pedido.contar:
        contagem = {"campo": pedido.contar_por,
                    "linhas": [{"valor": b["key"], "total": b["doc_count"]} for b in agregados.get("contagem", {}).get("buckets", [])]}
    # Só pagina quando a pessoa não pediu um limite: limite é o tamanho que ela quer ver.
    tem_mais = len(achados) == TAMANHO_DA_PAGINA and not pedido.limite
    return {
        "logs": [{"id": h["_id"], "bruto": h["_source"]} for h in achados],
        "proximo": json.dumps(achados[-1]["sort"][-2:]) if tem_mais and not pedido.ordem else None,
        "colunas": pedido.colunas,
        "contagem": contagem,
        "total": corpo["hits"]["total"]["value"],
        "total_exato": corpo["hits"]["total"]["relation"] == "eq",
        "linha_do_tempo": [{"quando": b["key_as_string"], "total": b["doc_count"]}
                           for b in agregados.get("linha_do_tempo", {}).get("buckets", [])],
        "campos": {campo: [{"valor": b["key"], "total": b["doc_count"]} for b in agregados.get(f"campo_{i}", {}).get("buckets", [])]
                   for i, campo in enumerate(CAMPOS_DE_LOG)},
    }


@app.get("/api/ativos")
def ativos(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            """SELECT a.agente_id, a.nome, a.ip, a.sistema, a.versao, a.estado, a.grupos, a.ultima_conexao, a.sca_politica,
                      a.sca_nota, a.sca_aprovados, a.sca_reprovados,
                      (SELECT count(*) FROM eventos e WHERE e.gerenciador_id = a.gerenciador_id AND e.agente_id = a.agente_id
                        AND e.nivel >= %s AND e.ocorrido_em >= now() - interval '7 days') AS alertas_7_dias
               FROM ativos a WHERE a.agente_id <> '000' ORDER BY a.nome""", (NIVEL_MINIMO_NA_FILA,)).fetchall()
    return {"ativos": linhas}


@app.get("/api/mitre/matriz")
def matriz_mitre(request: Request, sessao=Depends(exige(permissoes.VER)), dias: int = 30):
    """A matriz inteira do ATT&CK, com o que foi observado e o que tem regra, somando as subtécnicas."""
    dias = max(1, min(dias, 90))
    with do_cliente(request, sessao) as con:
        taticas = con.execute("SELECT tatica, nome FROM taticas_attack ORDER BY ordem").fetchall()
        tecnicas = con.execute(
            """WITH observadas AS (
                 SELECT split_part(t, '.', 1) AS tecnica, count(*) AS total
                 FROM eventos e, unnest(e.mitre) AS t
                 WHERE e.ocorrido_em >= now() - make_interval(days => %s) GROUP BY 1),
               cobertas AS (
                 SELECT split_part(t, '.', 1) AS tecnica, count(DISTINCT r.regra_id) AS total
                 FROM regras r, unnest(r.mitre) AS t GROUP BY 1),
               defendidas AS (
                 SELECT split_part(tecnica, '.', 1) AS tecnica, count(DISTINCT defesa_id) AS total
                 FROM tecnicas_defesa GROUP BY 1)
               SELECT a.tecnica, a.nome, a.taticas, coalesce(o.total, 0) AS observados, coalesce(c.total, 0) AS regras,
                      coalesce(d.total, 0) AS defesas
               FROM tecnicas_attack a
                 LEFT JOIN observadas o ON o.tecnica = a.tecnica
                 LEFT JOIN cobertas c ON c.tecnica = a.tecnica
                 LEFT JOIN defendidas d ON d.tecnica = a.tecnica
               WHERE a.pai IS NULL ORDER BY coalesce(o.total, 0) DESC, a.tecnica""", (dias,)).fetchall()
        versao = con.execute("SELECT max(versao) AS versao FROM tecnicas_attack").fetchone()["versao"]
    return {"taticas": taticas, "tecnicas": tecnicas, "versao": versao}


@app.get("/api/mitre/tecnicas/{tecnica}")
def tecnica_mitre(tecnica: str, request: Request, sessao=Depends(exige(permissoes.VER)), dias: int = 30):
    """As regras que deram match com a técnica, as que cobrem e ainda não dispararam, e as defesas."""
    if not re.fullmatch(r"T\d{4}(\.\d{3})?", tecnica):
        raise HTTPException(status_code=404)
    dias = max(1, min(dias, 90))
    familia = [tecnica, f"{tecnica}.%"]
    with do_cliente(request, sessao) as con:
        dados = con.execute("SELECT tecnica, nome, taticas, endereco FROM tecnicas_attack WHERE tecnica = %s", (tecnica,)).fetchone()
        if not dados:
            raise HTTPException(status_code=404)
        match = con.execute(
            """SELECT e.regra_id, max(e.regra_descricao) AS descricao, max(e.nivel) AS nivel, count(*) AS disparos, max(e.ocorrido_em) AS ultimo,
                      array_agg(DISTINCT t) AS tecnicas
               FROM eventos e, unnest(e.mitre) AS t
               WHERE (t = %s OR t LIKE %s) AND e.ocorrido_em >= now() - make_interval(days => %s)
               GROUP BY e.regra_id ORDER BY disparos DESC LIMIT 100""", (*familia, dias)).fetchall()
        com_match = [m["regra_id"] for m in match]
        cobertura = con.execute(
            """SELECT DISTINCT r.regra_id, r.descricao, r.nivel, r.nivel AS ordem FROM regras r, unnest(r.mitre) AS t
               WHERE (t = %s OR t LIKE %s) AND NOT (r.regra_id = ANY(%s)) ORDER BY ordem DESC, r.regra_id LIMIT 100""",
            (*familia, com_match)).fetchall()
        subtecnicas = con.execute("SELECT tecnica, nome FROM tecnicas_attack WHERE pai = %s ORDER BY tecnica",
                                  (tecnica,)).fetchall()
        # Subtécnica sem mapeamento próprio herda as defesas da técnica mãe.
        defesas = con.execute(
            """SELECT DISTINCT defesa_id, defesa_nome, tatica_defesa FROM tecnicas_defesa
               WHERE tecnica = %s OR tecnica LIKE %s OR tecnica = %s ORDER BY tatica_defesa, defesa_nome""",
            (*familia, tecnica.split(".")[0])).fetchall()
    return {"tecnica": dados, "match": match, "cobertura": cobertura, "subtecnicas": subtecnicas, "defesas": defesas}


NORMAS_CONHECIDAS = {"pci_dss": "PCI DSS", "gdpr": "GDPR", "hipaa": "HIPAA", "nist_800_53": "NIST 800-53", "tsc": "TSC", "gpg13": "GPG13"}


@app.get("/api/normas")
def normas(request: Request, sessao=Depends(exige(permissoes.VER)), norma: str = "gdpr", dias: int = 30):
    """Alertas por controle da norma, como o Wazuh já os marca em cada regra."""
    if norma not in NORMAS_CONHECIDAS:
        raise HTTPException(status_code=422)
    dias = max(1, min(dias, 90))
    with do_cliente(request, sessao) as con:
        controles = con.execute(
            """SELECT c.controle, count(*) AS total, max(e.nivel) AS nivel, max(e.ocorrido_em) AS ultimo,
                      count(DISTINCT e.agente_id) AS ativos
               FROM eventos e, jsonb_array_elements_text(
                      CASE WHEN jsonb_typeof(e.bruto -> 'rule' -> %(n)s) = 'array' THEN e.bruto -> 'rule' -> %(n)s ELSE '[]' END
                    ) AS c(controle)
               WHERE e.ocorrido_em >= now() - make_interval(days => %(d)s)
               GROUP BY c.controle ORDER BY total DESC LIMIT 200""", {"n": norma, "d": dias}).fetchall()
        regras_da_norma = con.execute("SELECT count(*) AS total FROM regras WHERE normas ? %s", (norma,)).fetchone()["total"]
    return {"norma": norma, "normas": NORMAS_CONHECIDAS, "controles": controles, "regras_da_norma": regras_da_norma}


@app.get("/api/arquivos")
def arquivos(request: Request, sessao=Depends(exige(permissoes.VER)), dias: int = 30, busca: str = ""):
    """Mudanças em arquivos monitorados."""
    dias = max(1, min(dias, 90))
    condicao, parametros = "", [dias]
    busca = busca.strip()[:200]
    if busca:
        condicao = "AND (bruto #>> '{syscheck,path}' ILIKE %s OR agente_nome ILIKE %s)"
        termo = f"%{_sem_curinga(busca)}%"
        parametros += [termo, termo]
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            f"""SELECT id, ocorrido_em, severidade, agente_nome AS ativo, regra_descricao,
                       bruto #>> '{{syscheck,path}}' AS caminho, bruto #>> '{{syscheck,event}}' AS mudanca,
                       bruto #>> '{{syscheck,sha256_after}}' AS sha256, bruto #>> '{{syscheck,uname_after}}' AS dono
                FROM eventos WHERE 'syscheck' = ANY(regra_grupos) AND ocorrido_em >= now() - make_interval(days => %s) {condicao}
                ORDER BY id DESC LIMIT %s""", (*parametros, TAMANHO_DA_PAGINA)).fetchall()
    return {"arquivos": linhas}


@app.get("/api/relatorios")
def gerar_relatorio(request: Request, sessao=Depends(exige(permissoes.VER)), dias: int = 30, tipo: str = "completo", formato: str = "pdf"):
    """Reúne nomes e endereços em um arquivo que sai do sistema: toda geração fica registrada, com o resumo do arquivo."""
    if tipo not in ("completo", "executivo") or formato not in ("pdf", "json"):
        raise HTTPException(status_code=422, detail="Tipo ou formato desconhecido.")
    dias = max(1, min(dias, 365))
    with do_cliente(request, sessao) as con:
        dados = relatorios.coletar(con, dias)
    if formato == "json":
        conteudo, tipo_midia, extensao = relatorios.dados_em_json(dados), "application/json", "json"
    else:
        conteudo, tipo_midia, extensao = relatorios.gerar_pdf(relatorios.montar_html(dados, sessao, dias, tipo)), "application/pdf", "pdf"
    resumo = relatorios.resumo_do_arquivo(conteudo)
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'gerar_relatorio', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{tipo} {dias}d {extensao} sha256:{resumo}"))
    nome = f"relatorio-{tipo}-{datetime.now(timezone.utc):%Y%m%d}.{extensao}"
    return Response(conteudo, media_type=tipo_midia, headers={"Content-Disposition": f'attachment; filename="{nome}"', "X-Resumo-SHA256": resumo})


@app.get("/api/cves")
def consultar_cves(request: Request, sessao=Depends(exige(permissoes.VER)), busca: str = "", prioridade: str = "", deslocamento: int = 0):
    """A base é pública e igual para todos: nada aqui depende do cliente, nem revela o que ele tem."""
    condicoes, parametros = ["NOT rejeitado"], []
    busca = busca.strip()[:200]
    if busca:
        if re.fullmatch(r"(?i)CVE-\d{4}-\d+", busca):
            condicoes = ["cve = %s"]
            parametros.append(busca.upper())
        else:
            condicoes.append("busca @@ plainto_tsquery('simple', %s)")
            parametros.append(busca)
    if prioridade in ("agora", "alta", "media", "baixa", "sem_dados"):
        condicoes.append("prioridade = %s")
        parametros.append(prioridade)
    deslocamento = max(0, min(deslocamento, 10_000))
    onde = " AND ".join(condicoes)
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            f"""SELECT cve, publicado_em, rejeitado, coalesce(titulo, left(descricao, 160)) AS titulo, produto, cvss, epss, kev_desde, kev_ransomware, prioridade FROM cves
                WHERE {onde} ORDER BY kev_desde DESC NULLS LAST, epss DESC NULLS LAST, cve DESC LIMIT %s OFFSET %s""",
            (*parametros, TAMANHO_DA_PAGINA, deslocamento)).fetchall()
        carga = con.execute("SELECT total, versao, epss_data, carregada_em, falha, falha_em, carregada_em < now() - interval '3 days' AS velha FROM cves_carga").fetchone()
        contagem = con.execute("SELECT prioridade, count(*) AS total FROM cves WHERE NOT rejeitado GROUP BY 1").fetchall() if not busca and not prioridade else []
    return {"cves": linhas, "carga": carga, "contagem": contagem}


@app.get("/api/cves/{cve}")
def detalhe_de_cve(cve: str, request: Request, sessao=Depends(exige(permissoes.VER))):
    if not re.fullmatch(r"(?i)CVE-\d{4}-\d+", cve):
        raise HTTPException(status_code=404)
    with do_cliente(request, sessao) as con:
        linha = con.execute(
            """SELECT cve, publicado_em, rejeitado, titulo, descricao, produto, cvss, vetor, cvss_fonte, kev_desde, kev_ransomware, kev_prazo, epss, epss_percentil, prioridade
               FROM cves WHERE cve = %s""", (cve.upper(),)).fetchone()
    if not linha:
        raise HTTPException(status_code=404)
    return linha


class CaminhoDeFim(BaseModel):
    caminho: str = Field(max_length=400)
    sistema: str
    modo: str = "agendado"


class PedidoDeVarredura(BaseModel):
    agente_id: str = Field(pattern=r"^[0-9]{3,8}$")


@app.get("/api/fim")
def visao_de_fim(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        caminhos = con.execute(
            "SELECT id, caminho, sistema, modo, estado, mensagem, criado_em FROM fim_caminhos WHERE estado <> 'desativado' ORDER BY sistema, caminho").fetchall()
        ativos_ = con.execute(
            """SELECT a.agente_id, a.nome, a.sistema, a.estado, a.fim_inicio, a.fim_fim,
                      (SELECT count(*) FROM fim_base b WHERE b.gerenciador_id = a.gerenciador_id AND b.agente_id = a.agente_id) AS arquivos
               FROM ativos a WHERE a.agente_id <> '000' ORDER BY a.nome""").fetchall()
        por_dia = con.execute(
            """SELECT ocorrido_em::date AS dia, bruto #>> '{syscheck,event}' AS mudanca, count(*) AS total FROM eventos
               WHERE 'syscheck' = ANY(regra_grupos) AND ocorrido_em >= now() - interval '30 days' GROUP BY 1, 2 ORDER BY 1""").fetchall()
    return {"caminhos": caminhos, "ativos": ativos_, "por_dia": por_dia}


@app.get("/api/fim/ativos/{agente}/arquivos")
def base_de_arquivos(agente: str, request: Request, sessao=Depends(exige(permissoes.VER)), busca: str = "", deslocamento: int = 0):
    if not re.fullmatch(r"[0-9]{3,8}", agente):
        raise HTTPException(status_code=404)
    termo = f"%{_sem_curinga(busca.strip()[:200])}%"
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            """SELECT caminho, tamanho, modificado_em, sha256, dono, permissao, count(*) OVER () AS total FROM fim_base
               WHERE agente_id = %s AND caminho ILIKE %s ORDER BY caminho LIMIT %s OFFSET %s""",
            (agente, termo, TAMANHO_DA_PAGINA, max(0, deslocamento))).fetchall()
    return {"arquivos": linhas, "total": linhas[0]["total"] if linhas else 0}


@app.post("/api/fim/caminhos", status_code=201)
def criar_caminho_de_fim(dados: CaminhoDeFim, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    try:
        caminho = fim.validar_caminho(dados.caminho, dados.sistema, dados.modo)
    except fim.CaminhoInvalido as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    try:
        with do_cliente(request, sessao) as con:
            gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
            if not gerenciador:
                raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
            novo = con.execute(
                "INSERT INTO fim_caminhos (cliente_id, gerenciador_id, caminho, sistema, modo, criado_por) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (sessao["cliente_id"], gerenciador["id"], caminho, dados.sistema, dados.modo, sessao["usuario_id"])).fetchone()["id"]
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_caminho_fim', %s)",
                        (sessao["cliente_id"], sessao["usuario_id"], caminho))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Este caminho já está monitorado.")
    return {"id": novo, "estado": "pendente"}


@app.post("/api/fim/caminhos/{identificador}/desativar", status_code=204)
def desativar_caminho_de_fim(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute("UPDATE fim_caminhos SET estado = 'desativado' WHERE id = %s RETURNING caminho", (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'desativar_caminho_fim', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], linha["caminho"]))


@app.post("/api/fim/varreduras", status_code=202)
def pedir_varredura(dados: PedidoDeVarredura, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """Só aceita ativo do próprio cliente: o gerenciador vem da linha do ativo, sob o RLS."""
    with do_cliente(request, sessao) as con:
        ativo = con.execute("SELECT gerenciador_id FROM ativos WHERE agente_id = %s AND agente_id <> '000' ORDER BY atualizado_em DESC LIMIT 1", (dados.agente_id,)).fetchone()
        if not ativo:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO fim_varreduras (cliente_id, gerenciador_id, agente_id, pedida_por) VALUES (%s, %s, %s, %s)",
                    (sessao["cliente_id"], ativo["gerenciador_id"], dados.agente_id, sessao["usuario_id"]))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'pedir_varredura_fim', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], dados.agente_id))
    return {"estado": "pendente"}


@app.get("/api/regras")
def regras(request: Request, sessao=Depends(exige(permissoes.VER)), busca: str = "", dias: int = 30,
           so_disparadas: bool = False, deslocamento: int = 0):
    dias = max(1, min(dias, 90))
    deslocamento = max(0, min(deslocamento, 100000))
    condicoes, parametros = ["TRUE"], []
    busca = busca.strip()[:200]
    if busca:
        termo = f"%{_sem_curinga(busca)}%"
        condicoes.append("(r.regra_id = %s OR r.descricao ILIKE %s OR r.arquivo ILIKE %s"
                         " OR array_to_string(r.grupos, ' ') ILIKE %s OR array_to_string(r.mitre, ' ') ILIKE %s)")
        parametros += [busca, termo, termo, termo, termo]
    if so_disparadas:
        condicoes.append("d.total IS NOT NULL")
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            f"""WITH disparos AS (
                  SELECT gerenciador_id, regra_id, count(*) AS total, max(ocorrido_em) AS ultimo FROM eventos
                  WHERE ocorrido_em >= now() - make_interval(days => %s) GROUP BY gerenciador_id, regra_id)
                SELECT r.regra_id, r.nivel, r.descricao, r.grupos, r.mitre, r.arquivo, r.ativa,
                       (SELECT CASE WHEN p.desligada THEN 'desligada' ELSE 'editada' END FROM regras_proprias p
                        WHERE p.substitui = r.regra_id AND p.estado IN ('ativa', 'pendente') LIMIT 1) AS ajuste,
                       coalesce(d.total, 0) AS disparos, d.ultimo, count(*) OVER () AS total_filtrado
                FROM regras r LEFT JOIN disparos d ON d.gerenciador_id = r.gerenciador_id AND d.regra_id = r.regra_id
                WHERE {' AND '.join(condicoes)}
                ORDER BY coalesce(d.total, 0) DESC, r.nivel DESC, r.regra_id LIMIT %s OFFSET %s""",
            (dias, *parametros, TAMANHO_DA_PAGINA, deslocamento)).fetchall()
        catalogo = con.execute("SELECT count(*) AS total, max(atualizado_em) AS atualizado_em FROM regras").fetchone()
    return {"regras": linhas, "total_filtrado": linhas[0]["total_filtrado"] if linhas else 0,
            "catalogo": catalogo["total"], "atualizado_em": catalogo["atualizado_em"],
            "comportamento": REGRAS_DE_COMPORTAMENTO}


class RegraNova(BaseModel):
    formato: str = Field(pattern="^(sigma|guiada|xml)$")
    # Sigma ou XML escrito pela pessoa.
    sigma: str = Field(default="", max_length=65536)
    xml: str = Field(default="", max_length=65536)
    # Formulário guiado.
    titulo: str = Field(default="", max_length=200)
    origem: str = Field(default="", max_length=40)
    nivel: str = Field(default="medium", max_length=20)
    condicoes: list[dict] = Field(default_factory=list, max_length=10)
    tecnicas: list[str] = Field(default_factory=list, max_length=10)


def _converter(dados: RegraNova):
    """Devolve (título, origem, XML gerado, quantas regras). Nada é instalado ainda."""
    if dados.formato == "xml":
        try:
            regras = xml_proprio.analisar(dados.xml)
        except xml_proprio.XmlInvalido as erro:
            raise HTTPException(status_code=422, detail=str(erro))
        return regras[0][0][:200], dados.xml, dados.xml, len(regras)
    try:
        if dados.formato == "guiada":
            origem = sigma.sigma_da_regra_guiada(dados.titulo, dados.origem, dados.nivel, dados.condicoes, dados.tecnicas)
        else:
            origem = dados.sigma
        resultados = sigma.converter_textos([origem])
    except sigma.NaoConvertivel as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    if len(resultados) != 1:
        raise HTTPException(status_code=422, detail="Informe uma regra por vez.")
    if not resultados[0].xml:
        raise HTTPException(status_code=422, detail=f"Não foi possível converter: {resultados[0].motivo}")
    return resultados[0].titulo, origem, "\n".join(resultados[0].xml), len(resultados[0].xml)


@app.post("/api/regras/converter")
def converter_regra(dados: RegraNova, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    titulo, origem, xml, ramos = _converter(dados)
    return {"titulo": titulo, "sigma": origem, "xml": xml, "regras_geradas": ramos}


@app.get("/api/regras/proprias")
def listar_regras_proprias(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            """SELECT id, titulo, formato, estado, mensagem, criada_em, aplicada_em, origem FROM regras_proprias
               WHERE substitui IS NULL ORDER BY id DESC LIMIT 200""").fetchall()
    return {"regras": linhas}


@app.post("/api/regras/proprias", status_code=201)
def criar_regra_propria(dados: RegraNova, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    titulo, origem, xml, _ = _converter(dados)
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
        novo = _gravar_regra_propria(con, sessao, gerenciador["id"], titulo, dados.formato, origem, xml)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_regra', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(novo)))
    return {"id": novo, "estado": "pendente"}


@app.put("/api/regras/proprias/{identificador}")
def editar_regra_propria(identificador: int, dados: RegraNova, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    """Volta a ser pendente: a versão editada passa pela mesma validação no gerenciador."""
    _inteiro_valido(identificador)
    titulo, origem, xml, _ = _converter(dados)
    with do_cliente(request, sessao) as con:
        linha = con.execute(
            """UPDATE regras_proprias SET titulo = %s, formato = %s, origem = %s, xml_regras = %s, estado = 'pendente', mensagem = NULL
               WHERE id = %s AND substitui IS NULL RETURNING id""", (titulo, dados.formato, origem, xml, identificador)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'editar_regra', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))
    return {"id": identificador, "estado": "pendente"}


@app.post("/api/regras/proprias/{identificador}/desativar", status_code=204)
def desativar_regra_propria(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute("UPDATE regras_proprias SET estado = 'desativada' WHERE id = %s RETURNING id", (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'desativar_regra', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))


class ImportacaoDeRegras(BaseModel):
    formato: str = Field(pattern="^(sigma|xml)$")
    conteudo: str = Field(max_length=2_000_000)


def _gravar_regra_propria(con, sessao, gerenciador, titulo, formato, origem, xml):
    return con.execute(
        """INSERT INTO regras_proprias (cliente_id, gerenciador_id, titulo, formato, origem, xml_regras, criada_por)
           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (sessao["cliente_id"], gerenciador, titulo, formato, origem, xml, sessao["usuario_id"])).fetchone()["id"]


@app.post("/api/regras/importar")
def importar_regras(dados: ImportacaoDeRegras, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    """Importa um arquivo inteiro e diz o que entrou e o que não entrou, com o motivo."""
    criadas, recusadas = [], []
    if dados.formato == "xml":
        try:
            regras = xml_proprio.analisar(dados.conteudo)
            criadas.append((regras[0][0][:200], dados.conteudo, dados.conteudo))
        except xml_proprio.XmlInvalido as erro:
            recusadas.append({"titulo": "Arquivo", "motivo": str(erro)})
    else:
        # Um YAML com várias regras separadas por "---" vira uma regra própria para cada.
        for documento in re.split(r"(?m)^---\s*$", dados.conteudo)[:500]:
            if not documento.strip():
                continue
            resultado = sigma.converter_textos([documento])[0]
            if resultado.xml:
                criadas.append((resultado.titulo[:200], documento, "\n".join(resultado.xml)))
            else:
                recusadas.append({"titulo": resultado.titulo[:200], "motivo": resultado.motivo})
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
        for titulo, origem, xml in criadas:
            _gravar_regra_propria(con, sessao, gerenciador["id"], titulo, dados.formato, origem, xml)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'importar_regras', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{len(criadas)} criadas, {len(recusadas)} recusadas"))
    return {"criadas": [c[0] for c in criadas], "recusadas": recusadas}


@app.get("/api/regras/exportar")
def exportar_regras(request: Request, sessao=Depends(exige(permissoes.VER))):
    """As regras criadas aqui, cada uma no formato de origem."""
    with do_cliente(request, sessao) as con:
        linhas = con.execute("SELECT titulo, formato, origem, xml_regras, estado FROM regras_proprias WHERE substitui IS NULL ORDER BY id").fetchall()
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'exportar_regras', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(len(linhas))))
    return Response(json.dumps({"regras": linhas}, ensure_ascii=False, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="regras-roar.json"'})


@app.get("/api/regras/biblioteca")
def biblioteca(request: Request, sessao=Depends(exige(permissoes.VER)), busca: str = "", so_convertiveis: bool = True, deslocamento: int = 0):
    deslocamento = max(0, min(deslocamento, 100000))
    condicoes, parametros = ["TRUE"], []
    busca = busca.strip()[:200]
    if busca:
        termo = f"%{_sem_curinga(busca)}%"
        condicoes.append("(titulo ILIKE %s OR descricao ILIKE %s OR autor ILIKE %s OR array_to_string(tecnicas, ' ') ILIKE %s)")
        parametros += [termo, termo, termo, termo]
    if so_convertiveis:
        condicoes.append("convertivel")
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            f"""SELECT id, titulo, descricao, autor, nivel, origem, tecnicas, endereco, convertivel, motivo,
                       count(*) OVER () AS total_filtrado
                FROM biblioteca_regras WHERE {' AND '.join(condicoes)} ORDER BY titulo LIMIT %s OFFSET %s""",
            (*parametros, TAMANHO_DA_PAGINA, deslocamento)).fetchall()
        total = con.execute("SELECT count(*) AS total, count(*) FILTER (WHERE convertivel) AS convertiveis FROM biblioteca_regras").fetchone()
    return {"regras": linhas, "total_filtrado": linhas[0]["total_filtrado"] if linhas else 0, **total}


@app.post("/api/regras/biblioteca/{identificador}/ativar", status_code=201)
def ativar_da_biblioteca(identificador: str, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    if not re.fullmatch(r"[0-9a-fA-F-]{8,64}", identificador):
        raise HTTPException(status_code=404)
    with do_cliente(request, sessao) as con:
        regra = con.execute("SELECT titulo, conteudo, convertivel, motivo FROM biblioteca_regras WHERE id = %s", (identificador,)).fetchone()
        if not regra:
            raise HTTPException(status_code=404)
        if not regra["convertivel"]:
            raise HTTPException(status_code=422, detail=f"Esta regra não pode ser usada: {regra['motivo']}")
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
        ja_ativa = con.execute("SELECT 1 FROM regras_proprias WHERE origem = %s AND estado IN ('ativa', 'pendente')", (regra["conteudo"],)).fetchone()
        if ja_ativa:
            raise HTTPException(status_code=409, detail="Esta regra já está ativa.")
        novo = _gravar_regra_propria(con, sessao, gerenciador["id"], regra["titulo"][:200], "biblioteca", regra["conteudo"], "")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'ativar_da_biblioteca', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], identificador))
    return {"id": novo, "estado": "pendente"}


@app.get("/api/regras/arquivos/{arquivo}")
def arquivo_de_regras(arquivo: str, request: Request, sessao=Depends(exige(permissoes.VER))):
    """Exporta um arquivo de regras do Wazuh tal como ele é distribuído."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}\.xml", arquivo):
        raise HTTPException(status_code=404)
    with do_cliente(request, sessao) as con:
        linha = con.execute("SELECT conteudo FROM arquivos_de_regras WHERE arquivo = %s", (arquivo,)).fetchone()
    if not linha:
        raise HTTPException(status_code=404)
    return Response(linha["conteudo"], media_type="application/xml",
                    headers={"Content-Disposition": f'attachment; filename="{arquivo}"'})


@app.get("/api/regras/{regra_id}")
def detalhe_da_regra(regra_id: str, request: Request, sessao=Depends(exige(permissoes.VER)), dias: int = 30):
    if not re.fullmatch(r"\d{1,10}", regra_id):
        raise HTTPException(status_code=404)
    dias = max(1, min(dias, 90))
    with do_cliente(request, sessao) as con:
        regra = con.execute(
            """SELECT regra_id, nivel, descricao, grupos, mitre, arquivo, ativa, normas, detalhes FROM regras
               WHERE regra_id = %s LIMIT 1""", (regra_id,)).fetchone()
        if not regra:
            raise HTTPException(status_code=404)
        nomes = con.execute("SELECT tecnica, nome FROM tecnicas_attack WHERE tecnica = ANY(%s)", (regra["mitre"],)).fetchall()
        disparos = con.execute(
            """SELECT count(*) AS total, max(ocorrido_em) AS ultimo, count(DISTINCT agente_id) AS ativos FROM eventos
               WHERE regra_id = %s AND ocorrido_em >= now() - make_interval(days => %s)""", (regra_id, dias)).fetchone()
        recentes = con.execute(
            """SELECT id, ocorrido_em, severidade, agente_nome AS ativo, host(ip_origem) AS ip_origem, usuario FROM eventos
               WHERE regra_id = %s ORDER BY id DESC LIMIT 10""", (regra_id,)).fetchall()
        arquivo = con.execute("SELECT conteudo FROM arquivos_de_regras WHERE arquivo = %s", (regra["arquivo"],)).fetchone()
        ajuste = con.execute(
            """SELECT id, origem, estado, mensagem, desligada, aplicada_em FROM regras_proprias
               WHERE substitui = %s AND estado <> 'desativada' ORDER BY id DESC LIMIT 1""", (regra_id,)).fetchone()
    xml = xml_proprio.trecho_da_regra(arquivo["conteudo"], regra_id) if arquivo else None
    return {"regra": regra, "tecnicas": nomes, "disparos": disparos, "recentes": recentes, "xml": xml, "ajuste": ajuste}


class VersaoDaRegra(BaseModel):
    xml: str = Field(max_length=200_000)


def _original_da_regra(con, regra_id):
    if not re.fullmatch(r"\d{1,10}", regra_id):
        raise HTTPException(status_code=404)
    regra = con.execute("SELECT descricao, arquivo FROM regras WHERE regra_id = %s LIMIT 1", (regra_id,)).fetchone()
    arquivo = regra and con.execute("SELECT conteudo FROM arquivos_de_regras WHERE arquivo = %s", (regra["arquivo"],)).fetchone()
    xml = arquivo and xml_proprio.trecho_da_regra(arquivo["conteudo"], regra_id)
    if not xml:
        raise HTTPException(status_code=404, detail="O texto desta regra ainda não foi carregado.")
    return regra, xml


def _gravar_ajuste(con, sessao, regra_id, regra, origem, desligada, acao):
    """Troca a versão em uso, para o gerenciador instalar de novo. O gerenciador é o mais recente do cliente."""
    gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
    con.execute("UPDATE regras_proprias SET estado = 'desativada' WHERE substitui = %s AND estado <> 'desativada'", (regra_id,))
    novo = con.execute(
        """INSERT INTO regras_proprias (cliente_id, gerenciador_id, titulo, formato, origem, criada_por, substitui, desligada)
           VALUES (%s, %s, %s, 'substituicao', %s, %s, %s, %s) RETURNING id""",
        (sessao["cliente_id"], gerenciador["id"], f"Regra {regra_id}: {regra['descricao'] or ''}"[:200], origem,
         sessao["usuario_id"], regra_id, desligada)).fetchone()["id"]
    con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, %s, %s)",
                (sessao["cliente_id"], sessao["usuario_id"], acao, regra_id))
    return {"id": novo, "estado": "pendente"}


@app.put("/api/regras/{regra_id}/versao")
def editar_regra_do_catalogo(regra_id: str, dados: VersaoDaRegra, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    with do_cliente(request, sessao) as con:
        regra, original = _original_da_regra(con, regra_id)
        try:
            origem = xml_proprio.validar_substituicao(dados.xml, regra_id, original)
        except xml_proprio.XmlInvalido as erro:
            raise HTTPException(status_code=422, detail=str(erro))
        return _gravar_ajuste(con, sessao, regra_id, regra, origem, False, "editar_regra_do_catalogo")


@app.post("/api/regras/{regra_id}/desligar")
def desligar_regra_do_catalogo(regra_id: str, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    """Nível 0: a regra para de alertar, mas as que dependem dela continuam funcionando."""
    with do_cliente(request, sessao) as con:
        regra, original = _original_da_regra(con, regra_id)
        return _gravar_ajuste(con, sessao, regra_id, regra, original, True, "desligar_regra_do_catalogo")


@app.post("/api/regras/{regra_id}/restaurar", status_code=204)
def restaurar_regra_do_catalogo(regra_id: str, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    if not re.fullmatch(r"\d{1,10}", regra_id):
        raise HTTPException(status_code=404)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE regras_proprias SET estado = 'desativada' WHERE substitui = %s AND estado <> 'desativada' RETURNING id", (regra_id,)).fetchall():
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'restaurar_regra_do_catalogo', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], regra_id))


class FonteNova(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    protocolo: str = "tcp"
    origens: list[str] = Field(max_length=200)


def _agregar_origens_de_syslog(request, gerenciador_id):
    """Última vez que cada endereço mandou algo. Sem dado no índice, a tela diz que nunca recebeu."""
    corpo = {"size": 0, "query": {"range": {"timestamp": {"gte": f"now-{DIAS_DE_SAUDE}d"}}},
             "aggs": {"origens": {"terms": {"field": "location", "size": 500}, "aggs": {"ultimo": {"max": {"field": "timestamp"}}}}}}
    try:
        r = request.app.state.indexer.post(f"{INDEXER_URL}/wazuh-archives-4.x-{gerenciador_id}-*/_search", json=corpo, timeout=20)
        r.raise_for_status()
    except requests.RequestException:
        return None
    return [(b["key"], b["ultimo"]["value"]) for b in r.json().get("aggregations", {}).get("origens", {}).get("buckets", [])]


def _saude_da_fonte(fonte, origens):
    """Recebendo, parada ou nunca recebeu. Sem resposta do índice, diz que não sabe, em vez de chutar."""
    if fonte["tipo"] in ("webhook", "api"):
        ultimo = fonte.pop("ultimo_dado_em", None)
        if not ultimo:
            return {"saude": "nunca_recebeu", "ultimo_dado": None}
        parada = (datetime.now(timezone.utc) - ultimo).total_seconds() >= MINUTOS_ATE_PARADA * 60
        return {"saude": "parada" if parada else "recebendo", "ultimo_dado": ultimo.isoformat()}
    # Aviso não recebe dado: quem mostra se funcionou é o serviço de destino.
    if fonte["tipo"] in fontes_de_dados.TIPOS_DE_AVISO:
        return {"saude": None, "ultimo_dado": None}
    if origens is None:
        return {"saude": "desconhecida", "ultimo_dado": None}
    ultimos = []
    if fonte["tipo"] == "syslog":
        redes = [ipaddress.ip_network(r) for r in fonte["config"]["origens"]]
        for local, ultimo in origens:
            try:
                if ultimo and any(ipaddress.ip_address(local) in rede for rede in redes):
                    ultimos.append(ultimo)
            except ValueError:
                continue  # Agentes aparecem aqui com o caminho do arquivo, não com um endereço.
    else:
        # Os módulos de nuvem aparecem com o próprio nome no lugar da origem.
        nome = {"msgraph": "ms-graph", "aws": "Wazuh-AWS", "azure": "azure", "gcp": "Wazuh-GCloud"}.get(fonte["tipo"], fonte["tipo"])
        ultimos = [u for local, u in origens if u and local == nome]
    if not ultimos:
        return {"saude": "nunca_recebeu", "ultimo_dado": None}
    ultimo = max(ultimos) / 1000
    return {"saude": "recebendo" if time.time() - ultimo < MINUTOS_ATE_PARADA * 60 else "parada",
            "ultimo_dado": datetime.fromtimestamp(ultimo, timezone.utc).isoformat()}


@app.get("/api/fontes")
def listar_fontes(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id, porta_base FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
        fontes = con.execute(
            "SELECT id, tipo, nome, config, estado, mensagem, criada_em, aplicada_em, ultimo_dado_em FROM fontes WHERE estado <> 'desativada' ORDER BY id DESC LIMIT 200").fetchall()
        agentes = con.execute(
            """SELECT count(*) AS total, count(*) FILTER (WHERE estado = 'active') AS conectados
               FROM ativos WHERE agente_id <> '000' AND gerenciador_id = %s""", (gerenciador["id"] if gerenciador else "",)).fetchone()
    origens = _agregar_origens_de_syslog(request, gerenciador["id"]) if gerenciador and fontes else []
    for fonte in fontes:
        fonte.update(_saude_da_fonte(fonte, origens) if fonte["estado"] == "ativa" else {"saude": None, "ultimo_dado": None})
    return {"fontes": fontes, "agentes": agentes, "endereco": ENDERECO_PUBLICO,
            "porta_syslog": gerenciador["porta_base"] + DESLOCAMENTO_SYSLOG if gerenciador else None}


@app.post("/api/fontes", status_code=201)
def criar_fonte(dados: FonteNova, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    try:
        origens = fontes_de_dados.validar_syslog(dados.protocolo, dados.origens)
    except fontes_de_dados.FonteInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
        nova = con.execute(
            "INSERT INTO fontes (cliente_id, gerenciador_id, tipo, nome, config, criada_por) VALUES (%s, %s, 'syslog', %s, %s, %s) RETURNING id",
            (sessao["cliente_id"], gerenciador["id"], dados.nome, json.dumps({"protocolo": dados.protocolo, "origens": origens}), sessao["usuario_id"])).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_fonte', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(nova)))
    return {"id": nova, "estado": "pendente"}


class FonteDeNuvem(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    tipo: str = Field(pattern="^(github|office365|msgraph|aws|azure|gcp|slack|pagerduty|virustotal|maltiverse)$")
    campos: dict[str, str]
    # O arquivo de conta de serviço do Google Cloud passa de 2 KB com facilidade.
    segredo: str = Field(min_length=1, max_length=20_000)


@app.post("/api/fontes/nuvem", status_code=201)
def criar_fonte_de_nuvem(dados: FonteDeNuvem, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """A credencial sai daqui cifrada, e nenhuma rota a devolve depois."""
    try:
        config = fontes_de_dados.validar_nuvem(dados.tipo, dados.campos)
        fontes_de_dados.validar_segredo(dados.tipo, dados.segredo)
    except fontes_de_dados.FonteInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    nome_do_segredo = f"fonte-{secrets.token_hex(8)}"
    selado = cofre.selar(cofre.ler_publica(), sessao["cliente_id"], nome_do_segredo, dados.segredo)
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
        # O módulo do Google Cloud aceita só uma seção por gerenciador.
        if dados.tipo == "gcp" and con.execute("SELECT 1 FROM fontes WHERE tipo = 'gcp' AND estado <> 'desativada' LIMIT 1").fetchone():
            raise HTTPException(status_code=409, detail="Este cliente já tem uma assinatura do Google Cloud conectada.")
        con.execute("INSERT INTO segredos (cliente_id, nome, selado, criado_por) VALUES (%s, %s, %s, %s)",
                    (sessao["cliente_id"], nome_do_segredo, selado, sessao["usuario_id"]))
        nova = con.execute(
            "INSERT INTO fontes (cliente_id, gerenciador_id, tipo, nome, config, criada_por) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (sessao["cliente_id"], gerenciador["id"], dados.tipo, dados.nome, json.dumps({**config, "segredo": nome_do_segredo}), sessao["usuario_id"])).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_fonte', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(nova)))
    return {"id": nova, "estado": "pendente"}


class FonteApi(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    endereco: str = Field(max_length=2000)
    caminho: str = Field(default="", max_length=200)
    intervalo_minutos: int = 15
    cabecalho: str = Field(default="", max_length=64)
    segredo: str = Field(default="", max_length=4096)


@app.post("/api/fontes/api", status_code=201)
def criar_fonte_de_api(dados: FonteApi, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    try:
        config = fontes_de_dados.validar_api(dados.model_dump())
    except fontes_de_dados.FonteInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    nome_do_segredo = f"fonte-{secrets.token_hex(8)}" if dados.segredo else None
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
        if nome_do_segredo:
            selado = cofre.selar(cofre.ler_publica(), sessao["cliente_id"], nome_do_segredo, dados.segredo)
            con.execute("INSERT INTO segredos (cliente_id, nome, selado, criado_por) VALUES (%s, %s, %s, %s)",
                        (sessao["cliente_id"], nome_do_segredo, selado, sessao["usuario_id"]))
        nova = con.execute(
            """INSERT INTO fontes (cliente_id, gerenciador_id, tipo, nome, config, estado, criada_por, aplicada_em)
               VALUES (%s, %s, 'api', %s, %s, 'ativa', %s, now()) RETURNING id""",
            (sessao["cliente_id"], gerenciador["id"], dados.nome, json.dumps({**config, "segredo": nome_do_segredo}), sessao["usuario_id"])).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_fonte', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(nova)))
    return {"id": nova, "estado": "ativa"}


class FonteWebhook(BaseModel):
    nome: str = Field(min_length=1, max_length=120)


@app.post("/api/fontes/webhook", status_code=201)
def criar_webhook(dados: FonteWebhook, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """O token sai só nesta resposta: guardamos o hash, e perder o token é criar outro."""
    token = secrets.token_urlsafe(32)
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
        # Não muda a configuração do gerenciador, então já nasce ativa.
        nova = con.execute(
            """INSERT INTO fontes (cliente_id, gerenciador_id, tipo, nome, config, estado, criada_por, token_hash, aplicada_em)
               VALUES (%s, %s, 'webhook', %s, '{}', 'ativa', %s, %s, now()) RETURNING id""",
            (sessao["cliente_id"], gerenciador["id"], dados.nome, sessao["usuario_id"], _hash_do_token(token))).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_fonte', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(nova)))
    return {"id": nova, "token": token, "caminho": "/api/entrada/webhook"}


def _eventos_do_webhook(corpo):
    """Cada evento vira uma linha de JSON refeita aqui: nada do texto original passa sem ser analisado."""
    try:
        dados = json.loads(corpo)
    except (ValueError, RecursionError):
        raise HTTPException(status_code=422, detail="O corpo precisa ser JSON.")
    eventos = dados if isinstance(dados, list) else [dados]
    if not 1 <= len(eventos) <= EVENTOS_POR_ENVIO or not all(isinstance(e, dict) for e in eventos):
        raise HTTPException(status_code=422, detail=f"Envie um objeto ou uma lista de 1 a {EVENTOS_POR_ENVIO} objetos.")
    linhas = [json.dumps(e, ensure_ascii=False, separators=(",", ":")) for e in eventos]
    if any(len(l.encode()) > TAMANHO_MAXIMO_DO_EVENTO or "\x00" in l for l in linhas):
        raise HTTPException(status_code=413, detail="Evento grande demais.")
    return linhas


def _gravar_no_webhook(request, token, linhas):
    with request.app.state.banco.connection() as con:
        return con.execute("SELECT roar_receber_webhook(%s, %s, %s) AS r",
                           (_hash_do_token(token), linhas, LIMITE_DA_FILA_DO_WEBHOOK)).fetchone()["r"]


@app.post("/api/entrada/webhook", status_code=202)
async def receber_webhook(request: Request):
    """Sem sessão: quem chama é outro sistema. Só o token diz de qual cliente é o evento."""
    autorizacao = request.headers.get("authorization", "")
    if not autorizacao.startswith("Bearer ") or not 20 <= len(autorizacao) <= 200:
        raise HTTPException(status_code=401)
    declarado = request.headers.get("content-length", "")
    if declarado.isdigit() and int(declarado) > TAMANHO_MAXIMO_DO_ENVIO:
        raise HTTPException(status_code=413, detail="Corpo grande demais.")
    corpo = bytearray()
    async for pedaco in request.stream():
        corpo += pedaco
        if len(corpo) > TAMANHO_MAXIMO_DO_ENVIO:
            raise HTTPException(status_code=413, detail="Corpo grande demais.")
    linhas = _eventos_do_webhook(bytes(corpo))
    resultado = await run_in_threadpool(_gravar_no_webhook, request, autorizacao[7:], linhas)
    if resultado == "desconhecida":
        raise HTTPException(status_code=401)
    if resultado == "cheia":
        raise HTTPException(status_code=429, detail="Fila cheia: tente de novo em alguns minutos.")
    return {"recebidos": len(linhas)}


@app.post("/api/fontes/{identificador}/desativar", status_code=204)
def desativar_fonte(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute("UPDATE fontes SET estado = 'desativada' WHERE id = %s RETURNING config", (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        # Sem a fonte, a credencial não tem por que continuar guardada.
        if linha["config"].get("segredo"):
            con.execute("DELETE FROM segredos WHERE nome = %s", (linha["config"]["segredo"],))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'desativar_fonte', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))


@app.get("/api/fontes/instalacao")
def instalacao_de_agente(request: Request, sessao=Depends(exige(permissoes.INSTALAR_AGENTE))):
    """Traz a senha de inscrição do cliente, então cada consulta fica registrada."""
    with do_cliente(request, sessao) as con:
        linha = con.execute(
            """SELECT g.porta_base, i.senha FROM gerenciadores g JOIN inscricao_de_agentes i ON i.gerenciador_id = g.id
               ORDER BY g.criado_em DESC LIMIT 1""").fetchone()
        if not linha:
            raise HTTPException(status_code=409, detail="Este cliente ainda não tem como inscrever ativos.")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'ver_instalacao_de_agente', '')",
                    (sessao["cliente_id"], sessao["usuario_id"]))
    variaveis = {"WAZUH_MANAGER": ENDERECO_PUBLICO, "WAZUH_MANAGER_PORT": linha["porta_base"], "WAZUH_REGISTRATION_SERVER": ENDERECO_PUBLICO,
                 "WAZUH_REGISTRATION_PORT": linha["porta_base"] + 1, "WAZUH_REGISTRATION_PASSWORD": linha["senha"]}
    unix = " ".join(f"{k}='{v}'" for k, v in variaveis.items())
    janelas = " ".join(f'{k}="{v}"' for k, v in variaveis.items())
    return {"sistemas": [
        {"nome": "Linux, Debian e Ubuntu", "provado": True, "comando":
            f"curl -so agente.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_{VERSAO_DO_AGENTE}-1_amd64.deb && "
            f"sudo {unix} dpkg -i ./agente.deb && sudo systemctl enable --now wazuh-agent"},
        {"nome": "Linux, Red Hat e derivados", "provado": False, "comando":
            f"curl -so agente.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-{VERSAO_DO_AGENTE}-1.x86_64.rpm && "
            f"sudo {unix} rpm -ihv agente.rpm && sudo systemctl enable --now wazuh-agent"},
        {"nome": "Windows (PowerShell como administrador)", "provado": False, "comando":
            f"Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-{VERSAO_DO_AGENTE}-1.msi -OutFile agente.msi; "
            f"msiexec.exe /i agente.msi /q {janelas}; Start-Sleep 20; NET START WazuhSvc"},
    ]}


class PlaybookEntrada(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    definicao: dict
    intervalo_minutos: int = Field(default=60, ge=0, le=10080)


class TextoDePlaybook(BaseModel):
    texto: str = Field(max_length=100_000)


class DefinicaoEntrada(BaseModel):
    definicao: dict
    intervalo_minutos: int = Field(default=60, ge=0, le=10080)


class Decisao(BaseModel):
    motivo: str = Field(default="", max_length=500)


def _validar_definicao(definicao):
    try:
        return blocos.validar(definicao, acoes.validar_acao)
    except (blocos.DefinicaoInvalida, acoes.AcaoRecusada) as erro:
        raise HTTPException(status_code=422, detail=str(erro))


@app.get("/api/automacao")
def automacao(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        playbooks = con.execute(
            """SELECT p.id, p.nome, p.ativo, p.definicao, p.intervalo_minutos, p.criado_em, p.alterado_em,
                      (SELECT count(*) FROM execucoes x WHERE x.playbook_id = p.id) AS execucoes
               FROM playbooks p ORDER BY p.id DESC LIMIT 200""").fetchall()
        execucoes = con.execute(
            """SELECT x.id, x.playbook_id, p.nome AS playbook, x.origem_tipo, x.origem_id, x.alvo, x.agente_id, x.titulo,
                      x.estado, x.resultado, x.criada_em, x.concluida_em,
                      -- A API da resposta ativa diz sucesso mesmo em ativo sem firewall: quem confirma é o alerta do próprio ativo.
                      EXISTS (SELECT 1 FROM eventos v WHERE v.regra_id = %s AND v.gerenciador_id = x.gerenciador_id
                              AND v.agente_id = x.agente_id AND v.ocorrido_em >= x.criada_em
                              AND v.bruto #>> '{data,parameters,alert,data,srcip}' = x.alvo) AS bloqueio_confirmado
               FROM execucoes x JOIN playbooks p ON p.id = x.playbook_id
               ORDER BY x.id DESC LIMIT 200""", (REGRA_DE_BLOQUEIO_CONFIRMADO,)).fetchall()
        aprovacoes = con.execute(
            """SELECT a.id, a.execucao_id, a.descricao, a.estado, a.motivo, a.criada_em, a.decidida_em,
                      roar_nome_do_usuario(a.decidida_por) AS decidida_por, x.alvo, x.titulo, p.nome AS playbook
               FROM aprovacoes a JOIN execucoes x ON x.id = a.execucao_id JOIN playbooks p ON p.id = x.playbook_id
               ORDER BY a.estado = 'pendente' DESC, a.id DESC LIMIT 200""").fetchall()
    return {"playbooks": playbooks, "execucoes": execucoes, "aprovacoes": aprovacoes}


@app.post("/api/automacao/playbooks", status_code=201)
def criar_playbook(dados: PlaybookEntrada, request: Request, sessao=Depends(exige(permissoes.GERIR_PLAYBOOKS))):
    _validar_definicao(dados.definicao)
    with do_cliente(request, sessao) as con:
        novo = con.execute(
            """INSERT INTO playbooks (cliente_id, nome, definicao, intervalo_minutos, criado_por)
               VALUES (%s, %s, %s, %s, %s) RETURNING id""",
            (sessao["cliente_id"], dados.nome, json.dumps(dados.definicao), dados.intervalo_minutos, sessao["usuario_id"])).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_playbook', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(novo)))
    return {"id": novo}


@app.put("/api/automacao/playbooks/{identificador}", status_code=204)
def alterar_playbook(identificador: int, dados: PlaybookEntrada, request: Request, sessao=Depends(exige(permissoes.GERIR_PLAYBOOKS))):
    _inteiro_valido(identificador)
    _validar_definicao(dados.definicao)
    with do_cliente(request, sessao) as con:
        linha = con.execute(
            "UPDATE playbooks SET nome = %s, definicao = %s, intervalo_minutos = %s, alterado_em = now() WHERE id = %s RETURNING id",
            (dados.nome, json.dumps(dados.definicao), dados.intervalo_minutos, identificador)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'alterar_playbook', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))


@app.post("/api/automacao/playbooks/{identificador}/{acao}", status_code=204)
def ligar_playbook(identificador: int, acao: str, request: Request, sessao=Depends(exige(permissoes.GERIR_PLAYBOOKS))):
    _inteiro_valido(identificador)
    if acao not in ("ativar", "desativar"):
        raise HTTPException(status_code=404)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE playbooks SET ativo = %s WHERE id = %s RETURNING id", (acao == "ativar", identificador)).fetchone():
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, %s, %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{acao}_playbook", str(identificador)))


@app.post("/api/automacao/para-codigo")
def playbook_para_codigo(dados: PlaybookEntrada, sessao=Depends(exige(permissoes.VER))):
    _validar_definicao(dados.definicao)
    corpo = {"nome": dados.nome, "intervalo_minutos": dados.intervalo_minutos, **dados.definicao}
    return {"texto": yaml.safe_dump(corpo, allow_unicode=True, sort_keys=False)}


@app.post("/api/automacao/de-codigo")
def playbook_de_codigo(dados: TextoDePlaybook, sessao=Depends(exige(permissoes.VER))):
    # safe_load não instancia objetos: o texto pode ter sido copiado de qualquer lugar.
    try:
        corpo = yaml.safe_load(dados.texto)
    except yaml.YAMLError as erro:
        raise HTTPException(status_code=422, detail=f"O texto não é um YAML válido: {str(erro)[:200]}")
    if not isinstance(corpo, dict):
        raise HTTPException(status_code=422, detail="O texto precisa ter nome, quando, se e blocos.")
    nome = corpo.pop("nome", None)
    intervalo = corpo.pop("intervalo_minutos", 60)
    if not isinstance(nome, str) or not 1 <= len(nome) <= 120:
        raise HTTPException(status_code=422, detail="Dê um nome ao playbook.")
    if isinstance(intervalo, bool) or not isinstance(intervalo, int) or not 0 <= intervalo <= 10080:
        raise HTTPException(status_code=422, detail="O intervalo vai de 0 a 10080 minutos.")
    _validar_definicao(corpo)
    return {"nome": nome, "intervalo_minutos": intervalo, "definicao": corpo}


@app.post("/api/automacao/simular")
def simular_playbook(dados: DefinicaoEntrada, request: Request, sessao=Depends(exige(permissoes.GERIR_PLAYBOOKS))):
    """Refaz os últimos dias com as mesmas funções do disparo, sem executar nada."""
    definicao = _validar_definicao(dados.definicao)
    quando = definicao["quando"]
    with do_cliente(request, sessao) as con:
        if quando["tipo"] == "evento":
            lista = fatos.eventos_da_regra(con, quando["regra_id"], DIAS_DE_SIMULACAO, LIMITE_DE_SIMULACAO)
        else:
            lista = fatos.riscos_recentes(con, DIAS_DE_SIMULACAO)[:LIMITE_DE_SIMULACAO]
    intervalo = timedelta(minutes=dados.intervalo_minutos)
    ultimo_por_alvo, disparos, por_alvo, exemplos, recusas = {}, 0, Counter(), [], 0
    for fato in lista:
        if not blocos.atende(definicao, fato):
            continue
        anterior = ultimo_por_alvo.get(fato["alvo"])
        if anterior and fato["ocorrido_em"] - anterior < intervalo:
            continue
        ultimo_por_alvo[fato["alvo"]] = fato["ocorrido_em"]
        disparos += 1
        por_alvo[fato["alvo"] or "sem endereço"] += 1
        passos = []
        for bloco in blocos.plano(definicao["blocos"], fato):
            recusa = acoes.recusa_prevista(bloco["acao"], bloco.get("parametros", {}), fato["alvo"], fato.get("usuario")) if bloco["tipo"] == "acao" else None
            recusas += 1 if recusa else 0
            passos.append({"tipo": bloco["tipo"], "acao": bloco.get("acao"), "recusa": recusa})
        exemplos.append({"quando": fato["ocorrido_em"], "titulo": fato["titulo"], "alvo": fato["alvo"], "passos": passos})
    return {
        "dias": DIAS_DE_SIMULACAO, "analisados": len(lista), "limitado": len(lista) >= LIMITE_DE_SIMULACAO,
        "disparos": disparos, "recusas": recusas,
        "alvos": [{"alvo": a, "total": t} for a, t in por_alvo.most_common(20)],
        "exemplos": exemplos[-20:][::-1],
    }


def _decidir(identificador, novo_estado, motivo, request, sessao):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        # Decisão atômica: de dois cliques, só o primeiro encontra a aprovação pendente.
        linha = con.execute(
            """UPDATE aprovacoes SET estado = %s, decidida_por = %s, decidida_em = now(), motivo = %s
               WHERE id = %s AND estado = 'pendente' RETURNING id""",
            (novo_estado, sessao["usuario_id"], motivo or None, identificador)).fetchone()
        if not linha:
            raise HTTPException(status_code=409, detail="Esta aprovação não aguarda mais uma decisão.")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, %s, %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], "aprovar_execucao" if novo_estado == "aprovada" else "recusar_execucao", str(identificador)))


@app.post("/api/automacao/aprovacoes/{identificador}/aprovar", status_code=204)
def aprovar_execucao(identificador: int, dados: Decisao, request: Request, sessao=Depends(exige(permissoes.APROVAR))):
    _decidir(identificador, "aprovada", dados.motivo, request, sessao)


@app.post("/api/automacao/aprovacoes/{identificador}/recusar", status_code=204)
def recusar_execucao(identificador: int, dados: Decisao, request: Request, sessao=Depends(exige(permissoes.APROVAR))):
    _decidir(identificador, "recusada", dados.motivo, request, sessao)


def _inteiro_valido(identificador):
    # Fora do alcance de bigint viraria erro do banco; para quem pede, é só "não encontrado".
    if not 0 < identificador < 2**63:
        raise HTTPException(status_code=404)


@app.get("/api/riscos/{identificador}")
def risco(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        alerta = con.execute(
            """SELECT a.id, a.entidade_id, a.severidade, a.risco_maximo, a.aberto_em, a.encerrado_em, a.estado,
                      e.tipo AS entidade_tipo, coalesce(e.nome, e.chave) AS entidade, e.risco AS risco_atual,
                      e.primeira_vista, e.sucessos
               FROM alertas_risco a JOIN entidades e ON e.id = a.entidade_id WHERE a.id = %s""",
            (identificador,)).fetchone()
        if not alerta:
            raise HTTPException(status_code=404)
        sinais = con.execute(
            """SELECT s.tipo, s.peso, s.ocorrido_em, s.detalhes, v.id AS evento_id, v.regra_descricao,
                      v.agente_nome AS ativo, host(v.ip_origem) AS ip_origem, v.usuario
               FROM sinais s JOIN eventos v ON v.id = s.evento_id
               WHERE s.entidade_id = %s AND s.ocorrido_em >= %s::timestamptz - interval '7 days'
               ORDER BY s.ocorrido_em DESC LIMIT 200""",
            (alerta["entidade_id"], alerta["aberto_em"])).fetchall()
    return {"alerta": alerta, "sinais": sinais}


@app.get("/api/grupos/{identificador}")
def grupo(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        dados = con.execute(
            """SELECT g.id, g.severidade, g.nivel, g.total, g.regras, g.primeira_em, g.ultima_em,
                      host(g.ip_origem) AS ip_origem, g.agente_id FROM grupos_alerta g WHERE g.id = %s""",
            (identificador,)).fetchone()
        if not dados:
            raise HTTPException(status_code=404)
        eventos = con.execute(
            """SELECT id, ocorrido_em, severidade, nivel, regra_id, regra_descricao, mitre, agente_nome AS ativo,
                      host(ip_origem) AS ip_origem, usuario
               FROM eventos WHERE grupo_id = %s ORDER BY ocorrido_em DESC LIMIT 200""",
            (identificador,)).fetchall()
    return {"grupo": dados, "eventos": eventos}


app.mount("/estatico", StaticFiles(directory=ESTATICO), name="estatico")


@app.get("/", include_in_schema=False)
def inicio():
    return FileResponse(ESTATICO / "index.html")
