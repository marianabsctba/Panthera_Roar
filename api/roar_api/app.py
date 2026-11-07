"""API e tela do Roar. Por enquanto só leitura: fila de alertas e detalhe com as evidências.

    ROAR_API_ENDERECO=127.0.0.1:5433 uvicorn roar_api.app:app --port 8600

O cliente de cada consulta vem da sessão e vira a definição do RLS da transação. Nenhuma rota
aceita cliente vindo do navegador, então um id de outro cliente simplesmente não é encontrado.
"""

import base64
import binascii
import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import sys
import time
import uuid
from collections import Counter, defaultdict
from contextlib import asynccontextmanager, contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlencode
from xml.etree.ElementTree import Element as ElementoXml
from xml.etree.ElementTree import SubElement as SubElementoXml
from xml.etree.ElementTree import tostring as xml_em_texto

import psycopg
import requests
import yaml
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask
from requests.adapters import HTTPAdapter

# O mesmo conversor que a instalação das regras usa.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ingestao"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))
# A investigação do alerta usa a mesma chave de pessoa que o motor de risco.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ueba"))
from roar_api import consulta as linguagem_de_consulta  # noqa: E402
from roar_api import buscas as blocos_de_busca, correcao, investigacao, leitor_armazem, nota_externa, saml, entrada as outras_entradas, evidencia, listas as listas_de_observacao, mfa, modulos, normas as catalogo_de_normas, ocsf, ofuscacao, parsers as parsers_proprios, permissoes, relatorios, risco_de_ativos, saude_das_fontes  # noqa: E402
from roar_ingestao import avisos as avisos_por_email, cofre, copia_do_armazem, copia_fria, fim, rede_externa  # noqa: E402
from roar_ingestao import selo as selagem  # noqa: E402
from roar_ingestao import armazem as armazem_de_eventos  # noqa: E402
from roar_ingestao import vulnerabilidades  # noqa: E402
from roar_ingestao.normalizar import CAMPOS_DE_IP_DE_DESTINO, CAMPOS_DE_IP_DE_ORIGEM  # noqa: E402
from roar_ingestao import fluxos as fluxos_de_rede  # noqa: E402
from roar_ingestao.syslog_cifrado import PORTA as PORTA_DO_SYSLOG_CIFRADO, PASTA as PASTA_DO_SYSLOG_CIFRADO  # noqa: E402
from roar_ingestao import superficie as superficie_externa_  # noqa: E402
from roar_ingestao import fontes as fontes_de_dados  # noqa: E402
from roar_ingestao import contexto, inteligencia as inteligencia_de_ameacas, sigma, xml_proprio, yara_regras  # noqa: E402
from roar_motor import acoes, blocos, fatos  # noqa: E402

INDEXER_URL = os.getenv("ROAR_INDEXER_URL", "https://127.0.0.1:9200")
ESTATICO = Path(__file__).parent / "estatico"
COOKIE = "roar_sessao"
HORAS_DE_SESSAO = 12
SENHA_MINIMA = 12
log = logging.getLogger("roar.api")
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
# A porta que o equipamento usa; dentro do receptor é sempre PORTA_DO_SYSLOG_CIFRADO (infra/docker-compose.yml).
PORTA_NETFLOW = int(os.getenv("NETFLOW_PORTA") or fluxos_de_rede.PORTA_NETFLOW)
PORTA_SFLOW = int(os.getenv("SFLOW_PORTA") or fluxos_de_rede.PORTA_SFLOW)
PORTA_SYSLOG_CIFRADO = int(os.getenv("SYSLOG_CIFRADO_PORTA") or str(PORTA_DO_SYSLOG_CIFRADO))
# As fontes cujos eventos têm origem própria nos logs; webhook e API chegam todos pela mesma origem.
TIPOS_COM_VOLUME = ("syslog", "fluxo", "github", "office365", "msgraph", "aws", "azure", "gcp")
DESLOCAMENTO_SYSLOG = 3
VERSAO_DO_AGENTE = "4.14.9"
# Endereço que os ativos e equipamentos do cliente usam para chegar a este servidor.
ENDERECO_PUBLICO = os.getenv("ROAR_ENDERECO_PUBLICO", "ENDERECO_DESTE_SERVIDOR")
LIMITE_DE_SIMULACAO = 5000
# Os mesmos pesos do UEBA; o teste confere que não divergem.
REGRAS_DE_COMPORTAMENTO = [
    {"tipo": "sucesso_apos_falhas", "peso": 50.0},
    {"tipo": "ioc_tocado", "peso": 50.0},
    {"tipo": "grupo_administrativo", "peso": 40.0},
    {"tipo": "viagem_impossivel", "peso": 40.0},
    {"tipo": "primeiro_privilegio", "peso": 30.0},
    {"tipo": "taticas_em_sequencia", "peso": 30.0},
    {"tipo": "arquivo_sensivel", "peso": 25.0},
    {"tipo": "pico_de_falhas", "peso": 20.0},
    {"tipo": "conta_criada", "peso": 20.0},
    {"tipo": "pessoa_em_risco", "peso": 20.0},
    {"tipo": "ativo_em_risco", "peso": 15.0},
    {"tipo": "regra_disparada", "peso": 15.0},
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
    # O armazém de eventos (docs/clickhouse.md): sem a senha de leitura, a instalação ainda não tem um, e tudo lê do indexador.
    app.state.armazem = armazem_de_eventos.leitor(valores)
    # O apelido de cada usuário não pode ser refeito por quem só vê a tela: vem de um segredo do servidor.
    app.state.cofre_do_sso = outras_entradas.Cofre(valores["ROAR_API_SENHA"])
    app.state.chave_de_apelido = hashlib.sha256(b"apelido:" + valores["ROAR_API_SENHA"].encode()).digest()
    yield
    app.state.banco.close()


MODULOS = modulos.do_ambiente()
app = FastAPI(title="Panthera Roar", description="SIEM open source. Powered by Mariana BS.", lifespan=ciclo_de_vida, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def cabecalhos(request: Request, chamada):
    # Sem cabeçalho Origin é requisição fora do navegador; com ele, precisa ser a própria tela. A resposta do SAML vem
    # do site do provedor por definição, e vale pela assinatura e pelo pedido de uso único, não pela origem.
    origem = request.headers.get("origin")
    if (request.method not in ("GET", "HEAD") and origem and origem.split("://")[-1] != request.headers.get("host")
            and request.url.path != "/api/sso/saml/acs"):
        return Response(status_code=403)
    if not modulos.rota_liberada(request.url.path, MODULOS):
        resposta = Response(status_code=404)
        resposta.headers.update(SEGURANCA)
        return resposta
    resposta = await chamada(request)
    mascara = getattr(request.state, "mascara", None)
    if mascara and resposta.status_code == 200:
        resposta = await _mascarar_resposta(resposta, mascara)
    resposta.headers.update(SEGURANCA)
    chave = getattr(request.state, "chave_de_estilo", None)
    if chave:
        # A nova tela injeta uma tag de estilo: só aceita a que traz a chave desta resposta.
        resposta.headers["Content-Security-Policy"] = (
            f"default-src 'self'; style-src 'self' 'nonce-{chave}'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    # Dado de alerta nunca fica guardado; a tela sempre confere se há versão nova.
    resposta.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    return resposta


async def _mascarar_resposta(resposta, mascara):
    tipo = resposta.headers.get("content-type", "")
    if not tipo.startswith(("application/json", "text/csv", "application/xml")):
        return resposta
    corpo = b"".join([parte async for parte in resposta.body_iterator])
    if tipo.startswith("application/json"):
        corpo = json.dumps(mascara.dado(json.loads(corpo)), ensure_ascii=False, separators=(",", ":")).encode()
    else:
        corpo = mascara.texto(corpo.decode("utf-8")).encode()
    cabecalhos = {k: v for k, v in resposta.headers.items() if k.lower() not in ("content-length", "x-resumo-sha256")}
    return Response(corpo, status_code=resposta.status_code, headers=cabecalhos, media_type=tipo)


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


PREFIXO_DA_CHAVE = "roar_"


def _sessao_por_chave(request: Request):
    """A chave vem em "Authorization: Bearer roar_...". Inválida, vencida ou revogada é como não ter vindo."""
    cabecalho = request.headers.get("authorization", "")
    token = cabecalho[7:].strip() if cabecalho[:7].lower() == "bearer " else ""
    if not token.startswith(PREFIXO_DA_CHAVE) or len(token) > 200:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Bearer"})
    with request.app.state.banco.connection() as con:
        linha = con.execute("SELECT * FROM roar_sessao_por_chave(%s)", (_hash_do_token(token),)).fetchone()
    if not linha:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Bearer"})
    return linha


def sessao_ou_chave(request: Request):
    """As rotas de dado aceitam a tela ou uma chave. As de conta (senha, autenticador, sair) só aceitam a tela."""
    if request.headers.get("authorization"):
        return _sessao_por_chave(request)
    return sessao_atual(request)


def _sessao_liberada(sessao):
    """Passou da senha não basta: nada de dado até confirmar o segundo fator e cumprir o que a organização exige."""
    if sessao["mfa_pendente"]:
        raise HTTPException(status_code=403, detail="Confirme o código do autenticador para continuar.")
    # Senha gerada por outra pessoa é temporária: até trocar, ela só serve para trocar.
    if sessao["trocar_senha"]:
        raise HTTPException(status_code=403, detail="Troque a senha temporária para continuar.")
    if sessao["mfa_obrigatorio"] and not sessao["mfa_ativo"]:
        raise HTTPException(status_code=403, detail="Sua organização exige o autenticador: configure-o para continuar.")


def exige(permissao, mascarar=False):
    """Toda rota com dado declara o que pede. O teste de perfis confere cada uma contra a tabela esperada.

    `mascarar` vai só nas rotas que mostram o que foi monitorado: em tela de configuração, um valor mascarado
    poderia voltar salvo por cima do verdadeiro.
    """
    def verificar(request: Request, sessao=Depends(sessao_ou_chave)):
        _sessao_liberada(sessao)
        if not permissoes.pode(sessao["perfil"], permissao):
            raise HTTPException(status_code=403, detail="Seu perfil não permite esta ação.")
        if mascarar and _ve_mascarado(sessao):
            request.state.mascara = ofuscacao.Mascara(sessao["ofuscar"], request.app.state.chave_de_apelido, sessao["cliente_id"])
        return sessao
    verificar.permissao = permissao
    verificar.mascarar = mascarar
    return verificar


def _ve_mascarado(sessao):
    return bool(sessao["ofuscar"]) and not permissoes.pode(sessao["perfil"], permissoes.VER_DADO_PESSOAL)


def _exige_o_original(sessao):
    """Pacote de prova leva o log como chegou: mascarado, deixaria de bater com o selo."""
    if _ve_mascarado(sessao):
        raise HTTPException(status_code=403, detail="Seu perfil vê dados pessoais mascarados, e o pacote precisa do log original.")


@contextmanager
def do_cliente(request: Request, sessao):
    """Transação sob o RLS do cliente da sessão. A definição morre com a transação."""
    with request.app.state.banco.connection() as con:
        with con.transaction():
            con.execute("SELECT set_config('roar.cliente', %s, true), set_config('roar.origem', %s, true)", (str(sessao["cliente_id"]), _origem(request) or ""))
            yield con


class Entrada(BaseModel):
    email: str = Field(max_length=254)
    senha: str = Field(max_length=256)


def _bloqueado(chave):
    agora = time.monotonic()
    falhas_de_login[chave] = [t for t in falhas_de_login[chave] if agora - t < JANELA_TENTATIVAS]
    return len(falhas_de_login[chave]) >= TENTATIVAS


def _origem(request):
    return request.client.host if request.client else None


def _registrar_recusa_de_login(banco, email, origem):
    with banco.connection() as con:
        conhecido = con.execute("SELECT roar_registrar_recusa(%s, 'login_recusado', %s) AS ok", (email, origem)).fetchone()["ok"]
    if not conhecido:
        # Sem cliente a quem avisar. O e-mail foi escrito por quem tentou: vai truncado e entre aspas.
        log.warning("login recusado para e-mail desconhecido %r de %s", email[:80], origem)


@app.get("/api/saude")
def saude(request: Request):
    """Para quem monitora: diz se está de pé e nada além disso, porque não exige sessão."""
    try:
        with request.app.state.banco.connection() as con:
            con.execute("SELECT 1")
    except Exception:
        return JSONResponse({"estado": "fora"}, status_code=503)
    return {"estado": "ok"}


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
        # Depois da resposta: o tempo do registro não pode revelar se o e-mail existe.
        return JSONResponse({"detail": "E-mail ou senha incorretos."}, status_code=401,
                            background=BackgroundTask(_registrar_recusa_de_login, request.app.state.banco, email, _origem(request)))

    falhas_de_login.pop(email, None)
    with request.app.state.banco.connection() as con:
        quem = con.execute("SELECT * FROM roar_entrada_por_email(%s)", (email,)).fetchone()
    if quem and quem["sso_exigido"] and quem["perfil"] != "administrador":
        raise HTTPException(status_code=403, detail="Sua organização entra pelo login único (SSO).")
    token = secrets.token_urlsafe(32)
    with request.app.state.banco.connection() as con:
        precisa_de_codigo = con.execute("SELECT roar_mfa_ativo(%s) AS a", (usuario["id"],)).fetchone()["a"]
        if precisa_de_codigo:
            con.execute("SELECT roar_criar_sessao_mfa(%s, %s, %s)", (_hash_do_token(token), usuario["id"], MINUTOS_PARA_O_CODIGO))
        else:
            con.execute("SELECT roar_criar_sessao(%s, %s, %s)", (_hash_do_token(token), usuario["id"], HORAS_DE_SESSAO))
            # Com segundo fator, o logon só vale depois do código.
            con.execute("SELECT roar_registrar_acesso(%s, 'logon', %s)", (usuario["id"], _origem(request)))
    saida = JSONResponse({"mfa": True}) if precisa_de_codigo else Response(status_code=204)
    saida.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/", secure=os.getenv("ROAR_COOKIE_SEGURO", "1") == "1",
                     max_age=MINUTOS_PARA_O_CODIGO * 60 if precisa_de_codigo else HORAS_DE_SESSAO * 3600)
    return saida


def _abrir_sessao(request, usuario_id, acao, resposta):
    """Sessão completa: passkey e login único já valem como os dois fatores."""
    token = secrets.token_urlsafe(32)
    with request.app.state.banco.connection() as con:
        con.execute("SELECT roar_criar_sessao(%s, %s, %s)", (_hash_do_token(token), usuario_id, HORAS_DE_SESSAO))
        con.execute("SELECT roar_registrar_acesso(%s, %s, %s)", (usuario_id, acao, _origem(request)))
    resposta.set_cookie(COOKIE, token, httponly=True, samesite="lax" if acao == "logon_sso" else "strict", path="/",
                        secure=os.getenv("ROAR_COOKIE_SEGURO", "1") == "1", max_age=HORAS_DE_SESSAO * 3600)
    return resposta


def _endereco_publico(request):
    endereco = ENDERECO_PUBLICO if ENDERECO_PUBLICO != "ENDERECO_DESTE_SERVIDOR" else request.url.netloc
    return outras_entradas.parte_confiavel(endereco, request.headers.get("origin", ""))


def _retorno_do_sso(request):
    """Para onde o provedor manda a pessoa de volta: o endereço em que ela abriu a tela."""
    esquema = request.headers.get("x-forwarded-proto", request.url.scheme)
    return f"{esquema}://{request.headers.get('host', request.url.netloc)}/api/sso/retorno"


def _enderecos_do_saml(request):
    """O identificador do Roar e o endereço que recebe a resposta, que a organização cadastra no provedor."""
    base = _retorno_do_sso(request).rsplit("/api/", 1)[0]
    return f"{base}/api/sso/saml/metadados", f"{base}/api/sso/saml/acs"


class SenhaParaPasskey(BaseModel):
    senha: str = Field(max_length=256)


class FimDoCadastro(BaseModel):
    pedido: str = Field(max_length=100)
    credencial: dict
    nome: str = Field(min_length=1, max_length=80)


class FimDaEntrada(BaseModel):
    pedido: str = Field(max_length=100)
    credencial: dict


@app.get("/api/passkeys")
def minhas_passkeys(request: Request, sessao=Depends(sessao_atual)):
    _sessao_liberada(sessao)
    with request.app.state.banco.connection() as con:
        linhas = con.execute("SELECT id, nome, transportes, criada_em, ultima_vez FROM roar_passkeys_do_usuario(%s)", (sessao["usuario_id"],)).fetchall()
    return {"passkeys": linhas}


@app.post("/api/passkeys/cadastro/inicio")
def iniciar_cadastro_de_passkey(dados: SenhaParaPasskey, request: Request, sessao=Depends(sessao_atual)):
    """Passkey nova é uma forma nova de entrar: pede a senha, como o autenticador."""
    _sessao_liberada(sessao)
    if not _senha_confere(request, sessao["usuario_id"], dados.senha):
        raise HTTPException(status_code=403, detail="Senha incorreta.")
    rp_id, _ = _endereco_publico(request)
    with do_cliente(request, sessao) as con:
        email = con.execute("SELECT email FROM roar_listar_usuarios() WHERE id = %s", (sessao["usuario_id"],)).fetchone()
    with request.app.state.banco.connection() as con:
        ja = [l["credencial"] for l in con.execute("SELECT credencial FROM roar_passkeys_do_usuario(%s)", (sessao["usuario_id"],)).fetchall()]
        opcoes, desafio = outras_entradas.opcoes_de_cadastro(rp_id, sessao["usuario_id"], email["email"] if email else sessao["nome"], sessao["nome"], ja)
        pedido, resumo = outras_entradas.novo_pedido()
        con.execute("SELECT roar_guardar_pedido(%s, 'passkey_cadastro', %s, %s)",
                    (resumo, Jsonb({"usuario": str(sessao["usuario_id"]), "desafio": outras_entradas.para_texto(desafio)}), outras_entradas.MINUTOS_DO_PEDIDO))
    return {"pedido": pedido, "opcoes": opcoes}


@app.post("/api/passkeys/cadastro/fim", status_code=201)
def concluir_cadastro_de_passkey(dados: FimDoCadastro, request: Request, sessao=Depends(sessao_atual)):
    _sessao_liberada(sessao)
    rp_id, origens = _endereco_publico(request)
    with request.app.state.banco.connection() as con:
        pedido = con.execute("SELECT roar_tomar_pedido(%s, 'passkey_cadastro') AS d", (outras_entradas.resumo_do_pedido(dados.pedido),)).fetchone()["d"]
        if not pedido or pedido["usuario"] != str(sessao["usuario_id"]):
            raise HTTPException(status_code=409, detail="O pedido venceu. Comece de novo.")
        try:
            credencial, chave, contador, transportes = outras_entradas.conferir_cadastro(dados.credencial, outras_entradas.de_texto(pedido["desafio"]), rp_id, origens)
        except outras_entradas.EntradaRecusada as erro:
            raise HTTPException(status_code=422, detail=str(erro))
        try:
            identificador = con.execute("SELECT roar_criar_passkey(%s, %s, %s, %s, %s, %s) AS id",
                                        (sessao["usuario_id"], credencial, chave, contador, dados.nome.strip()[:80], transportes)).fetchone()["id"]
        except psycopg.errors.UniqueViolation:
            raise HTTPException(status_code=409, detail="Esta passkey já está cadastrada.")
        con.execute("SELECT roar_registrar_acesso(%s, 'criar_passkey', %s)", (sessao["usuario_id"], _origem(request)))
    return {"id": identificador}


@app.delete("/api/passkeys/{identificador}", status_code=204)
def apagar_passkey(identificador: int, request: Request, sessao=Depends(sessao_atual)):
    _sessao_liberada(sessao)
    _inteiro_valido(identificador)
    with request.app.state.banco.connection() as con:
        if not con.execute("SELECT roar_apagar_passkey(%s, %s) AS ok", (sessao["usuario_id"], identificador)).fetchone()["ok"]:
            raise HTTPException(status_code=404)
        con.execute("SELECT roar_registrar_acesso(%s, 'apagar_passkey', %s)", (sessao["usuario_id"], _origem(request)))


@app.post("/api/passkeys/entrar/inicio")
def iniciar_entrada_por_passkey(request: Request):
    if _bloqueado(f"passkey:{_origem(request)}"):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde alguns minutos.")
    rp_id, _ = _endereco_publico(request)
    opcoes, desafio = outras_entradas.opcoes_de_entrada(rp_id)
    pedido, resumo = outras_entradas.novo_pedido()
    with request.app.state.banco.connection() as con:
        con.execute("SELECT roar_guardar_pedido(%s, 'passkey_entrada', %s, %s)",
                    (resumo, Jsonb({"desafio": outras_entradas.para_texto(desafio)}), outras_entradas.MINUTOS_DO_PEDIDO))
    return {"pedido": pedido, "opcoes": opcoes}


@app.post("/api/passkeys/entrar/fim", status_code=204, response_model=None)
def concluir_entrada_por_passkey(dados: FimDaEntrada, request: Request):
    origem = f"passkey:{_origem(request)}"
    if _bloqueado(origem):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde alguns minutos.")
    rp_id, origens = _endereco_publico(request)
    with request.app.state.banco.connection() as con:
        pedido = con.execute("SELECT roar_tomar_pedido(%s, 'passkey_entrada') AS d", (outras_entradas.resumo_do_pedido(dados.pedido),)).fetchone()["d"]
        try:
            if not pedido:
                raise outras_entradas.EntradaRecusada("O pedido venceu. Tente de novo.")
            passkey = con.execute("SELECT * FROM roar_passkey_para_entrar(%s)", (outras_entradas.credencial_usada(dados.credencial),)).fetchone()
            if not passkey:
                raise outras_entradas.EntradaRecusada("Passkey não reconhecida.")
            contador = outras_entradas.conferir_entrada(dados.credencial, outras_entradas.de_texto(pedido["desafio"]), rp_id, origens,
                                                        passkey["chave_publica"], passkey["contador"])
        except outras_entradas.EntradaRecusada as erro:
            falhas_de_login[origem].append(time.monotonic())
            raise HTTPException(status_code=401, detail=str(erro))
        if passkey["sso_exigido"] and passkey["perfil"] != "administrador":
            raise HTTPException(status_code=403, detail="Sua organização entra pelo login único (SSO).")
        con.execute("SELECT roar_passkey_usada(%s, %s)", (passkey["id"], contador))
    return _abrir_sessao(request, passkey["usuario_id"], "logon_passkey", Response(status_code=204))


@app.get("/api/sso/inicio")
def iniciar_sso(request: Request, email: str = "", provedor: str = ""):
    """Devolve o endereço do provedor da organização de quem vai entrar. A tela leva a pessoa até lá."""
    email = email.strip().lower()[:254]
    if _bloqueado(f"sso:{_origem(request)}"):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde alguns minutos.")
    with request.app.state.banco.connection() as con:
        quem = con.execute("SELECT * FROM roar_entrada_por_email(%s)", (email,)).fetchone() if "@" in email else None
        config = con.execute("SELECT * FROM roar_sso_da_organizacao(%s)", (quem["cliente_id"],)).fetchone() if quem and quem["sso_ativo"] else None
    if not config:
        falhas_de_login[f"sso:{_origem(request)}"].append(time.monotonic())
        raise HTTPException(status_code=404, detail="Este e-mail não entra por login único. Use a senha ou a passkey.")
    # O botão clicado tem de ser o da organização: quem é da Microsoft não vai parar no Google.
    if provedor in PROVEDORES_DE_SSO and provedor != quem["sso_provedor"]:
        raise HTTPException(status_code=409, detail=f"Sua organização entra pelo {PROVEDORES_DE_SSO[quem['sso_provedor']]}. Use o botão dele.")
    if config["provedor"] == "saml":
        estado, resumo = outras_entradas.novo_pedido()
        _, acs = _enderecos_do_saml(request)
        url, id_do_pedido = saml.pedido_de_entrada(config["emissor"], config["client_id"], acs, estado, email)
        with request.app.state.banco.connection() as con:
            con.execute("SELECT roar_guardar_pedido(%s, 'sso', %s, %s)", (resumo, Jsonb({
                "cliente": str(quem["cliente_id"]), "email": email, "saml": id_do_pedido, "acs": acs}), 10))
        return {"url": url}
    try:
        documento = outras_entradas.descobrir(config["emissor"])
    except outras_entradas.EntradaRecusada as erro:
        raise HTTPException(status_code=502, detail=str(erro))
    estado, resumo = outras_entradas.novo_pedido()
    nonce = secrets.token_urlsafe(24)
    verificador, desafio = outras_entradas.pkce()
    retorno = _retorno_do_sso(request)
    with request.app.state.banco.connection() as con:
        con.execute("SELECT roar_guardar_pedido(%s, 'sso', %s, %s)", (resumo, Jsonb({
            "cliente": str(quem["cliente_id"]), "email": email, "nonce": nonce, "verificador": verificador, "retorno": retorno}), 10))
    return {"url": outras_entradas.endereco_de_autorizacao(documento, config["client_id"], retorno, estado, nonce, desafio, email)}


@app.get("/api/sso/retorno", response_model=None)
def retorno_do_sso(request: Request, code: str = "", state: str = "", error: str = ""):
    """O provedor devolve a pessoa aqui. Qualquer falha volta para a tela de entrada com o motivo, nunca com detalhe interno."""
    def falhou(motivo):
        return RedirectResponse(f"/?{urlencode({'sso': motivo[:200]})}", status_code=303)

    with request.app.state.banco.connection() as con:
        pedido = con.execute("SELECT roar_tomar_pedido(%s, 'sso') AS d", (outras_entradas.resumo_do_pedido(state[:100]),)).fetchone()["d"] if state else None
        if not pedido:
            return falhou("O pedido de login único venceu. Tente de novo.")
        if error or not code:
            return falhou("O provedor de login não liberou a entrada.")
        config = con.execute("SELECT * FROM roar_sso_da_organizacao(%s)", (pedido["cliente"],)).fetchone()
    if not config:
        return falhou("O login único desta organização foi desligado.")
    try:
        documento = outras_entradas.descobrir(config["emissor"])
        segredo = request.app.state.cofre_do_sso.abrir(config["segredo"]) if config["segredo"] else None
        id_token = outras_entradas.trocar_codigo(documento, config["client_id"], segredo, code[:2000], pedido["retorno"], pedido["verificador"])
        email = outras_entradas.conferir_token(documento, config["client_id"], id_token, pedido["nonce"])
    except outras_entradas.EntradaRecusada as erro:
        return falhou(str(erro))
    if config["dominios"] and email.split("@")[1] not in config["dominios"]:
        return falhou("Este e-mail não é de um domínio aceito pela organização.")
    with request.app.state.banco.connection() as con:
        quem = con.execute("SELECT * FROM roar_entrada_por_email(%s)", (email,)).fetchone()
    # A conta tem de existir e ser da mesma organização: o login único não cria pessoa nem muda ninguém de lugar.
    if not quem or str(quem["cliente_id"]) != pedido["cliente"]:
        return falhou("Não há usuário ativo com este e-mail nesta organização. Peça à administração.")
    return _abrir_sessao(request, quem["usuario_id"], "logon_sso", RedirectResponse("/", status_code=303))


@app.post("/api/sso/saml/acs", response_model=None)
async def resposta_do_saml(request: Request):
    """O provedor SAML devolve a pessoa aqui, com a resposta assinada num formulário. Falha volta para a entrada com o motivo."""
    def falhou(motivo):
        return RedirectResponse(f"/?{urlencode({'sso': motivo[:200]})}", status_code=303)

    corpo = await request.body()
    if len(corpo) > saml.TAMANHO_MAXIMO * 2:
        return falhou("A resposta do provedor veio grande demais.")
    campos = parse_qs(corpo.decode("ascii", errors="replace"), max_num_fields=10)
    resposta, estado = (campos.get("SAMLResponse") or [""])[0], (campos.get("RelayState") or [""])[0]
    return await run_in_threadpool(_concluir_saml, request, resposta, estado, falhou)


def _concluir_saml(request, resposta, estado, falhou):
    origem = f"sso:{_origem(request)}"
    if _bloqueado(origem):
        return falhou("Muitas tentativas. Aguarde alguns minutos.")
    with request.app.state.banco.connection() as con:
        pedido = con.execute("SELECT roar_tomar_pedido(%s, 'sso') AS d", (outras_entradas.resumo_do_pedido(estado[:100]),)).fetchone()["d"] if estado else None
        if not pedido or not pedido.get("saml"):
            return falhou("O pedido de login único venceu. Tente de novo.")
        config = con.execute("SELECT * FROM roar_sso_da_organizacao(%s)", (pedido["cliente"],)).fetchone()
    if not config or config["provedor"] != "saml":
        return falhou("O login único desta organização foi desligado.")
    try:
        email = saml.conferir_resposta(resposta, config["saml_certificado"], config["saml_entidade"], config["client_id"], pedido["acs"], pedido["saml"])
    except saml.SamlRecusado as erro:
        falhas_de_login[origem].append(time.monotonic())
        return falhou(str(erro))
    if config["dominios"] and email.split("@")[1] not in config["dominios"]:
        return falhou("Este e-mail não é de um domínio aceito pela organização.")
    with request.app.state.banco.connection() as con:
        quem = con.execute("SELECT * FROM roar_entrada_por_email(%s)", (email,)).fetchone()
    if not quem or str(quem["cliente_id"]) != pedido["cliente"]:
        return falhou("Não há usuário ativo com este e-mail nesta organização. Peça à administração.")
    return _abrir_sessao(request, quem["usuario_id"], "logon_sso", RedirectResponse("/", status_code=303))


@app.get("/api/sso/saml/metadados")
def metadados_do_saml(request: Request):
    """O que o provedor SAML lê para cadastrar o Roar. Não tem nada de nenhuma organização."""
    entidade, acs = _enderecos_do_saml(request)
    return Response(saml.metadados(entidade, acs), media_type="application/samlmetadata+xml")


PROVEDORES_DE_SSO = {"google": "Google", "microsoft": "Microsoft", "outro": "login único", "saml": "login único (SAML)"}
EMISSOR_DO_GOOGLE = "https://accounts.google.com"
LOCATARIO_DA_MICROSOFT = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _emissor_do_provedor(dados):
    """Google e Microsoft têm emissor conhecido: a pessoa só informa o que muda, e o Roar monta o resto."""
    if dados.provedor == "google":
        return EMISSOR_DO_GOOGLE
    if dados.provedor == "microsoft":
        locatario = (dados.locatario or "").strip()
        # Com o nome do domínio, a Microsoft declara o emissor pelo ID: a conferência do token falharia.
        if not LOCATARIO_DA_MICROSOFT.fullmatch(locatario):
            raise HTTPException(status_code=422, detail="Use o ID do locatário, que tem o formato 00000000-0000-0000-0000-000000000000.")
        return f"https://login.microsoftonline.com/{locatario.lower()}/v2.0"
    if not re.fullmatch(r"https://\S{3,500}", dados.emissor or ""):
        raise HTTPException(status_code=422, detail="O emissor precisa ser um endereço https.")
    return dados.emissor.strip().rstrip("/")


class ConfiguracaoDeSso(BaseModel):
    provedor: str = Field(default="outro", pattern="^(google|microsoft|outro|saml)$")
    emissor: str | None = Field(default=None, max_length=500)
    locatario: str | None = Field(default=None, max_length=100)
    # No SAML, o Roar preenche o client_id com o próprio identificador.
    client_id: str = Field(default="", max_length=300)
    saml_entidade: str | None = Field(default=None, max_length=500)
    saml_certificado: str | None = Field(default=None, max_length=20000)
    # Ausente mantém o guardado; vazio apaga, para cliente público com PKCE.
    segredo: str | None = Field(default=None, max_length=2000)
    dominios: list[str] = Field(default=[], max_length=20)
    ativo: bool = True
    exigir: bool = False


@app.get("/api/organizacao/sso")
def ver_sso(request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    with do_cliente(request, sessao) as con:
        config = con.execute("""SELECT provedor, emissor, client_id, segredo IS NOT NULL AS tem_segredo, dominios, ativo, exigir, atualizado_em, saml_entidade,
                                       saml_certificado IS NOT NULL AS tem_certificado FROM sso""").fetchone()
    if config and config["provedor"] == "microsoft":
        config["locatario"] = config["emissor"].split("/")[3]
    entidade, acs = _enderecos_do_saml(request)
    return {"config": config, "retorno": _retorno_do_sso(request), "saml": {"entidade": entidade, "acs": acs, "metadados": entidade}}


@app.put("/api/organizacao/sso", status_code=204)
def definir_sso(dados: ConfiguracaoDeSso, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    """Confere o provedor antes de guardar: configuração que não funciona trancaria a organização se fosse exigida."""
    dominios = sorted({d.strip().lower().lstrip("@") for d in dados.dominios if d.strip()})
    if any(not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", d) for d in dominios):
        raise HTTPException(status_code=422, detail="Domínio inválido. Use só o domínio, como empresa.com.br.")
    with do_cliente(request, sessao) as con:
        atual = con.execute("SELECT segredo, saml_certificado FROM sso").fetchone()
    entidade_do_provedor = certificado = None
    if dados.provedor == "saml":
        # No SAML não há descoberta: o que dá para conferir é o endereço, o identificador e o certificado.
        emissor = (dados.emissor or "").strip()
        if not re.fullmatch(r"https://\S{3,500}", emissor):
            raise HTTPException(status_code=422, detail="O endereço de login do provedor precisa começar com https://.")
        entidade_do_provedor = (dados.saml_entidade or "").strip()
        if not entidade_do_provedor:
            raise HTTPException(status_code=422, detail="Informe o identificador do provedor (Entity ID ou emissor).")
        if dados.saml_certificado:
            try:
                certificado = saml.certificado_em_pem(dados.saml_certificado)
            except saml.SamlRecusado as erro:
                raise HTTPException(status_code=422, detail=str(erro))
        elif atual and atual["saml_certificado"]:
            certificado = atual["saml_certificado"]
        else:
            raise HTTPException(status_code=422, detail="Cole o certificado de assinatura do provedor.")
        client_id = _enderecos_do_saml(request)[0]
    else:
        emissor = _emissor_do_provedor(dados)
        client_id = dados.client_id.strip()
        if not client_id:
            raise HTTPException(status_code=422, detail="Informe o ID do cliente.")
        if dados.ativo:
            try:
                outras_entradas.descobrir(emissor)
            except outras_entradas.EntradaRecusada as erro:
                raise HTTPException(status_code=422, detail=str(erro))
    with do_cliente(request, sessao) as con:
        if dados.provedor == "saml" or dados.segredo == "":
            segredo = None
        elif dados.segredo is None:
            segredo = atual["segredo"] if atual else None
        else:
            segredo = request.app.state.cofre_do_sso.fechar(dados.segredo)
        con.execute("""INSERT INTO sso (cliente_id, provedor, emissor, client_id, segredo, dominios, ativo, exigir, atualizado_por, saml_entidade, saml_certificado)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (cliente_id) DO UPDATE SET provedor = EXCLUDED.provedor, emissor = EXCLUDED.emissor, client_id = EXCLUDED.client_id,
                         segredo = EXCLUDED.segredo, dominios = EXCLUDED.dominios, ativo = EXCLUDED.ativo, exigir = EXCLUDED.exigir,
                         atualizado_por = EXCLUDED.atualizado_por, atualizado_em = now(), saml_entidade = EXCLUDED.saml_entidade, saml_certificado = EXCLUDED.saml_certificado""",
                    (sessao["cliente_id"], dados.provedor, emissor, client_id, segredo, dominios, dados.ativo, dados.exigir and dados.ativo, sessao["usuario_id"],
                     entidade_do_provedor, certificado))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'definir_sso', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{emissor} {'ligado' if dados.ativo else 'desligado'}{', exigido' if dados.exigir and dados.ativo else ''}"))


@app.delete("/api/organizacao/sso", status_code=204)
def remover_sso(request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    with do_cliente(request, sessao) as con:
        if not con.execute("DELETE FROM sso RETURNING emissor").fetchone():
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'remover_sso', '-')", (sessao["cliente_id"], sessao["usuario_id"]))


@app.post("/api/sair", status_code=204)
def sair(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        with request.app.state.banco.connection() as con:
            sessao = con.execute("SELECT usuario_id FROM roar_sessao(%s)", (_hash_do_token(token),)).fetchone()
            if sessao:
                con.execute("SELECT roar_registrar_acesso(%s, 'logoff', %s)", (sessao["usuario_id"], _origem(request)))
            con.execute("SELECT roar_encerrar_sessao(%s)", (_hash_do_token(token),))
    response.delete_cookie(COOKIE, path="/")


@app.get("/api/eu")
def eu(request: Request, sessao=Depends(sessao_atual)):
    restantes = 0
    if sessao["mfa_ativo"] and not sessao["mfa_pendente"]:
        with request.app.state.banco.connection() as con:
            restantes = con.execute("SELECT roar_mfa_codigos_restantes(%s) AS n", (sessao["usuario_id"],)).fetchone()["n"]
    with request.app.state.banco.connection() as con:
        plataforma = con.execute("SELECT roar_e_plataforma(%s) AS p", (sessao["usuario_id"],)).fetchone()["p"]
    return {"nome": sessao["nome"], "cliente": sessao["cliente_nome"], "fuso": sessao["fuso"], "perfil": sessao["perfil"], "plataforma": plataforma,
            "cliente_id": str(sessao["cliente_id"]), "cliente_proprio": sessao["cliente_proprio_nome"], "em_outra_organizacao": sessao["cliente_id"] != sessao["cliente_proprio"],
            "trocar_senha": sessao["trocar_senha"], "permissoes": sorted(permissoes.PERFIS.get(sessao["perfil"], ())),
            "mfa_pendente": sessao["mfa_pendente"], "mfa_ativo": sessao["mfa_ativo"], "mfa_obrigatorio": sessao["mfa_obrigatorio"],
            "mfa_codigos_restantes": restantes, "modulos": sorted(MODULOS),
            "ofuscar": sessao["ofuscar"], "dados_mascarados": _ve_mascarado(sessao)}


class CodigoDeMfa(BaseModel):
    codigo: str = Field(max_length=32)


class SenhaAtual(BaseModel):
    senha: str = Field(max_length=256)


class DesligarMfa(BaseModel):
    senha: str = Field(max_length=256)
    codigo: str = Field(max_length=32)


class PoliticaDeMfa(BaseModel):
    obrigatorio: bool


class CriticidadeDoAtivo(BaseModel):
    gerenciador_id: str = Field(max_length=64)
    agente_id: str = Field(max_length=16)
    criticidade: str = Field(pattern="^(baixa|normal|alta|critica)$")


class PoliticaDeOfuscacao(BaseModel):
    categorias: list[str] = Field(max_length=len(ofuscacao.CATEGORIAS))


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
            # Em conexão própria: o erro levantado aqui desfaria o registro.
            with request.app.state.banco.connection() as outra:
                outra.execute("SELECT roar_registrar_recusa_de(%s, 'mfa_recusado', %s)", (sessao["usuario_id"], _origem(request)))
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


@app.put("/api/organizacao/ofuscacao", status_code=204)
def definir_ofuscacao(dados: PoliticaDeOfuscacao, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    if not set(dados.categorias) <= set(ofuscacao.CATEGORIAS):
        raise HTTPException(status_code=422, detail="Categoria desconhecida.")
    categorias = [c for c in ofuscacao.CATEGORIAS if c in dados.categorias]
    with do_cliente(request, sessao) as con:
        con.execute("SELECT roar_definir_ofuscacao(%s)", (categorias,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'definir_ofuscacao', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], ",".join(categorias) or "nenhuma"))


@app.post("/api/usuarios/{identificador}/nova-senha")
def redefinir_senha(identificador: uuid.UUID, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    temporaria = secrets.token_urlsafe(18)
    with do_cliente(request, sessao) as con:
        if not con.execute("SELECT roar_redefinir_senha(%s, %s) AS ok", (identificador, hasher.hash(temporaria))).fetchone()["ok"]:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'redefinir_senha', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))
    return {"senha_temporaria": temporaria}


class OrganizacaoNova(BaseModel):
    nome: str = Field(min_length=1, max_length=120, pattern=r"\S")
    email: str = Field(max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RemocaoDeOrganizacao(BaseModel):
    confirmacao: str = Field(max_length=120)


def exige_plataforma(request: Request, sessao=Depends(sessao_atual)):
    """Poder sobre a instalação, não sobre uma organização: ser administrador da própria não basta."""
    _sessao_liberada(sessao)
    with request.app.state.banco.connection() as con:
        if not con.execute("SELECT roar_e_plataforma(%s) AS p", (sessao["usuario_id"],)).fetchone()["p"]:
            raise HTTPException(status_code=403, detail="Só quem administra a instalação pode fazer isto.")
    return sessao


@app.get("/api/organizacoes")
def listar_organizacoes(request: Request, sessao=Depends(exige_plataforma)):
    with request.app.state.banco.connection() as con:
        return {"organizacoes": con.execute("SELECT * FROM roar_listar_organizacoes(%s)", (sessao["usuario_id"],)).fetchall(),
                "pedidos": con.execute("SELECT * FROM roar_listar_pedidos_de_organizacao(%s)", (sessao["usuario_id"],)).fetchall()}


@app.post("/api/organizacoes", status_code=201)
def pedir_organizacao(dados: OrganizacaoNova, request: Request, sessao=Depends(exige_plataforma)):
    """A API só registra o pedido: quem cria o gerenciador é o serviço de organizações. A senha aparece só nesta resposta."""
    temporaria = secrets.token_urlsafe(18)
    nome = dados.nome.strip()
    with do_cliente(request, sessao) as con:
        novo = con.execute("SELECT roar_pedir_organizacao(%s, %s, %s, %s) AS id",
                           (sessao["usuario_id"], nome, dados.email.strip(), hasher.hash(temporaria))).fetchone()["id"]
        if novo == -1:
            raise HTTPException(status_code=409, detail="Já existe uma organização com este nome.")
        if novo == -2:
            raise HTTPException(status_code=409, detail="Não foi possível usar este e-mail.")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'pedir_organizacao', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], nome))
    return {"id": novo, "senha_temporaria": temporaria}


def _usar_organizacao(request, sessao, cliente):
    with request.app.state.banco.connection() as con:
        return con.execute("SELECT roar_usar_organizacao(%s, %s, %s, %s) AS nome",
                           (_hash_do_token(request.cookies.get(COOKIE, "")), sessao["usuario_id"], cliente, _origem(request))).fetchone()["nome"]


@app.post("/api/organizacoes/voltar")
def voltar_para_a_organizacao(request: Request, sessao=Depends(exige_plataforma)):
    return {"cliente": _usar_organizacao(request, sessao, sessao["cliente_proprio"])}


@app.post("/api/organizacoes/{cliente}/entrar")
def entrar_na_organizacao(cliente: uuid.UUID, request: Request, sessao=Depends(exige_plataforma)):
    nome = _usar_organizacao(request, sessao, cliente)
    if nome is None:
        raise HTTPException(status_code=404)
    return {"cliente": nome}


@app.post("/api/organizacoes/{cliente}/remover", status_code=202)
def pedir_remocao_de_organizacao(cliente: uuid.UUID, dados: RemocaoDeOrganizacao, request: Request, sessao=Depends(exige_plataforma)):
    with do_cliente(request, sessao) as con:
        novo = con.execute("SELECT roar_pedir_remocao_de_organizacao(%s, %s, %s) AS id", (sessao["usuario_id"], cliente, dados.confirmacao)).fetchone()["id"]
        if novo is None:
            raise HTTPException(status_code=409, detail="Confira o nome. A organização em que você está não pode ser removida.")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'remover_organizacao', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], dados.confirmacao))
    return {"id": novo}


@app.get("/api/fila")
def fila(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), limite: int = 200):
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
                        ORDER BY v.nivel DESC, v.id DESC LIMIT 1) AS descricao,
                      EXISTS (SELECT 1 FROM intel_ocorrencias o JOIN eventos v ON v.id = o.evento_id WHERE v.grupo_id = g.id) AS indicador,
                      (SELECT string_agg(DISTINCT r.rotulo, ', ') FROM contexto_redes r WHERE r.rede >>= g.ip_origem) AS rede
               FROM grupos_alerta g WHERE g.nivel >= %s ORDER BY g.nivel DESC, g.ultima_em DESC LIMIT %s""",
            (NIVEL_MINIMO_NA_FILA, limite)).fetchall()
    return {"riscos": riscos, "grupos": grupos}


# Quanto tempo o caso tem para ser encerrado, pela severidade, contado de quando foi aberto.
PRAZO_DO_CASO = {"critica": timedelta(hours=4), "alta": timedelta(hours=24), "media": timedelta(hours=72), "baixa": timedelta(days=7)}
ESTADOS_DO_CASO = {"aberto": "Aberto", "investigando": "Investigando", "encerrado": "Encerrado"}
DESFECHOS_DO_CASO = {"incidente": "Incidente confirmado", "falso_positivo": "Falso positivo", "sem_acao": "Sem ação necessária"}
LIMITE_DE_ITENS_DO_CASO = 500


class ItemDoCaso(BaseModel):
    tipo: str = Field(pattern="^(grupo|risco|evento)$")
    id: int = Field(ge=1, le=2**62)


class CasoNovo(BaseModel):
    titulo: str = Field(min_length=1, max_length=200)
    severidade: str = Field(pattern="^(baixa|media|alta|critica)$")
    itens: list[ItemDoCaso] = Field(default=[], max_length=50)
    nota: str = Field(default="", max_length=4000)


class CasoAlterado(BaseModel):
    titulo: str | None = Field(default=None, min_length=1, max_length=200)
    severidade: str | None = Field(default=None, pattern="^(baixa|media|alta|critica)$")
    estado: str | None = Field(default=None, pattern="^(aberto|investigando|encerrado)$")
    desfecho: str | None = Field(default=None, pattern="^(incidente|falso_positivo|sem_acao)$")
    # Vazio tira o responsável.
    responsavel_id: str | None = Field(default=None, max_length=36)


class NotaDoCaso(BaseModel):
    texto: str = Field(min_length=1, max_length=4000)
    # Fato é o que foi visto; hipótese é o que se acha, e fica aberta até ser confirmada ou descartada.
    tipo: str = Field(default="nota", pattern="^(nota|fato|hipotese)$")


class SituacaoDaHipotese(BaseModel):
    situacao: str = Field(pattern="^(aberta|confirmada|descartada)$")


class PassagemDePlantao(BaseModel):
    para: str = Field(min_length=1, max_length=64)
    feito: str = Field(default="", max_length=2000)
    pendente: str = Field(default="", max_length=2000)


class ArquivoDoCaso(BaseModel):
    nome: str = Field(min_length=1, max_length=200)
    tipo_midia: str = Field(default="application/octet-stream", max_length=100)
    descricao: str = Field(default="", max_length=1000)
    # Em base64: a API não recebe formulário de arquivo. O teto fica em TAMANHO_DA_EVIDENCIA depois de decodificar.
    conteudo: str = Field(max_length=14_000_000)


TAMANHO_DA_EVIDENCIA = 10 * 1024 * 1024
SITUACOES_DA_HIPOTESE = {"aberta": "reaberta", "confirmada": "confirmada", "descartada": "descartada"}


def _responsaveis(con):
    """Quem pode cuidar de um caso: usuário ativo da organização que pode triar."""
    return [{"id": str(u["id"]), "nome": u["nome"]} for u in con.execute("SELECT * FROM roar_listar_usuarios()").fetchall()
            if u["ativo"] and permissoes.pode(u["perfil"], permissoes.TRIAR)]


def _item_existe(con, item):
    tabela = {"grupo": "grupos_alerta", "risco": "alertas_risco", "evento": "eventos"}[item.tipo]
    return con.execute(f"SELECT 1 FROM {tabela} WHERE id = %s", (item.id,)).fetchone() is not None


def _nota_do_caso(con, sessao, caso, texto, automatica=False, tipo="nota"):
    con.execute("INSERT INTO casos_notas (cliente_id, caso_id, autor_id, autor_nome, automatica, texto, tipo, situacao) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (sessao["cliente_id"], caso, sessao["usuario_id"], sessao["nome"], automatica, texto[:4000], tipo, "aberta" if tipo == "hipotese" else None))


def _incluir_itens(con, sessao, caso, itens):
    incluidos = 0
    for item in itens:
        if not _item_existe(con, item):
            raise HTTPException(status_code=404, detail="Um dos itens não existe.")
        incluidos += con.execute(
            """INSERT INTO casos_itens (cliente_id, caso_id, tipo, item_id, adicionado_por_nome) VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT DO NOTHING""", (sessao["cliente_id"], caso, item.tipo, item.id, sessao["nome"])).rowcount
    total = con.execute("SELECT count(*) AS n FROM casos_itens WHERE caso_id = %s", (caso,)).fetchone()["n"]
    if total > LIMITE_DE_ITENS_DO_CASO:
        raise HTTPException(status_code=422, detail=f"Um caso guarda até {LIMITE_DE_ITENS_DO_CASO} itens.")
    return incluidos


@app.get("/api/casos")
def casos(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), estado: str = "abertos"):
    encerrados = estado == "encerrados"
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            f"""SELECT c.id, c.titulo, c.severidade, c.estado, c.desfecho, c.responsavel_nome, c.criado_por_nome, c.criado_em,
                       c.atualizado_em, c.prazo, c.encerrado_em, c.estado <> 'encerrado' AND c.prazo < now() AS atrasado,
                       (SELECT count(*) FROM casos_itens i WHERE i.caso_id = c.id) AS itens,
                       (SELECT count(*) FROM casos_notas n WHERE n.caso_id = c.id AND NOT n.automatica) AS notas
                FROM casos c WHERE c.estado {"=" if encerrados else "<>"} 'encerrado'
                ORDER BY {"c.encerrado_em DESC" if encerrados else "c.prazo, c.id"} LIMIT 500""").fetchall()
        responsaveis = _responsaveis(con)
    return {"casos": linhas, "responsaveis": responsaveis}


@app.get("/api/casos/do-item")
def casos_do_item(tipo: str, id: int, request: Request, sessao=Depends(exige(permissoes.VER))):
    """Em quais casos o item já está, para a Fila avisar antes de abrir outro."""
    if tipo not in ("grupo", "risco", "evento"):
        raise HTTPException(status_code=422)
    _inteiro_valido(id)
    with do_cliente(request, sessao) as con:
        return {"casos": con.execute(
            """SELECT c.id, c.titulo, c.estado FROM casos c JOIN casos_itens i ON i.caso_id = c.id
               WHERE i.tipo = %s AND i.item_id = %s ORDER BY c.id DESC""", (tipo, id)).fetchall()}


@app.post("/api/casos", status_code=201)
def criar_caso(dados: CasoNovo, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    titulo = dados.titulo.strip()
    if not titulo:
        raise HTTPException(status_code=422, detail="Dê um título ao caso.")
    agora = datetime.now(timezone.utc)
    with do_cliente(request, sessao) as con:
        caso = con.execute(
            """INSERT INTO casos (cliente_id, titulo, severidade, criado_por, criado_por_nome, criado_em, atualizado_em, prazo)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (sessao["cliente_id"], titulo, dados.severidade, sessao["usuario_id"], sessao["nome"], agora, agora,
             agora + PRAZO_DO_CASO[dados.severidade])).fetchone()["id"]
        _incluir_itens(con, sessao, caso, dados.itens)
        if dados.nota.strip():
            _nota_do_caso(con, sessao, caso, dados.nota.strip())
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_caso', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{caso} {titulo[:200]}"))
    return {"id": caso}


@app.get("/api/casos/{identificador}")
def caso(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        dados = con.execute(
            """SELECT id, titulo, severidade, estado, desfecho, responsavel_id, responsavel_nome, criado_por_nome, criado_em,
                      atualizado_em, prazo, encerrado_em, estado <> 'encerrado' AND prazo < now() AS atrasado
               FROM casos WHERE id = %s""", (identificador,)).fetchone()
        if not dados:
            raise HTTPException(status_code=404)
        dados["responsavel_id"] = dados["responsavel_id"] and str(dados["responsavel_id"])
        grupos = con.execute(
            """SELECT 'grupo' AS tipo, g.id, g.severidade, g.total, g.regras, g.primeira_em, g.ultima_em AS quando, host(g.ip_origem) AS ip_origem,
                      (SELECT v.agente_nome FROM eventos v WHERE v.grupo_id = g.id ORDER BY v.id DESC LIMIT 1) AS ativo,
                      (SELECT v.regra_descricao FROM eventos v WHERE v.grupo_id = g.id ORDER BY v.nivel DESC, v.id DESC LIMIT 1) AS descricao,
                      i.adicionado_por_nome, i.adicionado_em
               FROM casos_itens i JOIN grupos_alerta g ON g.id = i.item_id
               WHERE i.caso_id = %s AND i.tipo = 'grupo' ORDER BY g.ultima_em DESC""", (identificador,)).fetchall()
        riscos = con.execute(
            """SELECT 'risco' AS tipo, a.id, a.severidade, a.risco_maximo, a.estado, a.aberto_em AS quando,
                      e.tipo AS entidade_tipo, coalesce(e.nome, e.chave) AS entidade, i.adicionado_por_nome, i.adicionado_em
               FROM casos_itens i JOIN alertas_risco a ON a.id = i.item_id JOIN entidades e ON e.id = a.entidade_id
               WHERE i.caso_id = %s AND i.tipo = 'risco' ORDER BY a.aberto_em DESC""", (identificador,)).fetchall()
        eventos = con.execute(
            """SELECT 'evento' AS tipo, v.id, v.severidade, v.ocorrido_em AS quando, v.regra_descricao AS descricao, v.agente_nome AS ativo,
                      v.usuario, host(v.ip_origem) AS ip_origem, i.adicionado_por_nome, i.adicionado_em
               FROM casos_itens i JOIN eventos v ON v.id = i.item_id
               WHERE i.caso_id = %s AND i.tipo = 'evento' ORDER BY v.ocorrido_em DESC""", (identificador,)).fetchall()
        notas = con.execute(
            "SELECT id, autor_nome, automatica, texto, criado_em, tipo, situacao FROM casos_notas WHERE caso_id = %s ORDER BY criado_em, id",
            (identificador,)).fetchall()
        evidencias = con.execute(
            """SELECT id, tipo, nome, tipo_midia, descricao, tamanho, sha256, adicionado_por_nome, adicionado_em
               FROM casos_evidencias WHERE caso_id = %s ORDER BY adicionado_em, id""", (identificador,)).fetchall()
        responsaveis = _responsaveis(con)
    return {"caso": dados, "itens": grupos + riscos + eventos, "notas": notas, "evidencias": evidencias, "responsaveis": responsaveis}


@app.patch("/api/casos/{identificador}", status_code=204)
def alterar_caso(identificador: int, dados: CasoAlterado, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        atual = con.execute("SELECT * FROM casos WHERE id = %s FOR UPDATE", (identificador,)).fetchone()
        if not atual:
            raise HTTPException(status_code=404)
        mudancas, notas = {}, []
        if dados.titulo is not None and dados.titulo.strip() and dados.titulo.strip() != atual["titulo"]:
            mudancas["titulo"] = dados.titulo.strip()
            notas.append(f"Título mudou para \"{mudancas['titulo']}\".")
        if dados.severidade and dados.severidade != atual["severidade"]:
            mudancas["severidade"] = dados.severidade
            mudancas["prazo"] = atual["criado_em"] + PRAZO_DO_CASO[dados.severidade]
            notas.append(f"Severidade mudou de {atual['severidade']} para {dados.severidade}.")
        if dados.responsavel_id is not None:
            if dados.responsavel_id == "":
                novo = None
            else:
                novo = next((r for r in _responsaveis(con) if r["id"] == dados.responsavel_id), None)
                if not novo:
                    raise HTTPException(status_code=422, detail="Essa pessoa não pode cuidar de casos.")
            if (novo and novo["id"]) != (atual["responsavel_id"] and str(atual["responsavel_id"])):
                mudancas["responsavel_id"] = novo and novo["id"]
                mudancas["responsavel_nome"] = novo and novo["nome"]
                notas.append(f"Responsável: {novo['nome']}." if novo else "Ficou sem responsável.")
        if dados.estado and dados.estado != atual["estado"]:
            if dados.estado == "encerrado":
                if not dados.desfecho:
                    raise HTTPException(status_code=422, detail="Diga como o caso terminou.")
                mudancas.update(desfecho=dados.desfecho, encerrado_em=datetime.now(timezone.utc))
                notas.append(f"Encerrado: {DESFECHOS_DO_CASO[dados.desfecho].lower()}.")
            else:
                mudancas.update(desfecho=None, encerrado_em=None)
                notas.append("Reaberto." if atual["estado"] == "encerrado" else f"Estado: {ESTADOS_DO_CASO[dados.estado].lower()}.")
            mudancas["estado"] = dados.estado
        if not mudancas:
            return
        mudancas["atualizado_em"] = datetime.now(timezone.utc)
        colunas = ", ".join(f"{c} = %s" for c in mudancas)
        con.execute(f"UPDATE casos SET {colunas} WHERE id = %s", (*mudancas.values(), identificador))
        for texto in notas:
            _nota_do_caso(con, sessao, identificador, texto, automatica=True)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'alterar_caso', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{identificador} " + " ".join(notas)[:300]))


@app.post("/api/casos/{identificador}/itens", status_code=204)
def incluir_no_caso(identificador: int, item: ItemDoCaso, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        if not con.execute("SELECT 1 FROM casos WHERE id = %s FOR UPDATE", (identificador,)).fetchone():
            raise HTTPException(status_code=404)
        if _incluir_itens(con, sessao, identificador, [item]):
            rotulo = {"grupo": "alerta", "risco": "risco", "evento": "evento"}[item.tipo]
            _nota_do_caso(con, sessao, identificador, f"Incluiu o {rotulo} {item.id}.", automatica=True)
            con.execute("UPDATE casos SET atualizado_em = now() WHERE id = %s", (identificador,))


@app.delete("/api/casos/{identificador}/itens/{tipo}/{item}", status_code=204)
def tirar_do_caso(identificador: int, tipo: str, item: int, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    _inteiro_valido(identificador)
    _inteiro_valido(item)
    with do_cliente(request, sessao) as con:
        if not con.execute("DELETE FROM casos_itens WHERE caso_id = %s AND tipo = %s AND item_id = %s", (identificador, tipo, item)).rowcount:
            raise HTTPException(status_code=404)
        rotulo = {"grupo": "alerta", "risco": "risco", "evento": "evento"}.get(tipo, tipo)
        _nota_do_caso(con, sessao, identificador, f"Tirou o {rotulo} {item}.", automatica=True)
        con.execute("UPDATE casos SET atualizado_em = now() WHERE id = %s", (identificador,))


@app.post("/api/casos/{identificador}/notas", status_code=201)
def anotar_caso(identificador: int, dados: NotaDoCaso, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    _inteiro_valido(identificador)
    texto = dados.texto.strip()
    if not texto:
        raise HTTPException(status_code=422, detail="A nota está vazia.")
    with do_cliente(request, sessao) as con:
        if not con.execute("SELECT 1 FROM casos WHERE id = %s", (identificador,)).fetchone():
            raise HTTPException(status_code=404)
        _nota_do_caso(con, sessao, identificador, texto, tipo=dados.tipo)
        con.execute("UPDATE casos SET atualizado_em = now() WHERE id = %s", (identificador,))


@app.post("/api/casos/{identificador}/notas/{nota}/situacao", status_code=204)
def situacao_da_hipotese(identificador: int, nota: int, dados: SituacaoDaHipotese, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    """Só a hipótese muda de situação, e a mudança fica no histórico: o texto dela continua como foi escrito."""
    _inteiro_valido(identificador)
    _inteiro_valido(nota)
    with do_cliente(request, sessao) as con:
        hipotese = con.execute("SELECT texto, situacao FROM casos_notas WHERE id = %s AND caso_id = %s AND tipo = 'hipotese' FOR UPDATE",
                               (nota, identificador)).fetchone()
        if not hipotese:
            raise HTTPException(status_code=404)
        if hipotese["situacao"] == dados.situacao:
            return
        con.execute("UPDATE casos_notas SET situacao = %s WHERE id = %s", (dados.situacao, nota))
        resumo = hipotese["texto"] if len(hipotese["texto"]) <= 120 else hipotese["texto"][:117] + "..."
        _nota_do_caso(con, sessao, identificador, f"Hipótese {SITUACOES_DA_HIPOTESE[dados.situacao]}: \"{resumo}\"", automatica=True)
        con.execute("UPDATE casos SET atualizado_em = now() WHERE id = %s", (identificador,))


@app.post("/api/casos/{identificador}/passagem", status_code=204)
def passar_o_caso(identificador: int, dados: PassagemDePlantao, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    """Passa o caso para quem assume o plantão, com o que já foi feito e o que falta. O registro fica no histórico."""
    _inteiro_valido(identificador)
    if not dados.feito.strip() and not dados.pendente.strip():
        raise HTTPException(status_code=422, detail="Conte o que já foi feito ou o que falta fazer.")
    with do_cliente(request, sessao) as con:
        atual = con.execute("SELECT estado, responsavel_nome FROM casos WHERE id = %s FOR UPDATE", (identificador,)).fetchone()
        if not atual:
            raise HTTPException(status_code=404)
        if atual["estado"] == "encerrado":
            raise HTTPException(status_code=409, detail="O caso está encerrado. Reabra antes de passar.")
        novo = next((r for r in _responsaveis(con) if r["id"] == dados.para), None)
        if not novo:
            raise HTTPException(status_code=422, detail="Essa pessoa não pode cuidar de casos.")
        con.execute("UPDATE casos SET responsavel_id = %s, responsavel_nome = %s, atualizado_em = now() WHERE id = %s", (novo["id"], novo["nome"], identificador))
        partes = [f"Passou o caso para {novo['nome']}."]
        if dados.feito.strip():
            partes.append(f"Já feito: {dados.feito.strip()}")
        if dados.pendente.strip():
            partes.append(f"Falta: {dados.pendente.strip()}")
        _nota_do_caso(con, sessao, identificador, "\n".join(partes), tipo="passagem")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'passar_caso', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{identificador} para {novo['nome']}"))


@app.get("/api/casos-plantao")
def resumo_do_plantao(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), horas: int = 12):
    """O que mudou no plantão: casos novos, encerrados, passados, hipóteses abertas e atrasados. Vem também como texto pronto para colar."""
    horas = max(1, min(horas, 72))
    with do_cliente(request, sessao) as con:
        desde = "now() - make_interval(hours => %(h)s)"
        novos = con.execute(f"SELECT id, titulo, severidade, responsavel_nome FROM casos WHERE criado_em >= {desde} ORDER BY id", {"h": horas}).fetchall()
        encerrados = con.execute(f"SELECT id, titulo, desfecho FROM casos WHERE encerrado_em >= {desde} ORDER BY id", {"h": horas}).fetchall()
        abertos = con.execute(
            """SELECT c.id, c.titulo, c.severidade, c.responsavel_nome, c.prazo < now() AS atrasado,
                      (SELECT count(*) FROM casos_notas n WHERE n.caso_id = c.id AND n.tipo = 'hipotese' AND n.situacao = 'aberta') AS hipoteses,
                      (SELECT n.texto FROM casos_notas n WHERE n.caso_id = c.id AND n.tipo = 'passagem' ORDER BY n.criado_em DESC, n.id DESC LIMIT 1) AS ultima_passagem
               FROM casos c WHERE c.estado <> 'encerrado'
               ORDER BY array_position(ARRAY['critica', 'alta', 'media', 'baixa'], c.severidade), c.prazo""").fetchall()
    rotulos = {"critica": "crítica", "alta": "alta", "media": "média", "baixa": "baixa"}
    linhas = [f"Passagem de plantão: últimas {horas} horas", ""]
    linhas.append(f"Abertos: {len(abertos)}, dos quais {sum(1 for c in abertos if c['atrasado'])} atrasados.")
    linhas.append(f"Novos: {len(novos)}. Encerrados: {len(encerrados)}.")
    for c in abertos:
        linhas.append(f"- #{c['id']} {c['titulo']} ({rotulos[c['severidade']]}{', atrasado' if c['atrasado'] else ''}), com {c['responsavel_nome'] or 'ninguém'}"
                      + (f"; {c['hipoteses']} hipótese(s) aberta(s)" if c["hipoteses"] else ""))
    return {"horas": horas, "novos": novos, "encerrados": encerrados, "abertos": abertos, "texto": "\n".join(linhas)}


def _guardar_evidencia(con, sessao, caso, tipo, nome, tipo_midia, descricao, conteudo):
    resumo = relatorios.resumo_do_arquivo(conteudo)
    evidencia_id = con.execute(
        """INSERT INTO casos_evidencias (cliente_id, caso_id, tipo, nome, tipo_midia, descricao, conteudo, tamanho, sha256, adicionado_por, adicionado_por_nome)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (sessao["cliente_id"], caso, tipo, nome, tipo_midia, descricao, conteudo, len(conteudo), resumo, sessao["usuario_id"], sessao["nome"])).fetchone()["id"]
    _nota_do_caso(con, sessao, caso, f"Anexou a evidência \"{nome}\" ({len(conteudo):,} bytes, SHA-256 {resumo}).".replace(",", ".", 1), automatica=True)
    con.execute("UPDATE casos SET atualizado_em = now() WHERE id = %s", (caso,))
    con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'anexar_evidencia', %s)",
                (sessao["cliente_id"], sessao["usuario_id"], f"caso {caso} {nome[:120]} sha256:{resumo}"))
    return evidencia_id, resumo


@app.post("/api/casos/{identificador}/evidencias/pacote", status_code=201)
def pacote_do_caso(identificador: int, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    """O pacote de prova dos eventos do caso, com os selos, guardado no próprio caso."""
    _inteiro_valido(identificador)
    if not permissoes.pode(sessao["perfil"], permissoes.VER_BRUTO):
        raise HTTPException(status_code=403, detail="Seu perfil não pode gerar o pacote de prova, que leva o log como chegou.")
    _exige_o_original(sessao)
    with do_cliente(request, sessao) as con:
        caso = con.execute("SELECT titulo FROM casos WHERE id = %s", (identificador,)).fetchone()
        if not caso:
            raise HTTPException(status_code=404)
        ids = [l["origem_id"] for l in con.execute(
            """SELECT DISTINCT v.origem_id, v.ocorrido_em FROM casos_itens i
               JOIN eventos v ON (i.tipo = 'evento' AND v.id = i.item_id) OR (i.tipo = 'grupo' AND v.grupo_id = i.item_id)
               WHERE i.caso_id = %s ORDER BY v.ocorrido_em LIMIT %s""", (identificador, evidencia.LIMITE_DE_EVENTOS + 1)).fetchall()]
        gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
    if not ids:
        raise HTTPException(status_code=409, detail="O caso ainda não tem alerta nem evento para levar no pacote.")
    if len(ids) > evidencia.LIMITE_DE_EVENTOS:
        raise HTTPException(status_code=409, detail=f"O caso tem mais de {evidencia.LIMITE_DE_EVENTOS} eventos. Tire alguns ou gere o pacote pela tela Prova e evidência.")
    descricao = [("Caso", f"#{identificador} {caso['titulo']}"), ("Eventos no pacote", str(len(ids)))]
    try:
        with do_cliente(request, sessao) as con:
            pacotes = evidencia.montar_pacotes(con, request.app.state.indexer, INDEXER_URL, gerenciadores, "alertas", ids, selagem.ler_chave_publica(),
                                               **_armazem_da_pericia(request, sessao))
        conteudo = evidencia.gerar_zip_de_varios(pacotes, sessao, relatorios.gerar_pdf, descricao=descricao)
    except evidencia.EvidenciaRecusada as erro:
        raise HTTPException(status_code=409, detail=str(erro))
    nome = f"caso-{identificador}-evidencia-{datetime.now(timezone.utc):%Y%m%d-%H%M}.zip"
    with do_cliente(request, sessao) as con:
        evidencia_id, resumo = _guardar_evidencia(con, sessao, identificador, "pacote", nome, "application/zip", f"{len(ids)} eventos com os selos", conteudo)
    return {"id": evidencia_id, "sha256": resumo}


@app.post("/api/casos/{identificador}/evidencias/arquivo", status_code=201)
def anexar_ao_caso(identificador: int, dados: ArquivoDoCaso, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    _inteiro_valido(identificador)
    try:
        conteudo = base64.b64decode(dados.conteudo, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=422, detail="O arquivo não chegou inteiro. Tente de novo.")
    if not conteudo or len(conteudo) > TAMANHO_DA_EVIDENCIA:
        raise HTTPException(status_code=422, detail="O arquivo precisa ter até 10 MB.")
    nome = re.sub(r"[\\/\x00-\x1f]", "_", dados.nome.strip())[:200] or "arquivo"
    tipo_midia = dados.tipo_midia if re.fullmatch(r"[\w.+-]+/[\w.+-]+", dados.tipo_midia) else "application/octet-stream"
    with do_cliente(request, sessao) as con:
        if not con.execute("SELECT 1 FROM casos WHERE id = %s", (identificador,)).fetchone():
            raise HTTPException(status_code=404)
        evidencia_id, resumo = _guardar_evidencia(con, sessao, identificador, "arquivo", nome, tipo_midia, dados.descricao.strip(), conteudo)
    return {"id": evidencia_id, "sha256": resumo}


@app.get("/api/casos/{identificador}/evidencias/{evidencia_id}")
def baixar_evidencia_do_caso(identificador: int, evidencia_id: int, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO))):
    """Sai como anexo e nunca é mostrado na tela: um HTML anexado não roda dentro da console."""
    _inteiro_valido(identificador)
    _inteiro_valido(evidencia_id)
    _exige_o_original(sessao)
    with do_cliente(request, sessao) as con:
        linha = con.execute("SELECT nome, conteudo, sha256 FROM casos_evidencias WHERE id = %s AND caso_id = %s", (evidencia_id, identificador)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'baixar_evidencia', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"caso {identificador} {linha['nome'][:120]} sha256:{linha['sha256']}"))
    nome = re.sub(r'[^\w.-]', "_", linha["nome"])[:120]
    return Response(bytes(linha["conteudo"]), media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{nome}"', "X-Resumo-SHA256": linha["sha256"], "X-Content-Type-Options": "nosniff"})


@app.get("/api/panorama")
def panorama(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), dias: int = 30):
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
        paises = con.execute(
            f"""SELECT pais, count(*) AS total, count(*) FILTER (WHERE severidade IN ('alta', 'critica')) AS graves
                FROM eventos WHERE pais IS NOT NULL AND nivel >= %s AND ocorrido_em >= {desde}
                GROUP BY 1 ORDER BY total DESC, pais LIMIT 250""",
            (NIVEL_MINIMO_NA_FILA, dias)).fetchall()
        # A posição vem do alerta, que pode ter sido escrito por quem atacou: só número entra na conta.
        cidades = con.execute(
            f"""SELECT cidade, regiao, pais, count(*) AS total, count(*) FILTER (WHERE severidade IN ('alta', 'critica')) AS graves,
                       avg(CASE WHEN jsonb_typeof(bruto #> '{{GeoLocation,location,lat}}') = 'number' THEN (bruto #>> '{{GeoLocation,location,lat}}')::float END) AS lat,
                       avg(CASE WHEN jsonb_typeof(bruto #> '{{GeoLocation,location,lon}}') = 'number' THEN (bruto #>> '{{GeoLocation,location,lon}}')::float END) AS lon
                FROM eventos WHERE pais IS NOT NULL AND cidade IS NOT NULL AND nivel >= %s AND ocorrido_em >= {desde}
                GROUP BY 1, 2, 3 ORDER BY total DESC, cidade LIMIT 300""",
            (NIVEL_MINIMO_NA_FILA, dias)).fetchall()
        operadoras = con.execute(
            f"""SELECT operadora, asn, count(*) AS total, count(*) FILTER (WHERE severidade IN ('alta', 'critica')) AS graves
                FROM eventos WHERE operadora IS NOT NULL AND nivel >= %s AND ocorrido_em >= {desde}
                GROUP BY 1, 2 ORDER BY total DESC, operadora LIMIT 20""",
            (NIVEL_MINIMO_NA_FILA, dias)).fetchall()
        # Muitos endereços de operadora só dizem o país: sem este número, o mapa pareceria cobrir tudo.
        sem_cidade = con.execute(
            f"SELECT count(*) AS n FROM eventos WHERE pais IS NOT NULL AND cidade IS NULL AND nivel >= %s AND ocorrido_em >= {desde}",
            (NIVEL_MINIMO_NA_FILA, dias)).fetchone()["n"]
    return {"por_dia": por_dia, "sinais": sinais, "origens": origens, "paises": paises, "cidades": cidades, "sem_cidade": sem_cidade, "operadoras": operadoras,
            "riscos": [r for r in riscos if r["risco"] >= 1]}


def _sem_curinga(texto):
    return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class FiltroDeEventos(BaseModel):
    """Os filtros da tela de Eventos. A lista e a exportação contam do mesmo jeito."""
    busca: str = ""
    severidade: str = ""
    dias: int = 30
    pais: str = ""
    cidade: str = ""
    dia: str = ""
    severidades: str = ""
    origem: str = ""
    sinal: str = ""
    entidade: str = ""
    alertas: bool = False
    regra: str = ""
    agente: str = ""
    gerenciador: str = ""
    operadora: str = ""


def _condicoes_dos_eventos(sessao, f):
    busca, severidade, pais, cidade, dia, severidades = f.busca, f.severidade, f.pais, f.cidade, f.dia, f.severidades
    origem, sinal, entidade, alertas, regra, agente, gerenciador, operadora = f.origem, f.sinal, f.entidade, f.alertas, f.regra, f.agente, f.gerenciador, f.operadora
    dias = max(1, min(f.dias, 90))
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
    if pais:
        condicoes.append("pais = %s")
        parametros.append(pais[:100])
    if cidade:
        condicoes.append("cidade = %s")
        parametros.append(cidade[:100])
    # Cada número do panorama abre os eventos que ele conta: os filtros precisam contar do mesmo jeito.
    if alertas:
        condicoes.append("nivel >= %s")
        parametros.append(NIVEL_MINIMO_NA_FILA)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", dia):
        condicoes.append("(ocorrido_em AT TIME ZONE %s)::date = %s::date")
        parametros += [sessao["fuso"], dia]
    lista = [s for s in severidades.split(",") if s in ("baixa", "media", "alta", "critica")]
    if lista:
        condicoes.append("severidade = ANY(%s)")
        parametros.append(lista)
    if origem:
        condicoes.append("host(ip_origem) = %s")
        parametros.append(origem[:64])
    if sinal:
        condicoes.append("id IN (SELECT evento_id FROM sinais WHERE tipo = %s AND ocorrido_em >= now() - make_interval(days => %s))")
        parametros += [sinal[:64], dias]
    if entidade:
        condicoes.append("(usuario = %s OR agente_nome = %s)")
        parametros += [entidade[:200], entidade[:200]]
    if operadora:
        condicoes.append("operadora = %s")
        parametros.append(operadora[:200])
    if regra:
        condicoes.append("regra_id = %s")
        parametros.append(regra[:16])
    if agente:
        condicoes.append("agente_id = %s")
        parametros.append(agente[:16])
    # O número do agente só é único dentro do gerenciador: dois servidores da mesma organização podem ter o mesmo.
    if gerenciador:
        condicoes.append("gerenciador_id = %s")
        parametros.append(gerenciador[:64])
    return condicoes, parametros


@app.get("/api/eventos")
def eventos(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), filtro: FiltroDeEventos = Depends(), antes_de: int = 0):
    """Todos os eventos, inclusive os normais, em páginas do mais novo para o mais antigo."""
    condicoes, parametros = _condicoes_dos_eventos(sessao, filtro)
    if 0 < antes_de < 2**63:
        condicoes.append("id < %s")
        parametros.append(antes_de)
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            f"""SELECT id, ocorrido_em, severidade, nivel, regra_id, regra_descricao, agente_nome AS ativo,
                       host(ip_origem) AS ip_origem, usuario, pais, cidade, regiao, operadora, asn,
                       EXISTS (SELECT 1 FROM intel_ocorrencias o WHERE o.evento_id = eventos.id) AS indicador,
                       (SELECT string_agg(DISTINCT r.rotulo, ', ') FROM contexto_redes r WHERE r.rede >>= eventos.ip_origem) AS rede
                FROM eventos WHERE {' AND '.join(condicoes)} ORDER BY id DESC LIMIT %s""",
            (*parametros, TAMANHO_DA_PAGINA + 1)).fetchall()
    return {"eventos": linhas[:TAMANHO_DA_PAGINA], "ha_mais": len(linhas) > TAMANHO_DA_PAGINA}


LIMITE_DA_EXPORTACAO_OCSF = 10_000
COLUNAS_DO_OCSF = """id, origem, origem_id, ocorrido_em, recebido_em, nivel, severidade, regra_id, regra_descricao, regra_grupos, mitre,
                     gerenciador_id, agente_id, agente_nome, host(ip_origem) AS ip_origem, usuario, bruto, pais, cidade, regiao, operadora, asn"""


def _tecnicas_para_ocsf(con, linhas):
    codigos = sorted({c for l in linhas for t in (l["mitre"] or []) for c in (t, t.split(".")[0])})
    if not codigos:
        return {}
    return {t["tecnica"]: {"nome": t["nome"], "tatica": t["tatica"]} for t in con.execute(
        """SELECT a.tecnica, a.nome, coalesce(t.nome, a.taticas[1]) AS tatica
           FROM tecnicas_attack a LEFT JOIN taticas_attack t ON t.tatica = a.taticas[1] WHERE a.tecnica = ANY(%s)""", (codigos,)).fetchall()}


@app.get("/api/eventos/ocsf")
def exportar_eventos_em_ocsf(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), filtro: FiltroDeEventos = Depends()):
    """Os eventos do filtro em OCSF, uma linha de JSON por evento, para outro SIEM ou data lake."""
    condicoes, parametros = _condicoes_dos_eventos(sessao, filtro)
    with do_cliente(request, sessao) as con:
        linhas = con.execute(f"SELECT {COLUNAS_DO_OCSF} FROM eventos WHERE {' AND '.join(condicoes)} ORDER BY id DESC LIMIT %s",
                             (*parametros, LIMITE_DA_EXPORTACAO_OCSF)).fetchall()
        tecnicas = _tecnicas_para_ocsf(con, linhas)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'exportar_ocsf', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{len(linhas)} eventos, {filtro.dias} dias"))
    # NDJSON não passa pelo mascaramento da saída: aqui cada objeto é mascarado antes de virar texto.
    mascara = getattr(request.state, "mascara", None)
    request.state.mascara = None
    objetos = (ocsf.converter(l, tecnicas) for l in linhas)
    corpo = "".join(json.dumps(mascara.dado(o) if mascara else o, ensure_ascii=False, separators=(",", ":")) + "\n" for o in objetos)
    nome = f"eventos-ocsf-{datetime.now(timezone.utc):%Y%m%d-%H%M}.ndjson"
    return Response(corpo, media_type="application/x-ndjson", headers={"Content-Disposition": f'attachment; filename="{nome}"', "X-Eventos": str(len(linhas))})


@app.get("/api/eventos/{identificador}/ocsf")
def evento_em_ocsf(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True))):
    """Um evento em OCSF. O log como chegou não vai junto: ele fica em /bruto, para quem pode ver."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute(f"SELECT {COLUNAS_DO_OCSF} FROM eventos WHERE id = %s", (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        return ocsf.converter(linha, _tecnicas_para_ocsf(con, [linha]))


@app.get("/api/eventos/{identificador}/contexto")
def contexto_do_evento(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True))):
    """Só resultados de comparação: quem não pode ver o log bruto também pode saber que a origem é uma saída Tor."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        ev = con.execute("SELECT host(ip_origem) AS ip, pais, cidade, regiao, operadora, asn, bruto FROM eventos WHERE id = %s", (identificador,)).fetchone()
        if not ev:
            raise HTTPException(status_code=404)
        vistos = contexto.observaveis_do_alerta(ev["bruto"])
        sinais = []
        for o in con.execute(
            """SELECT DISTINCT i.tipo, i.valor, i.descricao, f.nome AS fonte, o.no_passado FROM intel_ocorrencias o
               JOIN intel_indicadores i ON i.id = o.indicador_id JOIN intel_fontes f ON f.id = i.fonte_id WHERE o.evento_id = %s LIMIT 10""", (identificador,)).fetchall():
            sinais.append({"tom": "agrava", "texto": f"Indicador de ameaça: {o['valor'][:60]}", "detalhe": f"{o['fonte']}. {o['descricao'] or ''}".strip()[:300]})
        origem = None
        if ev["ip"]:
            for r in con.execute("SELECT DISTINCT lista, rotulo FROM contexto_redes WHERE rede >>= %s::inet LIMIT 5", (ev["ip"],)).fetchall():
                sinais.append({"tom": "agrava" if r["lista"] == "tor" else "informa", "texto": r["rotulo"] if r["lista"] == "tor" else f"Rede de {r['rotulo']}"})
            soma = con.execute(
                """SELECT count(*) AS vezes, count(DISTINCT agente_id) AS ativos, min(ocorrido_em) AS primeira_em FROM eventos
                   WHERE ip_origem = %s::inet AND ocorrido_em >= now() - interval '30 days'""", (ev["ip"],)).fetchone()
            local = ", ".join(x for x in (ev["cidade"], ev["pais"]) if x) or None
            origem = {"ip": ev["ip"], "operadora": ev["operadora"], "asn": ev["asn"], "local": local, **soma}
        def itens(lista, chaves):
            if not chaves:
                return []
            return con.execute("SELECT chave, rotulo, detalhe, endereco FROM contexto_itens WHERE lista = %s AND chave = ANY(%s)", (lista, chaves)).fetchall()
        for i in itens("loldrivers", vistos["resumos"]):
            sinais.append({"tom": "agrava", "texto": i["rotulo"], "detalhe": i["detalhe"], "endereco": i["endereco"]})
        for i in itens("lolbas", vistos["programas"]):
            sinais.append({"tom": "informa", "texto": f"{i['rotulo']} costuma ser usado em ataques", "detalhe": i["detalhe"], "endereco": i["endereco"]})
        for i in itens("gtfobins", vistos["programas"]):
            sinais.append({"tom": "informa", "texto": f"{i['rotulo']} permite abuso no Linux", "detalhe": i["detalhe"], "endereco": i["endereco"]})
        for i in itens("tranco", contexto.dominios_candidatos(vistos["dominios"]))[:3]:
            sinais.append({"tom": "atenua", "texto": f"{i['chave']} é um site popular", "detalhe": f"Posição {i['rotulo']} no ranking de sites. Site popular também pode hospedar coisa ruim."})
        grupos = [{"tecnica": i["chave"], "grupos": i["rotulo"], "total": i["detalhe"], "endereco": i["endereco"]} for i in itens("attack", vistos["tecnicas"])[:3]]
    return {"sinais": sinais, "origem": origem, "grupos": grupos}


@app.get("/api/eventos/{identificador}/investigacao")
def investigacao_do_evento(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True))):
    """As perguntas de um analista sobre o alerta, respondidas com consultas fixas e os alertas que provam cada resposta."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        onde = _armazem_da_organizacao(request, con, sessao)
        pacote = investigacao.investigar(con, identificador, onde.get("armazem"), onde.get("banco"))
    if pacote is None:
        raise HTTPException(status_code=404)
    return pacote


@app.get("/api/eventos/{identificador}/bruto")
def evento_bruto(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO, mascarar=True))):
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


def _armazem_da_organizacao(request, con, sessao):
    """{"armazem", "banco"} quando a organização lê do armazém de eventos; vazio quando lê do indexador, inclusive quando
    ela ainda não tem banco no armazém (gerenciador recém-criado, instalação antiga no meio da troca)."""
    if request.app.state.armazem is None or not con.execute("SELECT ler_do_armazem FROM clientes").fetchone()["ler_do_armazem"]:
        return {}
    banco = armazem_de_eventos.banco_do(sessao["cliente_id"])
    if not _banco_no_armazem(request, banco):
        return {}
    return {"armazem": request.app.state.armazem, "banco": banco}


BANCOS_VISTOS = {}
SEGUNDOS_DO_CACHE_DE_BANCOS = 60


def _banco_no_armazem(request, banco):
    """Se o banco existe, lembrado por um minuto: a pergunta é a mesma em toda requisição da organização."""
    agora = time.monotonic()
    visto = BANCOS_VISTOS.get(banco)
    if visto is None or agora - visto[1] > SEGUNDOS_DO_CACHE_DE_BANCOS:
        try:
            existe = request.app.state.armazem.linhas("SELECT count() AS n FROM system.databases WHERE name = {b:String}", {"b": banco})[0]["n"] not in (0, "0")
        except (armazem_de_eventos.ArmazemRecusou, requests.RequestException):
            existe = False
        visto = BANCOS_VISTOS[banco] = (existe, agora)
    return visto[0]


def _armazem_da_pericia(request, sessao):
    """Para buscar os eventos selados no armazém: o pacote vê pelo id de onde cada evento veio."""
    if request.app.state.armazem is None:
        return {}
    return {"armazem": request.app.state.armazem, "banco": armazem_de_eventos.banco_do(sessao["cliente_id"])}


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


def _consulta_de_logs(busca, filtros):
    """O que a tela de Logs brutos pede, igual para a lista e para o pacote de perícia: o pacote traz o que a pessoa via."""
    try:
        pedido = linguagem_de_consulta.analisar(busca)
    except linguagem_de_consulta.ConsultaInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    condicoes, exclusoes = _filtros_de_campo(filtros)
    return pedido, condicoes, exclusoes


@app.get("/api/logs")
def logs(request: Request, sessao=Depends(exige(permissoes.VER_BRUTO, mascarar=True)), busca: str = "", dias: int = 7, depois_de: str = "", filtros: str = ""):
    """Logs como chegaram, inclusive os que não viraram alerta. Cada busca fica registrada."""
    dias = max(1, min(dias, 90))
    busca = busca.strip()
    pedido, condicoes, exclusoes = _consulta_de_logs(busca, filtros)
    with do_cliente(request, sessao) as con:
        gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
        onde = _armazem_da_organizacao(request, con, sessao)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'buscar_logs', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], (busca or "*")[:800] + (f" {filtros[:400]}" if filtros else "")))
    if not gerenciadores:
        return {"logs": [], "proximo": None, "total": 0, "linha_do_tempo": [], "campos": {}, "colunas": pedido.colunas, "contagem": None}
    if onde:
        return _logs_do_armazem(onde, pedido, condicoes, exclusoes, dias, depois_de)

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


def _logs_do_armazem(onde, pedido, condicoes, exclusoes, dias, depois_de):
    """A mesma resposta de /api/logs, lida do armazém de eventos."""
    cursor = None
    if depois_de:
        try:
            cursor = json.loads(depois_de)
        except ValueError:
            raise HTTPException(status_code=422)
        if not (isinstance(cursor, list) and len(cursor) == 2 and isinstance(cursor[0], int) and isinstance(cursor[1], str)
                and re.fullmatch(r"[0-9a-f-]{36}", cursor[1])):
            raise HTTPException(status_code=422)
    tamanho = min(pedido.limite, TAMANHO_DA_PAGINA) if pedido.limite else TAMANHO_DA_PAGINA
    try:
        r = leitor_armazem.logs(onde["armazem"], onde["banco"], pedido, condicoes, exclusoes, dias, cursor, tamanho, CAMPOS_DE_LOG, not depois_de)
    except linguagem_de_consulta.ConsultaInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    except armazem_de_eventos.ArmazemRecusou:
        raise HTTPException(status_code=422, detail="Este campo não aceita essa operação. Tente outro campo.")
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Não foi possível consultar os logs.")
    tem_mais = len(r["logs"]) == TAMANHO_DA_PAGINA and not pedido.limite
    return {"logs": r["logs"], "proximo": json.dumps(r["cursor"]) if tem_mais and not pedido.ordem else None, "colunas": pedido.colunas,
            "contagem": r["contagem"], "total": r["total"], "total_exato": r["total_exato"], "linha_do_tempo": r["linha_do_tempo"], "campos": r["campos"]}


class PacoteDePericia(BaseModel):
    busca: str = Field(default="", max_length=2000)
    dias: int = Field(default=7, ge=1, le=90)
    filtros: str = Field(default="", max_length=30000)


@app.post("/api/logs/evidencia")
def pacote_de_pericia(dados: PacoteDePericia, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO))):
    """Tudo o que a busca de Logs brutos acha no período, com a prova de cada log. Sai com dado pessoal: fica na auditoria com o resumo do arquivo."""
    _exige_o_original(sessao)
    busca = dados.busca.strip()
    pedido, condicoes, exclusoes = _consulta_de_logs(busca, dados.filtros)
    if pedido.contar or pedido.contar_por:
        raise HTTPException(status_code=422, detail="Tire a contagem da busca: o pacote leva os logs, não um resumo.")
    with do_cliente(request, sessao) as con:
        gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
        # Só entra o que já foi selado: o último trecho de cada gerenciador ainda está esperando o selo.
        cobertos = {l["gerenciador_id"]: l["ate"] for l in con.execute("SELECT gerenciador_id, max(fim) AS ate FROM selos WHERE fonte = 'logs' GROUP BY 1").fetchall()}
        onde = _armazem_da_organizacao(request, con, sessao)
        selados_no_armazem = {l["gerenciador_id"]: l["ate"] for l in con.execute(
            "SELECT gerenciador_id, max(fim) AS ate FROM selos WHERE fonte = 'logs' AND origem = 'armazem' GROUP BY 1").fetchall()} if onde else {}
    if not gerenciadores:
        raise HTTPException(status_code=404)
    if selados_no_armazem:
        return _pericia_do_armazem(request, sessao, dados, busca, pedido, condicoes, exclusoes, gerenciadores, onde, selados_no_armazem)
    indices = ",".join(f"wazuh-archives-4.x-{g}-*" for g in gerenciadores)
    base = [*condicoes, {"range": {"timestamp": {"gte": f"now-{dados.dias}d"}}}, pedido.filtro]
    selados = {"bool": {"should": [{"bool": {"filter": [{"prefix": {"_index": f"wazuh-archives-4.x-{g}-"}}, {"range": {"timestamp": {"lt": ate.isoformat()}}}]}}
                                   for g, ate in cobertos.items()], "minimum_should_match": 1}} if cobertos else {"match_none": {}}

    def buscar(corpo):
        r = request.app.state.indexer.post(f"{INDEXER_URL}/{indices}/_search?allow_no_indices=true&ignore_unavailable=true", json=corpo, timeout=60)
        if r.status_code == 400:
            raise HTTPException(status_code=422, detail="Este campo não aceita essa operação. Tente outro campo.")
        if not r.ok:
            raise HTTPException(status_code=502, detail="Não foi possível consultar os logs.")
        return r.json()

    todos = buscar({"size": 0, "track_total_hits": True, "query": {"bool": {"filter": base, "must_not": exclusoes}}})["hits"]["total"]["value"]
    ids, cursor = [], None
    while True:
        consulta = {"size": evidencia.LOTE_DE_BUSCA, "_source": False, "sort": [{"timestamp": "asc"}, {"_id": "asc"}], "track_total_hits": False,
                    "query": {"bool": {"filter": [*base, selados], "must_not": exclusoes}}}
        if cursor:
            consulta["search_after"] = cursor
        lote = buscar(consulta)["hits"]["hits"]
        ids.extend(h["_id"] for h in lote)
        if len(ids) > evidencia.LIMITE_DO_PERIODO:
            raise HTTPException(status_code=409, detail=f"A busca acha mais de {evidencia.LIMITE_DO_PERIODO:,} logs. Diminua o período ou refine a busca.".replace(",", "."))
        if len(lote) < evidencia.LOTE_DE_BUSCA:
            break
        cursor = lote[-1]["sort"]
    if not ids:
        raise HTTPException(status_code=409, detail="Nenhum log selado com essa busca nesse período. Os mais recentes são selados em até 30 minutos.")
    descricao = [("Período", f"últimos {dados.dias} {'dia' if dados.dias == 1 else 'dias'}"), ("Busca", busca or "todos os logs"),
                 ("Filtros", dados.filtros or "nenhum"), ("Logs no pacote", f"{len(ids):,}".replace(",", ".")),
                 ("Fora do pacote", f"{todos - len(ids)} log(s) ainda não selado(s), dos últimos minutos" if todos > len(ids) else "nenhum")]
    try:
        with do_cliente(request, sessao) as con:
            pacotes = evidencia.montar_pacotes(con, request.app.state.indexer, INDEXER_URL, gerenciadores, "logs", ids, selagem.ler_chave_publica())
        conteudo = evidencia.gerar_zip_de_varios(pacotes, sessao, relatorios.gerar_pdf, descricao=descricao)
    except evidencia.EvidenciaRecusada as erro:
        raise HTTPException(status_code=409, detail=str(erro))
    resumo = relatorios.resumo_do_arquivo(conteudo)
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'gerar_evidencia_de_periodo', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{dados.dias}d {(busca or '*')[:300]} {dados.filtros[:300]} {len(ids)} logs sha256:{resumo}"))
    nome = f"pericia-roar-{datetime.now(timezone.utc):%Y%m%d-%H%M}.zip"
    return Response(conteudo, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{nome}"', "X-Resumo-SHA256": resumo,
                                                                    "X-Logs": str(len(ids)), "X-Fora-Do-Pacote": str(todos - len(ids))})


def _pericia_do_armazem(request, sessao, dados, busca, pedido, condicoes, exclusoes, gerenciadores, onde, selados):
    """O mesmo pacote de perícia, com os logs e os selos do armazém de eventos."""
    try:
        ids, todos = leitor_armazem.ids_para_pericia(onde["armazem"], onde["banco"], pedido, condicoes, exclusoes, dados.dias, selados, evidencia.LIMITE_DO_PERIODO)
    except linguagem_de_consulta.ConsultaInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    if len(ids) > evidencia.LIMITE_DO_PERIODO:
        raise HTTPException(status_code=409, detail=f"A busca acha mais de {evidencia.LIMITE_DO_PERIODO:,} logs. Diminua o período ou refine a busca.".replace(",", "."))
    if not ids:
        raise HTTPException(status_code=409, detail="Nenhum log selado com essa busca nesse período. Os mais recentes são selados em até 30 minutos.")
    descricao = [("Período", f"últimos {dados.dias} {'dia' if dados.dias == 1 else 'dias'}"), ("Busca", busca or "todos os logs"),
                 ("Filtros", dados.filtros or "nenhum"), ("Logs no pacote", f"{len(ids):,}".replace(",", ".")),
                 ("Fora do pacote", f"{todos - len(ids)} log(s) ainda não selado(s), dos últimos minutos" if todos > len(ids) else "nenhum")]
    try:
        with do_cliente(request, sessao) as con:
            pacotes = evidencia.montar_pacotes(con, request.app.state.indexer, INDEXER_URL, gerenciadores, "logs", ids, selagem.ler_chave_publica(),
                                               armazem=onde["armazem"], banco=onde["banco"])
        conteudo = evidencia.gerar_zip_de_varios(pacotes, sessao, relatorios.gerar_pdf, descricao=descricao)
    except evidencia.EvidenciaRecusada as erro:
        raise HTTPException(status_code=409, detail=str(erro))
    resumo = relatorios.resumo_do_arquivo(conteudo)
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'gerar_evidencia_de_periodo', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{dados.dias}d {(busca or '*')[:300]} {dados.filtros[:300]} {len(ids)} logs sha256:{resumo}"))
    nome = f"pericia-roar-{datetime.now(timezone.utc):%Y%m%d-%H%M}.zip"
    return Response(conteudo, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{nome}"', "X-Resumo-SHA256": resumo,
                                                                    "X-Logs": str(len(ids)), "X-Fora-Do-Pacote": str(todos - len(ids))})


@app.get("/api/ativos")
def ativos(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            """SELECT a.gerenciador_id, a.agente_id, a.nome, a.ip, a.sistema, a.versao, a.estado, a.grupos, a.ultima_conexao, a.sca_politica,
                      a.sca_nota, a.sca_aprovados, a.sca_reprovados, a.criticidade,
                      (SELECT count(*) FROM eventos e WHERE e.gerenciador_id = a.gerenciador_id AND e.agente_id = a.agente_id
                        AND e.nivel >= %s AND e.ocorrido_em >= now() - interval '7 days') AS alertas_7_dias
               FROM ativos a WHERE a.agente_id <> '000' ORDER BY a.nome""", (NIVEL_MINIMO_NA_FILA,)).fetchall()
        riscos, sem_agente = risco_de_ativos.calcular(con)
    vazio = risco_de_ativos.nota()
    return {"ativos": [{**a, "risco": riscos.get((a["gerenciador_id"], a["agente_id"]), vazio)} for a in linhas], "sem_agente": sem_agente}


@app.put("/api/ativos/criticidade", status_code=204)
def definir_criticidade(dados: CriticidadeDoAtivo, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    """Muda quanto pesa todo sinal de comportamento que acontece no ativo, a partir de agora."""
    with do_cliente(request, sessao) as con:
        ativo = con.execute("UPDATE ativos SET criticidade = %s WHERE gerenciador_id = %s AND agente_id = %s RETURNING nome",
                            (dados.criticidade, dados.gerenciador_id, dados.agente_id)).fetchone()
        if not ativo:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'definir_criticidade', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{ativo['nome'] or dados.agente_id} {dados.criticidade}"))


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
def tecnica_mitre(tecnica: str, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), dias: int = 30):
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


NORMAS_CONHECIDAS = catalogo_de_normas.NORMAS


@app.get("/api/normas")
def normas(request: Request, sessao=Depends(exige(permissoes.VER)), norma: str = "lgpd", dias: int = 30):
    """Alertas por controle da norma, como o Wazuh já os marca em cada regra."""
    if norma not in NORMAS_CONHECIDAS:
        raise HTTPException(status_code=422)
    dias = max(1, min(dias, 90))
    with do_cliente(request, sessao) as con:
        controles = catalogo_de_normas.controles_com_alerta(con, norma, dias)
        regras_da_norma = catalogo_de_normas.regras_da_norma(con, norma)
    for c in controles:
        del c["regras"]
    chave, mapa = catalogo_de_normas.origem(norma)
    # A gaveta procura as regras pela marcação que vem nelas: a da LGPD é a do GDPR.
    return {"norma": norma, "chave": chave, "normas": NORMAS_CONHECIDAS, "controles": controles, "regras_da_norma": regras_da_norma,
            "derivada_de": catalogo_de_normas.NOMES_DA_ORIGEM.get(chave, chave) if mapa else None, "explicacao": catalogo_de_normas.EXPLICACOES.get(norma),
            "so_pelas_checagens": norma in catalogo_de_normas.SO_PELAS_CHECAGENS}


@app.get("/api/normas/relatorio")
def relatorio_da_norma(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), norma: str = "pci_dss", dias: int = 90, formato: str = "pdf"):
    """Evidência para a auditoria de uma norma. Toda geração fica registrada, com o resumo do arquivo."""
    if norma not in NORMAS_CONHECIDAS or formato not in ("pdf", "json"):
        raise HTTPException(status_code=422, detail="Norma ou formato desconhecido.")
    dias = max(1, min(dias, 365))
    with do_cliente(request, sessao) as con:
        dados = relatorios.coletar_norma(con, norma, dias)
    mascara = getattr(request.state, "mascara", None)
    if mascara:
        dados = mascara.dado(dados)
        request.state.mascara = None
    if formato == "json":
        conteudo, tipo_midia = relatorios.dados_em_json(dados), "application/json"
    else:
        conteudo, tipo_midia = relatorios.gerar_pdf(relatorios.montar_html_da_norma(dados, sessao, norma, dias)), "application/pdf"
    resumo = relatorios.resumo_do_arquivo(conteudo)
    nome = f"relatorio-{norma.replace('_', '-')}-{datetime.now(timezone.utc):%Y%m%d}.{formato}"
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'gerar_relatorio_de_norma', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{norma} {dias}d {formato} sha256:{resumo}"))
        guardado = _guardar_relatorio(con, sessao, "norma", norma, dias, formato, nome, conteudo, resumo)
    return Response(conteudo, media_type=tipo_midia, headers={"Content-Disposition": f'attachment; filename="{nome}"', "X-Resumo-SHA256": resumo, "X-Relatorio": str(guardado)})


@app.get("/api/arquivos")
def arquivos(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), dias: int = 30, busca: str = "", mudanca: str = ""):
    """Mudanças em arquivos monitorados."""
    dias = max(1, min(dias, 90))
    condicao, parametros = "", [dias]
    busca = busca.strip()[:200]
    if busca:
        condicao = "AND (bruto #>> '{syscheck,path}' ILIKE %s OR agente_nome ILIKE %s)"
        termo = f"%{_sem_curinga(busca)}%"
        parametros += [termo, termo]
    if mudanca in ("added", "modified", "deleted"):
        condicao += " AND bruto #>> '{syscheck,event}' = %s"
        parametros.append(mudanca)
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            f"""SELECT id, ocorrido_em, severidade, agente_nome AS ativo, regra_descricao,
                       bruto #>> '{{syscheck,path}}' AS caminho, bruto #>> '{{syscheck,event}}' AS mudanca,
                       bruto #>> '{{syscheck,sha256_after}}' AS sha256, bruto #>> '{{syscheck,uname_after}}' AS dono
                FROM eventos WHERE 'syscheck' = ANY(regra_grupos) AND ocorrido_em >= now() - make_interval(days => %s) {condicao}
                ORDER BY id DESC LIMIT %s""", (*parametros, TAMANHO_DA_PAGINA)).fetchall()
    return {"arquivos": linhas}


def _guardar_relatorio(con, sessao, tipo, norma, dias, formato, nome, conteudo, resumo):
    return con.execute(
        """INSERT INTO relatorios_gerados (cliente_id, tipo, norma, dias, formato, nome, conteudo, tamanho, sha256, mascarado, gerado_por, gerado_por_nome)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (sessao["cliente_id"], tipo, norma, dias, formato, nome, conteudo, len(conteudo), resumo, _ve_mascarado(sessao),
         sessao["usuario_id"], sessao["nome"])).fetchone()["id"]


def _pode_apagar_relatorio(sessao, relatorio):
    return relatorio["gerado_por"] == sessao["usuario_id"] or permissoes.pode(sessao["perfil"], permissoes.GERIR_USUARIOS)


class NovaChave(BaseModel):
    nome: str = Field(min_length=1, max_length=80)
    perfil: str = Field(pattern="^(analista_n1|analista_n2|engenharia|auditor)$")
    dias: int | None = Field(default=None, ge=1, le=730)


@app.get("/api/chaves")
def chaves_de_api(request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    with do_cliente(request, sessao) as con:
        linhas = con.execute("""SELECT id, nome, prefixo, perfil, criada_em, expira_em, ultima_vez, revogada_em,
                                       coalesce(roar_nome_do_usuario(usuario_id), 'Removida') AS dono,
                                       CASE WHEN revogada_em IS NOT NULL THEN 'revogada' WHEN expira_em <= now() THEN 'vencida' ELSE 'ativa' END AS estado
                                FROM chaves_api ORDER BY revogada_em IS NOT NULL, criada_em DESC""").fetchall()
    return {"chaves": linhas}


@app.post("/api/chaves", status_code=201)
def criar_chave_de_api(dados: NovaChave, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    """O segredo sai só nesta resposta. Depois, nem o administrador vê de novo: perdeu, revoga e cria outra."""
    nome = dados.nome.strip()
    if not nome:
        raise HTTPException(status_code=422, detail="Dê um nome à chave.")
    prefixo = secrets.token_hex(4)
    token = f"{PREFIXO_DA_CHAVE}{prefixo}_{secrets.token_urlsafe(32)}"
    expira = datetime.now(timezone.utc) + timedelta(days=dados.dias) if dados.dias else None
    with do_cliente(request, sessao) as con:
        identificador = con.execute(
            """INSERT INTO chaves_api (cliente_id, usuario_id, nome, prefixo, resumo, perfil, expira_em) VALUES (%s, %s, %s, %s, %s, %s, %s)
               RETURNING id""", (sessao["cliente_id"], sessao["usuario_id"], nome, prefixo, _hash_do_token(token), dados.perfil, expira)).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_chave_de_api', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{identificador} {nome} {dados.perfil}"))
    return {"id": identificador, "chave": token, "prefixo": prefixo, "expira_em": expira}


@app.delete("/api/chaves/{identificador}", status_code=204)
def revogar_chave_de_api(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        chave = con.execute("UPDATE chaves_api SET revogada_em = now() WHERE id = %s AND revogada_em IS NULL RETURNING nome", (identificador,)).fetchone()
        if not chave:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'revogar_chave_de_api', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{identificador} {chave['nome']}"))


def _permissao_da_rota(rota):
    return next((d.call.permissao for d in rota.dependant.dependencies if hasattr(d.call, "permissao")), None)


def openapi_publico():
    """Só o que uma chave alcança: rota de dado com permissão, menos as de administrar pessoas e chaves."""
    rotas = [r for r in app.routes if isinstance(r, APIRoute) and r.path.startswith("/api/")
             and _permissao_da_rota(r) not in (None, permissoes.GERIR_USUARIOS) and modulos.rota_liberada(r.path, MODULOS)]
    documento = get_openapi(
        title="Panthera Roar", version="1", routes=rotas,
        description="API do Panthera Roar. Autentique com uma chave criada em API, no menu: `Authorization: Bearer roar_...`. "
                    "A chave age com o perfil escolhido, só na organização em que foi criada, e respeita o mascaramento de dado pessoal.")
    documento.setdefault("components", {})["securitySchemes"] = {"chave": {"type": "http", "scheme": "bearer"}}
    documento["security"] = [{"chave": []}]
    for rota in rotas:
        for metodo in rota.methods:
            operacao = documento["paths"].get(rota.path, {}).get(metodo.lower())
            if operacao is not None:
                operacao["x-permissao"] = _permissao_da_rota(rota)
                operacao["tags"] = [rota.path.split("/")[2]]
    return documento


@app.get("/api/openapi.json")
def documentacao_da_api(request: Request, sessao=Depends(exige(permissoes.VER))):
    if not hasattr(request.app.state, "openapi_publico"):
        request.app.state.openapi_publico = openapi_publico()
    return request.app.state.openapi_publico


@app.get("/api/relatorios/historico")
def historico_de_relatorios(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        linhas = con.execute("""SELECT id, tipo, norma, dias, formato, nome, tamanho, sha256, mascarado, gerado_por, gerado_por_nome, gerado_em
                                FROM relatorios_gerados ORDER BY gerado_em DESC, id DESC LIMIT 500""").fetchall()
    mascarado = _ve_mascarado(sessao)
    for l in linhas:
        l["pode_apagar"] = _pode_apagar_relatorio(sessao, l)
        # Quem vê mascarado não baixa o que saiu sem máscara.
        l["pode_baixar"] = l["mascarado"] or not mascarado
        l["norma_nome"] = (NORMAS_CONHECIDAS.get(l["norma"]) or l["norma"]) if l["norma"] else None
        del l["gerado_por"]
    return {"relatorios": linhas}


@app.get("/api/relatorios/historico/{identificador}")
def baixar_relatorio_guardado(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        r = con.execute("SELECT nome, formato, conteudo, sha256, mascarado FROM relatorios_gerados WHERE id = %s", (identificador,)).fetchone()
        if not r:
            raise HTTPException(status_code=404)
        if not r["mascarado"] and _ve_mascarado(sessao):
            raise HTTPException(status_code=403, detail="Este relatório saiu sem máscara, e o seu perfil vê dado pessoal mascarado.")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'baixar_relatorio', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{r['nome']} sha256:{r['sha256']}"))
    return Response(bytes(r["conteudo"]), media_type="application/pdf" if r["formato"] == "pdf" else "application/json",
                    headers={"Content-Disposition": f'attachment; filename="{r["nome"]}"', "X-Resumo-SHA256": r["sha256"]})


@app.delete("/api/relatorios/historico/{identificador}", status_code=204)
def apagar_relatorio_guardado(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER))):
    """Quem gerou apaga o seu; o administrador apaga qualquer um. A auditoria guarda o nome e o resumo do que saiu."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        r = con.execute("SELECT nome, sha256, gerado_por FROM relatorios_gerados WHERE id = %s", (identificador,)).fetchone()
        if not r:
            raise HTTPException(status_code=404)
        if not _pode_apagar_relatorio(sessao, r):
            raise HTTPException(status_code=403, detail="Só quem gerou o relatório ou o administrador pode apagar.")
        con.execute("DELETE FROM relatorios_gerados WHERE id = %s", (identificador,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'apagar_relatorio', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{r['nome']} sha256:{r['sha256']}"))


@app.get("/api/relatorios")
def gerar_relatorio(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), dias: int = 30, tipo: str = "completo", formato: str = "pdf"):
    """Reúne nomes e endereços em um arquivo que sai do sistema: toda geração fica registrada, com o resumo do arquivo."""
    if tipo not in ("completo", "executivo") or formato not in ("pdf", "json"):
        raise HTTPException(status_code=422, detail="Tipo ou formato desconhecido.")
    dias = max(1, min(dias, 365))
    with do_cliente(request, sessao) as con:
        dados = relatorios.coletar(con, dias)
    mascara = getattr(request.state, "mascara", None)
    if mascara:
        # O PDF não passa pela máscara da resposta: os dados são mascarados antes de virar página.
        dados = mascara.dado(dados)
        request.state.mascara = None
    if formato == "json":
        conteudo, tipo_midia, extensao = relatorios.dados_em_json(dados), "application/json", "json"
    else:
        conteudo, tipo_midia, extensao = relatorios.gerar_pdf(relatorios.montar_html(dados, sessao, dias, tipo)), "application/pdf", "pdf"
    resumo = relatorios.resumo_do_arquivo(conteudo)
    nome = f"relatorio-{tipo}-{datetime.now(timezone.utc):%Y%m%d}.{extensao}"
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'gerar_relatorio', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{tipo} {dias}d {extensao} sha256:{resumo}"))
        guardado = _guardar_relatorio(con, sessao, tipo, None, dias, extensao, nome, conteudo, resumo)
    return Response(conteudo, media_type=tipo_midia, headers={"Content-Disposition": f'attachment; filename="{nome}"', "X-Resumo-SHA256": resumo, "X-Relatorio": str(guardado)})


class PedidoDeEvidencia(BaseModel):
    fonte: str = Field(pattern="^(alertas|logs)$")
    ids: list[str] = Field(min_length=1, max_length=evidencia.LIMITE_DE_EVENTOS)


@app.get("/api/integridade")
def integridade(request: Request, sessao=Depends(exige(permissoes.VER))):
    """Se a cadeia está de pé. Mostra identificador de evento, nunca o conteúdo: quem vê isto pode não ter acesso ao log."""
    with do_cliente(request, sessao) as con:
        selos = con.execute("""SELECT count(*) AS selos, coalesce(sum(total), 0) AS eventos, count(*) FILTER (WHERE tardio) AS tardios,
                                      max(selado_em) AS ultimo, max(fim) AS coberto_ate FROM selos""").fetchone()
        ultima = con.execute("SELECT quando, completa, selos_conferidos, eventos_conferidos, estado, achados FROM selo_verificacoes ORDER BY quando DESC, id DESC LIMIT 1").fetchone()
        ancoras = con.execute("SELECT count(*) AS total, max(criada_em) AS ultima FROM selo_ancoras").fetchone()
    try:
        publica = selagem.ler_chave_publica()
    except OSError:
        publica = None
    return {"selos": selos, "verificacao": ultima, "ancoras": ancoras, "impressao": selagem.impressao_da_chave(publica) if publica else None}


@app.post("/api/integridade/evidencia")
def gerar_evidencia(dados: PedidoDeEvidencia, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO))):
    """Sai do sistema com dado pessoal: quem gerou, quais eventos e o resumo do arquivo ficam na auditoria."""
    _exige_o_original(sessao)
    ids = list(dict.fromkeys(dados.ids))
    if any(not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", i) for i in ids):
        raise HTTPException(status_code=422, detail="Identificador de evento inválido.")
    try:
        with do_cliente(request, sessao) as con:
            gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
            if not gerenciadores:
                raise HTTPException(status_code=404)
            pacote, ancoras = evidencia.montar_pacote(con, request.app.state.indexer, INDEXER_URL, gerenciadores, dados.fonte, ids, selagem.ler_chave_publica(),
                                                      **_armazem_da_pericia(request, sessao))
        conteudo = evidencia.gerar_zip(pacote, ancoras, sessao, relatorios.gerar_pdf)
    except evidencia.EvidenciaRecusada as erro:
        raise HTTPException(status_code=409, detail=str(erro))
    resumo = relatorios.resumo_do_arquivo(conteudo)
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'gerar_evidencia', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{dados.fonte} {' '.join(ids)[:600]} sha256:{resumo}"))
    return Response(conteudo, media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="evidencia-roar.zip"', "X-Resumo-SHA256": resumo})


TAMANHO_DA_TRILHA = 100


def _consultar_trilha(con, dias, acao, pessoa, antes_de, limite):
    condicoes, valores = ["em >= now() - make_interval(days => %s)"], [max(1, min(dias, 3650))]
    if acao:
        condicoes.append("acao = %s")
        valores.append(acao[:80])
    if pessoa:
        condicoes.append("usuario_id = %s")
        valores.append(pessoa)
    if antes_de:
        condicoes.append("id < %s")
        valores.append(antes_de)
    return con.execute(f"SELECT id, em, usuario_id, acao, alvo, origem FROM auditoria WHERE {' AND '.join(condicoes)} ORDER BY id DESC LIMIT %s", (*valores, limite)).fetchall()


def _nomes_das_pessoas(con):
    nomes = {u["id"]: u["nome"] for u in con.execute("SELECT id, nome FROM roar_listar_usuarios()").fetchall()}
    nomes.update({u["id"]: f"{u['nome']} (administração da instalação)" for u in con.execute("SELECT id, nome FROM roar_pessoas_de_fora()").fetchall()})
    return nomes


@app.get("/api/auditoria")
def trilha(request: Request, sessao=Depends(exige(permissoes.VER_AUDITORIA)), dias: int = 30, acao: str = "", pessoa: uuid.UUID | None = None, antes_de: int | None = None):
    with do_cliente(request, sessao) as con:
        linhas = _consultar_trilha(con, dias, acao, pessoa, antes_de, TAMANHO_DA_TRILHA + 1)
        nomes = _nomes_das_pessoas(con)
        acoes = [a["acao"] for a in con.execute("SELECT DISTINCT acao FROM auditoria ORDER BY acao").fetchall()]
    tem_mais = len(linhas) > TAMANHO_DA_TRILHA
    linhas = linhas[:TAMANHO_DA_TRILHA]
    return {"linhas": [{**l, "pessoa": nomes.get(l["usuario_id"])} for l in linhas], "acoes": acoes, "pessoas": [{"id": i, "nome": n} for i, n in nomes.items()],
            "proximo": linhas[-1]["id"] if tem_mais else None}


def _celula_segura(valor):
    """Planilha executa célula que começa assim, e o alvo pode ter sido escrito por quem tentou entrar."""
    texto = "" if valor is None else str(valor)
    return f"'{texto}" if texto[:1] in ("=", "+", "-", "@", "\t", "\r") else texto


@app.get("/api/auditoria/exportar")
def exportar_trilha(request: Request, sessao=Depends(exige(permissoes.VER_AUDITORIA)), dias: int = 30, acao: str = "", pessoa: uuid.UUID | None = None):
    with do_cliente(request, sessao) as con:
        linhas = _consultar_trilha(con, dias, acao, pessoa, None, 100000)
        nomes = _nomes_das_pessoas(con)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'exportar_auditoria', %s)", (sessao["cliente_id"], sessao["usuario_id"], f"{dias}d {len(linhas)} linhas"))
    saida = io.StringIO()
    escritor = csv.writer(saida)
    escritor.writerow(["quando", "acao", "pessoa", "alvo", "origem"])
    for l in linhas:
        escritor.writerow([l["em"].isoformat(), *(_celula_segura(v) for v in (l["acao"], nomes.get(l["usuario_id"], ""), l["alvo"], l["origem"]))])
    return Response(saida.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="auditoria-roar.csv"'})


@app.get("/api/notificacoes")
def notificacoes(request: Request, sessao=Depends(exige(permissoes.VER_AUDITORIA))):
    with do_cliente(request, sessao) as con:
        return {"avisos": con.execute("SELECT id, tipo, alvo, origem, contagem, criada_em, atualizada_em FROM notificacoes WHERE lida_em IS NULL ORDER BY atualizada_em DESC LIMIT 50").fetchall()}


@app.post("/api/notificacoes/{identificador}/lida", status_code=204)
def marcar_notificacao(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER_AUDITORIA))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        con.execute("UPDATE notificacoes SET lida_em = now(), lida_por = %s WHERE id = %s AND lida_em IS NULL", (sessao["usuario_id"], identificador))


@app.post("/api/notificacoes/lidas", status_code=204)
def marcar_notificacoes(request: Request, sessao=Depends(exige(permissoes.VER_AUDITORIA))):
    with do_cliente(request, sessao) as con:
        con.execute("UPDATE notificacoes SET lida_em = now(), lida_por = %s WHERE lida_em IS NULL", (sessao["usuario_id"],))


SEVERIDADES = ("critica", "alta", "media", "baixa", "informativa")
ACHADOS_POR_PAGINA = 100
# A prioridade vem da base de CVEs: a falha mais urgente entre as que o achado cita.
PRIORIDADE_DO_ACHADO = """(SELECT c.prioridade FROM cves c WHERE c.cve = ANY(a.cves)
                          ORDER BY array_position(ARRAY['agora', 'alta', 'media', 'baixa', 'sem_dados'], c.prioridade) LIMIT 1) AS prioridade"""


class NovoModelo(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    ferramenta: str = Field(pattern="^(rede|web|conteiner|nuvem)$")
    intrusiva: bool = False
    todas_portas: bool = False


class NovoAlvo(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    hosts: list[str] = Field(min_length=1, max_length=256)
    modelo_id: int
    a_cada_dias: int = Field(default=30, ge=0, le=365)
    credencial_tipo: str | None = Field(default=None, pattern="^(ssh|smb|snmp)$")
    credencial_usuario: str | None = Field(default=None, max_length=120)
    credencial_senha: str | None = Field(default=None, max_length=4096)


class PedidoDeVarredura(BaseModel):
    alvo_id: int


class MudancaDeAchado(BaseModel):
    estado: str = Field(pattern="^(aberto|correcao_informada|aceito|falso_positivo)$")
    motivo: str = Field(default="", max_length=1000)


class MudancaDeAtivo(BaseModel):
    peso: int = Field(ge=1, le=5)


class PrazosDeCorrecao(BaseModel):
    critica: int = Field(ge=1, le=730)
    alta: int = Field(ge=1, le=730)
    media: int = Field(ge=1, le=730)
    baixa: int = Field(ge=1, le=730)
    explorada: int = Field(ge=1, le=730)


@app.get("/api/vuln/correcao")
def correcao_de_vulnerabilidades(request: Request, sessao=Depends(exige(permissoes.VER)), dias: int = 90):
    """Prazos, vencidos, idade dos abertos, tempo para corrigir e o que corrigir primeiro."""
    with do_cliente(request, sessao) as con:
        return correcao.indicadores(con, max(7, min(dias, 730)))


@app.put("/api/vuln/prazos", status_code=204)
def definir_prazos_de_correcao(dados: PrazosDeCorrecao, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    with do_cliente(request, sessao) as con:
        valores = dados.model_dump()
        con.execute(f"""INSERT INTO vuln_prazos (cliente_id, {", ".join(valores)}, definido_por) VALUES (%s, {", ".join(["%s"] * len(valores))}, %s)
                        ON CONFLICT (cliente_id) DO UPDATE SET {", ".join(f"{k} = EXCLUDED.{k}" for k in valores)}, definido_por = EXCLUDED.definido_por, definido_em = now()""",
                    (sessao["cliente_id"], *valores.values(), sessao["usuario_id"]))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'definir_prazos_de_correcao', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], ", ".join(f"{k} {v}" for k, v in valores.items())))


@app.get("/api/vuln/indicadores")
def indicadores_de_vulnerabilidades(request: Request, sessao=Depends(exige(permissoes.VER)), dias: int = 90):
    """Descoberta, priorização e remediação, com a conta aberta para quem quiser refazer."""
    dias = max(7, min(dias, 730))
    with do_cliente(request, sessao) as con:
        abertos = {l["severidade"]: l["n"] for l in con.execute("SELECT severidade, count(*) AS n FROM vuln_achados WHERE estado IN ('aberto', 'correcao_informada') GROUP BY 1").fetchall()}
        exposicao = con.execute(f"""SELECT coalesce(sum(t.peso * CASE a.severidade {" ".join(f"WHEN '{s}' THEN {p}" for s, p in vulnerabilidades.PONTOS.items())} END), 0) AS pontos, count(DISTINCT a.ativo_id) AS ativos
                                    FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id WHERE a.estado IN ('aberto', 'correcao_informada')""").fetchone()
        urgentes = con.execute(f"SELECT count(*) AS n FROM (SELECT {PRIORIDADE_DO_ACHADO} FROM vuln_achados a WHERE a.estado IN ('aberto', 'correcao_informada')) x WHERE prioridade = 'agora'").fetchone()["n"]
        remediacao = con.execute("""SELECT count(*) FILTER (WHERE primeira_vez >= now() - make_interval(days => %(d)s)) AS descobertos,
                                           count(*) FILTER (WHERE estado = 'corrigido' AND corrigido_em >= now() - make_interval(days => %(d)s)) AS corrigidos,
                                           count(*) FILTER (WHERE estado IN ('aceito', 'falso_positivo')) AS aceitos,
                                           extract(epoch FROM avg(corrigido_em - primeira_vez) FILTER (WHERE estado = 'corrigido' AND corrigido_em >= now() - make_interval(days => %(d)s))) / 86400 AS dias_para_corrigir
                                    FROM vuln_achados""", {"d": dias}).fetchone()
        # Reconstituído da história, e não de uma foto: inclui o que voltou depois de corrigido.
        evolucao = con.execute("""WITH dias AS (SELECT generate_series(date_trunc('day', now()) - make_interval(days => %s), date_trunc('day', now()), interval '1 day') AS dia),
                                  ultimo AS (SELECT d.dia, h.achado_id, (array_agg(h.para ORDER BY h.quando DESC, h.id DESC))[1] AS estado
                                             FROM dias d JOIN vuln_historico h ON h.quando < d.dia + interval '1 day' GROUP BY 1, 2)
                                  SELECT d.dia, count(u.achado_id) FILTER (WHERE u.estado IN ('aberto', 'correcao_informada')) AS abertos FROM dias d LEFT JOIN ultimo u USING (dia) GROUP BY 1 ORDER BY 1""", (min(dias, 90),)).fetchall()
        ultima = con.execute("SELECT max(terminada_em) AS em FROM vuln_varreduras WHERE estado = 'concluida'").fetchone()["em"]
    return {"abertos": {s: abertos.get(s, 0) for s in SEVERIDADES}, "exposicao": exposicao["pontos"], "ativos_expostos": exposicao["ativos"], "urgentes": urgentes,
            "descobertos": remediacao["descobertos"], "corrigidos": remediacao["corrigidos"], "aceitos": remediacao["aceitos"],
            "dias_para_corrigir": round(float(remediacao["dias_para_corrigir"]), 1) if remediacao["dias_para_corrigir"] is not None else None,
            "evolucao": evolucao, "ultima_varredura": ultima, "periodo": dias, "pontos": vulnerabilidades.PONTOS}


def _filtros_de_achado(severidade, estado, ativo, busca):
    condicoes, valores = [], []
    if severidade in SEVERIDADES:
        condicoes.append("a.severidade = %s")
        valores.append(severidade)
    if estado == "aberto":
        # Correção informada ainda não foi provada: continua entre os abertos, com a situação à vista.
        condicoes.append("a.estado IN ('aberto', 'correcao_informada')")
    elif estado in ("correcao_informada", "corrigido", "aceito", "falso_positivo"):
        condicoes.append("a.estado = %s")
        valores.append(estado)
    if ativo:
        condicoes.append("a.ativo_id = %s")
        valores.append(ativo)
    busca = busca.strip()[:200]
    if busca:
        # A chave traz o pacote: buscar pelo pacote acha todas as falhas dele.
        condicoes.append("(a.titulo ILIKE %s OR t.host ILIKE %s OR t.nome ILIKE %s OR a.chave ILIKE %s OR %s = ANY(a.cves))")
        padrao = "%" + busca.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        valores.extend([padrao, padrao, padrao, padrao, busca.upper()])
    return (" WHERE " + " AND ".join(condicoes)) if condicoes else "", valores


CONSULTA_DE_ACHADOS = f"""SELECT a.id, a.ativo_id, t.host, t.nome AS ativo, t.peso, a.fonte, a.titulo, a.cves, a.cvss, a.severidade, a.porta, a.estado, a.primeira_vez, a.ultima_vez, a.corrigido_em, {PRIORIDADE_DO_ACHADO},
                                {correcao.VENCE_EM} AS vence_em
                         FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id {correcao.JUNTAR_PRAZOS}"""
ORDEM_DE_ACHADOS = "ORDER BY array_position(ARRAY['aberto', 'correcao_informada', 'aceito', 'falso_positivo', 'corrigido'], a.estado), array_position(ARRAY['critica', 'alta', 'media', 'baixa', 'informativa'], a.severidade), t.peso DESC, a.id DESC"


@app.get("/api/vuln/achados")
def achados_de_vulnerabilidade(request: Request, sessao=Depends(exige(permissoes.VER)), severidade: str = "", estado: str = "aberto", ativo: int | None = None, busca: str = "", deslocamento: int = 0):
    onde, valores = _filtros_de_achado(severidade, estado, ativo, busca)
    with do_cliente(request, sessao) as con:
        linhas = con.execute(f"{CONSULTA_DE_ACHADOS}{onde} {ORDEM_DE_ACHADOS} LIMIT %s OFFSET %s", (*valores, ACHADOS_POR_PAGINA + 1, max(0, deslocamento))).fetchall()
    return {"achados": linhas[:ACHADOS_POR_PAGINA], "tem_mais": len(linhas) > ACHADOS_POR_PAGINA}


@app.get("/api/vuln/achados/exportar")
def exportar_achados(request: Request, sessao=Depends(exige(permissoes.VER)), severidade: str = "", estado: str = "aberto", ativo: int | None = None, busca: str = "",
                     formato: str = "csv"):
    if formato not in ("csv", "xml"):
        raise HTTPException(status_code=422)
    onde, valores = _filtros_de_achado(severidade, estado, ativo, busca)
    with do_cliente(request, sessao) as con:
        linhas = con.execute(f"{CONSULTA_DE_ACHADOS}{onde} {ORDEM_DE_ACHADOS} LIMIT 100000", valores).fetchall()
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'exportar_vulnerabilidades', %s)", (sessao["cliente_id"], sessao["usuario_id"], f"{len(linhas)} linhas"))
    colunas = ("host", "ativo", "titulo", "severidade", "cvss", "prioridade", "estado", "porta", "fonte")
    if formato == "xml":
        # Montado pela biblioteca, nunca colando texto: título e ativo podem ter vindo de quem foi varrido.
        raiz = ElementoXml("vulnerabilidades", {"gerado_em": datetime.now(timezone.utc).isoformat(), "total": str(len(linhas))})
        for l in linhas:
            item = SubElementoXml(raiz, "achado", {"id": str(l["id"])})
            for c in (*colunas, "primeira_vez", "ultima_vez", "corrigido_em"):
                valor = l[c]
                SubElementoXml(item, c).text = "" if valor is None else (valor.isoformat() if hasattr(valor, "isoformat") else str(valor))
            lista = SubElementoXml(item, "cves")
            for cve in l["cves"]:
                SubElementoXml(lista, "cve").text = cve
        return Response(xml_em_texto(raiz, encoding="utf-8", xml_declaration=True), media_type="application/xml",
                        headers={"Content-Disposition": 'attachment; filename="vulnerabilidades-roar.xml"'})
    saida = io.StringIO()
    escritor = csv.writer(saida)
    escritor.writerow([*colunas, "cves", "primeira_vez", "ultima_vez", "corrigido_em"])
    for l in linhas:
        escritor.writerow([*(_celula_segura(l[c]) for c in colunas), " ".join(l["cves"]), l["primeira_vez"].isoformat(), l["ultima_vez"].isoformat(), l["corrigido_em"].isoformat() if l["corrigido_em"] else ""])
    return Response(saida.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="vulnerabilidades-roar.csv"'})


@app.get("/api/vuln/achados/{identificador}")
def detalhe_de_achado(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        achado = con.execute(f"""SELECT a.*, t.host, t.nome AS ativo, t.peso, {PRIORIDADE_DO_ACHADO} FROM vuln_achados a JOIN vuln_ativos t ON t.id = a.ativo_id WHERE a.id = %s""", (identificador,)).fetchone()
        if not achado:
            raise HTTPException(status_code=404)
        nomes = _nomes_das_pessoas(con) if permissoes.pode(sessao["perfil"], permissoes.GERIR_USUARIOS) else {}
        historico = con.execute("SELECT quando, de, para, por, varredura_id, motivo FROM vuln_historico WHERE achado_id = %s ORDER BY quando DESC, id DESC", (identificador,)).fetchall()
    return {**achado, "historico": [{**h, "por": nomes.get(h["por"], "Pessoa da equipe") if h["por"] else None} for h in historico]}


@app.post("/api/vuln/achados/{identificador}/estado", status_code=204)
def mudar_estado_de_achado(identificador: int, dados: MudancaDeAchado, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    """Ninguém marca como corrigido na mão: a pessoa informa, e quem prova a correção é a varredura."""
    _inteiro_valido(identificador)
    motivo = dados.motivo.strip()
    if dados.estado != "aberto" and len(motivo) < 10:
        raise HTTPException(status_code=422, detail="Explique o que foi feito ou decidido, com pelo menos 10 caracteres: isso fica no histórico.")
    with do_cliente(request, sessao) as con:
        achado = con.execute("SELECT estado FROM vuln_achados WHERE id = %s FOR UPDATE", (identificador,)).fetchone()
        if not achado:
            raise HTTPException(status_code=404)
        if achado["estado"] == "corrigido":
            raise HTTPException(status_code=409, detail="Este achado já foi corrigido segundo a última varredura.")
        if achado["estado"] != dados.estado:
            con.execute("UPDATE vuln_achados SET estado = %s WHERE id = %s", (dados.estado, identificador))
            con.execute("INSERT INTO vuln_historico (cliente_id, achado_id, de, para, por, motivo) VALUES (%s, %s, %s, %s, %s, %s)",
                        (sessao["cliente_id"], identificador, achado["estado"], dados.estado, sessao["usuario_id"], motivo or None))
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'mudar_achado', %s)", (sessao["cliente_id"], sessao["usuario_id"], f"{identificador} {dados.estado}"))


@app.post("/api/vuln/achados/{identificador}/confirmar", status_code=201)
def confirmar_correcao(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    """Varre de novo o alvo que encontrou o achado, com o mesmo modelo: é o que pode provar a correção."""
    _inteiro_valido(identificador)
    try:
        with do_cliente(request, sessao) as con:
            alvo = con.execute("""SELECT a.id, a.modelo_id, a.nome FROM vuln_achados x JOIN vuln_varreduras v ON v.id = x.ultima_varredura JOIN vuln_alvos a ON a.id = v.alvo_id
                                  WHERE x.id = %s AND a.ativo""", (identificador,)).fetchone()
            if not alvo:
                raise HTTPException(status_code=409, detail="O alvo que encontrou este achado não existe mais. Crie um alvo para este ativo e varra de novo.")
            linha = con.execute("INSERT INTO vuln_varreduras (cliente_id, alvo_id, modelo_id, pedida_por) VALUES (%s, %s, %s, %s) RETURNING id", (sessao["cliente_id"], alvo["id"], alvo["modelo_id"], sessao["usuario_id"])).fetchone()
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'pedir_varredura', %s)", (sessao["cliente_id"], sessao["usuario_id"], alvo["nome"][:200]))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Este alvo já tem uma varredura em andamento: ela vai confirmar.")
    return {"id": linha["id"], "alvo": alvo["nome"]}


@app.get("/api/vuln/ativos")
def ativos_de_vulnerabilidade(request: Request, sessao=Depends(exige(permissoes.VER))):
    casos = " ".join(f"WHEN '{s}' THEN {p}" for s, p in vulnerabilidades.PONTOS.items())
    with do_cliente(request, sessao) as con:
        return {"ativos": con.execute(f"""SELECT t.id, t.host, t.nome, t.sistema, t.peso, t.monitorado, t.primeira_vez, t.ultima_varredura,
                                                 count(*) FILTER (WHERE a.estado IN ('aberto', 'correcao_informada')) AS abertos,
                                                 count(*) FILTER (WHERE a.estado IN ('aberto', 'correcao_informada') AND a.severidade IN ('critica', 'alta')) AS graves,
                                                 count(*) FILTER (WHERE a.estado = 'corrigido') AS corrigidos,
                                                 coalesce(sum(t.peso * CASE a.severidade {casos} END) FILTER (WHERE a.estado IN ('aberto', 'correcao_informada')), 0) AS exposicao
                                          FROM vuln_ativos t LEFT JOIN vuln_achados a ON a.ativo_id = t.id GROUP BY t.id ORDER BY exposicao DESC, t.host LIMIT 5000""").fetchall()}


@app.put("/api/vuln/ativos/{identificador}", status_code=204)
def mudar_ativo_de_vulnerabilidade(identificador: int, dados: MudancaDeAtivo, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE vuln_ativos SET peso = %s, peso_definido_por = %s WHERE id = %s RETURNING id", (dados.peso, sessao["usuario_id"], identificador)).fetchone():
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'mudar_peso_de_ativo', %s)", (sessao["cliente_id"], sessao["usuario_id"], f"{identificador} peso {dados.peso}"))


class DominioExterno(BaseModel):
    dominio: str = Field(min_length=3, max_length=253)
    # Quem cadastra declara que a organização é dona do domínio ou tem autorização para varrer.
    autorizado: bool = False
    descobrir_a_cada_horas: int = Field(default=24, ge=6, le=720)
    conferir_a_cada_horas: int = Field(default=6, ge=1, le=168)


class MudancaDeDominio(BaseModel):
    ativo: bool = True
    descobrir_a_cada_horas: int = Field(default=24, ge=6, le=720)
    conferir_a_cada_horas: int = Field(default=6, ge=1, le=168)


DOMINIO = re.compile(r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}")


@app.get("/api/vuln/superficie")
def superficie_externa(request: Request, sessao=Depends(exige(permissoes.VER))):
    """Os domínios com o andamento da fila (quantos nomes já foram conferidos, quantos esperam e quem está sendo conferido
    agora) e os nomes encontrados."""
    with do_cliente(request, sessao) as con:
        dominios = con.execute("""SELECT d.id, d.dominio, d.autorizado_por_nome, d.autorizado_em, d.ativo, d.descobrir_a_cada_horas, d.conferir_a_cada_horas,
                                         d.proxima_descoberta, d.ultima_descoberta, d.ultimo_erro,
                                         count(h.id) FILTER (WHERE NOT h.sumiu) AS nomes,
                                         count(h.id) FILTER (WHERE NOT h.sumiu AND h.conferido_em IS NOT NULL) AS conferidos,
                                         count(h.id) FILTER (WHERE NOT h.sumiu AND h.proxima_conferencia <= now()) AS na_fila,
                                         max(h.nome) FILTER (WHERE h.conferindo_desde > now() - interval '10 minutes') AS conferindo_agora,
                                         min(h.proxima_conferencia) FILTER (WHERE NOT h.sumiu) AS proxima_conferencia
                                  FROM superficie_dominios d LEFT JOIN superficie_hosts h ON h.dominio_id = d.id
                                  GROUP BY d.id ORDER BY d.dominio""").fetchall()
        hosts = con.execute("""SELECT h.id, h.dominio_id, h.nome, h.ips, h.origem, h.interno, h.sumiu, h.portas, h.servicos, h.email, h.cname, h.tls_vence, h.tls_emissor, h.tls_problema,
                                      h.conferido_em, h.proxima_conferencia, coalesce(h.conferindo_desde > now() - interval '10 minutes', false) AS conferindo,
                                      h.primeira_vez, h.ultima_vez, t.id AS ativo_id,
                                      (SELECT count(*) FROM vuln_achados a WHERE a.ativo_id = t.id AND a.fonte = 'externa'
                                        AND a.estado IN ('aberto', 'correcao_informada')) AS abertos
                               FROM superficie_hosts h LEFT JOIN vuln_ativos t ON t.host = h.nome
                               ORDER BY h.sumiu, h.interno, h.nome LIMIT 5000""").fetchall()
        mudancas = con.execute("SELECT id, dominio_id, nome, tipo, detalhe, em FROM superficie_mudancas ORDER BY em DESC, id DESC LIMIT 500").fetchall()
        nota = nota_externa.calcular(con)
    return {"dominios": dominios, "hosts": hosts, "mudancas": mudancas, "nota": nota}


@app.get("/api/vuln/superficie/nomes/{identificador}/servicos/{indice}")
def cves_do_servico(identificador: int, indice: int, request: Request, sessao=Depends(exige(permissoes.VER))):
    """As CVEs que pegam o serviço, refeitas na hora (a base muda todo dia), com a situação de cada uma: confirmada pelo
    pacote da distribuição, corrigida pela distribuição, a confirmar, pela versão, ou já explorada no produto (quando a
    versão não aparece)."""
    _inteiro_valido(identificador)
    colunas = "c.cve, coalesce(c.titulo, left(c.descricao, 200)) AS titulo, c.cvss, c.epss, c.kev_desde, c.kev_ransomware, c.prioridade"
    with do_cliente(request, sessao) as con:
        linha = con.execute("SELECT nome, servicos FROM superficie_hosts WHERE id = %s", (identificador,)).fetchone()
        if not linha or not 0 <= indice < len(linha["servicos"]):
            raise HTTPException(status_code=404)
        servico = linha["servicos"][indice]
        produtos = superficie_externa_.PRODUTOS_DO_SERVICO.get(servico.get("nome"), [])
        tipo, versao, pacote = servico.get("tipo", "servico"), servico.get("versao"), servico.get("pacote") or {}
        if tipo == "borda" or not versao:
            # Sem versão, não dá para dizer quais pegam: mostra as que já foram exploradas no produto, para conferir no equipamento.
            cves = con.execute(f"""SELECT DISTINCT ON (c.cve) {colunas}, 'explorada_no_produto' AS situacao FROM cves_versoes v JOIN cves c ON c.cve = v.cve
                                    WHERE v.produto = ANY(%s) AND c.kev_desde IS NOT NULL AND NOT c.rejeitado""", (produtos,)).fetchall()
        else:
            candidatas = con.execute(f"""SELECT v.exata, v.desde, v.desde_incluida, v.ate, v.ate_incluida, {colunas}
                                         FROM cves_versoes v JOIN cves c ON c.cve = v.cve WHERE v.produto = ANY(%s) AND NOT c.rejeitado""", (produtos,)).fetchall()
            pela_versao = {}
            for c in candidatas:
                if c["cve"] not in pela_versao and superficie_externa_.afeta(versao, c["exata"], c["desde"], c["desde_incluida"], c["ate"], c["ate_incluida"]):
                    pela_versao[c["cve"]] = {k: c[k] for k in ("cve", "titulo", "cvss", "epss", "kev_desde", "kev_ransomware", "prioridade")}
            abertas = None
            if pacote.get("confirmado"):
                guardada = con.execute("SELECT cves FROM distro_consultas WHERE distribuicao = %s AND pacote = %s AND versao = %s",
                                       (pacote.get("distribuicao"), pacote.get("nome"), pacote.get("versao"))).fetchone()
                abertas = set(guardada["cves"] or []) if guardada else None
            if abertas is not None:
                # A distribuição é quem sabe: a que ainda pega o pacote vale, mesmo que a faixa da NVD não a tenha trazido.
                extras = con.execute(f"SELECT {colunas} FROM cves c WHERE c.cve = ANY(%s) AND NOT c.rejeitado", (list(abertas - set(pela_versao)),)).fetchall()
                cves = [{**c, "situacao": "confirmada" if c["cve"] in abertas else "corrigida_na_distribuicao"} for c in [*pela_versao.values(), *extras]]
            else:
                cves = [{**c, "situacao": "a_confirmar" if servico.get("distribuicao") else "pela_versao"} for c in pela_versao.values()]
    ordem = ["agora", "alta", "media", "baixa", "sem_dados"]
    situacoes = ["confirmada", "pela_versao", "explorada_no_produto", "a_confirmar", "corrigida_na_distribuicao"]
    lista = sorted(cves, key=lambda c: (situacoes.index(c["situacao"]), ordem.index(c["prioridade"]), -(c["epss"] or 0), -(c["cvss"] or 0), c["cve"]))
    return {"nome": linha["nome"], "servico": servico, "cves": lista}


@app.post("/api/vuln/superficie", status_code=201)
def cadastrar_dominio(dados: DominioExterno, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    dominio = dados.dominio.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].rstrip(".")
    if not DOMINIO.fullmatch(dominio):
        raise HTTPException(status_code=422, detail="Use só o domínio, como empresa.com.br.")
    if not dados.autorizado:
        raise HTTPException(status_code=422, detail="Confirme que a organização é dona do domínio ou tem autorização para varrê-lo.")
    try:
        with do_cliente(request, sessao) as con:
            linha = con.execute("""INSERT INTO superficie_dominios (cliente_id, dominio, autorizado_por, autorizado_por_nome, descobrir_a_cada_horas, conferir_a_cada_horas)
                                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                                (sessao["cliente_id"], dominio, sessao["usuario_id"], sessao["nome"], dados.descobrir_a_cada_horas, dados.conferir_a_cada_horas)).fetchone()
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'cadastrar_dominio_externo', %s)",
                        (sessao["cliente_id"], sessao["usuario_id"], f"{dominio}, declarado como da organização"))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Este domínio já está cadastrado.")
    return {"id": linha["id"]}


@app.put("/api/vuln/superficie/{identificador}", status_code=204)
def mudar_dominio(identificador: int, dados: MudancaDeDominio, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE superficie_dominios SET ativo = %s, descobrir_a_cada_horas = %s, conferir_a_cada_horas = %s WHERE id = %s RETURNING id",
                           (dados.ativo, dados.descobrir_a_cada_horas, dados.conferir_a_cada_horas, identificador)).fetchone():
            raise HTTPException(status_code=404)


@app.post("/api/vuln/superficie/{identificador}/agora", status_code=204)
def varrer_dominio_agora(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    """Põe o domínio na frente da descoberta e os nomes dele na fila. Continua um por vez: só muda a ordem."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE superficie_dominios SET proxima_descoberta = now() WHERE id = %s AND ativo RETURNING id", (identificador,)).fetchone():
            raise HTTPException(status_code=404)
        con.execute("UPDATE superficie_hosts SET proxima_conferencia = now() WHERE dominio_id = %s AND NOT sumiu AND proxima_conferencia > now()", (identificador,))


@app.delete("/api/vuln/superficie/{identificador}", status_code=204)
def tirar_dominio(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    """Os achados já feitos continuam em Vulnerabilidades, com a história: tirar o domínio não apaga o que foi visto."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute("DELETE FROM superficie_dominios WHERE id = %s RETURNING dominio", (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'tirar_dominio_externo', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], linha["dominio"]))


@app.get("/api/vuln/modelos")
def modelos_de_varredura(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        return {"modelos": con.execute("SELECT id, nome, ferramenta, intrusiva, todas_portas FROM vuln_modelos WHERE ativo ORDER BY nome").fetchall()}


@app.post("/api/vuln/modelos", status_code=201)
def criar_modelo_de_varredura(dados: NovoModelo, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    try:
        with do_cliente(request, sessao) as con:
            linha = con.execute("INSERT INTO vuln_modelos (cliente_id, nome, ferramenta, intrusiva, todas_portas, criado_por) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                                (sessao["cliente_id"], dados.nome.strip(), dados.ferramenta, dados.intrusiva, dados.todas_portas, sessao["usuario_id"])).fetchone()
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_modelo_de_varredura', %s)", (sessao["cliente_id"], sessao["usuario_id"], dados.nome.strip()[:200]))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe um modelo com esse nome.")
    return {"id": linha["id"]}


@app.get("/api/vuln/alvos")
def alvos_de_varredura(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        return {"alvos": con.execute("""SELECT a.id, a.nome, a.hosts, a.modelo_id, m.nome AS modelo, m.intrusiva, a.credencial_tipo, a.credencial_usuario, a.credencial_segredo IS NOT NULL AS com_credencial, a.a_cada_dias, a.proxima_em
                                        FROM vuln_alvos a JOIN vuln_modelos m ON m.id = a.modelo_id WHERE a.ativo ORDER BY a.nome""").fetchall()}


@app.post("/api/vuln/alvos", status_code=201)
def criar_alvo_de_varredura(dados: NovoAlvo, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    """Varrer é tocar em sistema dos outros: a tela avisa, e quem criou o alvo fica na auditoria."""
    if bool(dados.credencial_tipo) != bool(dados.credencial_usuario and dados.credencial_senha):
        raise HTTPException(status_code=422, detail="Para usar credencial, informe o tipo, o usuário e a senha.")
    nome = dados.nome.strip()
    try:
        with do_cliente(request, sessao) as con:
            modelo = con.execute("SELECT ferramenta FROM vuln_modelos WHERE id = %s AND ativo", (dados.modelo_id,)).fetchone()
            if not modelo:
                raise HTTPException(status_code=422, detail="Modelo de varredura desconhecido.")
            try:
                hosts = sorted({vulnerabilidades.validar_alvo(h, modelo["ferramenta"]) for h in dados.hosts})
            except vulnerabilidades.HostInvalido as erro:
                raise HTTPException(status_code=422, detail=str(erro))
            segredo = None
            if dados.credencial_tipo:
                segredo = f"varredura-{secrets.token_hex(8)}"
                selado = cofre.selar(cofre.ler_publica(), sessao["cliente_id"], segredo, dados.credencial_senha)
                con.execute("INSERT INTO segredos (cliente_id, nome, selado, criado_por) VALUES (%s, %s, %s, %s)", (sessao["cliente_id"], segredo, selado, sessao["usuario_id"]))
            linha = con.execute("""INSERT INTO vuln_alvos (cliente_id, nome, hosts, modelo_id, credencial_tipo, credencial_usuario, credencial_segredo, a_cada_dias, proxima_em, criado_por)
                                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CASE WHEN %s > 0 THEN now() ELSE NULL END, %s) RETURNING id""",
                                (sessao["cliente_id"], nome, hosts, dados.modelo_id, dados.credencial_tipo, dados.credencial_usuario, segredo, dados.a_cada_dias, dados.a_cada_dias, sessao["usuario_id"])).fetchone()
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_alvo_de_varredura', %s)", (sessao["cliente_id"], sessao["usuario_id"], f"{nome[:120]}: {' '.join(hosts)[:600]}"))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe um alvo com esse nome.")
    return {"id": linha["id"]}


@app.delete("/api/vuln/alvos/{identificador}", status_code=204)
def desativar_alvo_de_varredura(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    """Os achados e a história continuam: tirar da agenda não apaga o que foi visto."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE vuln_alvos SET ativo = false, proxima_em = NULL WHERE id = %s AND ativo RETURNING id", (identificador,)).fetchone():
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'desativar_alvo_de_varredura', %s)", (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))


@app.get("/api/vuln/varreduras")
def varreduras(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        return {"varreduras": con.execute("""SELECT v.id, a.nome AS alvo, m.nome AS modelo, v.estado, v.pedida_por IS NULL AS agendada, v.pedida_em, v.iniciada_em, v.terminada_em, v.autenticada, v.hosts_respondendo, v.novos, v.corrigidos, v.mensagem
                                             FROM vuln_varreduras v JOIN vuln_alvos a ON a.id = v.alvo_id JOIN vuln_modelos m ON m.id = v.modelo_id ORDER BY v.id DESC LIMIT 200""").fetchall()}


@app.post("/api/vuln/varreduras", status_code=201)
def pedir_varredura(dados: PedidoDeVarredura, request: Request, sessao=Depends(exige(permissoes.GERIR_VULNERABILIDADES))):
    try:
        with do_cliente(request, sessao) as con:
            alvo = con.execute("SELECT id, modelo_id, nome FROM vuln_alvos WHERE id = %s AND ativo", (dados.alvo_id,)).fetchone()
            if not alvo:
                raise HTTPException(status_code=404)
            linha = con.execute("INSERT INTO vuln_varreduras (cliente_id, alvo_id, modelo_id, pedida_por) VALUES (%s, %s, %s, %s) RETURNING id", (sessao["cliente_id"], alvo["id"], alvo["modelo_id"], sessao["usuario_id"])).fetchone()
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'pedir_varredura', %s)", (sessao["cliente_id"], sessao["usuario_id"], alvo["nome"][:200]))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Este alvo já tem uma varredura em andamento.")
    return {"id": linha["id"]}


AMOSTRA_DE_TAMANHO = 500
HORAS_DE_EPS = 72


def _volume_do_indice(indexer, indices, dias):
    """EPS, pico e tamanho. O pico sai de contagens por minuto: um estouro de segundos fica diluído, e a tela diz isso."""
    corpo = {"size": AMOSTRA_DE_TAMANHO, "_source": ["full_log"], "sort": [{"timestamp": "desc"}], "track_total_hits": True,
             "query": {"range": {"timestamp": {"gte": f"now-{dias}d"}}},
             "aggs": {"por_minuto": {"date_histogram": {"field": "timestamp", "fixed_interval": "1m", "min_doc_count": 1}},
                      "por_dia": {"date_histogram": {"field": "timestamp", "calendar_interval": "1d", "min_doc_count": 0}},
                      "ativos": {"terms": {"field": "agent.name", "size": 15}},
                      "origens": {"terms": {"field": "decoder.name", "size": 15}},
                      "agora": {"filter": {"range": {"timestamp": {"gte": "now-6m", "lt": "now-1m"}}}}}}
    r = indexer.post(f"{INDEXER_URL}/{indices}/_search?allow_no_indices=true&ignore_unavailable=true", json=corpo, timeout=60)
    r.raise_for_status()
    d = r.json()
    a = d.get("aggregations") or {}
    amostra = [len(str(h["_source"].get("full_log", "")).encode()) for h in d["hits"]["hits"]]
    tamanho_medio = sum(amostra) / len(amostra) if amostra else 0
    total = d["hits"]["total"]["value"]
    minutos = a.get("por_minuto", {}).get("buckets", [])
    pico = max(minutos, key=lambda b: b["doc_count"], default=None)
    por_hora = {}
    for b in minutos:
        hora = b["key_as_string"][:13]
        contagem = por_hora.setdefault(hora, {"hora": hora, "eventos": 0, "maior_minuto": 0})
        contagem["eventos"] += b["doc_count"]
        contagem["maior_minuto"] = max(contagem["maior_minuto"], b["doc_count"])
    return {
        "total": total,
        # Hora sem evento não vem no histograma: a tela completa com zero, para o buraco aparecer.
        "eps_por_hora": [{"hora": h["hora"], "medio": round(h["eventos"] / 3600, 3), "pico": round(h["maior_minuto"] / 60, 2)} for h in list(por_hora.values())[-HORAS_DE_EPS:]],
        "eps_agora": round(a.get("agora", {}).get("doc_count", 0) / 300, 2),
        "eps_medio": round(total / (dias * 86400), 3),
        "eps_pico": round(pico["doc_count"] / 60, 2) if pico else 0,
        "pico_em": pico["key_as_string"] if pico else None,
        "bytes_por_evento": round(tamanho_medio),
        "por_dia": [{"dia": b["key_as_string"][:10], "eventos": b["doc_count"], "bytes_estimados": round(b["doc_count"] * tamanho_medio)} for b in a.get("por_dia", {}).get("buckets", [])],
        "ativos": [{"nome": b["key"], "eventos": b["doc_count"]} for b in a.get("ativos", {}).get("buckets", [])],
        "origens": [{"nome": b["key"], "eventos": b["doc_count"]} for b in a.get("origens", {}).get("buckets", [])],
    }


def _ocupado_no_indice(indexer, indices):
    r = indexer.get(f"{INDEXER_URL}/{indices}/_stats/store?allow_no_indices=true&ignore_unavailable=true", timeout=30)
    if not r.ok:
        return None
    return sum(i["primaries"]["store"]["size_in_bytes"] for i in r.json().get("indices", {}).values())


def _ocupado_por_dia(indexer, logs, alertas):
    """Cada índice é um dia: o nome diz qual, e o prefixo diz se é log ou alerta."""
    r = indexer.get(f"{INDEXER_URL}/{logs},{alertas}/_stats/store?allow_no_indices=true&ignore_unavailable=true", timeout=30)
    if not r.ok:
        return None
    dias, total = {}, {"logs": 0, "alertas": 0}
    for nome, dados in r.json().get("indices", {}).items():
        tipo = "logs" if nome.startswith("wazuh-archives-") else "alertas"
        tamanho = dados["primaries"]["store"]["size_in_bytes"]
        total[tipo] += tamanho
        achado = re.search(r"(\d{4})\.(\d{2})\.(\d{2})$", nome)
        if achado:
            dia = dias.setdefault("-".join(achado.groups()), {"logs": 0, "alertas": 0})
            dia[tipo] += tamanho
    return {**total, "por_dia": [{"dia": d, **v} for d, v in sorted(dias.items())]}


@app.get("/api/volume")
def volume(request: Request, sessao=Depends(exige(permissoes.VER)), dias: int = 7):
    """O quanto este cliente manda. Tudo vem dos índices dele, escolhidos pelo banco sob o RLS, nunca pela requisição."""
    dias = max(1, min(dias, 90))
    with do_cliente(request, sessao) as con:
        gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
        prazos = con.execute("SELECT retencao_alertas_dias, retencao_logs_dias FROM clientes").fetchone()
        onde = _armazem_da_organizacao(request, con, sessao)
    if not gerenciadores:
        return {"logs": None, "alertas": None, "dias": dias}
    if onde:
        try:
            resposta = {"logs": leitor_armazem.volume(onde["armazem"], onde["banco"], "logs", dias, HORAS_DE_EPS, AMOSTRA_DE_TAMANHO),
                        "alertas": leitor_armazem.volume(onde["armazem"], onde["banco"], "alertas", dias, HORAS_DE_EPS, AMOSTRA_DE_TAMANHO), "dias": dias}
            resposta["ocupado"] = leitor_armazem.ocupado(onde["armazem"], onde["banco"])
        except (armazem_de_eventos.ArmazemRecusou, requests.RequestException, KeyError, ValueError):
            raise HTTPException(status_code=503, detail="Não foi possível medir o volume agora.")
        resposta["ocupado_bytes"] = resposta["ocupado"]["logs"] + resposta["ocupado"]["alertas"]
        resposta["ocupado"].update(prazos)
        return resposta
    logs = ",".join(f"wazuh-archives-4.x-{g}-*" for g in gerenciadores)
    alertas = ",".join(f"wazuh-alerts-4.x-{g}-*" for g in gerenciadores)
    try:
        resposta = {"logs": _volume_do_indice(request.app.state.indexer, logs, dias), "alertas": _volume_do_indice(request.app.state.indexer, alertas, dias), "dias": dias}
    except (requests.RequestException, KeyError, ValueError):
        raise HTTPException(status_code=503, detail="Não foi possível medir o volume agora.")
    resposta["ocupado"] = _ocupado_por_dia(request.app.state.indexer, logs, alertas)
    # Da mesma leitura: o indexador compacta o tempo todo, e duas medidas seguidas não batem.
    resposta["ocupado_bytes"] = (resposta["ocupado"]["logs"] + resposta["ocupado"]["alertas"]) if resposta["ocupado"] else _ocupado_no_indice(request.app.state.indexer, f"{logs},{alertas}")
    if resposta["ocupado"]:
        resposta["ocupado"].update(prazos)
    return resposta


class Armazenamento(BaseModel):
    retencao_alertas_dias: int = Field(ge=30, le=3650)
    retencao_logs_dias: int = Field(ge=7, le=3650)
    guardar_logs: bool


@app.get("/api/organizacao/armazenamento")
def ver_armazenamento(request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    with do_cliente(request, sessao) as con:
        dados = con.execute("""SELECT retencao_alertas_dias, retencao_logs_dias, guardar_logs, armazenamento_estado AS estado,
                                      armazenamento_mensagem AS mensagem, ler_do_armazem, desvio_de_volume FROM clientes""").fetchone()
        do_armazem = _copia_do_armazem(request, con, sessao)
    # A cópia do armazém é por organização e por dia; a do indexador, da instalação inteira.
    arquivo = ({"ultima": do_armazem[1][-1].isoformat() if do_armazem[1] else None, "copias": len(do_armazem[1]), "dias": int(_ler_env().get("ROAR_ARQUIVO_DIAS", 365))}
               if do_armazem else _ultima_copia_fria(request.app.state.indexer))
    return {**dados, "arquivo": arquivo, "armazem_disponivel": _armazem_disponivel(request, sessao)}


def _armazem_disponivel(request, sessao):
    """A organização já tem banco no armazém de eventos: algum gerenciador dela tem coletor."""
    armazem = request.app.state.armazem
    if armazem is None:
        return False
    try:
        return bool(armazem.linhas("SELECT count() AS n FROM system.databases WHERE name = {b:String}",
                                   {"b": armazem_de_eventos.banco_do(sessao["cliente_id"])})[0]["n"] not in (0, "0"))
    except (armazem_de_eventos.ArmazemRecusou, requests.RequestException):
        return False


class LeituraDoArmazem(BaseModel):
    ler: bool


class DesvioDeVolume(BaseModel):
    desviar: bool


@app.put("/api/organizacao/armazenamento/desvio", status_code=204)
def definir_desvio_de_volume(dados: DesvioDeVolume, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    """O tráfego permitido dos firewalls conhecidos vai do coletor direto ao armazém, sem passar pelo gerenciador
    (roar_ingestao.coletor_syslog). Só com o armazém: sem ele, esse tráfego não ficaria guardado em lugar nenhum."""
    if dados.desviar and not _armazem_disponivel(request, sessao):
        raise HTTPException(status_code=409, detail="Esta organização ainda não tem o armazém novo.")
    with do_cliente(request, sessao) as con:
        con.execute("SELECT roar_definir_desvio_de_volume(%s)", (dados.desviar,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'definir_desvio_de_volume', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], "ligado" if dados.desviar else "desligado"))


@app.put("/api/organizacao/armazenamento/leitura", status_code=204)
def definir_leitura_do_armazem(dados: LeituraDoArmazem, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    """Durante a migração: a tela de logs, os painéis e as buscas agendadas passam a ler do armazém novo, ou voltam ao indexador."""
    if dados.ler and not _armazem_disponivel(request, sessao):
        raise HTTPException(status_code=409, detail="Esta organização ainda não tem o armazém novo.")
    with do_cliente(request, sessao) as con:
        con.execute("SELECT roar_definir_leitura_do_armazem(%s)", (dados.ler,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'definir_leitura_do_armazem', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], "armazém novo" if dados.ler else "indexador"))


class Recuperacao(BaseModel):
    de: date
    ate: date
    tipo: str = Field(pattern="^(alertas|logs|ambos)$")
    dias_de_consulta: int = Field(default=7, ge=1, le=30)


def _copia_do_armazem(request, con, sessao):
    """A organização que lê do armazém de eventos traz os dias de volta da cópia dele (roar_ingestao.copia_do_armazem)."""
    onde = _armazem_da_organizacao(request, con, sessao)
    if not onde:
        return None
    dias = [l["dia"] for l in con.execute("SELECT dia FROM copias_do_armazem ORDER BY dia").fetchall()]
    return onde, dias


@app.get("/api/organizacao/copia-fria")
def ver_copia_fria(request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    """Os dias que dá para trazer de volta: só os desta organização, escolhidos pelos gerenciadores dela."""
    with do_cliente(request, sessao) as con:
        gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
        pedidos = con.execute("SELECT id, de, ate, tipo, dias_de_consulta, estado, mensagem, cardinality(indices) AS indices, criado_em, expira_em "
                              "FROM recuperacoes ORDER BY id DESC LIMIT 20").fetchall()
        do_armazem = _copia_do_armazem(request, con, sessao)
    if do_armazem:
        onde, dias = do_armazem
        try:
            ja = copia_do_armazem.presentes(onde["armazem"], onde["banco"])
        except (armazem_de_eventos.ArmazemRecusou, requests.RequestException):
            return {"disponivel": None, "pedidos": pedidos}
        # Guardado na cópia e fora do armazém: nem na tabela de sempre, nem já de volta.
        return {"disponivel": {tipo: [d.isoformat() for d in dias if (tipo, d.strftime("%Y%m%d")) not in ja] for tipo in ("alertas", "logs")},
                "pedidos": pedidos}
    try:
        disponivel = copia_fria.dias_disponiveis(request.app.state.indexer.get, INDEXER_URL, gerenciadores)
    except requests.RequestException:
        disponivel = None
    return {"disponivel": disponivel, "pedidos": pedidos}


@app.post("/api/organizacao/copia-fria", status_code=201)
def pedir_recuperacao(dados: Recuperacao, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    if dados.ate < dados.de or (dados.ate - dados.de).days >= 31:
        raise HTTPException(status_code=422, detail="Escolha um período de até 31 dias.")
    with do_cliente(request, sessao) as con:
        if con.execute("SELECT count(*) AS n FROM recuperacoes WHERE estado IN ('pendente', 'em_andamento')").fetchone()["n"]:
            raise HTTPException(status_code=409, detail="Já há uma recuperação em andamento. Espere terminar.")
        origem = "armazem" if _armazem_da_organizacao(request, con, sessao) else "indexador"
        novo = con.execute("INSERT INTO recuperacoes (cliente_id, de, ate, tipo, dias_de_consulta, pedido_por, origem) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                           (sessao["cliente_id"], dados.de, dados.ate, dados.tipo, dados.dias_de_consulta, sessao["usuario_id"], origem)).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'recuperar_copia_fria', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{dados.tipo} de {dados.de} a {dados.ate}, por {dados.dias_de_consulta} dias"))
    return {"id": novo}


@app.post("/api/organizacao/copia-fria/{identificador}/devolver", status_code=202)
def devolver_recuperacao(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE recuperacoes SET estado = 'devolver' WHERE id = %s AND estado = 'pronto' RETURNING id", (identificador,)).fetchone():
            raise HTTPException(status_code=409, detail="Só dá para devolver o que já voltou.")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'devolver_copia_fria', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))


def _ultima_copia_fria(indexer):
    """Da instalação inteira: a cópia leva todas as organizações juntas, então só diz quando foi e por quanto tempo fica."""
    try:
        r = indexer.get(f"{INDEXER_URL}/_cat/snapshots/roar-arquivo?format=json&h=id,status,end_epoch", timeout=20)
    except requests.RequestException:
        return None
    if not r.ok:
        return None
    prontas = [int(s["end_epoch"]) for s in r.json() if s.get("status") == "SUCCESS" and s.get("end_epoch")]
    return {"ultima": datetime.fromtimestamp(max(prontas), timezone.utc).isoformat() if prontas else None,
            "copias": len(prontas), "dias": int(_ler_env().get("ROAR_ARQUIVO_DIAS", 365))}


@app.put("/api/organizacao/armazenamento", status_code=204)
def definir_armazenamento(dados: Armazenamento, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    """O serviço de fontes aplica no indexador e no gerenciador; a tela acompanha pelo estado."""
    with do_cliente(request, sessao) as con:
        con.execute("SELECT roar_definir_armazenamento(%s, %s, %s)", (dados.retencao_alertas_dias, dados.retencao_logs_dias, dados.guardar_logs))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'definir_armazenamento', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"],
                     f"alertas {dados.retencao_alertas_dias} dias, logs brutos {dados.retencao_logs_dias} dias, {'guarda' if dados.guardar_logs else 'não guarda'} logs brutos"))


class NovaFonteDeInteligencia(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    tipo: str = Field(pattern="^(misp|taxii)$")
    endereco: str = Field(min_length=8, max_length=500)
    colecao: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._~-]*$")
    credencial: str | None = Field(default=None, max_length=4096)
    a_cada_minutos: int = Field(default=60, ge=5, le=10080)


@app.get("/api/inteligencia")
def inteligencia(request: Request, sessao=Depends(exige(permissoes.VER)), busca: str = ""):
    with do_cliente(request, sessao) as con:
        fontes = con.execute("""SELECT f.id, f.nome, f.tipo, f.endereco, f.colecao, f.segredo IS NOT NULL AS com_credencial, f.ativa, f.interna, f.a_cada_minutos, f.proxima_em, f.ultima_em, f.ultimo_erro,
                                       (SELECT count(*) FROM intel_indicadores i WHERE i.fonte_id = f.id) AS indicadores
                                FROM intel_fontes f WHERE f.ativa OR f.interna ORDER BY f.interna DESC, f.nome""").fetchall()
        condicao, valores = "", []
        busca = busca.strip()[:200]
        if busca:
            condicao = "WHERE i.valor ILIKE %s OR e.regra_descricao ILIKE %s OR e.agente_nome ILIKE %s"
            termo = f"%{_sem_curinga(busca)}%"
            valores = [termo, termo, termo]
        ocorrencias = con.execute(f"""SELECT o.evento_id, o.ocorrido_em, o.encontrada_em, o.no_passado, i.tipo, i.valor, i.descricao, f.nome AS fonte, e.regra_descricao, e.severidade, e.agente_nome AS ativo
                                      FROM intel_ocorrencias o JOIN intel_indicadores i ON i.id = o.indicador_id JOIN intel_fontes f ON f.id = i.fonte_id JOIN eventos e ON e.id = o.evento_id
                                      {condicao} ORDER BY o.ocorrido_em DESC LIMIT 200""", valores).fetchall()
        # Nos fluxos de rede (roar_ingestao.inteligencia.buscar_nos_fluxos): um resumo por indicador, endereço da rede e dia.
        condicao_dos_fluxos, valores_dos_fluxos = ("WHERE i.valor ILIKE %s OR x.interno ILIKE %s", [f"%{_sem_curinga(busca)}%"] * 2) if busca else ("", [])
        nos_fluxos = con.execute(f"""SELECT x.dia, x.interno, x.sentido, x.fluxos, x.bytes, x.primeira, x.ultima, x.exportador, x.no_passado, i.valor, i.descricao, f.nome AS fonte
                                     FROM intel_fluxos x JOIN intel_indicadores i ON i.id = x.indicador_id JOIN intel_fontes f ON f.id = i.fonte_id
                                     {condicao_dos_fluxos} ORDER BY x.ultima DESC LIMIT 200""", valores_dos_fluxos).fetchall()
        conferencia = con.execute("""SELECT (SELECT ocorrido_em FROM eventos WHERE id = c.ultimo_evento) AS ate,
                                            (SELECT count(*) FROM eventos WHERE id <= c.ultimo_evento AND ocorrido_em >= now() - interval '30 days') AS eventos_30_dias
                                     FROM intel_cursor c""").fetchone()
    indicadores = sum(int(f["indicadores"]) for f in fontes if f["ativa"])
    return {"fontes": fontes, "ocorrencias": ocorrencias, "nos_fluxos": nos_fluxos,
            "conferencia": {**conferencia, "indicadores": indicadores} if conferencia and conferencia["ate"] else None}


@app.post("/api/inteligencia/fontes", status_code=201)
def criar_fonte_de_inteligencia(dados: NovaFonteDeInteligencia, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """Cada organização liga a sua, ou nenhuma. A credencial fica no cofre e não volta para a tela."""
    endereco = dados.endereco.strip()
    if not endereco.startswith("https://") and os.getenv("ROAR_DESTINO_INTERNO") != "1":
        raise HTTPException(status_code=422, detail="Use um endereço https: a credencial da fonte não pode viajar aberta.")
    try:
        rede_externa.resolver(endereco)
    except rede_externa.DestinoRecusado as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    if dados.tipo == "taxii" and not dados.colecao:
        raise HTTPException(status_code=422, detail="Informe a coleção da fonte TAXII.")
    nome = dados.nome.strip()
    try:
        with do_cliente(request, sessao) as con:
            segredo = None
            if dados.credencial:
                segredo = f"inteligencia-{secrets.token_hex(8)}"
                con.execute("INSERT INTO segredos (cliente_id, nome, selado, criado_por) VALUES (%s, %s, %s, %s)",
                            (sessao["cliente_id"], segredo, cofre.selar(cofre.ler_publica(), sessao["cliente_id"], segredo, dados.credencial), sessao["usuario_id"]))
            linha = con.execute("""INSERT INTO intel_fontes (cliente_id, nome, tipo, endereco, colecao, segredo, a_cada_minutos, criado_por) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                                (sessao["cliente_id"], nome, dados.tipo, endereco, dados.colecao or None, segredo, dados.a_cada_minutos, sessao["usuario_id"])).fetchone()
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_fonte_de_inteligencia', %s)", (sessao["cliente_id"], sessao["usuario_id"], f"{nome[:120]} {endereco[:300]}"))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe uma fonte com esse nome.")
    return {"id": linha["id"]}


@app.delete("/api/inteligencia/fontes/{identificador}", status_code=204)
def desativar_fonte_de_inteligencia(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """Para de buscar. As ocorrências continuam: o que já foi visto faz parte da investigação."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE intel_fontes SET ativa = false WHERE id = %s AND ativa RETURNING id", (identificador,)).fetchone():
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'desativar_fonte_de_inteligencia', %s)", (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))


@app.post("/api/inteligencia/fontes/{identificador}/ligar", status_code=204)
def ligar_fonte_local(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """Só a fonte da instalação volta assim. As outras foram tiradas de vez: quem quiser cria de novo, com a credencial."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE intel_fontes SET ativa = true, proxima_em = now() WHERE id = %s AND interna AND NOT ativa RETURNING id", (identificador,)).fetchone():
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'ligar_fonte_de_inteligencia', %s)", (sessao["cliente_id"], sessao["usuario_id"], str(identificador)))


@app.post("/api/inteligencia/fontes/{identificador}/sincronizar", status_code=202)
def sincronizar_fonte_de_inteligencia(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE intel_fontes SET proxima_em = now() WHERE id = %s AND ativa AND tipo <> 'manual' RETURNING id", (identificador,)).fetchone():
            raise HTTPException(status_code=404)


MAXIMO_DE_INDICADORES_NA_CACA = 200
LIMITE_DE_ACHADOS_NA_CACA = 500
TIPO_DO_RESUMO = {32: "md5", 40: "sha1", 64: "sha256"}


class Caca(BaseModel):
    texto: str = Field(min_length=1, max_length=20000)
    dias: int = Field(default=30, ge=1, le=90)


class IndicadorVigiado(BaseModel):
    tipo: str = Field(pattern="^(ip|dominio|url|md5|sha1|sha256)$")
    valor: str = Field(min_length=1, max_length=2048)


class Vigilancia(BaseModel):
    indicadores: list[IndicadorVigiado] = Field(min_length=1, max_length=MAXIMO_DE_INDICADORES_NA_CACA)
    descricao: str = Field(default="", max_length=200)


def _desarmar(valor):
    """Relatório de ameaça escreve "hxxp" e "1.2.3[.]4" para ninguém clicar sem querer."""
    valor = valor.strip().strip("\"'<>()")
    valor = re.sub(r"(?i)^hxxp", "http", valor)
    for armado, normal in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://")):
        valor = valor.replace(armado, normal)
    return valor


def _classificar(texto):
    """O tipo e o valor comparável de um indicador colado, ou None."""
    valor = _desarmar(texto)
    try:
        # Na caça vale endereço interno: é a pessoa que está perguntando por ele.
        return "ip", str(ipaddress.ip_address(valor))
    except ValueError:
        pass
    if re.match(r"(?i)^https?://", valor):
        return "url", valor[:2048]
    if re.fullmatch(r"[0-9a-fA-F]+", valor) and len(valor) in TIPO_DO_RESUMO:
        return TIPO_DO_RESUMO[len(valor)], valor.lower()
    dominio = inteligencia_de_ameacas.normalizar("dominio", valor)
    return ("dominio", dominio) if dominio and not re.fullmatch(r"[\d.]+", dominio) else None


def _valores_do_evento(ip, bruto):
    """Como observaveis() da inteligência, mas sem descartar endereço interno."""
    bruto = bruto if isinstance(bruto, dict) else {}
    dados = bruto.get("data") if isinstance(bruto.get("data"), dict) else {}
    arquivo = bruto.get("syscheck") if isinstance(bruto.get("syscheck"), dict) else {}
    saida = defaultdict(set)
    for candidato in (ip, *(dados.get(c) for c in CAMPOS_DE_IP_DE_ORIGEM + CAMPOS_DE_IP_DE_DESTINO)):
        try:
            saida["ip"].add(str(ipaddress.ip_address(str(candidato))))
        except ValueError:
            pass
    for campo in ("hostname", "domain", "query", "dest_host"):
        if isinstance(dados.get(campo), str):
            saida["dominio"].add(dados[campo].lower().rstrip("."))
    if isinstance(dados.get("url"), str):
        saida["url"].add(dados["url"])
    for tipo in ("md5", "sha1", "sha256"):
        if isinstance(arquivo.get(f"{tipo}_after"), str):
            saida[tipo].add(arquivo[f"{tipo}_after"].lower())
    return saida


def _contar_nos_logs(request, con, sessao, indicadores, dias):
    """Quantas vezes cada indicador aparece nos logs brutos, inclusive os que não viraram alerta."""
    gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
    if not gerenciadores or not indicadores:
        return {}
    onde = _armazem_da_organizacao(request, con, sessao)
    if onde:
        try:
            return leitor_armazem.contar_indicadores(onde["armazem"], onde["banco"], indicadores, dias)
        except (armazem_de_eventos.ArmazemRecusou, requests.RequestException):
            return {}
    indices = ",".join(f"wazuh-archives-4.x-{g}-*" for g in gerenciadores)
    linhas = []
    for _, valor in indicadores:
        linhas.append(json.dumps({"index": indices, "ignore_unavailable": True, "allow_no_indices": True}))
        linhas.append(json.dumps({"size": 0, "track_total_hits": 10000, "query": {"bool": {"filter": [
            {"range": {"timestamp": {"gte": f"now-{dias}d"}}}, {"match_phrase": {"full_log": valor}}]}}}))
    try:
        resposta = request.app.state.indexer.post(f"{INDEXER_URL}/_msearch", data="\n".join(linhas) + "\n",
                                                  headers={"Content-Type": "application/x-ndjson"}, timeout=30)
        respostas = resposta.json()["responses"] if resposta.ok else []
    except (requests.RequestException, ValueError, KeyError):
        return {}
    return {chave: r["hits"]["total"]["value"] for chave, r in zip(indicadores, respostas) if "hits" in r}


@app.post("/api/inteligencia/cacar")
def cacar_indicadores(dados: Caca, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True))):
    """Procura agora, nos eventos dos últimos dias, indicadores que a pessoa colou. Não precisa de fonte."""
    reconhecidos, ignorados = {}, []
    for pedaco in re.split(r"[\s,;|]+", dados.texto):
        if not pedaco:
            continue
        achado = _classificar(pedaco)
        if achado:
            reconhecidos[achado] = None
        elif len(ignorados) < 50:
            ignorados.append(pedaco[:100])
    if not reconhecidos:
        raise HTTPException(status_code=422, detail="Nenhum indicador reconhecido. Cole IPs, domínios, URLs ou resumos MD5, SHA-1 ou SHA-256.")
    if len(reconhecidos) > MAXIMO_DE_INDICADORES_NA_CACA:
        raise HTTPException(status_code=422, detail=f"Cace até {MAXIMO_DE_INDICADORES_NA_CACA} indicadores por vez.")
    por_tipo = defaultdict(list)
    for tipo, valor in reconhecidos:
        por_tipo[tipo].append(valor)
    achados, contagem = [], Counter()
    with do_cliente(request, sessao) as con:
        # A busca olha dentro do log de cada evento: com período longo e muito evento, melhor parar e pedir menos.
        con.execute("SET LOCAL statement_timeout = '20s'")
        try:
            for tipo, valores in por_tipo.items():
                linhas = con.execute(
                    f"""SELECT id, ocorrido_em, severidade, regra_descricao, agente_nome AS ativo, usuario, host(ip_origem) AS ip_origem, bruto
                        FROM eventos WHERE ocorrido_em > now() - make_interval(days => %(d)s) AND {inteligencia_de_ameacas.CAMPOS_NO_PASSADO[tipo]}
                        ORDER BY ocorrido_em DESC LIMIT %(l)s""",
                    {"v": valores, "d": dados.dias, "l": LIMITE_DE_ACHADOS_NA_CACA}).fetchall()
                for linha in linhas:
                    vistos = _valores_do_evento(linha["ip_origem"], linha.pop("bruto"))[tipo]
                    for valor in sorted(vistos & set(valores)):
                        contagem[(tipo, valor)] += 1
                        achados.append({**linha, "tipo": tipo, "indicador": valor})
        except psycopg.errors.QueryCanceled:
            raise HTTPException(status_code=504, detail="A busca demorou demais. Diminua o período ou a lista.")
        vigiados = {(v["tipo"], v["valor"]) for v in con.execute(
            "SELECT DISTINCT tipo, valor FROM intel_indicadores WHERE valor = ANY(%s)", ([v for _, v in reconhecidos],)).fetchall()}
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'cacar_indicadores', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{len(reconhecidos)} indicadores, {dados.dias} dias, {len(achados)} eventos"))
        nos_logs = _contar_nos_logs(request, con, sessao, list(reconhecidos), dados.dias) if permissoes.pode(sessao["perfil"], permissoes.VER_BRUTO) else {}
    achados.sort(key=lambda a: a["ocorrido_em"], reverse=True)
    return {"dias": dados.dias, "ignorados": ignorados,
            "indicadores": [{"tipo": t, "valor": v, "eventos": contagem[(t, v)], "logs": nos_logs.get((t, v)), "vigiado": (t, v) in vigiados}
                            for t, v in reconhecidos],
            "achados": achados[:LIMITE_DE_ACHADOS_NA_CACA]}


@app.post("/api/inteligencia/vigiar", status_code=201)
def vigiar_indicadores(dados: Vigilancia, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """Passa a conferir cada evento novo contra os indicadores, como se viessem de uma fonte."""
    aceitos, recusados = {}, []
    for item in dados.indicadores:
        # Endereço interno ou reservado nunca bate na conferência dos eventos novos: vigiar seria prometer o que não acontece.
        valor = inteligencia_de_ameacas.normalizar(item.tipo, item.valor)
        if valor:
            aceitos[(item.tipo, valor)] = None
        else:
            recusados.append(item.valor[:100])
    if not aceitos:
        raise HTTPException(status_code=422, detail="Nenhum destes dá para vigiar. Endereços internos ou reservados ficam de fora.")
    with do_cliente(request, sessao) as con:
        fonte = con.execute("SELECT id FROM intel_fontes WHERE tipo = 'manual'").fetchone()
        if fonte:
            con.execute("UPDATE intel_fontes SET ativa = true WHERE id = %s", (fonte["id"],))
        else:
            fonte = con.execute(
                """INSERT INTO intel_fontes (cliente_id, nome, tipo, endereco, criado_por) VALUES (%s, 'Lista manual', 'manual', 'manual', %s)
                   RETURNING id""", (sessao["cliente_id"], sessao["usuario_id"])).fetchone()
        descricao = dados.descricao.strip() or f"Vigiado por {sessao['nome']}"
        for tipo, valor in aceitos:
            con.execute(
                """INSERT INTO intel_indicadores (cliente_id, fonte_id, tipo, valor, descricao) VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (fonte_id, tipo, valor) DO UPDATE SET ultima_vez = now(), descricao = EXCLUDED.descricao""",
                (sessao["cliente_id"], fonte["id"], tipo, valor, descricao[:200]))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'vigiar_indicadores', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{len(aceitos)} indicadores"))
    return {"vigiados": len(aceitos), "recusados": recusados}


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
    gerenciador_id: str | None = Field(default=None, max_length=64)


@app.get("/api/fim")
def visao_de_fim(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        caminhos = con.execute(
            "SELECT id, caminho, sistema, modo, estado, mensagem, criado_em FROM fim_caminhos WHERE estado <> 'desativado' ORDER BY sistema, caminho").fetchall()
        ativos_ = con.execute(
            """SELECT a.gerenciador_id, a.agente_id, a.nome, a.sistema, a.estado, a.fim_inicio, a.fim_fim,
                      (SELECT count(*) FROM fim_base b WHERE b.gerenciador_id = a.gerenciador_id AND b.agente_id = a.agente_id) AS arquivos
               FROM ativos a WHERE a.agente_id <> '000' ORDER BY a.nome""").fetchall()
        por_dia = con.execute(
            """SELECT ocorrido_em::date AS dia, bruto #>> '{syscheck,event}' AS mudanca, count(*) AS total FROM eventos
               WHERE 'syscheck' = ANY(regra_grupos) AND ocorrido_em >= now() - interval '30 days' GROUP BY 1, 2 ORDER BY 1""").fetchall()
    return {"caminhos": caminhos, "ativos": ativos_, "por_dia": por_dia}


@app.get("/api/fim/ativos/{agente}/arquivos")
def base_de_arquivos(agente: str, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True)), busca: str = "", deslocamento: int = 0, gerenciador: str = ""):
    if not re.fullmatch(r"[0-9]{3,8}", agente):
        raise HTTPException(status_code=404)
    termo = f"%{_sem_curinga(busca.strip()[:200])}%"
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            """SELECT caminho, tamanho, modificado_em, sha256, dono, permissao, count(*) OVER () AS total FROM fim_base
               WHERE agente_id = %s AND (%s = '' OR gerenciador_id = %s) AND caminho ILIKE %s ORDER BY caminho LIMIT %s OFFSET %s""",
            (agente, gerenciador, gerenciador, termo, TAMANHO_DA_PAGINA, max(0, deslocamento))).fetchall()
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
        ativo = con.execute("SELECT gerenciador_id FROM ativos WHERE agente_id = %s AND agente_id <> '000' AND (%s::text IS NULL OR gerenciador_id = %s) ORDER BY atualizado_em DESC LIMIT 1",
                            (dados.agente_id, dados.gerenciador_id, dados.gerenciador_id)).fetchone()
        if not ativo:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO fim_varreduras (cliente_id, gerenciador_id, agente_id, pedida_por) VALUES (%s, %s, %s, %s)",
                    (sessao["cliente_id"], ativo["gerenciador_id"], dados.agente_id, sessao["usuario_id"]))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'pedir_varredura_fim', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], dados.agente_id))
    return {"estado": "pendente"}


class RegraYara(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    fonte: str = Field(max_length=300000)


class AssinaturaDeYara(BaseModel):
    ativa: bool
    automatica: bool = True


@app.get("/api/yara")
def visao_de_yara(request: Request, sessao=Depends(exige(permissoes.VER))):
    """O servidor só aparece como pronto depois de avisar: o gerenciador não tem como saber se o script foi instalado."""
    with do_cliente(request, sessao) as con:
        regras = con.execute(
            "SELECT id, nome, identificadores, estado, mensagem, criado_em FROM yara_regras WHERE estado <> 'desativada' ORDER BY nome").fetchall()
        servidores = con.execute(
            """SELECT a.gerenciador_id, a.agente_id, a.nome, a.sistema, a.estado,
                      (SELECT max(e.ocorrido_em) FROM eventos e WHERE e.gerenciador_id = a.gerenciador_id AND e.agente_id = a.agente_id AND e.regra_id = %s) AS pronto_em,
                      (SELECT max(e.ocorrido_em) FROM eventos e WHERE e.gerenciador_id = a.gerenciador_id AND e.agente_id = a.agente_id AND e.regra_id = %s) AS erro_em
               FROM ativos a WHERE a.agente_id <> '000' ORDER BY a.nome""", (yara_regras.REGRA_PRONTO, yara_regras.REGRA_ERRO)).fetchall()
        achados = con.execute(
            """SELECT e.id, e.ocorrido_em, e.agente_nome AS ativo, e.bruto #>> '{data,yara_regra}' AS regra, e.bruto #>> '{data,yara_arquivo}' AS arquivo,
                      b.autor, b.repositorio, b.licenca, b.endereco
               FROM eventos e LEFT JOIN yara_biblioteca b ON b.nome = e.bruto #>> '{data,yara_regra}'
               WHERE e.regra_id = %s AND e.ocorrido_em >= now() - interval '30 days' ORDER BY e.ocorrido_em DESC LIMIT 100""", (yara_regras.REGRA_ACHADO,)).fetchall()
        assinatura = con.execute("SELECT ativa, automatica, versao, cardinality(excluidas) AS excluidas, estado, mensagem FROM yara_assinatura").fetchone()
        estado = con.execute(
            """SELECT b.versao, b.atualizada_em, b.erro, (SELECT regras FROM yara_pacotes p WHERE p.versao = b.versao) AS regras
               FROM bibliotecas_estado b WHERE b.nome = 'yara'""").fetchone()
    return {"regras": regras, "servidores": servidores, "achados": achados, "comando": yara_regras.COMANDO_DE_INSTALACAO,
            "comando_windows": yara_regras.COMANDO_DE_INSTALACAO_WINDOWS, "biblioteca": estado, "assinatura": assinatura}


@app.post("/api/yara/biblioteca")
def assinar_biblioteca_yara(dados: AssinaturaDeYara, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
        if dados.ativa and not con.execute("SELECT 1 FROM bibliotecas_estado WHERE nome = 'yara' AND versao IS NOT NULL").fetchone():
            raise HTTPException(status_code=409, detail="A biblioteca ainda não foi baixada. Tente de novo em alguns minutos.")
        con.execute(
            """INSERT INTO yara_assinatura (cliente_id, gerenciador_id, ativa, automatica) VALUES (%s, %s, %s, %s)
               ON CONFLICT (cliente_id) DO UPDATE SET ativa = EXCLUDED.ativa, automatica = EXCLUDED.automatica, estado = 'pendente', mensagem = NULL, atualizada_em = now()""",
            (sessao["cliente_id"], gerenciador["id"], dados.ativa, dados.automatica))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'mudar_biblioteca_yara', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"ativa={dados.ativa} automatica={dados.automatica}"))
    return {"estado": "pendente"}


@app.post("/api/yara/biblioteca/atualizar", status_code=202)
def atualizar_biblioteca_yara(request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """Para quem desligou a atualização sozinha: passa para a versão mais nova, uma vez."""
    with do_cliente(request, sessao) as con:
        atual = con.execute("SELECT versao FROM bibliotecas_estado WHERE nome = 'yara'").fetchone()
        linha = con.execute(
            "UPDATE yara_assinatura SET versao = %s, estado = 'pendente', mensagem = NULL, atualizada_em = now() WHERE ativa RETURNING cliente_id",
            (atual["versao"] if atual else None,)).fetchone()
        if not linha:
            raise HTTPException(status_code=409, detail="A biblioteca não está em uso.")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'atualizar_biblioteca_yara', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], atual["versao"]))
    return {"estado": "pendente"}


@app.get("/api/yara/biblioteca/regras")
def regras_da_biblioteca_yara(request: Request, sessao=Depends(exige(permissoes.VER)), busca: str = "", deslocamento: int = 0):
    deslocamento = max(0, min(deslocamento, 100000))
    termo = f"%{_sem_curinga(busca.strip()[:200])}%"
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            """SELECT nome, privada, descricao, autor, repositorio, licenca, endereco, pontuacao, count(*) OVER () AS total
               FROM yara_biblioteca WHERE nome ILIKE %s OR descricao ILIKE %s OR autor ILIKE %s OR repositorio ILIKE %s
               ORDER BY nome LIMIT %s OFFSET %s""", (termo, termo, termo, termo, TAMANHO_DA_PAGINA, deslocamento)).fetchall()
        linha = con.execute("SELECT excluidas FROM yara_assinatura").fetchone()
    excluidas = set(linha["excluidas"]) if linha else set()
    return {"regras": [{**l, "em_uso": l["nome"] not in excluidas} for l in linhas], "total": linhas[0]["total"] if linhas else 0}


@app.post("/api/yara/biblioteca/regras/{nome}/{acao}", status_code=204)
def escolher_regra_da_biblioteca(nome: str, acao: str, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    if acao not in ("usar", "nao-usar") or not re.fullmatch(r"\w{1,128}", nome):
        raise HTTPException(status_code=404)
    with do_cliente(request, sessao) as con:
        regra = con.execute("SELECT privada FROM yara_biblioteca WHERE nome = %s", (nome,)).fetchone()
        if not regra:
            raise HTTPException(status_code=404)
        if regra["privada"] and acao == "nao-usar":
            raise HTTPException(status_code=422, detail="Esta regra serve de base para outras e não pode sair sozinha.")
        conta = """array(SELECT DISTINCT x FROM unnest(excluidas) AS x WHERE x <> %s)""" if acao == "usar" else "array(SELECT DISTINCT x FROM unnest(excluidas || %s::text) AS x)"
        linha = con.execute(f"UPDATE yara_assinatura SET excluidas = {conta}, estado = 'pendente', mensagem = NULL, atualizada_em = now() RETURNING cliente_id", (nome,)).fetchone()
        if not linha:
            raise HTTPException(status_code=409, detail="Ative a biblioteca antes de escolher as regras.")
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, %s, %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], "usar_regra_yara" if acao == "usar" else "tirar_regra_yara", nome))


@app.post("/api/yara/regras", status_code=201)
def criar_regra_yara(dados: RegraYara, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    nome = dados.nome.strip()
    try:
        with do_cliente(request, sessao) as con:
            gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
            if not gerenciador:
                raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
            outras = [l["fonte"] for l in con.execute("SELECT fonte FROM yara_regras WHERE estado IN ('pendente', 'ativa')").fetchall()]
            # Com a biblioteca em uso, um nome repetido quebraria o conjunto todo nos servidores.
            outras += [l["conteudo"] for l in con.execute(
                "SELECT p.conteudo FROM yara_assinatura a JOIN yara_pacotes p ON p.versao = a.versao WHERE a.ativa").fetchall()]
            try:
                identificadores = yara_regras.validar(dados.fonte, outras)
            except yara_regras.RegraInvalida as erro:
                raise HTTPException(status_code=422, detail=str(erro))
            novo = con.execute(
                """INSERT INTO yara_regras (cliente_id, gerenciador_id, nome, fonte, identificadores, criado_por)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (sessao["cliente_id"], gerenciador["id"], nome, dados.fonte, identificadores, sessao["usuario_id"])).fetchone()["id"]
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_regra_yara', %s)",
                        (sessao["cliente_id"], sessao["usuario_id"], nome))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe uma regra com este nome.")
    return {"id": novo, "estado": "pendente", "identificadores": identificadores}


@app.post("/api/yara/regras/{identificador}/desativar", status_code=204)
def desativar_regra_yara(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute("UPDATE yara_regras SET estado = 'desativada' WHERE id = %s AND estado <> 'desativada' RETURNING nome", (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'desativar_regra_yara', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], linha["nome"]))


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


EMAIL = re.compile(r"[^@\s<>,;\"']{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}")
SEGUNDOS_ESPERANDO_O_EMAIL_DE_TESTE = 40


class ConfiguracaoDeEmail(BaseModel):
    servidor: str = Field(pattern=r"^[A-Za-z0-9.-]{1,253}$")
    porta: int
    seguranca: str = Field(pattern="^(starttls|ssl)$")
    usuario: str = Field(default="", max_length=200)
    # None mantém a senha guardada; texto vazio tira.
    senha: str | None = Field(default=None, max_length=500)
    remetente: str = Field(max_length=254)
    destinatarios: list[str] = Field(min_length=1, max_length=20)
    tipos: list[str] = Field(default_factory=list, max_length=40)
    ativo: bool = True


@app.get("/api/organizacao/email")
def email_da_organizacao(request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    with do_cliente(request, sessao) as con:
        config = con.execute("""SELECT servidor, porta, seguranca, usuario, remetente, destinatarios, tipos, ativo, ultimo_envio, ultimo_erro, teste_resultado, teste_em
                                FROM email_config""").fetchone()
        tem_senha = con.execute("SELECT 1 FROM segredos WHERE nome = %s", (avisos_por_email.SEGREDO,)).fetchone() is not None
    return {"config": config, "tem_senha": tem_senha, "tipos": avisos_por_email.NOMES}


@app.put("/api/organizacao/email", status_code=204)
def configurar_email(dados: ConfiguracaoDeEmail, request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    if dados.porta not in (25, 465, 587, 2525):
        raise HTTPException(status_code=422, detail="Use a porta 25, 465, 587 ou 2525.")
    enderecos = [e.strip() for e in dados.destinatarios if e.strip()]
    if not EMAIL.fullmatch(dados.remetente.strip()) or not enderecos or not all(EMAIL.fullmatch(e) for e in enderecos):
        raise HTTPException(status_code=422, detail="Confira o remetente e os destinatários: cada um precisa ser um e-mail.")
    with do_cliente(request, sessao) as con:
        # Começa do aviso mais novo: ligar o e-mail não manda o sino inteiro do passado.
        ultima = con.execute("SELECT coalesce(max(id), 0) AS n FROM notificacoes").fetchone()["n"]
        valores = (dados.servidor, dados.porta, dados.seguranca, dados.usuario.strip(), dados.remetente.strip(), enderecos, sorted(set(dados.tipos)), dados.ativo)
        con.execute("""INSERT INTO email_config (cliente_id, servidor, porta, seguranca, usuario, remetente, destinatarios, tipos, ativo, ultima_notificacao, atualizado_por)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (cliente_id) DO UPDATE SET servidor = EXCLUDED.servidor, porta = EXCLUDED.porta, seguranca = EXCLUDED.seguranca, usuario = EXCLUDED.usuario,
                         remetente = EXCLUDED.remetente, destinatarios = EXCLUDED.destinatarios, tipos = EXCLUDED.tipos, ativo = EXCLUDED.ativo,
                         atualizado_por = EXCLUDED.atualizado_por, atualizado_em = now()""",
                    (sessao["cliente_id"], *valores, ultima, sessao["usuario_id"]))
        if dados.senha is not None:
            con.execute("DELETE FROM segredos WHERE nome = %s", (avisos_por_email.SEGREDO,))
            if dados.senha:
                con.execute("INSERT INTO segredos (cliente_id, nome, selado, criado_por) VALUES (%s, %s, %s, %s)",
                            (sessao["cliente_id"], avisos_por_email.SEGREDO, cofre.selar(cofre.ler_publica(), sessao["cliente_id"], avisos_por_email.SEGREDO, dados.senha),
                             sessao["usuario_id"]))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'configurar_email', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{dados.servidor}:{dados.porta} para {len(enderecos)} destinatários"))


@app.delete("/api/organizacao/email", status_code=204)
def tirar_email(request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    with do_cliente(request, sessao) as con:
        con.execute("DELETE FROM email_config")
        con.execute("DELETE FROM segredos WHERE nome = %s", (avisos_por_email.SEGREDO,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'tirar_email', 'avisos por e-mail')", (sessao["cliente_id"], sessao["usuario_id"]))


@app.post("/api/organizacao/email/teste")
def testar_email(request: Request, sessao=Depends(exige(permissoes.GERIR_USUARIOS))):
    """Quem manda é o serviço de avisos, que abre a senha: o pedido fica marcado e a resposta volta em alguns segundos."""
    with do_cliente(request, sessao) as con:
        if not con.execute("UPDATE email_config SET teste_pedido_em = now(), teste_resultado = NULL RETURNING 1").fetchone():
            raise HTTPException(status_code=409, detail="Salve a configuração antes de testar.")
    fim = time.monotonic() + SEGUNDOS_ESPERANDO_O_EMAIL_DE_TESTE
    while time.monotonic() < fim:
        time.sleep(0.5)
        with do_cliente(request, sessao) as con:
            linha = con.execute("SELECT teste_pedido_em, teste_resultado FROM email_config").fetchone()
        if linha and linha["teste_pedido_em"] is None and linha["teste_resultado"]:
            if linha["teste_resultado"] != "ok":
                raise HTTPException(status_code=422, detail=linha["teste_resultado"])
            return {"enviado": True}
    raise HTTPException(status_code=504, detail="O servidor de e-mail demorou para responder. Tente de novo em instantes.")


class BlocoDeBusca(BaseModel):
    texto: str = Field(default="", max_length=2000)
    tipo: str = Field(pattern="^(numero|serie|rosca|barras|top|mapa|tabela)$")
    minutos: int
    campo: str | None = Field(default=None, max_length=120)
    tamanho: int = Field(default=10, ge=1, le=blocos_de_busca.MAXIMO_DE_LINHAS)


class BlocoDePainel(BlocoDeBusca):
    titulo: str = Field(min_length=1, max_length=80)
    # Colunas numa grade de 12. Os painéis da primeira versão guardaram 1 (metade) e 2 (inteira).
    largura: int = Field(default=6, ge=1, le=12)


class Painel(BaseModel):
    nome: str = Field(min_length=1, max_length=80)
    blocos: list[BlocoDePainel] = Field(default_factory=list, max_length=24)


class BuscaSalva(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    texto: str = Field(default="", max_length=2000)
    janela_minutos: int
    a_cada_minutos: int | None = Field(default=None, ge=5, le=10080)
    condicao: str = Field(default="qualquer", pattern="^(qualquer|mais_de|nenhum)$")
    limite: int = Field(default=0, ge=0, le=1_000_000_000)
    ativa: bool = True


def _conferir_busca(texto, tipo, minutos, campo=None, tamanho=10):
    try:
        blocos_de_busca.montar(texto, tipo, minutos, campo, tamanho)
    except blocos_de_busca.BuscaInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro)) from None


@app.get("/api/buscas/opcoes")
def opcoes_de_busca(sessao=Depends(exige(permissoes.VER))):
    return {"tipos": blocos_de_busca.TIPOS, "janelas": blocos_de_busca.JANELAS, "modelos": blocos_de_busca.MODELOS}


@app.post("/api/buscas/bloco")
def rodar_bloco(dados: BlocoDeBusca, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO, mascarar=True))):
    """Um bloco de painel. Os valores voltam na chave curta do campo, para a máscara reconhecer usuário e endereço."""
    with do_cliente(request, sessao) as con:
        gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
        onde = _armazem_da_organizacao(request, con, sessao)
    try:
        return blocos_de_busca.executar(request.app.state.indexer.post, INDEXER_URL, gerenciadores, dados.texto, dados.tipo, dados.minutos, dados.campo, dados.tamanho, **onde)
    except blocos_de_busca.BuscaInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro)) from None
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Não foi possível consultar os logs.") from None


@app.get("/api/buscas")
def buscas_salvas(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        linhas = con.execute("""SELECT id, nome, texto, janela_minutos, a_cada_minutos, condicao, limite, ativa, proxima_em, ultima_em, ultimo_total, ultimo_erro,
                                       criada_em, alterada_em,
                                       (SELECT count(*) FROM buscas_execucoes e WHERE e.busca_id = b.id AND e.disparou AND e.em >= now() - interval '7 days') AS disparos_7_dias
                                FROM buscas_salvas b ORDER BY nome""").fetchall()
    return {"buscas": linhas}


def _gravar_busca(con, dados, sessao, identificador=None):
    _conferir_busca(dados.texto, "numero", dados.janela_minutos)
    valores = (dados.nome.strip(), dados.texto.strip(), dados.janela_minutos, dados.a_cada_minutos, dados.condicao, dados.limite, dados.ativa)
    if identificador is None:
        return con.execute("""INSERT INTO buscas_salvas (cliente_id, nome, texto, janela_minutos, a_cada_minutos, condicao, limite, ativa, criada_por)
                              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""", (sessao["cliente_id"], *valores, sessao["usuario_id"])).fetchone()
    # Mudou a busca: roda no próximo ciclo, sem esperar o horário antigo.
    return con.execute("""UPDATE buscas_salvas SET nome = %s, texto = %s, janela_minutos = %s, a_cada_minutos = %s, condicao = %s, limite = %s, ativa = %s,
                          proxima_em = NULL, alterada_em = now() WHERE id = %s RETURNING id""", (*valores, identificador)).fetchone()


@app.post("/api/buscas", status_code=201)
def salvar_busca(dados: BuscaSalva, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    try:
        with do_cliente(request, sessao) as con:
            linha = _gravar_busca(con, dados, sessao)
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'salvar_busca', %s)", (sessao["cliente_id"], sessao["usuario_id"], dados.nome[:200]))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe uma busca com esse nome.")
    return {"id": linha["id"]}


@app.put("/api/buscas/{identificador}", status_code=204)
def mudar_busca(identificador: int, dados: BuscaSalva, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    _inteiro_valido(identificador)
    try:
        with do_cliente(request, sessao) as con:
            if not _gravar_busca(con, dados, sessao, identificador):
                raise HTTPException(status_code=404)
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'mudar_busca', %s)", (sessao["cliente_id"], sessao["usuario_id"], dados.nome[:200]))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe uma busca com esse nome.")


@app.delete("/api/buscas/{identificador}", status_code=204)
def apagar_busca(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute("DELETE FROM buscas_salvas WHERE id = %s RETURNING nome", (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'apagar_busca', %s)", (sessao["cliente_id"], sessao["usuario_id"], linha["nome"][:200]))


@app.get("/api/buscas/{identificador}/execucoes")
def execucoes_da_busca(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        return {"execucoes": con.execute("SELECT em, total, disparou, erro FROM buscas_execucoes WHERE busca_id = %s ORDER BY id DESC LIMIT 50", (identificador,)).fetchall()}


@app.get("/api/paineis")
def paineis(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        return {"paineis": con.execute("SELECT id, nome, blocos, criado_em, alterado_em FROM paineis ORDER BY nome").fetchall()}


def _gravar_painel(con, dados, sessao, identificador=None):
    for bloco in dados.blocos:
        _conferir_busca(bloco.texto, bloco.tipo, bloco.minutos, bloco.campo, bloco.tamanho)
    blocos = Jsonb([b.model_dump() for b in dados.blocos])
    if identificador is None:
        return con.execute("INSERT INTO paineis (cliente_id, nome, blocos, criado_por) VALUES (%s, %s, %s, %s) RETURNING id",
                           (sessao["cliente_id"], dados.nome.strip(), blocos, sessao["usuario_id"])).fetchone()
    return con.execute("UPDATE paineis SET nome = %s, blocos = %s, alterado_em = now() WHERE id = %s RETURNING id", (dados.nome.strip(), blocos, identificador)).fetchone()


@app.post("/api/paineis", status_code=201)
def criar_painel(dados: Painel, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO))):
    try:
        with do_cliente(request, sessao) as con:
            linha = _gravar_painel(con, dados, sessao)
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_painel', %s)", (sessao["cliente_id"], sessao["usuario_id"], dados.nome[:200]))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe um painel com esse nome.")
    return {"id": linha["id"]}


@app.put("/api/paineis/{identificador}", status_code=204)
def mudar_painel(identificador: int, dados: Painel, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO))):
    _inteiro_valido(identificador)
    try:
        with do_cliente(request, sessao) as con:
            if not _gravar_painel(con, dados, sessao, identificador):
                raise HTTPException(status_code=404)
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe um painel com esse nome.")


@app.get("/api/paineis/{identificador}/pdf")
def pdf_do_painel(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO, mascarar=True))):
    """O painel como está agora, em PDF, com a capa dos relatórios. Fica no histórico de relatórios, com o resumo do arquivo."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        painel = con.execute("SELECT nome, blocos FROM paineis WHERE id = %s", (identificador,)).fetchone()
        if not painel:
            raise HTTPException(status_code=404)
        gerenciadores = [g["id"] for g in con.execute("SELECT id FROM gerenciadores").fetchall()]
        onde = _armazem_da_organizacao(request, con, sessao)
    resultados = []
    for b in painel["blocos"]:
        try:
            resultados.append(blocos_de_busca.executar(request.app.state.indexer.post, INDEXER_URL, gerenciadores, b["texto"], b["tipo"], b["minutos"], b.get("campo"), b.get("tamanho", 10), **onde))
        except blocos_de_busca.BuscaInvalida as erro:
            resultados.append({"erro": str(erro)})
        except requests.RequestException:
            resultados.append({"erro": "Não foi possível consultar os logs."})
    mascara = getattr(request.state, "mascara", None)
    if mascara:
        resultados = mascara.dado(resultados)
        request.state.mascara = None
    conteudo = relatorios.gerar_pdf(relatorios.montar_html_do_painel(painel, resultados, sessao, blocos_de_busca.JANELAS))
    resumo = relatorios.resumo_do_arquivo(conteudo)
    nome = f"painel-{re.sub(r'[^a-z0-9]+', '-', painel['nome'].lower()).strip('-')[:60] or 'roar'}-{datetime.now(timezone.utc):%Y%m%d}.pdf"
    dias = max(1, -(-max((b["minutos"] for b in painel["blocos"]), default=1440) // 1440))
    with do_cliente(request, sessao) as con:
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'gerar_pdf_de_painel', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{painel['nome'][:120]} sha256:{resumo}"))
        guardado = _guardar_relatorio(con, sessao, "painel", painel["nome"][:120], dias, "pdf", nome, conteudo, resumo)
    return Response(conteudo, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{nome}"', "X-Resumo-SHA256": resumo, "X-Relatorio": str(guardado)})


@app.delete("/api/paineis/{identificador}", status_code=204)
def apagar_painel(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER_BRUTO))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute("DELETE FROM paineis WHERE id = %s RETURNING nome", (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'apagar_painel', %s)", (sessao["cliente_id"], sessao["usuario_id"], linha["nome"][:200]))


class PedidoDeParser(BaseModel):
    nome: str = Field(pattern=r"^[a-z0-9][a-z0-9_]{0,40}$")
    modo: str = Field(pattern="^(guiado|xml)$")
    definicao: dict | None = None
    xml: str | None = Field(default=None, max_length=parsers_proprios.TAMANHO_MAXIMO)


class NovoParser(PedidoDeParser):
    titulo: str = Field(min_length=1, max_length=120)
    exemplo: str = Field(default="", max_length=8000)


class TesteDeParser(BaseModel):
    log: str = Field(min_length=1, max_length=8000)
    parser: PedidoDeParser | None = None


SEGUNDOS_ESPERANDO_O_TESTE = 30


def _xml_do_parser(dados):
    try:
        return parsers_proprios.xml_do_pedido(dados.nome, dados.modo, dados.definicao, dados.xml)
    except parsers_proprios.ParserInvalido as erro:
        raise HTTPException(status_code=422, detail=str(erro)) from None


@app.get("/api/parsers")
def parsers_da_organizacao(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        linhas = con.execute("""SELECT id, nome, titulo, modo, definicao, xml, exemplo, ativo, estado, mensagem, criado_em, alterado_em, aplicado_em
                                FROM parsers ORDER BY titulo""").fetchall()
    return {"parsers": linhas, "valores": parsers_proprios.NOMES_DE_VALOR, "campos": parsers_proprios.CAMPOS_CONHECIDOS}


@app.post("/api/parsers/testar")
def testar_parser(dados: TesteDeParser, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    return _testar_no_servidor(request, sessao, dados.log, _xml_do_parser(dados.parser) if dados.parser else None)


class LinhaDeEquipamento(BaseModel):
    log: str = Field(min_length=1, max_length=8000)


@app.post("/api/fontes/testar-linha")
def testar_linha_de_equipamento(dados: LinhaDeEquipamento, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """Como o servidor lê uma linha do equipamento, antes de apontar o envio. Só lê: parser novo é na aba Parsers."""
    return _testar_no_servidor(request, sessao, dados.log, None)


def _testar_no_servidor(request, sessao, texto, xml):
    """Quem fala com o servidor é a ingestão: o pedido fica na fila e a resposta volta em um ou dois segundos."""
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY id LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Esta organização ainda não tem servidor para testar.")
        teste = con.execute("INSERT INTO parser_testes (cliente_id, gerenciador_id, log, xml) VALUES (%s, %s, %s, %s) RETURNING id",
                            (sessao["cliente_id"], gerenciador["id"], texto.strip(), xml)).fetchone()["id"]
    fim = time.monotonic() + SEGUNDOS_ESPERANDO_O_TESTE
    while time.monotonic() < fim:
        time.sleep(0.3)
        with do_cliente(request, sessao) as con:
            linha = con.execute("SELECT estado, resultado FROM parser_testes WHERE id = %s", (teste,)).fetchone()
        if linha["estado"] == "erro":
            raise HTTPException(status_code=502, detail=linha["resultado"].get("erro"))
        if linha["estado"] == "pronto":
            return {**linha["resultado"], "xml": xml}
    raise HTTPException(status_code=504, detail="O servidor demorou para responder ao teste. Tente de novo em instantes.")


@app.post("/api/parsers", status_code=201)
def criar_parser(dados: NovoParser, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    xml = _xml_do_parser(dados)
    try:
        with do_cliente(request, sessao) as con:
            linha = con.execute("""INSERT INTO parsers (cliente_id, nome, titulo, modo, definicao, xml, exemplo, criado_por)
                                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                                (sessao["cliente_id"], dados.nome, dados.titulo.strip(), dados.modo, Jsonb(dados.definicao) if dados.modo == "guiado" else None,
                                 xml, dados.exemplo, sessao["usuario_id"])).fetchone()
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_parser', %s)", (sessao["cliente_id"], sessao["usuario_id"], dados.nome))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe um parser com esse nome.")
    return {"id": linha["id"]}


def _parser(con, identificador):
    _inteiro_valido(identificador)
    linha = con.execute("SELECT id, nome FROM parsers WHERE id = %s", (identificador,)).fetchone()
    if not linha:
        raise HTTPException(status_code=404)
    return linha


@app.put("/api/parsers/{identificador}", status_code=204)
def mudar_parser(identificador: int, dados: NovoParser, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    with do_cliente(request, sessao) as con:
        atual = _parser(con, identificador)
        if atual["nome"] != dados.nome:
            raise HTTPException(status_code=422, detail="O nome do parser não muda depois de criado.")
        xml = _xml_do_parser(dados)
        con.execute("""UPDATE parsers SET titulo = %s, modo = %s, definicao = %s, xml = %s, exemplo = %s, estado = 'pendente', mensagem = NULL,
                       alterado_em = now() WHERE id = %s""",
                    (dados.titulo.strip(), dados.modo, Jsonb(dados.definicao) if dados.modo == "guiado" else None, xml, dados.exemplo, identificador))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'mudar_parser', %s)", (sessao["cliente_id"], sessao["usuario_id"], dados.nome))


@app.post("/api/parsers/{identificador}/ativo", status_code=204)
def ligar_parser(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS)), ligado: bool = True):
    with do_cliente(request, sessao) as con:
        atual = _parser(con, identificador)
        con.execute("UPDATE parsers SET ativo = %s, estado = 'pendente', mensagem = NULL, alterado_em = now() WHERE id = %s", (ligado, identificador))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, %s, %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], "ligar_parser" if ligado else "desligar_parser", atual["nome"]))


@app.delete("/api/parsers/{identificador}", status_code=204)
def apagar_parser(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    with do_cliente(request, sessao) as con:
        atual = _parser(con, identificador)
        con.execute("DELETE FROM parsers WHERE id = %s", (identificador,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'apagar_parser', %s)", (sessao["cliente_id"], sessao["usuario_id"], atual["nome"]))


class NovaLista(BaseModel):
    nome: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    titulo: str = Field(min_length=1, max_length=120)
    descricao: str = Field(default="", max_length=1000)
    tipo: str = Field(pattern="^(ip|usuario|dominio|hash|texto)$")


class MudancaDeLista(BaseModel):
    titulo: str = Field(min_length=1, max_length=120)
    descricao: str = Field(default="", max_length=1000)


class ItemDeLista(BaseModel):
    valor: str = Field(min_length=1, max_length=300)
    nota: str = Field(default="", max_length=200)


class ItensDeLista(BaseModel):
    itens: list[ItemDeLista] = Field(min_length=1, max_length=listas_de_observacao.ITENS_POR_VEZ)


class ValoresDeLista(BaseModel):
    valores: list[str] = Field(min_length=1, max_length=listas_de_observacao.ITENS_POR_VEZ)


def _lista(con, identificador):
    _inteiro_valido(identificador)
    lista = con.execute("SELECT id, nome, titulo, descricao, tipo, criada_em, alterada_em FROM listas WHERE id = %s", (identificador,)).fetchone()
    if not lista:
        raise HTTPException(status_code=404)
    return lista


@app.get("/api/listas")
def listas_de_observacao_da_organizacao(request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        linhas = con.execute("""SELECT l.id, l.nome, l.titulo, l.descricao, l.tipo, l.criada_em, l.alterada_em, count(i.valor) AS itens
                                FROM listas l LEFT JOIN listas_itens i ON i.lista_id = l.id GROUP BY l.id ORDER BY l.titulo""").fetchall()
    return {"listas": linhas, "tipos": listas_de_observacao.TIPOS, "limite": listas_de_observacao.ITENS_POR_LISTA}


@app.post("/api/listas", status_code=201)
def criar_lista(dados: NovaLista, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    try:
        with do_cliente(request, sessao) as con:
            linha = con.execute("INSERT INTO listas (cliente_id, nome, titulo, descricao, tipo, criada_por) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                                (sessao["cliente_id"], dados.nome, dados.titulo.strip(), dados.descricao.strip(), dados.tipo, sessao["usuario_id"])).fetchone()
            con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_lista', %s)", (sessao["cliente_id"], sessao["usuario_id"], dados.nome))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Já existe uma lista com esse nome.")
    return {"id": linha["id"]}


@app.get("/api/listas/{identificador}")
def ver_lista(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER))):
    with do_cliente(request, sessao) as con:
        lista = _lista(con, identificador)
        itens = con.execute("SELECT valor, nota, adicionado_em FROM listas_itens WHERE lista_id = %s ORDER BY valor LIMIT %s",
                            (identificador, listas_de_observacao.ITENS_POR_LISTA)).fetchall()
    return {**lista, "itens": itens, "regra": listas_de_observacao.exemplo_de_regra(lista["nome"], lista["tipo"], lista["titulo"]),
            "campo": listas_de_observacao.CONSULTA[lista["tipo"]][0]}


@app.put("/api/listas/{identificador}", status_code=204)
def mudar_lista(identificador: int, dados: MudancaDeLista, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    with do_cliente(request, sessao) as con:
        _lista(con, identificador)
        con.execute("UPDATE listas SET titulo = %s, descricao = %s, alterada_em = now() WHERE id = %s", (dados.titulo.strip(), dados.descricao.strip(), identificador))


@app.delete("/api/listas/{identificador}", status_code=204)
def apagar_lista(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    with do_cliente(request, sessao) as con:
        lista = _lista(con, identificador)
        con.execute("DELETE FROM listas WHERE id = %s", (identificador,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'apagar_lista', %s)", (sessao["cliente_id"], sessao["usuario_id"], lista["nome"]))


@app.post("/api/listas/{identificador}/itens")
def acrescentar_itens(identificador: int, dados: ItensDeLista, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    """Confere tudo antes de gravar: um item ruim recusa o pedido inteiro, com o motivo de cada um."""
    with do_cliente(request, sessao) as con:
        lista = _lista(con, identificador)
        bons, ruins = {}, []
        for item in dados.itens:
            try:
                bons[listas_de_observacao.normalizar(lista["tipo"], item.valor)] = item.nota.strip().replace("\n", " ")
            except listas_de_observacao.ItemInvalido as erro:
                ruins.append(str(erro))
        if ruins:
            raise HTTPException(status_code=422, detail=" ".join(ruins[:5]) + (f" E mais {len(ruins) - 5}." if len(ruins) > 5 else ""))
        outros = con.execute("SELECT count(*) AS n FROM listas_itens WHERE lista_id = %s AND NOT (valor = ANY(%s))", (identificador, list(bons))).fetchone()["n"]
        if outros + len(bons) > listas_de_observacao.ITENS_POR_LISTA:
            raise HTTPException(status_code=422, detail=f"Uma lista guarda até {listas_de_observacao.ITENS_POR_LISTA} itens.")
        with con.cursor() as cursor:
            cursor.executemany("""INSERT INTO listas_itens (cliente_id, lista_id, valor, nota, adicionado_por) VALUES (%s, %s, %s, %s, %s)
                                  ON CONFLICT (lista_id, valor) DO UPDATE SET nota = EXCLUDED.nota""",
                               [(sessao["cliente_id"], identificador, v, n, sessao["usuario_id"]) for v, n in bons.items()])
        con.execute("UPDATE listas SET alterada_em = now() WHERE id = %s", (identificador,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'acrescentar_itens_na_lista', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{lista['nome']}: {len(bons)} itens"))
    return {"gravados": len(bons)}


@app.post("/api/listas/{identificador}/itens/remover")
def remover_itens(identificador: int, dados: ValoresDeLista, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    with do_cliente(request, sessao) as con:
        lista = _lista(con, identificador)
        n = con.execute("DELETE FROM listas_itens WHERE lista_id = %s AND valor = ANY(%s)", (identificador, dados.valores)).rowcount
        con.execute("UPDATE listas SET alterada_em = now() WHERE id = %s", (identificador,))
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'remover_itens_da_lista', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{lista['nome']}: {n} itens"))
    return {"removidos": n}


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
        estado = con.execute("SELECT versao, atualizada_em, erro FROM bibliotecas_estado WHERE nome = 'sigma'").fetchone()
    return {"regras": linhas, "total_filtrado": linhas[0]["total_filtrado"] if linhas else 0, "estado": estado, **total}


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
    # O cartão do catálogo de onde veio (web/src/telas/Fontes.tsx): só para a tela mostrar a fonte no cartão certo.
    fabricante: Literal["fortigate", "pfsense", "opnsense", "paloalto", "sophos", "ciscoasa", "mikrotik"] | None = None


def _agregar_origens_de_syslog(request, gerenciador_id, onde=None):
    """Última vez que cada endereço mandou algo. Sem dado no índice, a tela diz que nunca recebeu."""
    if onde:
        try:
            return leitor_armazem.origens(onde["armazem"], onde["banco"], gerenciador_id, DIAS_DE_SAUDE)
        except (armazem_de_eventos.ArmazemRecusou, requests.RequestException):
            return None
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
    if fonte["tipo"] in ("syslog", "fluxo"):
        # O fluxo aparece com o exportador depois de "fluxo:" (saude_das_fontes.PREFIXO_DO_FLUXO).
        prefixo = saude_das_fontes.PREFIXO_DO_FLUXO if fonte["tipo"] == "fluxo" else ""
        redes = [ipaddress.ip_network(r) for r in fonte["config"]["origens"]]
        for local, ultimo in origens:
            if not local.startswith(prefixo) or (not prefixo and local.startswith(saude_das_fontes.PREFIXO_DO_FLUXO)):
                continue
            try:
                if ultimo and any(ipaddress.ip_address(local[len(prefixo):]) in rede for rede in redes):
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
        onde = _armazem_da_organizacao(request, con, sessao)
    resumo = None
    if onde and gerenciador and fontes:
        try:
            resumo = saude_das_fontes.ler(onde["armazem"], onde["banco"], gerenciador["id"])
        except (armazem_de_eventos.ArmazemRecusou, requests.RequestException):
            resumo = None  # Banco ainda sem o resumo por hora: a saúde sai da leitura antiga, sem a vazão.
    if resumo is not None:
        origens = [(local, o["ultimo"]) for local, o in resumo.items()]
    else:
        origens = _agregar_origens_de_syslog(request, gerenciador["id"], onde) if gerenciador and fontes else []
    for fonte in fontes:
        fonte.update(_saude_da_fonte(fonte, origens) if fonte["estado"] == "ativa" else {"saude": None, "ultimo_dado": None})
        if resumo is not None and fonte["estado"] == "ativa" and fonte["tipo"] in TIPOS_COM_VOLUME:
            fonte["volume"] = saude_das_fontes.da_fonte(fonte, resumo)
    return {"fontes": fontes, "agentes": agentes, "endereco": ENDERECO_PUBLICO,
            "porta_syslog": gerenciador["porta_base"] + DESLOCAMENTO_SYSLOG if gerenciador else None,
            # Só com o receptor preparado (infra/servicos.sh): sem ele, a tela não oferece o syslog cifrado.
            "porta_syslog_cifrado": PORTA_SYSLOG_CIFRADO if (PASTA_DO_SYSLOG_CIFRADO / "certificados" / "autoridade.pem").is_file() else None,
            # Fluxos de rede só com o coletor de fluxos preparado (infra/servicos.sh).
            "portas_de_fluxo": {"netflow": PORTA_NETFLOW, "sflow": PORTA_SFLOW} if (fluxos_de_rede.PASTA / "dados").is_dir() else None}


@app.get("/api/fontes/certificado-syslog")
def certificado_do_syslog_cifrado(sessao=Depends(exige(permissoes.VER))):
    """A autoridade que assina o certificado do receptor de syslog cifrado: o equipamento importa este arquivo para
    confiar no receptor. É público; a chave da autoridade fica no servidor."""
    arquivo = PASTA_DO_SYSLOG_CIFRADO / "certificados" / "autoridade.pem"
    if not arquivo.is_file():
        raise HTTPException(status_code=404, detail="O syslog cifrado ainda não foi preparado nesta instalação.")
    return Response(arquivo.read_bytes(), media_type="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="panthera-roar-syslog-cifrado.pem"'})


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
            (sessao["cliente_id"], gerenciador["id"], dados.nome, json.dumps({"protocolo": dados.protocolo, "origens": origens, **({"fabricante": dados.fabricante} if dados.fabricante else {})}), sessao["usuario_id"])).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_fonte', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(nova)))
    return {"id": nova, "estado": "pendente"}


class FonteDeFluxo(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    origens: list[str] = Field(max_length=200)


@app.post("/api/fontes/fluxo", status_code=201)
def criar_fonte_de_fluxo(dados: FonteDeFluxo, request: Request, sessao=Depends(exige(permissoes.GERIR_FONTES))):
    """Os equipamentos que exportam NetFlow, IPFIX ou sFlow para esta organização (roar_ingestao.fluxos)."""
    try:
        origens = fontes_de_dados.validar_fluxo(dados.origens)
    except fontes_de_dados.FonteInvalida as erro:
        raise HTTPException(status_code=422, detail=str(erro))
    with do_cliente(request, sessao) as con:
        gerenciador = con.execute("SELECT id FROM gerenciadores ORDER BY criado_em DESC LIMIT 1").fetchone()
        if not gerenciador:
            raise HTTPException(status_code=409, detail="Nenhum gerenciador disponível.")
        if not _armazem_da_organizacao(request, con, sessao):
            raise HTTPException(status_code=409, detail="Os fluxos de rede ficam no armazém novo, e esta organização ainda não lê dele.")
        nova = con.execute("INSERT INTO fontes (cliente_id, gerenciador_id, tipo, nome, config, criada_por) VALUES (%s, %s, 'fluxo', %s, %s, %s) RETURNING id",
                           (sessao["cliente_id"], gerenciador["id"], dados.nome, json.dumps({"origens": origens}), sessao["usuario_id"])).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'criar_fonte', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], str(nova)))
    return {"id": nova, "estado": "pendente"}


@app.get("/api/fluxos")
def ver_fluxos(request: Request, sessao=Depends(exige(permissoes.VER)), horas: int = 24, ip: str = ""):
    """Os fluxos de rede da organização no armazém: totais, horas, quem mais conversa, portas, países e os mais recentes."""
    horas = max(1, min(horas, 24 * 30))
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            raise HTTPException(status_code=422, detail="Endereço inválido.")
    with do_cliente(request, sessao) as con:
        onde = _armazem_da_organizacao(request, con, sessao)
    if not onde:
        return {"disponivel": False}
    try:
        return {"disponivel": True, **leitor_armazem.fluxos(onde["armazem"], onde["banco"], horas, ip or None)}
    except (armazem_de_eventos.ArmazemRecusou, requests.RequestException):
        raise HTTPException(status_code=503, detail="O armazém não respondeu. Tente de novo em instantes.")


class FonteDeNuvem(BaseModel):
    nome: str = Field(min_length=1, max_length=120)
    tipo: str = Field(pattern="^(github|office365|msgraph|aws|azure|gcp|okta|workspace|slack|pagerduty|virustotal|maltiverse)$")
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
        {"nome": "Windows (PowerShell como administrador)", "provado": True, "comando":
            f"Invoke-WebRequest -UseBasicParsing -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-{VERSAO_DO_AGENTE}-1.msi -OutFile agente.msi; "
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
        elif quando["tipo"] == "indicador":
            lista = fatos.indicadores_recentes(con, DIAS_DE_SIMULACAO, LIMITE_DE_SIMULACAO)
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


# Os mesmos números do motor de UEBA (Parametros): o teste confere que não se separaram.
MEIA_VIDA_DO_RISCO_HORAS = 24.0
LIMITE_DO_RISCO_ALTO = 60.0
LIMITE_DO_RISCO_CRITICO = 100.0
# Os mesmos do motor do UEBA; o teste confere que não divergem.
APRENDIZADO_DIAS = 14
APRENDIZADO_SUCESSOS = 20
HORARIO_MINIMO = 30
HORARIO_PROBABILIDADE = 0.02
LIMITE_DO_NORMAL = 15

# A técnica do ATT&CK que cada sinal sugere. A do próprio evento, quando houver, vem antes.
TECNICA_DO_SINAL = {
    "sucesso_apos_falhas": "T1110", "pico_de_falhas": "T1110",
    "viagem_impossivel": "T1078", "horario_incomum": "T1078", "primeiro_ip": "T1078",
    "primeiro_privilegio": "T1548", "primeiro_host": "T1021", "host_raro_no_cliente": "T1021",
    "ioc_tocado": "T1071", "grupo_administrativo": "T1098", "conta_criada": "T1136", "arquivo_sensivel": "T1222",
    "pessoa_em_risco": "T1078", "ativo_em_risco": "T1021",
}


def _linha_do_tempo(sinais, tecnicas):
    """Em ordem de acontecimento, com o risco logo depois de cada sinal, pela mesma conta do motor."""
    janela = timedelta(hours=MEIA_VIDA_DO_RISCO_HORAS * 7)
    ordenados = sorted(sinais, key=lambda s: s["ocorrido_em"])
    for i, s in enumerate(ordenados):
        risco = 0.0
        for anterior in ordenados[:i + 1]:
            idade = s["ocorrido_em"] - anterior["ocorrido_em"]
            if idade < janela:
                risco += float(anterior["peso"]) * 0.5 ** (idade.total_seconds() / 3600 / MEIA_VIDA_DO_RISCO_HORAS)
        s["risco_depois"] = round(risco, 1)
        do_evento = [t for t in (s.pop("mitre") or []) if t.split(".")[0] in tecnicas]
        codigo = do_evento[0] if do_evento else (s.get("detalhes") or {}).get("tecnica") or TECNICA_DO_SINAL.get(s["tipo"])
        tecnica = tecnicas.get(codigo) or tecnicas.get((codigo or "").split(".")[0])
        s["tecnica"] = {"codigo": codigo, **tecnica} if tecnica else None
    return ordenados


@app.get("/api/riscos/{identificador}")
def risco(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        alerta = con.execute(
            """SELECT a.id, a.entidade_id, a.severidade, a.risco_maximo, a.aberto_em, a.encerrado_em, a.estado,
                      a.motivo, a.nota, a.decidido_por_nome,
                      e.tipo AS entidade_tipo, coalesce(e.nome, e.chave) AS entidade, e.risco AS risco_atual,
                      e.primeira_vista, e.sucessos, e.risco_desde,
                      (SELECT t.criticidade FROM ativos t WHERE e.tipo = 'ativo'
                        AND t.gerenciador_id || ':' || t.agente_id = e.chave) AS criticidade
               FROM alertas_risco a JOIN entidades e ON e.id = a.entidade_id WHERE a.id = %s""",
            (identificador,)).fetchone()
        if not alerta:
            raise HTTPException(status_code=404)
        # Alerta aberto depois de uma decisão só conta o que veio depois dela, como o motor.
        desde = alerta.pop("risco_desde")
        desde = desde if desde and desde <= alerta["aberto_em"] else None
        sinais = con.execute(
            """SELECT s.tipo, s.peso, s.ocorrido_em, s.detalhes, v.id AS evento_id, v.regra_descricao,
                      v.agente_nome AS ativo, host(v.ip_origem) AS ip_origem, v.usuario, v.mitre, v.pais
               FROM sinais s JOIN eventos v ON v.id = s.evento_id
               WHERE s.entidade_id = %s AND s.ocorrido_em >= %s::timestamptz - interval '7 days'
                 AND s.ocorrido_em > coalesce(%s, '-infinity'::timestamptz)
               ORDER BY s.ocorrido_em DESC LIMIT 200""",
            (alerta["entidade_id"], alerta["aberto_em"], desde)).fetchall()
        pares = con.execute(
            """SELECT coalesce(e.nome, e.chave) AS entidade, e.tipo AS entidade_tipo, round(p.semelhanca::numeric, 2) AS semelhanca
               FROM pares p JOIN entidades e ON e.id = p.par_id WHERE p.entidade_id = %s ORDER BY p.semelhanca DESC""",
            (alerta["entidade_id"],)).fetchall()
        silencios = con.execute(
            """SELECT id, tipo, motivo, criado_por_nome, criado_em, expira_em FROM silencios
               WHERE entidade_id = %s AND (expira_em IS NULL OR expira_em > now()) ORDER BY criado_em DESC""",
            (alerta["entidade_id"],)).fetchall()
        do_evento = {t for s in sinais for t in (s["mitre"] or [])} | {s["detalhes"]["tecnica"] for s in sinais if (s["detalhes"] or {}).get("tecnica")}
        codigos = sorted(do_evento | {t.split(".")[0] for t in do_evento} | set(TECNICA_DO_SINAL.values()))
        tecnicas = {t["tecnica"]: {"nome": t["nome"], "tatica": t["tatica"]} for t in con.execute(
            """SELECT a.tecnica, a.nome, coalesce(t.nome, a.taticas[1]) AS tatica
               FROM tecnicas_attack a LEFT JOIN taticas_attack t ON t.tatica = a.taticas[1]
               WHERE a.tecnica = ANY(%s)""", (codigos,)).fetchall()}
    return {"alerta": alerta, "sinais": _linha_do_tempo(sinais, tecnicas), "pares": pares, "silencios": silencios,
            "limites": {"alto": LIMITE_DO_RISCO_ALTO, "critico": LIMITE_DO_RISCO_CRITICO, "meia_vida_horas": MEIA_VIDA_DO_RISCO_HORAS}}


def _horas_do_normal(contagens):
    """As 24 horas, marcando as que o motor acharia incomuns, pela mesma conta dele."""
    total = sum(contagens.values())
    conhecido = total >= HORARIO_MINIMO
    horas = []
    for hora in range(24):
        vizinhas = sum(contagens.get((hora + d) % 24, 0) for d in (-1, 0, 1))
        horas.append({"hora": hora, "contagem": contagens.get(hora, 0),
                      "incomum": conhecido and (vizinhas + 1) / (total + 24) < HORARIO_PROBABILIDADE})
    return horas, total, conhecido


@app.get("/api/entidades/{identificador}/normal")
def normal_da_entidade(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True))):
    """O que o UEBA aprendeu como normal: é contra isso que cada sinal de "primeira vez" é medido."""
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        entidade = con.execute(
            """SELECT id, tipo AS entidade_tipo, coalesce(nome, chave) AS entidade, chave, primeira_vista, ultima_vista, sucessos, risco
               FROM entidades WHERE id = %s""", (identificador,)).fetchone()
        if not entidade:
            raise HTTPException(status_code=404)
        chave = entidade.pop("chave")
        nomes = {}

        def nome_do_ativo(valor):
            if valor not in nomes:
                linha = con.execute("SELECT coalesce(nome, chave) AS nome FROM entidades WHERE tipo = 'ativo' AND chave = %s", (valor,)).fetchone()
                nomes[valor] = linha["nome"] if linha else valor
            return nomes[valor]

        def vistos(dimensao):
            linhas = con.execute(
                """SELECT valor, contagem, primeira_vez, count(*) OVER () AS total FROM vistos
                   WHERE entidade_id = %s AND dimensao = %s ORDER BY contagem DESC, valor LIMIT %s""",
                (identificador, dimensao, LIMITE_DO_NORMAL)).fetchall()
            return linhas, (linhas[0]["total"] if linhas else 0)

        if entidade["entidade_tipo"] == "ativo":
            # O ativo não tem rotina própria: o normal dele é quem costuma entrar.
            pessoas = con.execute(
                """SELECT coalesce(e.nome, e.chave) AS usuario, v.contagem, v.primeira_vez, count(*) OVER () AS total
                   FROM vistos v JOIN entidades e ON e.id = v.entidade_id
                   WHERE v.dimensao = 'host' AND v.valor = %s ORDER BY v.contagem DESC LIMIT %s""",
                (chave, LIMITE_DO_NORMAL)).fetchall()
            return {"entidade": entidade, "pessoas": [{k: v for k, v in p.items() if k != "total"} for p in pessoas],
                    "total_de_pessoas": pessoas[0]["total"] if pessoas else 0}

        contagens = {h["hora"]: h["contagem"] for h in con.execute(
            "SELECT hora, contagem FROM horas WHERE entidade_id = %s", (identificador,)).fetchall()}
        ativos, total_de_ativos = vistos("host")
        ips, total_de_ips = vistos("ip")
        privilegios, total_de_privilegios = vistos("privilegio")
        cria_conta, _ = vistos("cria_conta")
        ativos = [{"ativo": nome_do_ativo(v["valor"]), "contagem": v["contagem"], "primeira_vez": v["primeira_vez"]} for v in ativos]
        ips = [{"ip": v["valor"], "contagem": v["contagem"], "primeira_vez": v["primeira_vez"]} for v in ips]
        privilegios = [{"ativo": nome_do_ativo(":".join(v["valor"].split(":", 2)[:2])), "como": v["valor"].split(":", 2)[-1],
                        "contagem": v["contagem"], "primeira_vez": v["primeira_vez"]} for v in privilegios]
        cria_conta = [{"ativo": nome_do_ativo(v["valor"]), "contagem": v["contagem"]} for v in cria_conta]
    horas, total_de_acessos, conhecido = _horas_do_normal(contagens)
    ate = entidade["primeira_vista"] + timedelta(days=APRENDIZADO_DIAS)
    faltam = max(0, APRENDIZADO_SUCESSOS - entidade["sucessos"])
    return {"entidade": entidade, "horas": horas, "total_de_acessos": total_de_acessos, "horario_conhecido": conhecido,
            "aprendizado": {"aprendendo": faltam > 0 or ate > datetime.now(timezone.utc), "ate": ate, "acessos_faltando": faltam},
            "ativos": ativos, "total_de_ativos": total_de_ativos, "ips": ips, "total_de_ips": total_de_ips,
            "privilegios": privilegios, "total_de_privilegios": total_de_privilegios, "cria_conta": cria_conta}


class DecisaoDeRisco(BaseModel):
    motivo: str = Field(pattern="^(resolvido|falso_positivo|esperado)$")
    nota: str = Field(default="", max_length=500)


# O sinal de "primeira vez" e o que ele ensina quando o analista diz que era esperado.
APRENDE_COM_O_SINAL = {"primeiro_host": "host", "host_raro_no_cliente": "host", "primeiro_ip": "ip", "primeiro_privilegio": "privilegio",
                       "conta_criada": "cria_conta"}


@app.post("/api/riscos/{identificador}/decisao", status_code=204)
def decidir_risco(identificador: int, dados: DecisaoDeRisco, request: Request, sessao=Depends(exige(permissoes.TRIAR))):
    """Encerra o risco e zera o que o abriu. "Falso positivo" e "esperado" também ensinam: aquilo vira normal para a pessoa."""
    _inteiro_valido(identificador)
    nota = dados.nota.strip()
    with do_cliente(request, sessao) as con:
        alerta = con.execute("SELECT id, entidade_id, aberto_em FROM alertas_risco WHERE id = %s AND estado = 'aberto' FOR UPDATE",
                             (identificador,)).fetchone()
        if not alerta:
            raise HTTPException(status_code=409, detail="Este risco já foi encerrado.")
        agora = datetime.now(timezone.utc)
        anterior = con.execute("SELECT risco_desde FROM entidades WHERE id = %s", (alerta["entidade_id"],)).fetchone()["risco_desde"]
        con.execute("""UPDATE alertas_risco SET estado = 'encerrado', encerrado_em = %s, motivo = %s, nota = %s,
                         decidido_por = %s, decidido_por_nome = %s WHERE id = %s""",
                    (agora, dados.motivo, nota or None, sessao["usuario_id"], sessao["nome"], identificador))
        con.execute("UPDATE entidades SET risco = 0, risco_em = %s, risco_desde = %s WHERE id = %s", (agora, agora, alerta["entidade_id"]))
        aprendidos = 0
        if dados.motivo in ("falso_positivo", "esperado"):
            for tipo, dimensao in APRENDE_COM_O_SINAL.items():
                aprendidos += con.execute(
                    """INSERT INTO vistos (cliente_id, entidade_id, dimensao, valor, primeira_vez)
                       SELECT DISTINCT ON (valor) cliente_id, entidade_id, %s, valor, ocorrido_em FROM sinais
                       WHERE entidade_id = %s AND tipo = %s AND ocorrido_em >= %s::timestamptz - interval '7 days'
                         AND ocorrido_em > coalesce(%s, '-infinity'::timestamptz)
                       ORDER BY valor, ocorrido_em
                       ON CONFLICT DO NOTHING""",
                    (dimensao, alerta["entidade_id"], tipo, alerta["aberto_em"], anterior)).rowcount
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'decidir_risco', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{identificador} {dados.motivo}" + (f" ({aprendidos} aprendidos)" if aprendidos else "")))


class NovoSilencio(BaseModel):
    tipo: str = Field(max_length=64)
    entidade_id: int | None = None
    motivo: str = Field(min_length=1, max_length=500)
    dias: int | None = Field(default=None, ge=1, le=365)


@app.get("/api/silencios")
def silencios(request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True))):
    with do_cliente(request, sessao) as con:
        linhas = con.execute(
            """SELECT s.id, s.tipo, s.motivo, s.criado_por_nome, s.criado_em, s.expira_em, s.entidade_id,
                      coalesce(e.nome, e.chave) AS entidade, e.tipo AS entidade_tipo
               FROM silencios s LEFT JOIN entidades e ON e.id = s.entidade_id
               WHERE s.expira_em IS NULL OR s.expira_em > now() ORDER BY s.criado_em DESC""").fetchall()
    return {"silencios": linhas}


@app.post("/api/silencios", status_code=201)
def silenciar(dados: NovoSilencio, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    """Um tipo de sinal deixa de somar, para uma pessoa ou para todas. Vale daqui para frente: o que já somou fica."""
    if dados.tipo not in {r["tipo"] for r in REGRAS_DE_COMPORTAMENTO}:
        raise HTTPException(status_code=422, detail="Sinal desconhecido.")
    expira = datetime.now(timezone.utc) + timedelta(days=dados.dias) if dados.dias else None
    with do_cliente(request, sessao) as con:
        if dados.entidade_id is not None and not con.execute("SELECT 1 FROM entidades WHERE id = %s", (dados.entidade_id,)).fetchone():
            raise HTTPException(status_code=404)
        novo = con.execute(
            """INSERT INTO silencios (cliente_id, entidade_id, tipo, motivo, criado_por, criado_por_nome, expira_em)
               VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (sessao["cliente_id"], dados.entidade_id, dados.tipo, dados.motivo.strip(), sessao["usuario_id"], sessao["nome"], expira)).fetchone()["id"]
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'silenciar_sinal', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{dados.tipo} {'entidade ' + str(dados.entidade_id) if dados.entidade_id else 'todos'}"))
    return {"id": novo}


@app.delete("/api/silencios/{identificador}", status_code=204)
def remover_silencio(identificador: int, request: Request, sessao=Depends(exige(permissoes.GERIR_REGRAS))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        linha = con.execute("DELETE FROM silencios WHERE id = %s RETURNING tipo", (identificador,)).fetchone()
        if not linha:
            raise HTTPException(status_code=404)
        con.execute("INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo) VALUES (%s, %s, 'remover_silencio', %s)",
                    (sessao["cliente_id"], sessao["usuario_id"], f"{identificador} {linha['tipo']}"))


@app.get("/api/grupos/{identificador}")
def grupo(identificador: int, request: Request, sessao=Depends(exige(permissoes.VER, mascarar=True))):
    _inteiro_valido(identificador)
    with do_cliente(request, sessao) as con:
        dados = con.execute(
            """SELECT g.id, g.severidade, g.nivel, g.total, g.regras, g.primeira_em, g.ultima_em,
                      host(g.ip_origem) AS ip_origem, g.agente_id,
                      EXISTS (SELECT 1 FROM intel_ocorrencias o JOIN eventos v ON v.id = o.evento_id WHERE v.grupo_id = g.id) AS indicador
               FROM grupos_alerta g WHERE g.id = %s""",
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


@app.get("/novo", include_in_schema=False)
@app.get("/novo/{resto:path}", include_in_schema=False)
def endereco_antigo(resto: str = ""):
    """Quem guardou o endereço de quando a console nova ficava ao lado da antiga."""
    return RedirectResponse(f"/{resto}" if re.fullmatch(r"[a-z0-9/-]*", resto) and not resto.startswith("/") else "/")


# Fica por último: toda rota da console devolve a mesma página, mas caminho de API desconhecido continua 404.
@app.get("/{resto:path}", include_in_schema=False)
def console(request: Request, resto: str = ""):
    pagina = ESTATICO / "console" / "index.html"
    # Arquivo que não existe e rota fechada não podem parecer tela.
    if resto.split("/")[0] in ("api", "docs", "redoc") or "." in resto or not pagina.exists():
        raise HTTPException(status_code=404)
    request.state.chave_de_estilo = secrets.token_urlsafe(18)
    return Response(pagina.read_text(encoding="utf-8").replace("__CHAVE__", request.state.chave_de_estilo), media_type="text/html")
