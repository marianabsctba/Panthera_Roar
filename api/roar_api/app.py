"""API e tela do Roar. Por enquanto só leitura: fila de alertas e detalhe com as evidências.

    ROAR_API_ENDERECO=127.0.0.1:5433 uvicorn roar_api.app:app --port 8600

O cliente de cada consulta vem da sessão e vira a definição do RLS da transação. Nenhuma rota
aceita cliente vindo do navegador, então um id de outro cliente simplesmente não é encontrado.
"""

import hashlib
import os
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

ESTATICO = Path(__file__).parent / "estatico"
COOKIE = "roar_sessao"
HORAS_DE_SESSAO = 12
TENTATIVAS = 5
JANELA_TENTATIVAS = 900
# Abaixo disso são acontecimentos normais, como login: alimentam o UEBA, mas não pedem atenção.
NIVEL_MINIMO_NA_FILA = 5
TAMANHO_DA_PAGINA = 100
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


def _url_do_banco():
    url = os.getenv("ROAR_API_URL")
    if url:
        return url
    valores = {}
    with open(os.getenv("ROAR_ENV", "/opt/panthera-roar/.env"), encoding="utf-8") as f:
        for linha in f:
            if "=" in linha and not linha.startswith("#"):
                k, v = linha.strip().split("=", 1)
                valores[k] = v
    return (f"postgresql://roar_api:{valores['ROAR_API_SENHA']}@"
            f"{os.getenv('ROAR_BANCO_ENDERECO', '127.0.0.1:5433')}/roar")


@asynccontextmanager
async def ciclo_de_vida(app):
    app.state.banco = ConnectionPool(_url_do_banco(), min_size=1, max_size=10, open=True,
                                     kwargs={"row_factory": dict_row})
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
    if request.url.path.startswith("/api/"):
        resposta.headers["Cache-Control"] = "no-store"
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


@app.post("/api/entrar", status_code=204)
def entrar(dados: Entrada, request: Request, response: Response):
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
        con.execute("SELECT roar_criar_sessao(%s, %s, %s)", (_hash_do_token(token), usuario["id"], HORAS_DE_SESSAO))
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/",
                        secure=os.getenv("ROAR_COOKIE_SEGURO", "1") == "1", max_age=HORAS_DE_SESSAO * 3600)


@app.post("/api/sair", status_code=204)
def sair(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        with request.app.state.banco.connection() as con:
            con.execute("SELECT roar_encerrar_sessao(%s)", (_hash_do_token(token),))
    response.delete_cookie(COOKIE, path="/")


@app.get("/api/eu")
def eu(sessao=Depends(sessao_atual)):
    return {"nome": sessao["nome"], "cliente": sessao["cliente_nome"], "fuso": sessao["fuso"]}


@app.get("/api/fila")
def fila(request: Request, sessao=Depends(sessao_atual), limite: int = 200):
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
def panorama(request: Request, sessao=Depends(sessao_atual), dias: int = 30):
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
def eventos(request: Request, sessao=Depends(sessao_atual), busca: str = "", severidade: str = "",
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
def evento_bruto(identificador: int, request: Request, sessao=Depends(sessao_atual)):
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


@app.get("/api/regras")
def regras(request: Request, sessao=Depends(sessao_atual), busca: str = "", dias: int = 30,
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
                       coalesce(d.total, 0) AS disparos, d.ultimo, count(*) OVER () AS total_filtrado
                FROM regras r LEFT JOIN disparos d ON d.gerenciador_id = r.gerenciador_id AND d.regra_id = r.regra_id
                WHERE {' AND '.join(condicoes)}
                ORDER BY coalesce(d.total, 0) DESC, r.nivel DESC, r.regra_id LIMIT %s OFFSET %s""",
            (dias, *parametros, TAMANHO_DA_PAGINA, deslocamento)).fetchall()
        catalogo = con.execute("SELECT count(*) AS total, max(atualizado_em) AS atualizado_em FROM regras").fetchone()
    return {"regras": linhas, "total_filtrado": linhas[0]["total_filtrado"] if linhas else 0,
            "catalogo": catalogo["total"], "atualizado_em": catalogo["atualizado_em"],
            "comportamento": REGRAS_DE_COMPORTAMENTO}


def _inteiro_valido(identificador):
    # Fora do alcance de bigint viraria erro do banco; para quem pede, é só "não encontrado".
    if not 0 < identificador < 2**63:
        raise HTTPException(status_code=404)


@app.get("/api/riscos/{identificador}")
def risco(identificador: int, request: Request, sessao=Depends(sessao_atual)):
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
def grupo(identificador: int, request: Request, sessao=Depends(sessao_atual)):
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
