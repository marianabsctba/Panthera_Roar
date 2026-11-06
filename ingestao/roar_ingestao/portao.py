"""Portão entre os gerenciadores e o indexador, só para o que os detectores do Wazuh gravam.

    python -m roar_ingestao.portao

O conector do Wazuh tenta criar os modelos de índice toda vez que liga, mesmo que já existam. Criar modelo é
permissão do cluster inteiro: com ela, um gerenciador mexeria nos índices das outras organizações. Aqui o pedido
de criar modelo recebe "ok" e não segue; os modelos de verdade são criados por provisao.preparar, com a credencial
de administração. Todo o resto segue como chegou, com a credencial do próprio gerenciador, e é o indexador que
decide: cada gerenciador só alcança os próprios índices de estado.

O portão não guarda credencial e não acrescenta permissão. Escuta só no endereço da rede dos contêineres.
"""

import contextlib
import logging
import os
import ssl
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

log = logging.getLogger("roar.portao")
PASTA = Path(os.getenv("ROAR_PORTAO_PASTA", "/opt/panthera-roar/portao"))
PORTA = 9201
INDEXADOR = os.getenv("ROAR_INDEXER_URL", "https://127.0.0.1:9200")
# O certificado do indexador é emitido para este nome; a conexão vai pelo IP, então o nome vai na verificação.
NOME_DO_INDEXADOR = "wazuh.indexer"
LIMITE_DO_CORPO = 64 * 1024 * 1024
# O que passa sem tocar no conteúdo. Content-Length e Host são refeitos pelo cliente.
CABECALHOS_QUE_SEGUEM = ("authorization", "content-type", "accept", "accept-encoding", "content-encoding")


def modelo_de_indice(metodo, caminho):
    return metodo in ("PUT", "POST") and caminho.startswith(("/_index_template/", "/_template/", "/_component_template/"))


def _cliente():
    contexto = ssl.create_default_context(cafile=os.getenv("ROAR_INDEXER_CA", "/opt/panthera-roar/ca-indexer.pem"))
    return httpx.AsyncClient(verify=contexto, timeout=httpx.Timeout(120, connect=10))


async def repassar(request: Request):
    caminho = request.url.path
    if modelo_de_indice(request.method, caminho):
        # Já existe: provisao.preparar criou, com o mesmo conteúdo que vem no gerenciador.
        log.info("modelo de índice respondido sem repassar: %s", caminho)
        return JSONResponse({"acknowledged": True})
    corpo = await request.body()
    if len(corpo) > LIMITE_DO_CORPO:
        return JSONResponse({"error": "corpo grande demais"}, status_code=413)
    cabecalhos = {k: v for k, v in request.headers.items() if k.lower() in CABECALHOS_QUE_SEGUEM}
    destino = f"{INDEXADOR}{caminho}" + (f"?{request.url.query}" if request.url.query else "")
    try:
        resposta = await request.app.state.cliente.request(request.method, destino, content=corpo, headers=cabecalhos,
                                                           extensions={"sni_hostname": NOME_DO_INDEXADOR})
    except httpx.HTTPError as erro:
        log.warning("indexador não respondeu: %s %s: %s", request.method, caminho, type(erro).__name__)
        return JSONResponse({"error": "indexador indisponível"}, status_code=502)
    if resposta.status_code >= 400:
        log.info("%s %s respondeu %d", request.method, caminho, resposta.status_code)
    devolver = {k: v for k, v in resposta.headers.items() if k.lower() in ("content-type",)}
    return Response(resposta.content, status_code=resposta.status_code, headers=devolver)


@contextlib.asynccontextmanager
async def _ciclo(aplicacao):
    aplicacao.state.cliente = _cliente()
    yield
    await aplicacao.state.cliente.aclose()


app = Starlette(routes=[Route("/{caminho:path}", repassar, methods=["GET", "HEAD", "POST", "PUT", "DELETE"])], lifespan=_ciclo)


def main():
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # Cada lote do detector seria uma linha: fica só o que o portão respondeu e o que o indexador recusou.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    endereco = os.environ["ROAR_PORTAO_ENDERECO"]
    uvicorn.run(app, host=endereco, port=PORTA, ssl_keyfile=str(PASTA / "portao-key.pem"), ssl_certfile=str(PASTA / "portao.pem"),
                log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
