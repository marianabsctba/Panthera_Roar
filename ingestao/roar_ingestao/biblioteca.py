"""Mantém em dia as bibliotecas públicas de regras: Sigma e YARA.

    python -m roar_ingestao.biblioteca            (fica rodando e confere de tempos em tempos)
    python -m roar_ingestao.biblioteca --uma-vez

Se a versão nova vier estranha, a anterior continua valendo: regra velha é melhor que regra quebrada.
Atualizar o catálogo não muda nenhuma regra Sigma já ativa: ela é uma cópia, e quem a ativou decide.

As regras não ficam no nosso repositório. Vêm das fontes oficiais com a licença de cada uma: autor,
licença e endereço aparecem na tela.
"""

import argparse
import hashlib
import io
import logging
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

import requests
import yaml

from . import yara_regras
from .ciclo import conexoes
from .sigma import converter_textos

log = logging.getLogger("roar.biblioteca")
SIGMA_ULTIMA = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
SIGMA_ARQUIVO = "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/tags/{versao}"
ENDERECO_BASE = "https://github.com/SigmaHQ/sigma/blob/{versao}/{caminho}"
YARA_ULTIMA = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
ARQUIVO_YARA = "yara-forge-rules-core.zip"
TEMPO = 120
MAXIMO_DOWNLOAD = 200 * 1024 * 1024
# Abaixo disso o pacote veio cortado ou mudou de formato.
MINIMO_SIGMA = 1000
MINIMO_SIGMA_CONVERTIVEIS = 500
SEGUNDOS_ENTRE_CONFERENCIAS = 6 * 3600
SEGUNDOS_APOS_FALHA = 3600


class BaseEstranha(Exception):
    """A mensagem aparece na tela: precisa fazer sentido para quem administra."""


def _baixar(url):
    with requests.get(url, stream=True, timeout=TEMPO) as r:
        r.raise_for_status()
        dados = io.BytesIO()
        for pedaco in r.iter_content(1024 * 1024):
            dados.write(pedaco)
            if dados.tell() > MAXIMO_DOWNLOAD:
                raise BaseEstranha("O arquivo baixado é maior do que o esperado.")
    return dados.getvalue()


def _estado(banco, nome):
    # Sempre em transação própria: um SELECT solto deixaria a conexão aberta e o que vem depois nunca seria gravado.
    with banco.con.transaction():
        linha = banco.con.execute("SELECT versao FROM bibliotecas_estado WHERE nome = %s", (nome,)).fetchone()
    return linha[0] if linha else None


def _registrar(banco, nome, versao=None, erro=None):
    with banco.con.transaction():
        banco.con.execute(
            """INSERT INTO bibliotecas_estado (nome, versao, atualizada_em, tentativa_em, erro)
               VALUES (%(n)s, %(v)s, CASE WHEN %(v)s::text IS NULL THEN NULL ELSE now() END, now(), %(e)s)
               ON CONFLICT (nome) DO UPDATE SET tentativa_em = now(), erro = EXCLUDED.erro,
                 versao = coalesce(EXCLUDED.versao, bibliotecas_estado.versao),
                 atualizada_em = coalesce(EXCLUDED.atualizada_em, bibliotecas_estado.atualizada_em)""",
            {"n": nome, "v": versao, "e": erro})


# ------------------------------------------------------------------ Sigma

def _uma_regra(arquivo, raiz, versao):
    texto = arquivo.read_text(encoding="utf-8")
    dados = yaml.safe_load(texto)
    if not isinstance(dados, dict) or not dados.get("id") or not dados.get("title"):
        return None
    origem = dados.get("logsource") or {}
    tecnicas = sorted({t.split(".", 1)[1].upper() for t in dados.get("tags") or []
                       if isinstance(t, str) and t.lower().startswith("attack.t")})
    resultado = converter_textos([texto])[0]
    return (str(dados["id"]), str(dados["title"])[:300], str(dados.get("description") or "")[:2000] or None,
            str(dados.get("author") or "")[:300] or None, dados.get("level"),
            " / ".join(str(origem[k]) for k in ("product", "category", "service") if origem.get(k)) or None, tecnicas,
            ENDERECO_BASE.format(versao=versao, caminho=arquivo.relative_to(raiz).as_posix()), texto,
            bool(resultado.xml), resultado.motivo, versao)


def carregar_sigma(banco, raiz, versao, minimo=MINIMO_SIGMA, minimo_convertiveis=MINIMO_SIGMA_CONVERTIVEIS):
    raiz = Path(raiz)
    linhas = []
    for arquivo in sorted((raiz / "rules").rglob("*.yml")):
        try:
            linha = _uma_regra(arquivo, raiz, versao)
        except (yaml.YAMLError, UnicodeDecodeError) as erro:
            log.warning("regra Sigma ilegível %s: %s", arquivo.name, type(erro).__name__)
            continue
        if linha:
            linhas.append(linha)
    convertiveis = sum(1 for l in linhas if l[9])
    if len(linhas) < minimo or convertiveis < minimo_convertiveis:
        raise BaseEstranha(f"A versão {versao} da biblioteca Sigma veio com {len(linhas)} regras, menos que o esperado.")
    with banco.con.transaction():
        banco.con.execute("DELETE FROM biblioteca_regras")
        with banco.con.cursor() as c:
            c.executemany(
                """INSERT INTO biblioteca_regras (id, titulo, descricao, autor, nivel, origem, tecnicas, endereco, conteudo,
                     convertivel, motivo, versao) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (id) DO NOTHING""", linhas)
        _registrar(banco, "sigma", versao)
    return len(linhas), convertiveis


def atualizar_sigma(banco):
    versao = requests.get(SIGMA_ULTIMA, timeout=TEMPO).json()["tag_name"]
    if versao == _estado(banco, "sigma"):
        return False
    dados = _baixar(SIGMA_ARQUIVO.format(versao=versao))
    with tempfile.TemporaryDirectory(prefix="roar-sigma-") as pasta:
        with tarfile.open(fileobj=io.BytesIO(dados), mode="r:gz") as tar:
            # Só as regras, e o filtro recusa caminho que saia da pasta.
            tar.extractall(pasta, members=[m for m in tar.getmembers() if m.isfile() and "/rules/" in m.name and m.name.endswith(".yml")], filter="data")
        raizes = [p for p in Path(pasta).iterdir() if p.is_dir()]
        if len(raizes) != 1:
            raise BaseEstranha("O arquivo da biblioteca Sigma veio em formato desconhecido.")
        total, convertiveis = carregar_sigma(banco, raizes[0], versao)
    log.info("Sigma %s: %d regras, %d convertíveis", versao, total, convertiveis)
    return True


# ------------------------------------------------------------------ YARA

def publicar_yara(banco, versao, texto):
    """Passa pelo portão antes de qualquer cliente ver. Quem usa recebe no ciclo das fontes."""
    with banco.con.transaction():
        linha = banco.con.execute("SELECT regras FROM yara_pacotes ORDER BY publicado_em DESC LIMIT 1").fetchone()
    total = yara_regras.conferir_pacote(texto, linha[0] if linha else None)
    regras = yara_regras.regras_do_pacote(texto)
    with banco.con.transaction():
        banco.con.execute(
            "INSERT INTO yara_pacotes (versao, conteudo, regras, sha256) VALUES (%s, %s, %s, %s) ON CONFLICT (versao) DO NOTHING",
            (versao, texto, total, hashlib.sha256(texto.encode()).hexdigest()))
        banco.con.execute("DELETE FROM yara_biblioteca")
        with banco.con.cursor() as c:
            c.executemany(
                """INSERT INTO yara_biblioteca (nome, privada, descricao, autor, repositorio, licenca, endereco, pontuacao, conteudo)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (nome) DO NOTHING""",
                [(r["nome"], r["privada"], r["descricao"], r["autor"], r["repositorio"], r["licenca"], r["endereco"], r["pontuacao"], texto[r["inicio"]:r["fim"]]) for r in regras])
        _registrar(banco, "yara", versao)
        # Fica a anterior, para quem desligou a atualização e para voltar atrás. O serviço não enxerga as organizações, então guarda as cinco últimas; quem ficar para trás mantém o que já recebeu.
        banco.con.execute("DELETE FROM yara_pacotes WHERE versao NOT IN (SELECT versao FROM yara_pacotes ORDER BY publicado_em DESC LIMIT 5)")
    return total


def atualizar_yara(banco):
    release = requests.get(YARA_ULTIMA, timeout=TEMPO).json()
    versao = release["tag_name"]
    if versao == _estado(banco, "yara"):
        return False
    url = next((a["browser_download_url"] for a in release["assets"] if a["name"] == ARQUIVO_YARA), None)
    if not url:
        raise BaseEstranha(f"A versão {versao} da biblioteca YARA não traz o pacote esperado.")
    with zipfile.ZipFile(io.BytesIO(_baixar(url))) as z:
        nomes = [n for n in z.namelist() if n.endswith(".yar")]
        if len(nomes) != 1:
            raise BaseEstranha(f"A versão {versao} da biblioteca YARA veio em formato desconhecido.")
        texto = z.read(nomes[0]).decode("utf-8", errors="replace")
    total = publicar_yara(banco, versao, texto)
    log.info("YARA %s: %d regras", versao, total)
    return True


def ciclo(banco):
    falhou = False
    for nome, atualizar in (("yara", atualizar_yara), ("sigma", atualizar_sigma)):
        try:
            atualizar(banco)
            _registrar(banco, nome)
        except (BaseEstranha, yara_regras.RegraInvalida) as erro:
            log.error("biblioteca %s: %s", nome, erro)
            _registrar(banco, nome, erro=str(erro)[:300])
            falhou = True
        except (requests.RequestException, KeyError, ValueError, zipfile.BadZipFile, tarfile.TarError, OSError) as erro:
            log.warning("biblioteca %s: %s", nome, type(erro).__name__)
            _registrar(banco, nome, erro="Não foi possível buscar a versão nova. A atual continua valendo.")
            falhou = True
    return not falhou


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--uma-vez", action="store_true")
    a = args.parse_args()
    _, banco, _ = conexoes()
    while True:
        deu_certo = ciclo(banco)
        if a.uma_vez:
            return
        time.sleep(SEGUNDOS_ENTRE_CONFERENCIAS if deu_certo else SEGUNDOS_APOS_FALHA)


if __name__ == "__main__":
    main()
