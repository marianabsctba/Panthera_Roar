"""Carrega a base pública de CVEs, com exploração conhecida e estimativa de exploração.

    python -m roar_ingestao.cves            (fica rodando e atualiza todo dia)
    python -m roar_ingestao.cves --uma-vez

Fontes: o registro oficial de CVEs, o catálogo KEV da CISA e o EPSS. Se uma delas vier estranha,
a carga para e a base anterior continua valendo: dado velho é melhor que dado pela metade.
"""

import argparse
import csv
import gzip
import json
import logging
import re
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

log = logging.getLogger("roar.cves")
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
REGISTRO = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
NVD = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{ano}.json.gz"
ANO_INICIAL_NVD = 2002
MINIMO_NVD = 150_000
HORAS_ENTRE_CARGAS = 23
SEGUNDOS_ENTRE_CONFERENCIAS = 1800
SEGUNDOS_APOS_FALHA = 3600
# Abaixo disso o feed veio cortado ou mudou de formato.
MINIMO_KEV = 1000
MINIMO_EPSS = 200_000
MINIMO_CVES = 300_000
MAXIMO_ILEGIVEIS = 100
TEMPO_PEQUENO = 180
TEMPO_GRANDE = 1800
EPSS_ALTO = 0.5
EPSS_MEDIO = 0.05
CVSS_CRITICO = 9.0
CVSS_ALTO = 7.0
NOME_DE_CVE = re.compile(r"CVE-\d{4}-\d+")
COLUNAS = ("cve", "publicado_em", "rejeitado", "titulo", "descricao", "produto", "cvss", "vetor", "cvss_fonte", "kev_desde",
           "kev_ransomware", "kev_prazo", "epss", "epss_percentil", "prioridade")


class FonteEstranha(Exception):
    pass


def prioridade(kev_desde, epss, cvss):
    """Exploração confirmada vem primeiro; depois a chance de exploração; depois o tamanho do estrago.

    Falta de dado nunca vira prioridade baixa: EPSS baixo diz que a chance é pequena, não que o estrago é.
    Sem a nota, a tela diz que não sabe. Quase metade do registro oficial não traz CVSS.
    """
    if kev_desde:
        return "agora"
    if epss is not None and epss >= EPSS_ALTO:
        return "alta"
    if cvss is not None and cvss >= CVSS_CRITICO:
        return "alta"
    if (epss is not None and epss >= EPSS_MEDIO) or (cvss is not None and cvss >= CVSS_ALTO):
        return "media"
    if cvss is None:
        return "sem_dados"
    return "baixa"


def _texto(valor, limite):
    # O banco não aceita o caractere nulo, e o registro público aceita qualquer coisa.
    return str(valor).replace("\x00", "")[:limite] if valor else None


def ler_registro(dados):
    """Só o que a tela usa. Prefere a versão mais nova da nota, de quem publicou ou de quem enriqueceu o registro."""
    meta = dados.get("cveMetadata") or {}
    if meta.get("state") == "REJECTED":
        return {"cve": meta.get("cveId"), "rejeitado": True}
    conteineres = dados.get("containers") or {}
    cna = conteineres.get("cna") or {}
    metricas = [m for c in [cna, *(conteineres.get("adp") or [])] for m in (c.get("metrics") or [])]
    cvss, vetor = None, None
    for versao in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        achado = next((m[versao] for m in metricas if isinstance(m.get(versao), dict)), None)
        if achado and isinstance(achado.get("baseScore"), (int, float)):
            cvss, vetor = float(achado["baseScore"]), achado.get("vectorString")
            break
    descricoes = cna.get("descriptions") or []
    descricao = next((d.get("value") for d in descricoes if str(d.get("lang", "")).startswith("en")), None)
    if descricao is None and descricoes:
        descricao = descricoes[0].get("value")
    afetado = next((a for a in (cna.get("affected") or []) if a.get("product") and a.get("product") != "n/a"), None)
    produto = " ".join(x for x in (afetado.get("vendor"), afetado.get("product")) if x and x != "n/a") if afetado else None
    return {"cve": meta.get("cveId"), "rejeitado": False, "publicado_em": meta.get("datePublished"), "titulo": _texto(cna.get("title"), 500),
            "descricao": _texto(descricao, 4000), "produto": _texto(produto, 300), "cvss": cvss, "vetor": _texto(vetor, 200)}


def baixar_kev():
    r = requests.get(KEV, timeout=TEMPO_PEQUENO)
    r.raise_for_status()
    itens = r.json().get("vulnerabilities")
    if not isinstance(itens, list) or len(itens) < MINIMO_KEV:
        raise FonteEstranha("KEV veio pequeno demais")
    return {i["cveID"]: {"desde": i.get("dateAdded"), "prazo": i.get("dueDate"), "ransomware": i.get("knownRansomwareCampaignUse") == "Known"} for i in itens}


def baixar_epss():
    r = requests.get(EPSS, timeout=TEMPO_PEQUENO)
    r.raise_for_status()
    linhas = gzip.decompress(r.content).decode().splitlines()
    data = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", linhas[0])
    if not data or linhas[1].strip() != "cve,epss,percentile":
        raise FonteEstranha("EPSS em formato inesperado")
    notas = {l[0]: (float(l[1]), float(l[2])) for l in csv.reader(linhas[2:]) if len(l) == 3}
    if len(notas) < MINIMO_EPSS:
        raise FonteEstranha("EPSS veio pequeno demais")
    return data.group(1), notas


def _nota_da_nvd(item):
    metricas = item.get("metrics") or {}
    for versao in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lista = metricas.get(versao) or []
        # Prefere a análise da própria NVD à de quem publicou.
        escolhida = next((m for m in lista if m.get("type") == "Primary"), lista[0] if lista else None)
        dados = (escolhida or {}).get("cvssData") or {}
        if isinstance(dados.get("baseScore"), (int, float)):
            return float(dados["baseScore"]), dados.get("vectorString")
    return None


def baixar_nvd(ano_final=None):
    """Um arquivo por ano. Só serve para preencher o que o registro oficial não traz."""
    notas = {}
    for ano in range(ANO_INICIAL_NVD, (ano_final or datetime.now(timezone.utc).year) + 1):
        r = requests.get(NVD.format(ano=ano), timeout=TEMPO_GRANDE)
        r.raise_for_status()
        itens = json.loads(gzip.decompress(r.content)).get("vulnerabilities")
        if not isinstance(itens, list) or (not itens and ano < datetime.now(timezone.utc).year):
            raise FonteEstranha(f"NVD de {ano} em formato inesperado")
        for envelope in itens:
            item = envelope.get("cve") or {}
            nota = _nota_da_nvd(item)
            if nota and item.get("id"):
                notas[item["id"]] = nota
    if len(notas) < MINIMO_NVD:
        raise FonteEstranha(f"NVD veio pequena demais: {len(notas)}")
    return notas


def percorrer_registro(pasta):
    """A base vem como um zip dentro de outro, com um JSON por CVE. Os nomes não são usados como caminho."""
    versao = requests.get(REGISTRO, timeout=TEMPO_PEQUENO)
    versao.raise_for_status()
    release = versao.json()
    ativo = next((a for a in release.get("assets", []) if a["name"].endswith("_all_CVEs_at_midnight.zip.zip")), None)
    if not ativo:
        raise FonteEstranha("base de CVEs sem o arquivo esperado")
    fora = Path(pasta) / "fora.zip"
    with requests.get(ativo["browser_download_url"], stream=True, timeout=TEMPO_GRANDE) as r:
        r.raise_for_status()
        with open(fora, "wb") as f:
            for pedaco in r.iter_content(1 << 20):
                f.write(pedaco)
    dentro = Path(pasta) / "dentro.zip"
    with zipfile.ZipFile(fora) as z:
        interno = next((n for n in z.namelist() if n.endswith(".zip")), None)
        if not interno:
            raise FonteEstranha("zip da base sem o zip interno")
        with z.open(interno) as origem, open(dentro, "wb") as destino:
            while pedaco := origem.read(1 << 20):
                destino.write(pedaco)
    fora.unlink()
    ilegiveis = 0
    with zipfile.ZipFile(dentro) as z:
        for nome in z.namelist():
            if not re.search(r"CVE-\d{4}-\d+\.json$", nome):
                continue
            try:
                dados = json.loads(z.read(nome))
                if (dados.get("cveMetadata") or {}).get("state") in ("PUBLISHED", "REJECTED"):
                    yield ler_registro(dados)
            except (ValueError, AttributeError, TypeError, KeyError):
                ilegiveis += 1
                if ilegiveis > MAXIMO_ILEGIVEIS:
                    raise FonteEstranha(f"{ilegiveis} CVEs ilegíveis na base")
    carregar_versao[0] = release.get("tag_name")


carregar_versao = [None]


def linhas_para_gravar(registros, kev, epss, nvd=None):
    nvd = nvd or {}
    vistos = set()
    for r in registros:
        cve = r.get("cve")
        if not cve or not NOME_DE_CVE.fullmatch(cve):
            continue
        vistos.add(cve)
        yield _linha(cve, r, kev.get(cve), epss.get(cve), nvd.get(cve))
    # O KEV às vezes traz CVE que o registro ainda não publicou: não pode sumir da base.
    for cve, k in kev.items():
        if cve not in vistos and NOME_DE_CVE.fullmatch(cve):
            yield _linha(cve, {"rejeitado": False}, k, epss.get(cve), nvd.get(cve))


def _linha(cve, r, k, e, n=None):
    epss_nota, percentil = e if e else (None, None)
    kev_desde = k["desde"] if k else None
    # O próprio programa CVE retirou o registro: não é prioridade de ninguém, a não ser que estejam explorando.
    if r.get("rejeitado") and not kev_desde:
        epss_nota, percentil = None, None
        n = None
    cvss, vetor, fonte = r.get("cvss"), r.get("vetor"), "registro" if r.get("cvss") is not None else None
    if cvss is None and n:
        cvss, vetor, fonte = n[0], _texto(n[1], 200), "nvd"
    return (cve, r.get("publicado_em"), r.get("rejeitado", False), r.get("titulo"), r.get("descricao"), r.get("produto"), cvss, vetor, fonte,
            kev_desde, bool(k and k["ransomware"]), k["prazo"] if k else None, epss_nota, percentil, prioridade(kev_desde, epss_nota, cvss))


def carregar(banco):
    """Troca tudo em uma transação: ninguém vê a base pela metade, e uma falha mantém a anterior."""
    kev = baixar_kev()
    data_epss, epss = baixar_epss()
    nvd = baixar_nvd()
    log.info("KEV %d, EPSS %d (%s), NVD %d", len(kev), len(epss), data_epss, len(nvd))
    with tempfile.TemporaryDirectory(prefix="roar-cves-") as pasta, banco.con.transaction():
        banco.con.execute("CREATE TEMP TABLE cves_nova (LIKE cves INCLUDING DEFAULTS EXCLUDING GENERATED) ON COMMIT DROP")
        total = 0
        with banco.con.cursor().copy(f"COPY cves_nova ({', '.join(COLUNAS)}) FROM STDIN") as copia:
            for linha in linhas_para_gravar(percorrer_registro(pasta), kev, epss, nvd):
                copia.write_row(linha)
                total += 1
        if total < MINIMO_CVES:
            raise FonteEstranha(f"base de CVEs veio pequena demais: {total}")
        banco.con.execute("DELETE FROM cves")
        colunas = ", ".join(COLUNAS)
        banco.con.execute(f"INSERT INTO cves ({colunas}) SELECT {colunas} FROM cves_nova ON CONFLICT (cve) DO NOTHING")
        banco.con.execute(
            """INSERT INTO cves_carga (id, total, versao, epss_data, carregada_em) VALUES (1, %s, %s, %s, now())
               ON CONFLICT (id) DO UPDATE SET total = EXCLUDED.total, versao = EXCLUDED.versao, epss_data = EXCLUDED.epss_data,
               carregada_em = now(), falha = NULL, falha_em = NULL""",
            (total, carregar_versao[0], data_epss))
    return total


def _precisa_carregar(banco):
    with banco.con.transaction():
        return banco.con.execute(
            "SELECT NOT EXISTS (SELECT 1 FROM cves_carga WHERE carregada_em > now() - make_interval(hours => %s))", (HORAS_ENTRE_CARGAS,)).fetchone()[0]


def _registrar_falha(banco, erro):
    # A mensagem vai para a tela: só o tipo do problema, nunca um endereço ou resposta de fora.
    texto = str(erro)[:200] if isinstance(erro, FonteEstranha) else "Não foi possível falar com uma das fontes."
    with banco.con.transaction():
        banco.con.execute("UPDATE cves_carga SET falha = %s, falha_em = now()", (texto,))


def rodar_para_sempre(banco, carga=carregar, dormir=time.sleep, agentes=None):
    """Base velha é melhor que base nenhuma: uma falha mantém a anterior e tenta de novo mais tarde."""
    while True:
        espera = SEGUNDOS_ENTRE_CONFERENCIAS
        if agentes:
            # O que o próprio agente achou entra em Vulnerabilidades no mesmo ritmo da conferência das CVEs.
            agentes()
        if _precisa_carregar(banco):
            try:
                log.info("%d CVEs carregadas", carga(banco))
            except (FonteEstranha, requests.RequestException, OSError, ValueError, zipfile.BadZipFile) as erro:
                log.error("carga de CVEs falhou: %s", type(erro).__name__)
                _registrar_falha(banco, erro)
                espera = SEGUNDOS_APOS_FALHA
        dormir(espera)


def main():
    from .ciclo import conexoes

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--uma-vez", action="store_true")
    a = args.parse_args()
    indexer, banco, _ = conexoes()
    if a.uma_vez:
        log.info("%d CVEs carregadas", carregar(banco))
        return
    from . import vuln_agentes
    rodar_para_sempre(banco, agentes=lambda: vuln_agentes.ciclo(banco, indexer.sessao.post, indexer.url))


if __name__ == "__main__":
    main()
