"""Ubuntu e Debian corrigem falhas sem trocar o número da versão: "OpenSSH 8.2p1" pode estar corrigido ou não.

O número completo que o serviço anuncia (OpenSSH_8.2p1 Ubuntu-4ubuntu0.5) é o pacote instalado. Com ele, este módulo
descobre de qual versão da distribuição o pacote é (pela revisão, pelo Launchpad ou pelo índice de fontes do Debian) e
pergunta ao OSV, a base pública de falhas por pacote, quais CVEs ainda pegam aquela versão exata. Só sai daqui o nome e a
versão do pacote, nada da organização.
"""

import re

import requests

TEMPO = 20
LAUNCHPAD = "https://api.launchpad.net/devel/ubuntu/+archive/primary"
FONTES_DO_DEBIAN = "https://sources.debian.org/api/src/{pacote}/"
OSV = "https://api.osv.dev/v1/query"
# Série do Ubuntu e os ecossistemas no OSV: o normal e o Pro (ESM), que segue corrigindo depois do fim do suporte padrão.
UBUNTU = {"xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04"}
DEBIAN = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
# Serviço, a revisão no que ele anuncia, os nomes do pacote-fonte e a época que o Debian põe na frente da versão.
PACOTES = {
    "OpenSSH": (re.compile(r"OpenSSH_[\w.]+ (?:Ubuntu|Debian)-(\S+)"), lambda v: ["openssh"], "1:"),
    "MariaDB": (re.compile(r"\d+\.\d+\.\d+-MariaDB-([^\x00\s]+)"), lambda v: [f"mariadb-{_maior(v)}", "mariadb"], "1:"),
    "MySQL": (re.compile(r"\d+\.\d+\.\d+-(\d+(?:ubuntu|\+deb)[^\x00\s]*)"), lambda v: [f"mysql-{_maior(v)}"], ""),
    "PHP": (re.compile(r"PHP/[\d.]+-(\S+)"), lambda v: [f"php{_maior(v)}"], ""),
}


def _maior(versao):
    return ".".join(versao.split(".")[:2])


def pacote_anunciado(servico, versao, resposta):
    """{"nomes", "versao", "epoca", "distribuicao"} do pacote que o serviço anuncia, ou None sem revisão."""
    if servico not in PACOTES:
        return None
    padrao, nomes, epoca = PACOTES[servico]
    m = padrao.search(resposta or "")
    if not m:
        return None
    revisao = m.group(1)
    distribuicao = "ubuntu" if "ubuntu" in revisao.lower() or "Ubuntu" in resposta else "debian"
    return {"nomes": nomes(versao), "versao": f"{versao}-{revisao}", "epoca": epoca, "distribuicao": distribuicao}


def _ecossistemas_do_ubuntu(numero):
    return [f"Ubuntu:{numero}:LTS", f"Ubuntu:Pro:{numero}:LTS"]


def serie(pacote, buscar=requests.get):
    """(nome do pacote, versão com época, [ecossistemas no OSV]) ou None quando não dá para saber de onde ele é."""
    versao = pacote["versao"]
    if pacote["distribuicao"] == "debian":
        m = re.search(r"\+deb(\d+)u", versao)
        if m:
            return pacote["nomes"][0], pacote["epoca"] + versao, [f"Debian:{m.group(1)}"]
        for nome in pacote["nomes"]:
            r = buscar(FONTES_DO_DEBIAN.format(pacote=nome), timeout=TEMPO, headers={"User-Agent": "PantheraRoar"})
            if r.status_code == 404:
                continue
            r.raise_for_status()
            for item in r.json().get("versions", []):
                if item.get("version") in (versao, pacote["epoca"] + versao):
                    numeros = sorted({DEBIAN[s.split("-")[0]] for s in item.get("suites", []) if s.split("-")[0] in DEBIAN})
                    if numeros:
                        return nome, item["version"], [f"Debian:{n}" for n in numeros]
        return None
    m = re.search(r"ubuntu\d*\.(\d\d\.\d\d)", versao)
    if m and m.group(1) in UBUNTU.values():
        return pacote["nomes"][0], pacote["epoca"] + versao, _ecossistemas_do_ubuntu(m.group(1))
    for nome in pacote["nomes"]:
        for completa in dict.fromkeys((pacote["epoca"] + versao, versao)):
            r = buscar(LAUNCHPAD, timeout=TEMPO, headers={"User-Agent": "PantheraRoar"},
                       params={"ws.op": "getPublishedSources", "source_name": nome, "version": completa, "exact_match": "true"})
            r.raise_for_status()
            series = {e.get("distro_series_link", "").rsplit("/", 1)[-1] for e in r.json().get("entries", [])}
            numeros = sorted(UBUNTU[s] for s in series if s in UBUNTU)
            if numeros:
                return nome, completa, [e for n in numeros for e in _ecossistemas_do_ubuntu(n)]
    return None


def falhas(nome, versao, ecossistemas, postar=requests.post):
    """As CVEs que o OSV diz que ainda pegam esta versão exata do pacote, em qualquer um dos ecossistemas."""
    cves = set()
    for ecossistema in ecossistemas:
        corpo = {"package": {"name": nome, "ecosystem": ecossistema}, "version": versao}
        for _ in range(20):
            r = postar(OSV, json=corpo, timeout=TEMPO, headers={"User-Agent": "PantheraRoar"})
            r.raise_for_status()
            dados = r.json()
            for v in dados.get("vulns", []):
                for nome_da_cve in [v.get("id", ""), *(v.get("upstream") or []), *(v.get("aliases") or [])]:
                    cves.update(re.findall(r"CVE-\d{4}-\d+", nome_da_cve))
            if not dados.get("next_page_token"):
                break
            corpo["page_token"] = dados["next_page_token"]
    return sorted(cves)
