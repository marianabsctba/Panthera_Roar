"""Listas públicas que dão contexto a um alerta: de quem é a rede, se é saída Tor, se o programa costuma ser usado em ataques.

Tudo fica numa base local: consultar um serviço de fora revelaria quem está atacando cada cliente.
Se uma lista vier estranha, a anterior continua valendo.
"""

import csv
import io
import ipaddress
import json
import logging
import re
import zipfile

import requests

log = logging.getLogger("roar.contexto")
TEMPO = 180
MAXIMO = 128 * 1024 * 1024
DOMINIOS_DA_TRANCO = 200_000
HORAS_ENTRE_ATUALIZACOES = 24


class ListaEstranha(Exception):
    pass


def _baixar(url, cabecalhos=None):
    with requests.get(url, stream=True, timeout=TEMPO, headers=cabecalhos or {"User-Agent": "Panthera-Roar"}) as r:
        r.raise_for_status()
        dados = io.BytesIO()
        for pedaco in r.iter_content(1024 * 1024):
            dados.write(pedaco)
            if dados.tell() > MAXIMO:
                raise ListaEstranha("arquivo maior que o esperado")
    return dados.getvalue()


def _json(url):
    return json.loads(_baixar(url))


def _rede(texto):
    try:
        return str(ipaddress.ip_network(str(texto).strip(), strict=False))
    except ValueError:
        return None


def _redes(rotulo, textos):
    return sorted({(rotulo, r) for r in map(_rede, textos) if r})


def ler_aws(d):
    return _redes("AWS", [p["ip_prefix"] for p in d["prefixes"]] + [p["ipv6_prefix"] for p in d.get("ipv6_prefixes", [])])


def ler_google(d):
    return _redes("Google Cloud", [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in d["prefixes"]])


def ler_oracle(d):
    return _redes("Oracle Cloud", [c["cidr"] for r in d["regions"] for c in r["cidrs"]])


def ler_azure(d):
    return _redes("Microsoft Azure", [p for v in d["values"] if v["name"] == "AzureCloud" for p in v["properties"]["addressPrefixes"]])


def ler_lista_de_texto(rotulo, corpo):
    return _redes(rotulo, [l for l in corpo.decode("utf-8", "replace").splitlines() if l.strip() and not l.startswith("#")])


def _endereco_da_azure():
    pagina = _baixar("https://www.microsoft.com/en-us/download/details.aspx?id=56519", {"User-Agent": "Mozilla/5.0 Panthera-Roar"}).decode("utf-8", "replace")
    achado = re.search(r"https://download\.microsoft\.com/[^\"']+ServiceTags_Public_\d+\.json", pagina)
    if not achado:
        raise ListaEstranha("a página da Azure mudou")
    return achado[0]


# Lista, leitura e quantos itens uma lista boa tem pelo menos: abaixo disso veio cortada.
REDES = {
    "aws": (lambda: ler_aws(_json("https://ip-ranges.amazonaws.com/ip-ranges.json")), 1000),
    "google": (lambda: ler_google(_json("https://www.gstatic.com/ipranges/cloud.json")), 100),
    "oracle": (lambda: ler_oracle(_json("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json")), 100),
    "azure": (lambda: ler_azure(_json(_endereco_da_azure())), 500),
    "cloudflare": (lambda: ler_lista_de_texto("Cloudflare", _baixar("https://www.cloudflare.com/ips-v4") + b"\n" + _baixar("https://www.cloudflare.com/ips-v6")), 10),
    "tor": (lambda: ler_lista_de_texto("Saída da rede Tor", _baixar("https://check.torproject.org/torbulkexitlist")), 200),
}


def ler_lolbas(d):
    saida = {}
    for item in d:
        nome = str(item.get("Name", "")).lower()
        if nome:
            usos = sorted({c.get("Category") for c in item.get("Commands") or [] if c.get("Category")})
            saida[nome] = (item["Name"], ", ".join(usos)[:300] or None, f"https://lolbas-project.github.io/lolbas/{_tipo_lolbas(item)}/{item['Name'].rsplit('.', 1)[0]}/")
    return saida


def _tipo_lolbas(item):
    caminho = str((item.get("Full_Path") or [{}])[0].get("Path", "")).lower()
    return "Binaries" if ".exe" in caminho or not caminho else "Libraries" if ".dll" in caminho else "Scripts"


def ler_gtfobins(d):
    saida = {}
    for nome, item in (d.get("executables") or {}).items():
        funcoes = sorted((item.get("functions") or {}).keys())
        saida[nome.lower()] = (nome, ", ".join(funcoes)[:300] or None, f"https://gtfobins.github.io/gtfobins/{nome}/")
    return saida


def ler_loldrivers(d):
    saida = {}
    for item in d:
        categoria = "Driver malicioso" if str(item.get("Category", "")).lower() == "malicious" else "Driver vulnerável"
        for amostra in item.get("KnownVulnerableSamples") or []:
            for campo in ("SHA256", "SHA1", "MD5"):
                valor = str(amostra.get(campo) or "").lower()
                if valor and valor != "-":
                    nome = amostra.get("Filename") or (item.get("Tags") or ["driver"])[0]
                    saida[valor] = (categoria, str(nome)[:200], f"https://www.loldrivers.io/drivers/{item.get('Id')}/")
    return saida


def ler_tranco(corpo):
    with zipfile.ZipFile(io.BytesIO(corpo)) as z:
        texto = z.read(z.namelist()[0]).decode("utf-8", "replace")
    saida = {}
    for linha in csv.reader(io.StringIO(texto)):
        if len(linha) == 2 and linha[0].isdigit():
            if int(linha[0]) > DOMINIOS_DA_TRANCO:
                break
            saida[linha[1].lower()] = (linha[0], None, None)
    return saida


def ler_attack(d):
    """Quem usa cada técnica. Só grupos ativos, e subtécnica conta também para a técnica mãe."""
    objetos = {o["id"]: o for o in d["objects"] if "id" in o and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    por_tecnica = {}
    for r in d["objects"]:
        if r.get("type") != "relationship" or r.get("relationship_type") != "uses" or r.get("revoked") or r.get("x_mitre_deprecated"):
            continue
        grupo, tecnica = objetos.get(r.get("source_ref")), objetos.get(r.get("target_ref"))
        if not grupo or not tecnica or grupo.get("type") != "intrusion-set" or tecnica.get("type") != "attack-pattern":
            continue
        codigo = next((e["external_id"] for e in tecnica.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
        if codigo:
            por_tecnica.setdefault(codigo, set()).add(grupo["name"])
            if "." in codigo:
                por_tecnica.setdefault(codigo.split(".")[0], set()).add(grupo["name"])
    return {c: (", ".join(sorted(g)[:12]), str(len(g)), f"https://attack.mitre.org/techniques/{c.replace('.', '/')}/") for c, g in por_tecnica.items()}


ITENS = {
    "lolbas": (lambda: ler_lolbas(_json("https://lolbas-project.github.io/api/lolbas.json")), 100),
    "gtfobins": (lambda: ler_gtfobins(_json("https://gtfobins.github.io/api.json")), 100),
    "loldrivers": (lambda: ler_loldrivers(_json("https://www.loldrivers.io/api/drivers.json")), 1000),
    "tranco": (lambda: ler_tranco(_baixar("https://tranco-list.eu/top-1m.csv.zip")), 100_000),
    "attack": (lambda: ler_attack(_json("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")), 100),
}


def publicar_redes(banco, lista, linhas, minimo):
    if len(linhas) < minimo:
        raise ListaEstranha(f"{lista} veio com {len(linhas)} redes")
    with banco.con.transaction():
        banco.con.execute("DELETE FROM contexto_redes WHERE lista = %s", (lista,))
        with banco.con.cursor() as c, c.copy("COPY contexto_redes (lista, rotulo, rede) FROM STDIN") as copia:
            for rotulo, rede in linhas:
                copia.write_row((lista, rotulo, rede))


def publicar_itens(banco, lista, itens, minimo):
    if len(itens) < minimo:
        raise ListaEstranha(f"{lista} veio com {len(itens)} itens")
    with banco.con.transaction():
        banco.con.execute("DELETE FROM contexto_itens WHERE lista = %s", (lista,))
        with banco.con.cursor() as c, c.copy("COPY contexto_itens (lista, chave, rotulo, detalhe, endereco) FROM STDIN") as copia:
            for chave, (rotulo, detalhe, endereco) in itens.items():
                copia.write_row((lista, chave, rotulo, detalhe, endereco))


def _vencidas(banco, nomes):
    with banco.con.transaction():
        frescas = {l[0] for l in banco.con.execute(
            "SELECT nome FROM bibliotecas_estado WHERE atualizada_em > now() - make_interval(hours => %s)", (HORAS_ENTRE_ATUALIZACOES,)).fetchall()}
    return [n for n in nomes if f"contexto-{n}" not in frescas]


def _registrar(banco, lista, erro=None):
    with banco.con.transaction():
        banco.con.execute(
            """INSERT INTO bibliotecas_estado (nome, versao, atualizada_em, tentativa_em, erro)
               VALUES (%(n)s, 'do dia', CASE WHEN %(e)s::text IS NULL THEN now() END, now(), %(e)s)
               ON CONFLICT (nome) DO UPDATE SET tentativa_em = now(), erro = EXCLUDED.erro,
                 atualizada_em = coalesce(EXCLUDED.atualizada_em, bibliotecas_estado.atualizada_em)""",
            {"n": f"contexto-{lista}", "e": erro})


def ciclo(banco):
    """Uma lista fora do ar não atrapalha as outras."""
    falhas = 0
    for lista in _vencidas(banco, [*REDES, *ITENS]):
        try:
            if lista in REDES:
                ler, minimo = REDES[lista]
                publicar_redes(banco, lista, ler(), minimo)
            else:
                ler, minimo = ITENS[lista]
                publicar_itens(banco, lista, ler(), minimo)
            _registrar(banco, lista)
        except (ListaEstranha, requests.RequestException, KeyError, ValueError, TypeError, AttributeError, zipfile.BadZipFile) as erro:
            log.warning("lista %s: %s", lista, str(erro)[:200])
            _registrar(banco, lista, "Não foi possível atualizar. A versão anterior continua valendo.")
            falhas += 1
    return falhas == 0


_RESUMOS = re.compile(r"(MD5|SHA1|SHA256)=([0-9A-Fa-f]+)")


def observaveis_do_alerta(bruto):
    """Só compara: o log pode ter sido escrito por quem ataca, e nada aqui vira comando."""
    bruto = bruto if isinstance(bruto, dict) else {}
    dados = bruto.get("data") if isinstance(bruto.get("data"), dict) else {}
    win = ((dados.get("win") or {}).get("eventdata") or {}) if isinstance(dados.get("win"), dict) else {}
    auditoria = dados.get("audit") if isinstance(dados.get("audit"), dict) else {}
    arquivo = bruto.get("syscheck") if isinstance(bruto.get("syscheck"), dict) else {}
    programas = set()
    for caminho in (win.get("image"), win.get("newProcessName"), win.get("parentImage"), auditoria.get("exe"), dados.get("yara_arquivo"), arquivo.get("path")):
        if caminho:
            nome = re.split(r"[\\/]", str(caminho))[-1].strip().lower()
            if nome:
                programas.add(nome)
    previo = (bruto.get("predecoder") or {}) if isinstance(bruto.get("predecoder"), dict) else {}
    if previo.get("program_name"):
        programas.add(str(previo["program_name"]).lower())
    resumos = {str(arquivo.get(c)).lower() for c in ("md5_after", "sha1_after", "sha256_after") if arquivo.get(c)}
    resumos |= {valor.lower() for _, valor in _RESUMOS.findall(str(win.get("hashes", "")))}
    dominios = set()
    for campo in ("hostname", "domain", "query", "dest_host"):
        if dados.get(campo):
            dominios.add(str(dados[campo]).strip().lower().rstrip("."))
    if win.get("queryName"):
        dominios.add(str(win["queryName"]).strip().lower().rstrip("."))
    regra = bruto.get("rule") if isinstance(bruto.get("rule"), dict) else {}
    mitre = regra.get("mitre") if isinstance(regra.get("mitre"), dict) else {}
    tecnicas = mitre.get("id") if isinstance(mitre.get("id"), list) else []
    return {"programas": sorted(programas), "resumos": sorted(resumos), "dominios": sorted(dominios), "tecnicas": [str(t) for t in tecnicas][:20]}


def dominios_candidatos(dominios):
    """www.exemplo.com.br conta como exemplo.com.br: a lista só tem o domínio registrado."""
    saida = set()
    for d in dominios:
        partes = d.split(".")
        for i in range(max(0, len(partes) - 4), len(partes) - 1):
            saida.add(".".join(partes[i:]))
    return sorted(saida)
