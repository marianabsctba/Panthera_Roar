"""O e-mail do domínio: se alguém de fora consegue mandar mensagem em nome da organização.

Três registros públicos no DNS dizem isso. O SPF lista quem pode mandar; o DKIM assina as mensagens; o DMARC diz o que
fazer com a mensagem que falha nos dois, e é ele que de fato barra o e-mail falso. Tudo é consulta de DNS, nada é
enviado ao servidor de e-mail.
"""

import base64
import re

import dns.exception
import dns.resolver
from cryptography.hazmat.primitives.serialization import load_der_public_key

TEMPO = 5
# O SPF aceita no máximo 10 consultas de DNS para ser avaliado; passou disso, o próprio SPF falha.
MAXIMO_DE_CONSULTAS = 10
# O DKIM fica num nome que só quem configurou sabe: estes são os mais usados (Microsoft 365, Google, provedores).
SELETORES = ("selector1", "selector2", "google", "default", "dkim", "mail", "k1", "k2", "s1", "s2", "smtp", "mx", "key1", "zoho",
             "mandrill", "sendgrid", "everlytic", "protonmail", "mxvault", "sig1", "amazonses")


def txt(nome, resolver=None):
    """Os textos TXT do nome. Nome sem registro devolve lista vazia; falha de rede levanta."""
    resolver = resolver or dns.resolver.Resolver()
    try:
        respostas = resolver.resolve(nome, "TXT", lifetime=TEMPO)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in respostas]


def _spf_de(textos):
    return [t for t in textos if t.lower().startswith("v=spf1")]


def consultas_do_spf(dominio, consultar, vistos=None):
    """Quantas consultas de DNS o SPF gasta, contando os includes e redirects por dentro."""
    vistos = vistos if vistos is not None else set()
    if dominio in vistos or len(vistos) > 30:
        return 0
    vistos.add(dominio)
    registros = _spf_de(consultar(dominio))
    if not registros:
        return 0
    total = 0
    for termo in registros[0].split()[1:]:
        termo = termo.lstrip("+-~?").lower()
        if termo.startswith(("include:", "redirect=")):
            total += 1 + consultas_do_spf(re.split(r"[:=]", termo, 1)[1], consultar, vistos)
        elif termo.split(":")[0].split("/")[0] in ("a", "mx", "ptr", "exists"):
            total += 1
    return total


def _tamanho_da_chave(registro):
    m = re.search(r"(?:^|;)\s*p=([A-Za-z0-9+/=\s]*)", registro)
    if not m or not m.group(1).strip():
        return 0
    try:
        return load_der_public_key(base64.b64decode(re.sub(r"\s", "", m.group(1)))).key_size
    except (ValueError, TypeError, AttributeError):
        return None


def conferir(dominio, consultar=txt):
    """{"spf", "dmarc", "dkim"} com o que foi achado, para a tela, e "achados": [(regra, título, severidade, evidência, solução)]."""
    achados = []
    spf = _spf_de(consultar(dominio))
    if not spf:
        achados.append(("email|spf-ausente", f"{dominio} não tem SPF", "media", f"Nenhum registro TXT de {dominio} começa com v=spf1.",
                        "Publique um SPF com os servidores que mandam e-mail pela organização, terminando em -all. Se o domínio não manda e-mail, use v=spf1 -all."))
    elif len(spf) > 1:
        achados.append(("email|spf-duplicado", f"{dominio} tem mais de um SPF", "media", f"{len(spf)} registros v=spf1: o SPF inteiro passa a falhar.",
                        "Junte tudo num registro SPF só."))
    else:
        final = next((t.lower() for t in spf[0].split() if t.lower().lstrip("+-~?") == "all"), None)
        if final in ("all", "+all"):
            achados.append(("email|spf-aberto", f"O SPF de {dominio} libera qualquer servidor", "alta", f"O SPF termina em {final}: {spf[0][:200]}",
                            "Troque o final por -all (ou ~all enquanto ajusta). Com +all, qualquer servidor do mundo passa no SPF."))
        elif final == "?all" or (final is None and "redirect=" not in spf[0].lower()):
            achados.append(("email|spf-neutro", f"O SPF de {dominio} não barra ninguém", "media", f"O SPF termina em {final or 'nada'}: {spf[0][:200]}",
                            "Termine o SPF em -all, ou ~all enquanto ajusta, para dizer que os outros servidores não podem mandar em nome do domínio."))
        consultas = consultas_do_spf(dominio, consultar)
        if consultas > MAXIMO_DE_CONSULTAS:
            achados.append(("email|spf-consultas", f"O SPF de {dominio} passa do limite de consultas", "media",
                            f"O SPF precisa de {consultas} consultas de DNS para ser avaliado; o limite é {MAXIMO_DE_CONSULTAS}, e passado dele o SPF falha.",
                            "Tire includes que não são mais usados, ou troque includes por endereços IP."))

    dmarc = [t for t in consultar(f"_dmarc.{dominio}") if t.lower().startswith("v=dmarc1")]
    politica = None
    if not dmarc:
        achados.append(("email|dmarc-ausente", f"{dominio} não tem DMARC", "alta", f"Não há registro v=DMARC1 em _dmarc.{dominio}.",
                        "Sem DMARC, e-mail falso em nome do domínio chega na caixa de entrada. Comece com p=none e um endereço em rua para receber os "
                        "relatórios, ajuste o SPF e o DKIM, e suba para p=quarantine e depois p=reject."))
    else:
        campos = {k.strip().lower(): v.strip() for k, _, v in (parte.partition("=") for parte in dmarc[0].split(";")) if k.strip()}
        politica = campos.get("p", "").lower()
        if politica not in ("quarantine", "reject"):
            achados.append(("email|dmarc-sem-efeito", f"O DMARC de {dominio} só observa", "media", f"A política é p={politica or 'nada'}: {dmarc[0][:200]}",
                            "Com p=none o DMARC só manda relatório e não barra e-mail falso. Depois de conferir os relatórios, suba para p=quarantine e p=reject."))
        elif campos.get("pct", "100") != "100":
            achados.append(("email|dmarc-parcial", f"O DMARC de {dominio} vale só para parte das mensagens", "baixa",
                            f"pct={campos['pct']}: o resto das mensagens que falham passa.", "Suba o pct para 100, ou tire o pct."))

    chaves = {}
    for seletor in SELETORES:
        registro = next((t for t in consultar(f"{seletor}._domainkey.{dominio}") if "p=" in t), None)
        if registro:
            chaves[seletor] = _tamanho_da_chave(registro)
    fracas = {s: t for s, t in chaves.items() if t and t < 1024}
    if fracas:
        achados.append(("email|dkim-fraco", f"Chave DKIM fraca em {dominio}", "media",
                        "; ".join(f"seletor {s}: chave de {t} bits" for s, t in fracas.items()) + ".",
                        "Gere uma chave nova de 2048 bits no serviço de e-mail e publique no DNS. Chave curta pode ser quebrada e usada para assinar e-mail falso."))
    if not chaves and spf:
        achados.append(("email|dkim-nao-achado", f"DKIM não encontrado em {dominio}", "informativa",
                        f"Nenhum dos seletores mais usados ({', '.join(SELETORES[:6])}…) tem chave DKIM.",
                        "Confira no serviço de e-mail se o DKIM está ligado. Ele pode existir com outro seletor, que só o serviço sabe."))
    return {"spf": spf[0][:300] if len(spf) == 1 else None, "dmarc": politica, "dkim": sorted(chaves), "achados": achados}
