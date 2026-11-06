"""Subdomínio abandonado: o nome ainda aponta (CNAME) para um serviço de nuvem que já foi apagado.

Quem criar de novo esse serviço, com o mesmo nome, passa a responder pelo subdomínio da organização: página falsa,
captura de senha, cookie do domínio. Dois sinais, sem tentar criar nada: o destino do CNAME não existe mais no DNS, ou
a página do provedor diz que aquele site não existe.
"""

import re

import dns.exception
import dns.resolver

TEMPO = 5
# (destino do CNAME, provedor, como saber que foi apagado: "dns" quando o nome some, ou o texto da página do provedor)
PROVEDORES = (
    (re.compile(r"\.azurewebsites\.net$"), "Azure App Service", "dns"),
    (re.compile(r"\.cloudapp\.net$|\.cloudapp\.azure\.com$"), "Azure Cloud Service", "dns"),
    (re.compile(r"\.trafficmanager\.net$"), "Azure Traffic Manager", "dns"),
    (re.compile(r"\.blob\.core\.windows\.net$"), "Azure Storage", "dns"),
    (re.compile(r"\.azureedge\.net$"), "Azure CDN", "dns"),
    (re.compile(r"\.elasticbeanstalk\.com$"), "AWS Elastic Beanstalk", "dns"),
    (re.compile(r"\.s3[\w.-]*\.amazonaws\.com$"), "AWS S3", "NoSuchBucket"),
    (re.compile(r"\.herokuapp\.com$|\.herokudns\.com$"), "Heroku", "No such app"),
    (re.compile(r"\.github\.io$"), "GitHub Pages", "There isn't a GitHub Pages site here"),
    (re.compile(r"\.myshopify\.com$"), "Shopify", "Sorry, this shop is currently unavailable"),
    (re.compile(r"\.fastly\.net$"), "Fastly", "Fastly error: unknown domain"),
    (re.compile(r"\.zendesk\.com$"), "Zendesk", "Help Center Closed"),
    (re.compile(r"\.wordpress\.com$"), "WordPress.com", "Do you want to register"),
    (re.compile(r"\.surge\.sh$"), "Surge", "project not found"),
)


def cname(nome, resolver=None):
    """O destino final da cadeia de CNAME, ou None quando o nome não é um apelido."""
    resolver = resolver or dns.resolver.Resolver()
    destino = None
    atual = nome
    for _ in range(8):
        try:
            resposta = resolver.resolve(atual, "CNAME", lifetime=TEMPO)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            break
        atual = destino = str(resposta[0].target).rstrip(".").lower()
    return destino


def existe(nome, resolver=None):
    """O nome responde no DNS com algum endereço."""
    resolver = resolver or dns.resolver.Resolver()
    for tipo in ("A", "AAAA"):
        try:
            resolver.resolve(nome, tipo, lifetime=TEMPO)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
    return False


def avaliar(nome, destino, existe_=existe, pagina=None):
    """(regra, título, severidade, evidência, solução) quando o nome pode ser tomado, ou None. `pagina` devolve o texto que o
    nome responde na web; só é chamada quando o provedor se reconhece pela página."""
    if not destino:
        return None
    provedor = next(((p, sinal) for padrao, p, sinal in PROVEDORES if padrao.search(destino)), None)
    solucao = (f"Apague o registro CNAME de {nome} no DNS, ou recrie o serviço no provedor com a conta da organização. "
               "Enquanto o registro existir, qualquer pessoa que criar esse serviço responde por este nome.")
    if provedor:
        nome_do_provedor, sinal = provedor
        texto = (pagina() if callable(pagina) else pagina) if sinal != "dns" else None
        apagado = not existe_(destino) if sinal == "dns" else bool(texto and sinal.lower() in texto.lower())
        if apagado:
            prova = "não existe mais no DNS" if sinal == "dns" else f"responde \"{sinal}\""
            return ("tomada|subdominio", f"{nome} pode ser tomado: aponta para {nome_do_provedor} apagado", "alta",
                    f"{nome} é um apelido (CNAME) de {destino}, que {prova}.", solucao)
        return None
    if not existe_(destino):
        return ("tomada|subdominio", f"{nome} aponta para um nome que não existe", "media",
                f"{nome} é um apelido (CNAME) de {destino}, que não existe no DNS. Se o domínio de destino estiver livre para registro, quem registrar responde por {nome}.",
                solucao)
    return None
