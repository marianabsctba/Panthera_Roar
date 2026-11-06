"""Login único por SAML 2.0: o Roar pede a entrada ao provedor da organização e confere a resposta assinada.

Só o que a assinatura cobre é lido. A biblioteca devolve o elemento assinado, e tudo sai dele: um atacante que embrulha
uma asserção falsa em volta de uma assinatura verdadeira (o ataque de embrulho) não consegue fazer a falsa ser lida.
Também recusa DOCTYPE, asserção cifrada e e-mail com comentário no meio, outro truque conhecido contra SAML.
"""

import base64
import binascii
import re
import secrets
import zlib
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from xml.sax.saxutils import escape, quoteattr

from cryptography import x509
from lxml import etree
from signxml import XMLVerifier
from signxml.exceptions import InvalidInput, InvalidSignature

NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
SUCESSO = "urn:oasis:names:tc:SAML:2.0:status:Success"
TOLERANCIA = timedelta(minutes=2)
TAMANHO_MAXIMO = 256 * 1024
# Onde os provedores mais usados põem o e-mail, quando ele não vem no NameID.
ATRIBUTOS_DE_EMAIL = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "email", "mail", "Email", "emailAddress",
                      "urn:oid:0.9.2342.19200300.100.1.3", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")


class SamlRecusado(Exception):
    """A mensagem volta para a tela de entrada: diz o que aconteceu, sem detalhe interno."""


def _agora():
    return datetime.now(timezone.utc)


def _instante(texto):
    try:
        return datetime.fromisoformat(texto.replace("Z", "+00:00")) if texto else None
    except ValueError:
        raise SamlRecusado("A resposta do provedor traz uma data inválida.") from None


def certificado_em_pem(texto):
    """Aceita o certificado com ou sem as linhas BEGIN/END, como os provedores mostram. Recusa o que não for certificado."""
    corpo = re.sub(r"-----(BEGIN|END) CERTIFICATE-----|\s", "", texto or "")
    try:
        der = base64.b64decode(corpo, validate=True)
        x509.load_der_x509_certificate(der)
    except (binascii.Error, ValueError):
        raise SamlRecusado("O certificado não é válido. Cole o certificado de assinatura do provedor, em Base64.") from None
    linhas = "\n".join(corpo[i:i + 64] for i in range(0, len(corpo), 64))
    return f"-----BEGIN CERTIFICATE-----\n{linhas}\n-----END CERTIFICATE-----\n"


def pedido_de_entrada(destino, entidade_do_roar, acs, estado, email=""):
    """O endereço para mandar a pessoa ao provedor (HTTP-Redirect) e o ID do pedido, que a resposta precisa citar."""
    identificador = "_" + secrets.token_hex(20)
    instante = _agora().strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{identificador}" Version="2.0" IssueInstant="{instante}" '
           f'Destination={quoteattr(destino)} AssertionConsumerServiceURL={quoteattr(acs)} ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
           f'<saml:Issuer>{escape(entidade_do_roar)}</saml:Issuer>'
           f'<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>')
    compactado = zlib.compress(xml.encode())[2:-4]  # deflate cru, como o padrão pede no redirect
    parametros = {"SAMLRequest": base64.b64encode(compactado).decode(), "RelayState": estado}
    if email:
        parametros["login_hint"] = email
    return f"{destino}{'&' if '?' in destino else '?'}{urlencode(parametros)}", identificador


def _texto_simples(elemento):
    """O texto do elemento, recusando filho ou comentário dentro: 'ana@x.com<!---->.y.com' viraria só 'ana@x.com'."""
    if elemento is None:
        return None
    if len(elemento):
        raise SamlRecusado("A resposta do provedor traz um valor com marcação dentro. A entrada foi recusada.")
    return (elemento.text or "").strip()


def conferir_resposta(resposta_b64, certificado, entidade_do_provedor, entidade_do_roar, acs, id_do_pedido, agora=None):
    """Devolve o e-mail de quem entrou, ou SamlRecusado com o motivo."""
    agora = agora or _agora()
    if not resposta_b64 or len(resposta_b64) > TAMANHO_MAXIMO * 2:
        raise SamlRecusado("A resposta do provedor veio vazia ou grande demais.")
    try:
        bruto = base64.b64decode(resposta_b64, validate=False)
    except (binascii.Error, ValueError):
        raise SamlRecusado("A resposta do provedor não pôde ser lida.") from None
    if len(bruto) > TAMANHO_MAXIMO or b"<!DOCTYPE" in bruto.upper() or b"<!ENTITY" in bruto.upper():
        raise SamlRecusado("A resposta do provedor não pôde ser lida.")
    leitor = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, remove_blank_text=False)
    try:
        raiz = etree.fromstring(bruto, leitor)
    except etree.XMLSyntaxError:
        raise SamlRecusado("A resposta do provedor não pôde ser lida.") from None
    if raiz.tag != f"{{{NS['samlp']}}}Response":
        raise SamlRecusado("A resposta do provedor não é uma resposta de login.")
    status = raiz.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != SUCESSO:
        raise SamlRecusado("O provedor de login não liberou a entrada.")
    if raiz.findall(".//saml:EncryptedAssertion", NS):
        raise SamlRecusado("A resposta veio cifrada. No provedor, desligue a criptografia da asserção para o Roar.")
    if len(raiz.findall(".//saml:Assertion", NS)) != 1:
        raise SamlRecusado("A resposta do provedor precisa trazer exatamente uma asserção.")

    try:
        verificado = XMLVerifier().verify(bruto, x509_cert=certificado)
    except (InvalidSignature, InvalidInput):
        raise SamlRecusado("A assinatura da resposta não confere com o certificado cadastrado.") from None
    assinado = verificado[0].signed_xml if isinstance(verificado, list) else verificado.signed_xml
    # Daqui em diante, só o que está debaixo da assinatura.
    if assinado.tag == f"{{{NS['saml']}}}Assertion":
        assercao = assinado
    elif assinado.tag == f"{{{NS['samlp']}}}Response":
        assercoes = assinado.findall("saml:Assertion", NS)
        if len(assercoes) != 1:
            raise SamlRecusado("A resposta do provedor precisa trazer exatamente uma asserção.")
        assercao = assercoes[0]
    else:
        raise SamlRecusado("A assinatura não cobre a asserção.")

    if _texto_simples(assercao.find("saml:Issuer", NS)) != entidade_do_provedor:
        raise SamlRecusado("A resposta veio de outro provedor, não do cadastrado pela organização.")
    condicoes = assercao.find("saml:Conditions", NS)
    if condicoes is None:
        raise SamlRecusado("A resposta do provedor não traz o prazo de validade.")
    antes, depois = _instante(condicoes.get("NotBefore")), _instante(condicoes.get("NotOnOrAfter"))
    if (antes and agora + TOLERANCIA < antes) or (depois and agora - TOLERANCIA >= depois):
        raise SamlRecusado("A resposta do provedor está fora do prazo. Confira o relógio do servidor e tente de novo.")
    publicos = [_texto_simples(p) for p in condicoes.findall("saml:AudienceRestriction/saml:Audience", NS)]
    if entidade_do_roar not in publicos:
        raise SamlRecusado("A resposta foi feita para outro sistema. No provedor, o identificador precisa ser o que a tela do Roar mostra.")
    confirmada = False
    for confirmacao in assercao.findall("saml:Subject/saml:SubjectConfirmation", NS):
        dados = confirmacao.find("saml:SubjectConfirmationData", NS)
        if confirmacao.get("Method") != "urn:oasis:names:tc:SAML:2.0:cm:bearer" or dados is None:
            continue
        validade = _instante(dados.get("NotOnOrAfter"))
        if dados.get("Recipient") == acs and dados.get("InResponseTo") == id_do_pedido and validade and agora - TOLERANCIA < validade:
            confirmada = True
    if not confirmada:
        raise SamlRecusado("A resposta não corresponde ao pedido de entrada feito pelo Roar. Tente de novo.")

    email = _texto_simples(assercao.find("saml:Subject/saml:NameID", NS))
    if not email or "@" not in email:
        for atributo in assercao.findall("saml:AttributeStatement/saml:Attribute", NS):
            if atributo.get("Name") in ATRIBUTOS_DE_EMAIL:
                valor = _texto_simples(atributo.find("saml:AttributeValue", NS))
                if valor and "@" in valor:
                    email = valor
                    break
    if not email or "@" not in email:
        raise SamlRecusado("O provedor não mandou o e-mail. Configure o NameID como e-mail, ou um atributo de e-mail.")
    return email.lower()


def metadados(entidade_do_roar, acs):
    """O que o provedor pede para cadastrar o Roar: o identificador e o endereço de retorno."""
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID={quoteattr(entidade_do_roar)}>'
            f'<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            f'<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>'
            f'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location={quoteattr(acs)} index="0" isDefault="true"/>'
            f'</md:SPSSODescriptor></md:EntityDescriptor>\n')
