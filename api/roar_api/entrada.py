"""Outras formas de entrar: passkey (WebAuthn) e login único da organização (OIDC).

Tudo o que vem do navegador ou do provedor é conferido aqui antes de virar sessão: assinatura, origem,
desafio de uso único, emissor, audiência, validade e nonce. O provedor só é buscado em endereço público.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import time

import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, ResidentKeyRequirement,
                                      UserVerificationRequirement)

from roar_ingestao import rede_externa

NOME_DO_SITE = "Panthera Roar"
MINUTOS_DO_PEDIDO = 5
LIMITE_DO_PROVEDOR = 512 * 1024
ALGORITMOS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]
SEGUNDOS_DA_DESCOBERTA = 3600
_descobertas = {}


class EntradaRecusada(Exception):
    """A mensagem aparece para quem tentou entrar: diz o que fazer, sem revelar detalhe interno."""


def novo_pedido():
    """O identificador vai para o navegador; o banco guarda só o resumo dele."""
    pedido = secrets.token_urlsafe(32)
    return pedido, hashlib.sha256(pedido.encode()).hexdigest()


def resumo_do_pedido(pedido):
    return hashlib.sha256(str(pedido).encode()).hexdigest()


# ------------------------------------------------------------------ passkey

def parte_confiavel(endereco_publico, origem_do_pedido):
    """O domínio a que a passkey fica presa, e as origens aceitas. Em localhost, vale a porta em que a tela abriu."""
    rp_id = endereco_publico.split(":")[0]
    origens = [f"https://{endereco_publico}"]
    if rp_id == "localhost" and re.fullmatch(r"https?://localhost(:\d{1,5})?", origem_do_pedido or ""):
        origens.append(origem_do_pedido)
    return rp_id, origens


def opcoes_de_cadastro(rp_id, usuario_id, email, nome, ja_cadastradas):
    opcoes = generate_registration_options(
        rp_id=rp_id, rp_name=NOME_DO_SITE, user_id=usuario_id.bytes, user_name=email, user_display_name=nome,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=bytes(c)) for c in ja_cadastradas],
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.REQUIRED,
                                                               user_verification=UserVerificationRequirement.REQUIRED))
    return json.loads(options_to_json(opcoes)), opcoes.challenge


def conferir_cadastro(credencial, desafio, rp_id, origens):
    try:
        conferida = verify_registration_response(credential=credencial, expected_challenge=desafio, expected_rp_id=rp_id,
                                                 expected_origin=origens, require_user_verification=True)
    except Exception as erro:
        raise EntradaRecusada("O aparelho não confirmou a passkey. Tente de novo.") from erro
    transportes = [str(t) for t in (credencial.get("response", {}).get("transports") or []) if isinstance(t, str)][:8]
    return conferida.credential_id, conferida.credential_public_key, conferida.sign_count, transportes


def opcoes_de_entrada(rp_id):
    # Sem lista de credenciais: o aparelho oferece as passkeys que tem para este site, e a pessoa escolhe.
    opcoes = generate_authentication_options(rp_id=rp_id, user_verification=UserVerificationRequirement.REQUIRED)
    return json.loads(options_to_json(opcoes)), opcoes.challenge


def credencial_usada(credencial):
    try:
        return base64url_to_bytes(str(credencial.get("rawId") or credencial.get("id") or ""))
    except (ValueError, TypeError) as erro:
        raise EntradaRecusada("Passkey não reconhecida.") from erro


def conferir_entrada(credencial, desafio, rp_id, origens, chave_publica, contador):
    try:
        conferida = verify_authentication_response(credential=credencial, expected_challenge=desafio, expected_rp_id=rp_id, expected_origin=origens,
                                                   credential_public_key=bytes(chave_publica), credential_current_sign_count=contador,
                                                   require_user_verification=True)
    except Exception as erro:
        raise EntradaRecusada("Passkey não reconhecida.") from erro
    return conferida.new_sign_count


def para_texto(dado):
    return base64.urlsafe_b64encode(dado).decode().rstrip("=")


def de_texto(texto):
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


# ------------------------------------------------------------------ login único (OIDC)

class Cofre:
    """Cifra o segredo do cliente OIDC com uma chave que só a API deriva."""

    def __init__(self, segredo_da_api):
        self._aes = AESGCM(hashlib.sha256(b"sso:" + segredo_da_api.encode()).digest())

    def fechar(self, texto):
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, texto.encode(), b"roar-sso")

    def abrir(self, dado):
        dado = bytes(dado)
        return self._aes.decrypt(dado[:12], dado[12:], b"roar-sso").decode()


def _buscar(metodo, endereco, **kwargs):
    """Só endereço público, sem redirecionamento: a configuração do SSO não vira ponte para a rede interna."""
    try:
        resposta, corpo = rede_externa.chamar(metodo, endereco, limite_de_bytes=LIMITE_DO_PROVEDOR, **kwargs)
    except rede_externa.DestinoRecusado as erro:
        raise EntradaRecusada(f"O provedor de login recusou a conexão: {erro}") from erro
    except Exception as erro:
        raise EntradaRecusada("O provedor de login não respondeu.") from erro
    try:
        return resposta.status_code, json.loads(corpo)
    except ValueError as erro:
        raise EntradaRecusada("O provedor de login respondeu algo que não é JSON.") from erro


def descobrir(emissor):
    emissor = emissor.rstrip("/")
    guardada = _descobertas.get(emissor)
    if guardada and time.monotonic() - guardada[0] < SEGUNDOS_DA_DESCOBERTA:
        return guardada[1]
    codigo, documento = _buscar("GET", f"{emissor}/.well-known/openid-configuration")
    if codigo != 200 or not isinstance(documento, dict):
        raise EntradaRecusada("Não achei a configuração OpenID deste emissor. Confira o endereço.")
    if str(documento.get("issuer", "")).rstrip("/") != emissor:
        raise EntradaRecusada("O emissor informado não é o que o provedor declara. Confira o endereço.")
    for campo in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not str(documento.get(campo, "")).startswith("https://"):
            raise EntradaRecusada("A configuração do provedor está incompleta.")
    _descobertas[emissor] = (time.monotonic(), documento)
    return documento


def endereco_de_autorizacao(documento, client_id, redirecionar_para, estado, nonce, desafio_pkce, email):
    from urllib.parse import urlencode

    parametros = {"response_type": "code", "client_id": client_id, "redirect_uri": redirecionar_para, "scope": "openid email profile",
                  "state": estado, "nonce": nonce, "code_challenge": desafio_pkce, "code_challenge_method": "S256", "login_hint": email}
    return f"{documento['authorization_endpoint']}?{urlencode(parametros)}"


def pkce():
    verificador = secrets.token_urlsafe(48)
    desafio = base64.urlsafe_b64encode(hashlib.sha256(verificador.encode()).digest()).decode().rstrip("=")
    return verificador, desafio


def trocar_codigo(documento, client_id, segredo, codigo, redirecionar_para, verificador):
    dados = {"grant_type": "authorization_code", "code": codigo, "redirect_uri": redirecionar_para, "client_id": client_id, "code_verifier": verificador}
    autenticacao = None
    if segredo:
        if "client_secret_basic" in (documento.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]):
            autenticacao = (client_id, segredo)
        else:
            dados["client_secret"] = segredo
    situacao, resposta = _buscar("POST", documento["token_endpoint"], data=dados, auth=autenticacao, cabecalhos={"Accept": "application/json"})
    if situacao != 200 or not isinstance(resposta, dict) or not resposta.get("id_token"):
        raise EntradaRecusada("O provedor de login não confirmou a entrada.")
    return resposta["id_token"]


def conferir_token(documento, client_id, id_token, nonce):
    """Assinatura pelas chaves do provedor, emissor, audiência, validade e o nonce deste pedido."""
    try:
        cabecalho = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as erro:
        raise EntradaRecusada("O provedor de login devolveu um token inválido.") from erro
    if cabecalho.get("alg") not in ALGORITMOS:
        raise EntradaRecusada("O provedor de login assinou o token de um jeito que não é aceito.")
    situacao, chaves = _buscar("GET", documento["jwks_uri"])
    if situacao != 200 or not isinstance(chaves, dict):
        raise EntradaRecusada("Não consegui as chaves do provedor de login.")
    try:
        conjunto = jwt.PyJWKSet.from_dict(chaves)
        chave = next(k for k in conjunto.keys if k.key_id == cabecalho.get("kid")) if cabecalho.get("kid") else conjunto.keys[0]
        conteudo = jwt.decode(id_token, chave.key, algorithms=[cabecalho["alg"]], audience=client_id, issuer=documento["issuer"],
                              options={"require": ["exp", "iat", "iss", "aud", "sub"]}, leeway=60)
    except (jwt.PyJWTError, StopIteration, IndexError) as erro:
        raise EntradaRecusada("O token do provedor de login não passou na conferência.") from erro
    if not secrets.compare_digest(str(conteudo.get("nonce", "")), nonce):
        raise EntradaRecusada("O token do provedor de login não é deste pedido.")
    if conteudo.get("email_verified") is False:
        raise EntradaRecusada("O provedor de login não confirmou este e-mail.")
    email = str(conteudo.get("email") or conteudo.get("preferred_username") or conteudo.get("upn") or "").strip().lower()
    if "@" not in email:
        raise EntradaRecusada("O provedor de login não informou o e-mail.")
    return email
