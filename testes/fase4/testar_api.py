#!/usr/bin/env python3
"""Fase 4, primeira parte: login e fila de alertas. Requer infra/subir.sh já executado e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_api.py

Usa o banco de verdade e apaga no final tudo o que criou.
"""

import base64
import hashlib
import json
import os
import random
import re
import secrets
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api")]

ENV = {}
for linha in Path("/opt/panthera-roar/.env").read_text().splitlines():
    if "=" in linha and not linha.startswith("#"):
        k, v = linha.split("=", 1)
        ENV[k] = v
ADMIN = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
URL_API = f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar"

from roar_api.app import COOKIE, ESTATICO, app, falhas_de_login  # noqa: E402

XSS = '<img src=x onerror="alert(1)">'
COOKIE_DE_SESSAO = "roar_sessao"
RESULTADOS = []
CRIADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def recusado(funcao):
    try:
        funcao()
        return False
    except psycopg.Error:
        return True


def novo_cliente(nome):
    sufixo = uuid.uuid4().hex[:10]
    cliente = ADMIN.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{sufixo}",)).fetchone()[0]
    ger = f"t{sufixo}"
    ADMIN.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)",
                  (ger, cliente, random.randint(40000, 60000)))
    senha = secrets.token_urlsafe(18)
    email = f"analista-{sufixo}@exemplo.test"
    ADMIN.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, %s, %s, 'administrador')",
                  (cliente, email, f"Analista {nome}", PasswordHasher().hash(senha)))
    agora = datetime.now(timezone.utc)
    entidade = ADMIN.execute(
        "INSERT INTO entidades (cliente_id, tipo, chave, nome, primeira_vista, ultima_vista, risco)"
        " VALUES (%s, 'usuario', %s, %s, %s, %s, 75) RETURNING id", (cliente, f"maria{sufixo}", XSS, agora, agora)).fetchone()[0]
    ADMIN.execute("UPDATE entidades SET risco_em = %s WHERE id = %s", (agora, entidade))
    grupo = ADMIN.execute(
        "INSERT INTO grupos_alerta (cliente_id, chave, dia, gerenciador_id, agente_id, nivel, severidade, regras,"
        " primeira_em, ultima_em) VALUES (%s, 'k', %s, %s, '001', 10, 'media', '{5712}', %s, %s) RETURNING id",
        (cliente, agora.date(), ger, agora, agora)).fetchone()[0]
    evento = ADMIN.execute(
        "INSERT INTO eventos (cliente_id, grupo_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel, severidade,"
        " regra_id, regra_descricao, agente_id, agente_nome, ip_origem, usuario, bruto)"
        " VALUES (%s, %s, %s, 'wazuh', 'e1', %s, 10, 'media', '5712', %s, '001', 'servidor', '203.0.113.5', %s, %s)"
        " RETURNING id", (cliente, grupo, ger, agora, XSS, XSS, Jsonb({"segredo_do_bruto": "nao-sair"}))).fetchone()[0]
    # O peso bate com o risco do alerta: com menos, o motor de risco, que roda junto, encerra o alerta por ter caído.
    ADMIN.execute(
        "INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id, detalhes)"
        " VALUES (%s, %s, 'primeiro_host', 'h', %s, 75, %s, %s, %s)",
        (cliente, entidade, agora.date(), agora, evento, Jsonb({"host": XSS})))
    alerta = ADMIN.execute(
        "INSERT INTO alertas_risco (cliente_id, entidade_id, severidade, risco_maximo, aberto_em)"
        " VALUES (%s, %s, 'alta', 75, %s) RETURNING id", (cliente, entidade, agora)).fetchone()[0]
    dados = {"id": cliente, "ger": ger, "email": email, "senha": senha, "alerta": alerta, "grupo": grupo}
    CRIADOS.append(dados)
    return dados


def limpar():
    ids = [c["id"] for c in CRIADOS]
    for tabela in ("email_config", "segredos", "sso", "chaves_api", "relatorios_gerados", "notificacoes", "intel_ocorrencias", "intel_indicadores", "intel_fontes", "casos_notas", "casos_itens", "casos", "regras_proprias", "ativos", "auditoria", "regras", "sinais", "alertas_risco", "vistos", "horas", "silencios", "pares", "entidades", "eventos", "grupos_alerta",
                   "gerenciadores", "usuarios"):
        ADMIN.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (ids,))
    ADMIN.execute("DELETE FROM clientes WHERE id = ANY(%s)", (ids,))


def entrar(http, cliente):
    return http.post("/api/entrar", json={"email": cliente["email"], "senha": cliente["senha"]})


def testar_linha_do_tempo():
    print("\n== Linha do tempo do risco", flush=True)
    from roar_api.app import LIMITE_DO_RISCO_ALTO, LIMITE_DO_RISCO_CRITICO, MEIA_VIDA_DO_RISCO_HORAS, _linha_do_tempo
    sys.path.insert(0, str(RAIZ / "ueba"))
    from roar_ueba.motor import Parametros
    p = Parametros()
    registrar("a tela usa os mesmos números do motor", (MEIA_VIDA_DO_RISCO_HORAS, LIMITE_DO_RISCO_ALTO, LIMITE_DO_RISCO_CRITICO)
              == (p.meia_vida_horas, p.limite_alerta, p.limite_critico))
    inicio = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tecnicas = {"T1110": {"nome": "Brute Force", "tatica": "Credential Access"}, "T1078": {"nome": "Valid Accounts", "tatica": "Initial Access"}}
    sinais = [
        {"tipo": "primeiro_ip", "peso": 10, "ocorrido_em": inicio + timedelta(hours=24), "mitre": []},
        {"tipo": "sucesso_apos_falhas", "peso": 40, "ocorrido_em": inicio, "mitre": ["T9999"]},
        {"tipo": "primeiro_host", "peso": 15, "ocorrido_em": inicio + timedelta(days=7, hours=12), "mitre": None},
    ]
    linha = _linha_do_tempo(sinais, tecnicas)
    registrar("sinais saem em ordem de acontecimento", [s["tipo"] for s in linha] == ["sucesso_apos_falhas", "primeiro_ip", "primeiro_host"])
    registrar("risco decai pela meia-vida", [s["risco_depois"] for s in linha][:2] == [40.0, 30.0], str([s["risco_depois"] for s in linha]))
    registrar("sinal fora da janela não soma", linha[2]["risco_depois"] == round(15 + 10 * 0.5 ** 6.5, 1), str(linha[2]["risco_depois"]))
    registrar("técnica desconhecida do evento cai na do sinal", linha[0]["tecnica"] == {"codigo": "T1110", **tecnicas["T1110"]})
    registrar("sinal sem técnica conhecida fica sem", linha[2]["tecnica"] is None)


def testar_mascara_sem_banco():
    print("\n== Máscara de dado pessoal", flush=True)
    from roar_api.ofuscacao import CATEGORIAS, Mascara
    m = Mascara(CATEGORIAS, b"chave", "cliente")
    texto = m.texto("cpf 529.982.247-25 cnpj 11.222.333/0001-81 cartao 4111 1111 1111 1111 tel (41) 99876-5432 mail fulano@exemplo.com.br de 203.0.113.5")
    registrar("CPF, CNPJ, cartão, telefone, e-mail e IP somem do texto",
              texto == "cpf ***.***.***-** cnpj **.***.***/****-** cartao **** **** **** 1111 tel (**) *****-**** mail f***@exemplo.com.br de 203.0.x.x", texto)
    intacto = "versão 1.2.3.4.5, dia 2026-11-05 10:20:30, número 12345678901, cartão 4111 1111 1111 1112"
    registrar("versão, data e número que não passam na conferência ficam", m.texto(intacto) == intacto, m.texto(intacto))
    dado = m.dado({"usuario": "maria.silva", "bruto": {"full_log": "senha errada para maria.silva", "data": {"srcuser": "Maria.Silva"}},
                   "riscos": [{"entidade": "maria.silva", "entidade_tipo": "usuario"}, {"entidade": "web-01", "entidade_tipo": "ativo"}], "peso": 15})
    apelido = dado["usuario"]
    registrar("usuário vira apelido", apelido.startswith("usuario-") and "maria" not in json.dumps(dado).lower(), json.dumps(dado))
    registrar("o mesmo usuário tem o mesmo apelido em todo lugar", dado["bruto"]["data"]["srcuser"] == dado["riscos"][0]["entidade"] == apelido
              and dado["bruto"]["full_log"] == f"senha errada para {apelido}")
    registrar("ativo não é mascarado como usuário", dado["riscos"][1]["entidade"] == "web-01" and dado["peso"] == 15)
    registrar("apelido muda de uma organização para outra", Mascara(CATEGORIAS, b"chave", "outro").apelido("maria.silva") != apelido)
    so_ip = Mascara(["ip"], b"chave", "cliente").dado({"usuario": "maria", "ip_origem": "2001:db8::1", "texto": "maria@x.com"})
    registrar("só o que está ligado é mascarado", so_ip == {"usuario": "maria", "ip_origem": "2001:x:x", "texto": "maria@x.com"}, str(so_ip))


def testar_ocsf_sem_banco():
    print("\n== OCSF", flush=True)
    from roar_api.ocsf import converter
    agora = datetime.now(timezone.utc)
    base = {"id": 7, "ocorrido_em": agora, "recebido_em": agora, "severidade": "media", "regra_id": "5715", "agente_nome": "srv", "agente_id": "001",
            "ip_origem": "203.0.113.9", "usuario": "ana"}
    login = converter({**base, "regra_grupos": ["sshd", "authentication_success"], "bruto": {}})
    registrar("login vira Authentication com sucesso", (login["class_uid"], login["type_uid"], login["status_id"], login["user"]["name"])
              == (3002, 300201, 1, "ana"), str(login)[:200])
    falha = converter({**base, "regra_grupos": ["authentication_failed"], "bruto": {}})
    registrar("falha de login vira Authentication com falha", (falha["class_uid"], falha["status"]) == (3002, "Failure"))
    arquivo = converter({**base, "usuario": None, "regra_grupos": ["ossec", "syscheck"],
                         "bruto": {"syscheck": {"path": "/etc/shadow", "event": "modified", "sha256_after": "ab" * 32}}})
    registrar("integridade vira File System Activity com o resumo", (arquivo["class_uid"], arquivo["activity_name"], arquivo["file"]["name"],
              arquivo["file"]["hashes"][0]["algorithm"]) == (1001, "Update", "shadow", "SHA-256"), str(arquivo.get("file")))
    grupo = converter({**base, "regra_grupos": ["windows"], "bruto": {"data": {"win": {"system": {"eventID": "4732"}, "eventdata": {
        "targetUserName": "Administrators", "memberName": "bob", "subjectUserName": "ana"}}}}})
    registrar("entrada em grupo vira Group Management", (grupo["class_uid"], grupo["group"]["name"], grupo["user"]["name"], grupo["actor"]["user"]["name"])
              == (3006, "Administrators", "bob", "ana"))
    registrar("sudo vira Authorize Session", converter({**base, "regra_grupos": ["sudo"], "bruto": {}})["class_uid"] == 3003)
    achado = converter({**base, "regra_grupos": ["web", "attack"], "mitre": ["T1190"], "bruto": {}},
                       {"T1190": {"nome": "Exploit Public-Facing Application", "tatica": "Initial Access"}})
    registrar("o resto vira Detection Finding com a técnica do ATT&CK", (achado["class_uid"], achado["finding_info"]["attacks"][0]["technique"]["name"],
              achado["finding_info"]["attacks"][0]["tactic"]["name"], achado["severity_id"]) == (2004, "Exploit Public-Facing Application", "Initial Access", 3))
    sca = converter({**base, "usuario": None, "regra_grupos": ["sca"], "bruto": {"data": {"sca": {"type": "check", "policy": "CIS Debian 12",
                    "check": {"id": "28500", "title": "Garantir /tmp separado", "result": "failed", "compliance": {"cis": "1.1.2"}}}}}})
    registrar("checagem de configuração vira Compliance Finding", (sca["class_uid"], sca["compliance"]["status"], sca["compliance"]["standards"],
              sca["finding_info"]["title"]) == (2003, "Fail", ["CIS Debian 12"], "Garantir /tmp separado"), str(sca)[:200])
    registrar("campo vazio não aparece", "status" not in converter({**base, "regra_grupos": [], "bruto": {}, "usuario": None}).get("user", {}))


def _b64(dado):
    import base64
    return base64.urlsafe_b64encode(dado).decode().rstrip("=")


def _de_b64(texto):
    import base64
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


class Autenticador:
    """Um aparelho de passkey em software: chave P-256, resposta WebAuthn montada e assinada como um celular faria."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.privada = ec.generate_private_key(ec.SECP256R1())
        self.credencial = os.urandom(16)
        self.contador = 0
        self.usuario = None

    def _dados(self, rp_id, flags, extra=b""):
        return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + self.contador.to_bytes(4, "big") + extra

    def criar(self, opcoes, origem):
        import cbor2
        numeros = self.privada.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numeros.x.to_bytes(32, "big"), -3: numeros.y.to_bytes(32, "big")})
        anexo = bytes(16) + len(self.credencial).to_bytes(2, "big") + self.credencial + cose
        self.usuario = opcoes["user"]["id"]
        cliente = json.dumps({"type": "webauthn.create", "challenge": opcoes["challenge"], "origin": origem, "crossOrigin": False}).encode()
        atestado = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": self._dados(opcoes["rp"]["id"], 0x45, anexo)})
        return {"id": _b64(self.credencial), "rawId": _b64(self.credencial), "type": "public-key",
                "response": {"clientDataJSON": _b64(cliente), "attestationObject": _b64(atestado), "transports": ["internal"]}}

    def assinar(self, opcoes, origem, contador=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        self.contador = self.contador + 1 if contador is None else contador
        cliente = json.dumps({"type": "webauthn.get", "challenge": opcoes["challenge"], "origin": origem, "crossOrigin": False}).encode()
        dados = self._dados(opcoes["rpId"], 0x05)
        assinatura = self.privada.sign(dados + hashlib.sha256(cliente).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": _b64(self.credencial), "rawId": _b64(self.credencial), "type": "public-key",
                "response": {"clientDataJSON": _b64(cliente), "authenticatorData": _b64(dados), "signature": _b64(assinatura), "userHandle": self.usuario}}


def testar_passkeys(http, a):
    print("\n== Passkeys", flush=True)
    origem = "https://testserver"
    aparelho = Autenticador()
    entrar(http, a)
    registrar("cadastrar passkey pede a senha", http.post("/api/passkeys/cadastro/inicio", json={"senha": "errada"}).status_code == 403)
    inicio = http.post("/api/passkeys/cadastro/inicio", json={"senha": a["senha"]}).json()
    registrar("o pedido exige passkey guardada no aparelho e verificação da pessoa",
              inicio["opcoes"]["authenticatorSelection"]["residentKey"] == "required" and inicio["opcoes"]["authenticatorSelection"]["userVerification"] == "required")
    outro = Autenticador()
    registrar("resposta de outro site é recusada", http.post("/api/passkeys/cadastro/fim", json={
        "pedido": inicio["pedido"], "credencial": outro.criar(inicio["opcoes"], "https://phishing.exemplo"), "nome": "x"}).status_code == 422)
    inicio = http.post("/api/passkeys/cadastro/inicio", json={"senha": a["senha"]}).json()
    fim = http.post("/api/passkeys/cadastro/fim", json={"pedido": inicio["pedido"], "credencial": aparelho.criar(inicio["opcoes"], origem), "nome": "Celular"})
    registrar("passkey cadastrada", fim.status_code == 201, fim.text[:160])
    registrar("o mesmo pedido não serve duas vezes", http.post("/api/passkeys/cadastro/fim", json={
        "pedido": inicio["pedido"], "credencial": aparelho.criar(inicio["opcoes"], origem), "nome": "Celular"}).status_code == 409)
    registrar("a passkey aparece na conta", [p["nome"] for p in http.get("/api/passkeys").json()["passkeys"]] == ["Celular"])
    http.post("/api/sair")
    http.cookies.clear()

    pedido = http.post("/api/passkeys/entrar/inicio").json()
    entrada = http.post("/api/passkeys/entrar/fim", json={"pedido": pedido["pedido"], "credencial": aparelho.assinar(pedido["opcoes"], origem)})
    registrar("entra com a passkey, sem senha nem código", entrada.status_code == 204 and http.get("/api/eu").status_code == 200, entrada.text[:160])
    http.post("/api/sair")
    http.cookies.clear()
    pedido = http.post("/api/passkeys/entrar/inicio").json()
    registrar("contador que volta para trás é recusado, como credencial clonada", http.post("/api/passkeys/entrar/fim", json={
        "pedido": pedido["pedido"], "credencial": aparelho.assinar(pedido["opcoes"], origem, contador=1)}).status_code == 401)
    pedido = http.post("/api/passkeys/entrar/inicio").json()
    registrar("passkey desconhecida é recusada", http.post("/api/passkeys/entrar/fim", json={
        "pedido": pedido["pedido"], "credencial": Autenticador().assinar(pedido["opcoes"], origem)}).status_code == 401)
    pedido = http.post("/api/passkeys/entrar/inicio").json()
    registrar("assinatura feita para outro site é recusada", http.post("/api/passkeys/entrar/fim", json={
        "pedido": pedido["pedido"], "credencial": aparelho.assinar(pedido["opcoes"], "https://phishing.exemplo")}).status_code == 401)
    registrar("entrar por passkey fica na trilha", ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao IN ('criar_passkey', 'logon_passkey')",
                                                                 (a["id"],)).fetchone()[0] == 2)
    entrar(http, a)
    registrar("a pessoa apaga a própria passkey", http.request("DELETE", f"/api/passkeys/{fim.json()['id']}").status_code == 204
              and http.get("/api/passkeys").json()["passkeys"] == [])
    http.post("/api/sair")
    http.cookies.clear()
    falhas_de_login.clear()


class ProvedorFalso:
    """Um provedor OpenID em memória: assina com a própria chave e guarda o que recebeu."""

    def __init__(self, emissor):
        from cryptography.hazmat.primitives.asymmetric import rsa
        import jwt as pyjwt
        self.emissor, self.privada, self.recebido, self.conteudo = emissor, rsa.generate_private_key(public_exponent=65537, key_size=2048), [], {}
        publica = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(self.privada.public_key()))
        self.jwks = {"keys": [{**publica, "kid": "k1", "alg": "RS256", "use": "sig"}]}

    def __call__(self, metodo, endereco, **kwargs):
        import jwt as pyjwt
        self.recebido.append((metodo, endereco, kwargs))
        if endereco.endswith("/.well-known/openid-configuration"):
            return 200, {"issuer": self.emissor, "authorization_endpoint": f"{self.emissor}/autorizar", "token_endpoint": f"{self.emissor}/token",
                         "jwks_uri": f"{self.emissor}/chaves", "token_endpoint_auth_methods_supported": ["client_secret_basic"]}
        if endereco.endswith("/chaves"):
            return 200, self.jwks
        if endereco.endswith("/token"):
            agora = int(time.time())
            conteudo = {"iss": self.emissor, "aud": "roar", "sub": "pessoa-1", "iat": agora, "exp": agora + 300, "email_verified": True, **self.conteudo}
            return 200, {"id_token": pyjwt.encode(conteudo, self.privada, algorithm="RS256", headers={"kid": "k1"})}
        return 404, {}


def testar_sso(http, a, b):
    print("\n== Login único (SSO)", flush=True)
    from urllib.parse import parse_qs, urlsplit
    from roar_api import entrada as modulo
    emissor = "https://idp.exemplo.test"
    provedor = ProvedorFalso(emissor)
    original, modulo._buscar = modulo._buscar, provedor
    modulo._descobertas.clear()
    senha_n1 = secrets.token_urlsafe(18)
    email_n1 = f"n1sso-{uuid.uuid4().hex[:6]}@exemplo.test"
    ADMIN.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Pessoa N1', %s, 'analista_n1')",
                  (a["id"], email_n1, PasswordHasher().hash(senha_n1)))
    try:
        entrar(http, a)
        registrar("emissor sem https é recusado", http.request("PUT", "/api/organizacao/sso", json={"emissor": "http://idp", "client_id": "roar"}).status_code == 422)
        r = http.request("PUT", "/api/organizacao/sso", json={"emissor": emissor, "client_id": "roar", "segredo": "s3gredo", "dominios": ["exemplo.test"]})
        registrar("o administrador configura o SSO", r.status_code == 204, r.text[:160])
        visto = http.get("/api/organizacao/sso").json()
        registrar("o segredo não volta para a tela", visto["config"]["tem_segredo"] is True and "s3gredo" not in json.dumps(visto)
                  and visto["retorno"].endswith("/api/sso/retorno"))
        registrar("o segredo fica cifrado no banco", b"s3gredo" not in bytes(ADMIN.execute("SELECT segredo FROM sso WHERE cliente_id = %s", (a["id"],)).fetchone()[0]))
        http.post("/api/sair")
        http.cookies.clear()

        def iniciar(email):
            resposta = http.get("/api/sso/inicio", params={"email": email})
            return resposta, {k: v[0] for k, v in parse_qs(urlsplit(resposta.json().get("url", "")).query).items()} if resposta.status_code == 200 else {}

        registrar("e-mail sem SSO não inicia", iniciar(b["email"])[0].status_code == 404)
        registrar("o botão de outro provedor não serve", http.get("/api/sso/inicio", params={"email": a["email"], "provedor": "google"}).status_code == 409)
        resposta, parametros = iniciar(a["email"])
        registrar("o início leva ao provedor com PKCE, nonce e estado", resposta.status_code == 200 and parametros["code_challenge_method"] == "S256"
                  and parametros["nonce"] and parametros["state"] and parametros["client_id"] == "roar", str(parametros)[:200])
        provedor.conteudo = {"email": a["email"], "nonce": parametros["nonce"]}
        volta = http.get("/api/sso/retorno", params={"code": "codigo-1", "state": parametros["state"]}, follow_redirects=False)
        registrar("o retorno abre a sessão e volta para a tela", volta.status_code == 303 and volta.headers["location"] == "/"
                  and http.get("/api/eu").json()["nome"] == "Analista a", str(volta.headers)[:200])
        troca_de_codigo = next(k for m, e, k in provedor.recebido if e.endswith("/token"))
        verificador = troca_de_codigo["data"]["code_verifier"]
        import base64
        registrar("o PKCE confere e o segredo vai na autenticação do cliente",
                  base64.urlsafe_b64encode(hashlib.sha256(verificador.encode()).digest()).decode().rstrip("=") == parametros["code_challenge"]
                  and troca_de_codigo["auth"] == ("roar", "s3gredo"))
        http.post("/api/sair")
        http.cookies.clear()
        repetido = http.get("/api/sso/retorno", params={"code": "codigo-1", "state": parametros["state"]}, follow_redirects=False)
        registrar("o mesmo retorno não serve duas vezes", "venceu" in repetido.headers["location"] or "venceu" in __import__("urllib.parse").parse.unquote_plus(repetido.headers["location"]))

        def tentar(conteudo):
            _, p = iniciar(a["email"])
            provedor.conteudo = {"nonce": p["nonce"], **conteudo}
            volta = http.get("/api/sso/retorno", params={"code": "c", "state": p["state"]}, follow_redirects=False)
            entrou = http.get("/api/eu").status_code == 200
            http.post("/api/sair")
            http.cookies.clear()
            return entrou

        registrar("token de outro pedido é recusado", not tentar({"email": a["email"], "nonce": "outro"}))
        registrar("token para outro cliente é recusado", not tentar({"email": a["email"], "aud": "outro-sistema"}))
        registrar("token de outro emissor é recusado", not tentar({"email": a["email"], "iss": "https://falso.exemplo"}))
        registrar("e-mail não confirmado é recusado", not tentar({"email": a["email"], "email_verified": False}))
        registrar("pessoa de outra organização não entra por este SSO", not tentar({"email": b["email"]}))
        registrar("domínio fora da lista é recusado", not tentar({"email": "alguem@outro.exemplo"}))

        entrar(http, a)
        registrar("exigir o SSO", http.request("PUT", "/api/organizacao/sso", json={"emissor": emissor, "client_id": "roar", "dominios": ["exemplo.test"],
                                                                                     "exigir": True}).status_code == 204)
        http.post("/api/sair")
        http.cookies.clear()
        registrar("com o SSO exigido, a senha não entra", http.post("/api/entrar", json={"email": email_n1, "senha": senha_n1}).status_code == 403)
        registrar("quem administra continua entrando com senha", entrar(http, a).status_code == 204)
        registrar("configurar o SSO fica na auditoria", ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'definir_sso'",
                                                                      (a["id"],)).fetchone()[0] == 2)
        registrar("a configuração diz o provedor", http.get("/api/organizacao/sso").json()["config"]["provedor"] == "outro")
        registrar("Microsoft pede o ID do locatário", http.request("PUT", "/api/organizacao/sso", json={
            "provedor": "microsoft", "locatario": "empresa.onmicrosoft.com", "client_id": "roar"}).status_code == 422)
        google = ProvedorFalso("https://accounts.google.com")
        modulo._buscar = google
        registrar("Google monta o emissor sozinho", http.request("PUT", "/api/organizacao/sso", json={"provedor": "google", "client_id": "roar"}).status_code == 204
                  and http.get("/api/organizacao/sso").json()["config"]["emissor"] == "https://accounts.google.com")
        registrar("o SSO sai", http.request("DELETE", "/api/organizacao/sso").status_code == 204)
        http.post("/api/sair")
        http.cookies.clear()
        registrar("sem SSO, a senha volta a valer", http.post("/api/entrar", json={"email": email_n1, "senha": senha_n1}).status_code == 204)
        http.post("/api/sair")
        http.cookies.clear()
    finally:
        modulo._buscar = original
        modulo._descobertas.clear()


def testar_saml(http, a, b):
    """Um provedor SAML de mentira, com chave e certificado próprios, assinando respostas de verdade."""
    print("\n== Login único por SAML", flush=True)
    import base64
    import zlib
    from urllib.parse import parse_qs, urlsplit

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from lxml import etree
    from signxml import XMLSigner

    def chave_e_certificado(nome):
        chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sujeito = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome)])
        agora_ = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(sujeito).issuer_name(sujeito).public_key(chave.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(agora_ - timedelta(days=1)).not_valid_after(agora_ + timedelta(days=30)).sign(chave, hashes.SHA256()))
        return chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), cert.public_bytes(serialization.Encoding.PEM)

    chave, cert = chave_e_certificado("idp.exemplo.test")
    outra_chave, outro_cert = chave_e_certificado("atacante.exemplo.test")
    entidade_idp = "https://idp.exemplo.test/metadata"
    entrar(http, a)
    sem_cabecalho = "".join(cert.decode().splitlines()[1:-1])
    feito = http.put("/api/organizacao/sso", json={"provedor": "saml", "emissor": "https://idp.exemplo.test/sso", "saml_entidade": entidade_idp,
                                                   "saml_certificado": sem_cabecalho, "ativo": True})
    registrar("salva o SAML, aceitando o certificado sem as linhas BEGIN e END", feito.status_code == 204, feito.text[:200])
    registrar("certificado inválido é recusado", http.put("/api/organizacao/sso", json={"provedor": "saml", "emissor": "https://idp.exemplo.test/sso", "saml_entidade": entidade_idp,
                                                                                        "saml_certificado": "não é certificado", "ativo": True}).status_code == 422)
    visto = http.get("/api/organizacao/sso").json()
    entidade_roar, acs = visto["saml"]["entidade"], visto["saml"]["acs"]
    registrar("a tela mostra o identificador e o endereço de retorno para cadastrar no provedor", acs.endswith("/api/sso/saml/acs") and visto["config"]["tem_certificado"])
    metadados = http.get("/api/sso/saml/metadados")
    registrar("os metadados do Roar saem para o provedor ler", metadados.status_code == 200 and acs in metadados.text and entidade_roar in metadados.text)
    http.post("/api/sair")

    def pedir():
        r = http.get("/api/sso/inicio", params={"email": a["email"]})
        url = urlsplit(r.json()["url"])
        q = parse_qs(url.query)
        pedido = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15)
        return etree.fromstring(pedido).get("ID"), q["RelayState"][0], url

    def resposta(id_do_pedido, email=None, assinar_com=(chave, cert), publico=None, validade=timedelta(minutes=5), quando=None, extra_antes=""):
        agora_ = quando or datetime.now(timezone.utc)
        z = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        email = email or a["email"]
        xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r{secrets.token_hex(8)}" Version="2.0" IssueInstant="{z(agora_)}" InResponseTo="{id_do_pedido}"><saml:Issuer>{entidade_idp}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{extra_antes}<saml:Assertion ID="_a{secrets.token_hex(8)}" Version="2.0" IssueInstant="{z(agora_)}"><saml:Issuer>{entidade_idp}</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"/><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{id_do_pedido}" Recipient="{acs}" NotOnOrAfter="{z(agora_ + validade)}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{z(agora_ - timedelta(minutes=1))}" NotOnOrAfter="{z(agora_ + validade)}"><saml:AudienceRestriction><saml:Audience>{publico or entidade_roar}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{z(agora_)}"/></saml:Assertion></samlp:Response>"""
        raiz = etree.fromstring(xml.encode())
        assercao = raiz.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        assinada = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(assercao, key=assinar_com[0], cert=assinar_com[1], reference_uri=assercao.get("ID"))
        raiz.replace(assercao, assinada)
        return raiz

    def mandar(raiz, estado, origem="https://idp.exemplo.test"):
        corpo = urlencode({"SAMLResponse": base64.b64encode(etree.tostring(raiz)).decode(), "RelayState": estado})
        return http.post("/api/sso/saml/acs", content=corpo, headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": origem}, follow_redirects=False)

    id_do_pedido, estado, url = pedir()
    registrar("o pedido vai ao endereço de login do provedor, com o e-mail como dica", url.netloc == "idp.exemplo.test" and "login_hint" in url.query)
    certo = mandar(resposta(id_do_pedido), estado)
    registrar("resposta assinada abre a sessão, mesmo vindo do site do provedor", certo.status_code == 303 and certo.headers["location"] == "/" and COOKIE_DE_SESSAO in certo.cookies,
              f"{certo.status_code} {certo.headers.get('location')}")
    registrar("e a pessoa está dentro", http.get("/api/eu").status_code == 200)
    http.post("/api/sair")
    registrar("a mesma resposta não serve de novo", "sso=" in mandar(resposta(id_do_pedido), estado).headers.get("location", ""))

    def recusado(nome, montar, origem="https://idp.exemplo.test"):
        # Cada recusa conta como tentativa: sem zerar, a proteção contra força bruta bloquearia os casos seguintes.
        falhas_de_login.clear()
        id_, estado_, _ = pedir()
        r = mandar(montar(id_), estado_, origem)
        destino = r.headers.get("location", "")
        registrar(nome, r.status_code == 303 and destino.startswith("/?sso=") and COOKIE_DE_SESSAO not in r.cookies, destino[:160])
        http.cookies.clear()

    def trocado(id_):
        raiz = resposta(id_)
        raiz.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID").text = b["email"]
        return raiz
    recusado("e-mail trocado depois da assinatura é recusado", trocado)

    def embrulho(id_):
        raiz = resposta(id_)
        falsa = etree.fromstring(etree.tostring(raiz.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")))
        falsa.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID").text = "chefe@exemplo.test"
        for assinatura in falsa.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
            falsa.remove(assinatura)
        raiz.insert(2, falsa)
        return raiz
    recusado("asserção falsa embrulhando a verdadeira é recusada", embrulho)

    def comentario(id_):
        usuario, dominio = a["email"].split("@")
        return resposta(id_, email=f"{usuario}@{dominio}<!---->.atacante.test")
    recusado("comentário escondido no e-mail é recusado", comentario)
    recusado("resposta assinada por outra chave é recusada", lambda id_: resposta(id_, assinar_com=(outra_chave, outro_cert)))
    recusado("resposta feita para outro sistema é recusada", lambda id_: resposta(id_, publico="https://outro.sistema.test"))
    recusado("resposta vencida é recusada", lambda id_: resposta(id_, quando=datetime.now(timezone.utc) - timedelta(hours=1)))
    recusado("resposta a outro pedido é recusada", lambda id_: resposta("_pedido_inventado"))
    recusado("e-mail de outra organização não entra", lambda id_: resposta(id_, email=b["email"]))
    falhas_de_login.clear()
    bloqueou = False
    for _ in range(10):
        inicio = http.get("/api/sso/inicio", params={"email": a["email"]})
        if inicio.status_code == 429:
            bloqueou = True
            break
        q = parse_qs(urlsplit(inicio.json()["url"]).query)
        id_ = etree.fromstring(zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15)).get("ID")
        mandar(resposta(id_, assinar_com=(outra_chave, outro_cert)), q["RelayState"][0])
    registrar("muitas respostas recusadas da mesma origem bloqueiam por um tempo", bloqueou)
    falhas_de_login.clear()
    entrar(http, a)
    http.delete("/api/organizacao/sso")
    http.post("/api/sair")


def testar_email(http, a, b):
    print("\n== Avisos por e-mail", flush=True)
    entrar(http, a)
    config = {"servidor": "smtp.nao-existe.invalid", "porta": 587, "seguranca": "starttls", "usuario": "roar", "senha": "segredo-do-smtp",
              "remetente": "roar@exemplo.test", "destinatarios": ["soc@exemplo.test", "chefe@exemplo.test"]}
    registrar("porta fora da lista é recusada", http.put("/api/organizacao/email", json={**config, "porta": 22}).status_code == 422)
    registrar("destinatário que não é e-mail é recusado", http.put("/api/organizacao/email", json={**config, "destinatarios": ["não é e-mail"]}).status_code == 422)
    registrar("servidor com caractere estranho é recusado", http.put("/api/organizacao/email", json={**config, "servidor": "smtp;rm -rf"}).status_code == 422)
    ADMIN.execute("INSERT INTO notificacoes (cliente_id, tipo, alvo) VALUES (%s, 'busca_agendada', 'antes de ligar')", (a["id"],))
    registrar("salva a configuração", http.put("/api/organizacao/email", json=config).status_code == 204)
    visto = http.get("/api/organizacao/email").json()
    registrar("a senha fica no cofre e não volta", visto["tem_senha"] is True and "segredo-do-smtp" not in str(visto) and "senha" not in (visto["config"] or {}), str(visto)[:200])
    selado = ADMIN.execute("SELECT selado FROM segredos WHERE cliente_id = %s AND nome = 'email-senha'", (a["id"],)).fetchone()
    registrar("no banco, a senha está cifrada", selado and b"segredo-do-smtp" not in bytes(selado[0]))
    inicio = ADMIN.execute("SELECT ultima_notificacao, (SELECT max(id) FROM notificacoes WHERE cliente_id = %s) FROM email_config WHERE cliente_id = %s", (a["id"], a["id"])).fetchone()
    registrar("ligar o e-mail não manda o sino do passado", inicio[0] == inicio[1], str(inicio))
    registrar("sem mudar a senha, ela continua guardada", http.put("/api/organizacao/email", json={**config, "senha": None}).status_code == 204 and http.get("/api/organizacao/email").json()["tem_senha"])
    teste = http.post("/api/organizacao/email/teste")
    registrar("o e-mail de teste passa pelo serviço e volta o motivo da falha", teste.status_code == 422 and "encontrar" in teste.json()["detail"], teste.text[:200])
    entrar(http, b)
    registrar("outra organização não vê a configuração", http.get("/api/organizacao/email").json()["config"] is None)
    registrar("e não pede teste por ela", http.post("/api/organizacao/email/teste").status_code == 409)
    entrar(http, a)
    registrar("para os avisos por e-mail", http.delete("/api/organizacao/email").status_code == 204 and http.get("/api/organizacao/email").json() == {"config": None, "tem_senha": False, "tipos": http.get("/api/organizacao/email").json()["tipos"]})


def testar_superficie(http, a, b):
    print("\n== Superfície externa", flush=True)
    entrar(http, a)
    registrar("sem a declaração de autorização, o domínio é recusado", http.post("/api/vuln/superficie", json={"dominio": "exemplo.test"}).status_code == 422)
    registrar("endereço que não é domínio é recusado", http.post("/api/vuln/superficie", json={"dominio": "exemplo;ls", "autorizado": True}).status_code == 422)
    criado = http.post("/api/vuln/superficie", json={"dominio": "https://Exemplo.test/", "autorizado": True, "conferir_a_cada_horas": 12})
    registrar("cadastra o domínio limpando o endereço", criado.status_code == 201, criado.text[:200])
    dominio = criado.json()["id"]
    registrar("o mesmo domínio duas vezes é recusado", http.post("/api/vuln/superficie", json={"dominio": "exemplo.test", "autorizado": True}).status_code == 409)
    alvo = ADMIN.execute("SELECT alvo FROM auditoria WHERE cliente_id = %s AND acao = 'cadastrar_dominio_externo'", (a["id"],)).fetchone()
    registrar("a declaração fica na auditoria", alvo and "exemplo.test" in alvo[0])
    for i, nome in enumerate(("exemplo.test", "vpn.exemplo.test", "www.exemplo.test")):
        ADMIN.execute("""INSERT INTO superficie_hosts (cliente_id, dominio_id, nome, origem, proxima_conferencia, conferido_em, conferindo_desde)
                         VALUES (%s, %s, %s, 'dns', now() + make_interval(hours => %s), CASE WHEN %s > 0 THEN now() END, CASE WHEN %s = 2 THEN now() END)""",
                      (a["id"], dominio, nome, i, i, i))
    visto = http.get("/api/vuln/superficie").json()
    d = visto["dominios"][0]
    registrar("mostra o andamento da fila", (d["dominio"], d["nomes"], d["conferidos"], d["na_fila"], d["conferindo_agora"], d["conferir_a_cada_horas"])
              == ("exemplo.test", 3, 2, 1, "www.exemplo.test", 12), str(d)[:300])
    registrar("e os nomes, com quem está sendo conferido", [h["conferindo"] for h in visto["hosts"]] == [False, False, True], str(visto["hosts"])[:300])
    falsas = ["CVE-1999-9800001", "CVE-1999-9800002"]
    try:
        for cve, kev in zip(falsas, ("2021-11-03", None)):
            ADMIN.execute("INSERT INTO cves (cve, titulo, cvss, kev_desde, prioridade) VALUES (%s, 'Falha de teste', 9.8, %s, %s)", (cve, kev, "agora" if kev else "alta"))
        ADMIN.execute("""INSERT INTO cves_versoes (cve, produto, exata, desde, ate) VALUES (%s, 'beasts:vsftpd', NULL, NULL, '3.0.4'), (%s, 'beasts:vsftpd', '2.3.4', NULL, NULL)""", falsas)
        ADMIN.execute("""UPDATE superficie_hosts SET servicos = '[{"porta": 21, "nome": "vsftpd", "versao": "3.0.3", "resposta": "220 (vsFTPd 3.0.3)", "distribuicao": false, "falhas": 1}]'
                         WHERE dominio_id = %s AND nome = 'vpn.exemplo.test'""", (dominio,))
        host = next(h["id"] for h in http.get("/api/vuln/superficie").json()["hosts"] if h["nome"] == "vpn.exemplo.test")
        lista = http.get(f"/api/vuln/superficie/nomes/{host}/servicos/0").json()
        nossas = [c["cve"] for c in lista["cves"] if c["cve"] in falsas]
        registrar("o serviço mostra as CVEs da versão, cruzadas com a base", nossas == falsas[:1] and lista["cves"][0]["prioridade"] == "agora" and lista["servico"]["nome"] == "vsftpd",
                  str(lista)[:300])
        registrar("cada CVE vem com a situação", lista["cves"] and all(c["situacao"] == "pela_versao" for c in lista["cves"]))
        ADMIN.execute("INSERT INTO cves_versoes (cve, produto, exata) VALUES (%s, 'fortinet:fortios', '7.0.0')", (falsas[0],))
        ADMIN.execute("""UPDATE superficie_hosts SET servicos = '[{"porta": 443, "nome": "Fortinet SSL VPN", "versao": null, "tipo": "borda", "resposta": "", "distribuicao": false, "falhas": 0}]'
                         WHERE id = %s""", (host,))
        borda = http.get(f"/api/vuln/superficie/nomes/{host}/servicos/0").json()["cves"]
        registrar("VPN sem versão mostra as falhas já exploradas no produto", falsas[0] in [c["cve"] for c in borda]
                  and all(c["situacao"] == "explorada_no_produto" and c["kev_desde"] for c in borda), str(borda)[:300])
        registrar("serviço que não existe dá 404", http.get(f"/api/vuln/superficie/nomes/{host}/servicos/5").status_code == 404)
        entrar(http, b)
        registrar("outra organização não vê os serviços", http.get(f"/api/vuln/superficie/nomes/{host}/servicos/0").status_code == 404)
        entrar(http, a)
    finally:
        ADMIN.execute("DELETE FROM cves_versoes WHERE cve = ANY(%s)", (falsas,))
        ADMIN.execute("DELETE FROM cves WHERE cve = ANY(%s)", (falsas,))
    from roar_api import nota_externa
    registrar("nota: uma crítica derruba para C, duas para F", (nota_externa.letra(nota_externa.pontos({"critica": 1})), nota_externa.letra(nota_externa.pontos({"critica": 2})),
                                                                nota_externa.letra(100)) == ("C", "F", "A"))
    ativo = ADMIN.execute("INSERT INTO vuln_ativos (cliente_id, host) VALUES (%s, 'vpn.exemplo.test') RETURNING id", (a["id"],)).fetchone()[0]
    try:
        ADMIN.execute("""INSERT INTO vuln_achados (cliente_id, ativo_id, chave, fonte, titulo, severidade) VALUES
                         (%s, %s, 'externa|porta|3389', 'externa', 'RDP aberto para a internet', 'critica'),
                         (%s, %s, 'externa|sem-https', 'externa', 'Site sem HTTPS', 'media')""", (a["id"], ativo, a["id"], ativo))
        nota = http.get("/api/vuln/superficie").json()["nota"]
        registrar("a nota desconta os achados externos abertos", (nota["pontos"], nota["letra"], nota["por_severidade"]["critica"]) == (71, "C", 1), str(nota)[:300])
        registrar("e a do domínio também", nota["dominios"][str(dominio)] == {"pontos": 71, "letra": "C"})
        registrar("a evolução termina hoje com a nota de agora", nota["historico"] and nota["historico"][-1]["pontos"] == 71, str(nota["historico"][-3:]))
        rel = http.get("/api/relatorios", params={"tipo": "completo", "formato": "json", "dias": 30})
        sup = rel.json()["vuln"]["superficie"] if rel.status_code == 200 else None
        registrar("o relatório traz a superfície externa", sup and sup["letra"] == "C" and sup["achados"][0]["severidade"] == "critica" and "<svg" in (sup["grafico"] or "<svg"),
                  rel.text[:200] if not sup else str(sup)[:200])
        pdf = http.get("/api/relatorios", params={"tipo": "completo", "formato": "pdf", "dias": 30})
        registrar("e o PDF sai com ela", pdf.status_code == 200 and pdf.content[:4] == b"%PDF")
    finally:
        ADMIN.execute("DELETE FROM vuln_achados WHERE ativo_id = %s", (ativo,))
        ADMIN.execute("DELETE FROM vuln_ativos WHERE id = %s", (ativo,))
    registrar("conferir agora põe tudo na frente da fila", http.post(f"/api/vuln/superficie/{dominio}/agora").status_code == 204
              and http.get("/api/vuln/superficie").json()["dominios"][0]["na_fila"] == 3)
    registrar("pausa o domínio", http.put(f"/api/vuln/superficie/{dominio}", json={"ativo": False}).status_code == 204
              and http.get("/api/vuln/superficie").json()["dominios"][0]["ativo"] is False)
    registrar("domínio pausado não vai para a frente da fila", http.post(f"/api/vuln/superficie/{dominio}/agora").status_code == 404)
    entrar(http, b)
    registrar("outra organização não vê o domínio", http.get("/api/vuln/superficie").json() == {"dominios": [], "hosts": [], "mudancas": [], "nota": None})
    registrar("nem tira", http.delete(f"/api/vuln/superficie/{dominio}").status_code == 404)
    registrar("e pode cadastrar o mesmo domínio para ela", http.post("/api/vuln/superficie", json={"dominio": "exemplo.test", "autorizado": True}).status_code == 201)
    entrar(http, a)
    registrar("tira o domínio e os nomes dele", http.delete(f"/api/vuln/superficie/{dominio}").status_code == 204
              and ADMIN.execute("SELECT count(*) FROM superficie_hosts WHERE dominio_id = %s", (dominio,)).fetchone()[0] == 0)


def testar_buscas_e_paineis(http, a, b):
    print("\n== Buscas e painéis", flush=True)
    from roar_api import buscas
    corpo, _ = buscas.montar('usuario=maria E "falha"', "numero", 60)
    filtros = corpo["query"]["bool"]["filter"]
    registrar("o indicador busca a janela e a anterior, e conta a atual à parte", corpo["size"] == 0 and filtros[0] == {"range": {"timestamp": {"gte": "now-120m"}}}
              and corpo["aggs"]["atual"] == {"filter": {"range": {"timestamp": {"gte": "now-60m"}}}} and len(filtros) == 2, str(corpo)[:300])
    lido = buscas.ler({"hits": {"total": {"value": 30}, "hits": []}, "aggregations": {"atual": {"doc_count": 12}}}, "numero")
    registrar("o indicador separa o período atual do anterior", lido == {"total": 12, "anterior": 18})
    corpo, campo = buscas.montar("nivel>=3", "serie", 10080, "nivel")
    registrar("a linha do tempo divide pelo campo", campo == "rule.level" and corpo["aggs"]["serie"]["aggs"]["por"]["terms"]["field"] == "rule.level")
    lido = buscas.ler({"hits": {"total": {"value": 5}, "hits": []}, "aggregations": {"serie": {"buckets": [{"key_as_string": "t", "doc_count": 5, "por": {"buckets": [{"key": 3, "doc_count": 4}]}}]}}}, "serie", "rule.level")
    registrar("cada ponto traz a divisão", lido["pontos"] == [{"quando": "t", "total": 5, "por": {"3": 4}}])
    corpo, campo = buscas.montar("", "mapa", 60)
    registrar("o mapa agrupa pelo país", campo == "GeoLocation.country_name" and corpo["aggs"]["top"]["terms"]["field"] == campo)
    lido = buscas.ler({"hits": {"total": {"value": 10}, "hits": []}, "aggregations": {"top": {"buckets": [{"key": "a", "doc_count": 7}], "sum_other_doc_count": 1}}}, "rosca", "agent.name")
    registrar("outros na rosca são só os valores que ficaram de fora, não os logs sem o campo", lido["outros"] == 1)
    registrar("colunas que terminam igual ganham chaves diferentes", buscas.chaves_da_tabela(["agent.name", "decoder.name", "data.srcip"]) == ["agent_name", "decoder_name", "srcip"])
    corpo, campo = buscas.montar("", "top", 1440, "usuario", 5)
    registrar("mais frequentes conta pelo campo, com o apelido trocado", campo == "data.srcuser" and corpo["aggs"]["top"]["terms"] == {"field": "data.srcuser", "size": 5})
    corpo, campo = buscas.montar("ativo=x | contar por origem", "top", 1440)
    registrar("ou pelo campo que a busca já conta", campo == "data.srcip")
    corpo, colunas = buscas.montar("", "tabela", 60, tamanho=500)
    registrar("tabela tem teto de linhas", corpo["size"] == buscas.MAXIMO_DE_LINHAS and colunas == buscas.COLUNAS_PADRAO)
    for nome, args in (("janela fora da lista", ("", "numero", 61)), ("tipo desconhecido", ("", "pizza", 60)), ("busca quebrada", ('"aberta', "numero", 60)),
                       ("mais frequentes sem campo", ("", "top", 60)), ("campo com caractere estranho", ("", "top", 60, "a b"))):
        try:
            buscas.montar(*args)
            registrar(f"recusa {nome}", False)
        except buscas.BuscaInvalida:
            registrar(f"recusa {nome}", True)
    ruins = []
    for chave, modelo in buscas.MODELOS.items():
        for bloco in modelo["blocos"]:
            try:
                buscas.montar(bloco["texto"], bloco["tipo"], bloco["minutos"], bloco["campo"], bloco["tamanho"])
            except buscas.BuscaInvalida as erro:
                ruins.append(f"{chave}/{bloco['titulo']}: {erro}")
    registrar("todo bloco dos painéis prontos é uma busca válida", not ruins and len(buscas.MODELOS) >= 2, str(ruins))
    registrar("grupo e descricao viram os campos da regra", buscas.montar("", "top", 60, "grupo")[1] == "rule.groups" and buscas.montar("", "top", 60, "descricao")[1] == "rule.description")
    lido = buscas.ler({"hits": {"total": {"value": 9}, "hits": []}, "aggregations": {"top": {"buckets": [{"key": "maria", "doc_count": 7}]}}}, "top", "data.srcuser")
    registrar("o valor volta na chave curta do campo, para a máscara reconhecer", lido["linhas"] == [{"srcuser": "maria", "total": 7}] and lido["chave"] == "srcuser")
    lido = buscas.ler({"hits": {"total": {"value": 1}, "hits": [{"_source": {"agent": {"name": "srv"}, "timestamp": "t"}}]}}, "tabela", ["timestamp", "agent.name", "data.srcip"])
    registrar("tabela tira os campos aninhados", lido["linhas"] == [{"timestamp": "t", "name": "srv", "srcip": None}], str(lido))

    entrar(http, a)
    registrar("bloco sem logs na janela volta zero", http.post("/api/buscas/bloco", json={"texto": "", "tipo": "numero", "minutos": 60}).json() == {"total": 0, "anterior": 0})
    registrar("bloco de rosca sem campo volta o motivo", http.post("/api/buscas/bloco", json={"texto": "", "tipo": "rosca", "minutos": 60}).status_code == 422)
    registrar("bloco com busca quebrada volta o motivo", http.post("/api/buscas/bloco", json={"texto": '"aberta', "tipo": "numero", "minutos": 60}).status_code == 422)
    nova = {"nome": "Admin fora do horário", "texto": "usuario=admin", "janela_minutos": 60, "a_cada_minutos": 15, "condicao": "mais_de", "limite": 3}
    criada = http.post("/api/buscas", json=nova)
    registrar("salva a busca agendada", criada.status_code == 201, criada.text[:200])
    bid = criada.json()["id"]
    registrar("busca quebrada não é salva", http.post("/api/buscas", json={**nova, "nome": "x", "texto": '"aberta'}).status_code == 422)
    registrar("intervalo curto demais é recusado", http.post("/api/buscas", json={**nova, "nome": "y", "a_cada_minutos": 1}).status_code == 422)
    registrar("nome repetido é recusado", http.post("/api/buscas", json=nova).status_code == 409)
    lista = http.get("/api/buscas").json()["buscas"]
    registrar("a lista mostra a agenda", [(x["nome"], x["a_cada_minutos"], x["condicao"], x["disparos_7_dias"]) for x in lista] == [("Admin fora do horário", 15, "mais_de", 0)], str(lista)[:200])
    ADMIN.execute("UPDATE buscas_salvas SET proxima_em = now() + interval '1 hour' WHERE id = %s", (bid,))
    registrar("mudar a busca faz ela rodar já", http.put(f"/api/buscas/{bid}", json={**nova, "limite": 10}).status_code == 204
              and ADMIN.execute("SELECT proxima_em FROM buscas_salvas WHERE id = %s", (bid,)).fetchone()[0] is None)
    painel = {"nome": "Diretoria", "blocos": [{"titulo": "Falhas", "tipo": "numero", "texto": "falha", "minutos": 1440}, {"titulo": "Quem", "tipo": "top", "texto": "", "minutos": 60, "campo": "usuario", "largura": 2}]}
    feito = http.post("/api/paineis", json=painel)
    registrar("cria o painel com os blocos", feito.status_code == 201, feito.text[:200])
    pid = feito.json()["id"]
    visto = http.get("/api/paineis").json()["paineis"][0]
    registrar("o painel guarda os blocos com os padrões", [b["titulo"] for b in visto["blocos"]] == ["Falhas", "Quem"] and visto["blocos"][1]["largura"] == 2 and visto["blocos"][0]["tamanho"] == 10)
    registrar("bloco inválido não entra no painel", http.put(f"/api/paineis/{pid}", json={"nome": "Diretoria", "blocos": [{"titulo": "x", "tipo": "top", "texto": "", "minutos": 60}]}).status_code == 422)
    pdf = http.get(f"/api/paineis/{pid}/pdf")
    registrar("o painel sai em PDF", pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and pdf.headers["content-type"] == "application/pdf", str(pdf.status_code))
    historico = http.get("/api/relatorios/historico").json()["relatorios"]
    registrar("e entra no histórico de relatórios", any(r["tipo"] == "painel" and r["norma"] == "Diretoria" for r in historico), str(historico)[:200])
    from roar_api import relatorios
    from datetime import datetime as _data, timezone as _fuso
    painel_de_teste = {"nome": "Teste", "blocos": [
        {"titulo": "Logs", "tipo": "numero", "minutos": 10080, "largura": 3}, {"titulo": "Por nível", "tipo": "serie", "minutos": 10080, "largura": 8},
        {"titulo": "Países", "tipo": "rosca", "minutos": 10080, "largura": 4}, {"titulo": "Regras", "tipo": "barras", "minutos": 10080, "largura": 6},
        {"titulo": "Mapa", "tipo": "mapa", "minutos": 10080, "largura": 6}, {"titulo": "Últimos", "tipo": "tabela", "minutos": 10080, "largura": 12}]}
    resultados = [
        {"total": 30, "anterior": 20},
        {"total": 5, "campo": "rule.level", "pontos": [{"quando": "2026-11-01T00:00:00.000Z", "total": 5, "por": {"3": 4, "7": 1}}]},
        {"total": 9, "campo": "GeoLocation.country_name", "chave": "country_name", "linhas": [{"country_name": "Brazil", "total": 6}], "outros": 3},
        {"total": 2, "campo": "rule.description", "chave": "description", "linhas": [{"description": "<script>alert(1)</script>", "total": 2}], "outros": 0},
        {"erro": "Não foi possível consultar os logs."},
        {"total": 1, "colunas": [{"campo": "timestamp", "chave": "timestamp"}, {"campo": "agent.name", "chave": "name"}],
         "linhas": [{"timestamp": "2026-11-06T01:36:00.254+0000", "name": "srv-a"}]}]
    html = relatorios.montar_html_do_painel(painel_de_teste, resultados, {"fuso": "America/Sao_Paulo", "cliente_nome": "Org", "nome": "Ana"},
                                            buscas.JANELAS, agora=_data(2026, 11, 6, tzinfo=_fuso.utc))
    registrar("cada tipo de bloco vira desenho ou tabela no papel", html.count("<svg") >= 2 and "+50% sobre o período anterior" in html and "nível 7" in html, html[:0])
    registrar("o país sai em português, e Outros só com os que ficaram de fora", "Brasil" in html and "Outros" in html)
    registrar("valor vindo do log não vira HTML", "<script>alert(1)" not in html and "&lt;script&gt;" in html)
    registrar("o horário do índice sai no fuso da pessoa", "05/11/2026 22:36" in html)
    registrar("bloco que falhou mostra o motivo sem derrubar o painel", "Não foi possível consultar os logs." in html)
    registrar("blocos se juntam em linhas de 12 colunas", [len(l) for l in relatorios._em_linhas([{"largura": w} for w in (3, 3, 3, 3, 8, 4, 6, 6, 12)])] == [4, 2, 2, 1])
    registrar("o PDF é gerado com os desenhos", relatorios.gerar_pdf(html).startswith(b"%PDF"))
    entrar(http, b)
    registrar("outra organização não baixa o painel", http.get(f"/api/paineis/{pid}/pdf").status_code == 404)
    registrar("outra organização não vê buscas nem painéis", http.get("/api/buscas").json()["buscas"] == [] and http.get("/api/paineis").json()["paineis"] == [])
    registrar("outra organização não apaga", http.delete(f"/api/buscas/{bid}").status_code == 404 and http.delete(f"/api/paineis/{pid}").status_code == 404)
    entrar(http, a)
    registrar("apaga busca e painel", http.delete(f"/api/buscas/{bid}").status_code == 204 and http.delete(f"/api/paineis/{pid}").status_code == 204)


def testar_parsers(http, a, b):
    print("\n== Parsers próprios", flush=True)
    from roar_api import parsers
    guiado = {"reconhecer": "programa", "valor": "FWX", "campos": [{"nome": "srcip", "antes": "src=", "tipo": "ip"}, {"nome": "msg", "antes": 'texto "', "tipo": "resto"}]}
    xml = parsers.gerar_xml("fw", guiado)
    registrar("o guiado vira um pai e um irmão por campo", xml.count("<decoder ") == 3 and "<program_name>FWX</program_name>" in xml
              and xml.count("<parent>roar_fw</parent>") == 2 and "src=([0-9A-Fa-f:.]+)" in xml, xml)
    registrar("o texto antes entra literal e escapado no XML", 'texto\\ &quot;' in xml or 'texto\\ "' in xml, xml)
    por_texto = parsers.gerar_xml("fw", {**guiado, "reconhecer": "texto", "valor": "a<b (x)"})
    registrar("reconhecer por texto escapa a expressão e o XML", '<prematch type="pcre2">a&lt;b\\ \\(x\\)</prematch>' in por_texto, por_texto)
    for nome, definicao in (("sem campos", {**guiado, "campos": []}), ("campo repetido", {**guiado, "campos": guiado["campos"] * 2}),
                            ("campo com nome ruim", {**guiado, "campos": [{"nome": "Src IP", "antes": "x", "tipo": "ip"}]}),
                            ("programa com espaço", {**guiado, "valor": "meu programa"}), ("sem texto antes", {**guiado, "campos": [{"nome": "x", "antes": " ", "tipo": "ip"}]})):
        try:
            parsers.gerar_xml("fw", definicao)
            registrar(f"guiado recusa {nome}", False)
        except parsers.ParserInvalido:
            registrar(f"guiado recusa {nome}", True)
    for nome, ruim in (("outro nome", '<decoder name="sshd"><prematch>x</prematch></decoder>'), ("entidade", '<!DOCTYPE x [<!ENTITY a "b">]><decoder name="roar_fw"/>'),
                       ("elemento estranho", '<decoder name="roar_fw"><script>x</script></decoder>'), ("pai de fora", '<decoder name="roar_fw_x"><parent>sshd</parent></decoder>'),
                       ("regra no lugar", '<rule id="1"/>'), ("mal formado", '<decoder name="roar_fw">')):
        try:
            parsers.conferir_xml("fw", ruim)
            registrar(f"XML à mão recusa {nome}", False)
        except parsers.ParserInvalido:
            registrar(f"XML à mão recusa {nome}", True)
    registrar("XML à mão bom passa", parsers.conferir_xml("fw", xml) == xml)

    entrar(http, a)
    criado = http.post("/api/parsers", json={"titulo": "Firewall X", "nome": "fw_x", "modo": "guiado", "definicao": guiado, "exemplo": "FWX: src=1.2.3.4"})
    registrar("cria o parser guiado", criado.status_code == 201, criado.text[:200])
    pid = criado.json()["id"]
    lista = http.get("/api/parsers").json()
    registrar("o parser fica esperando o servidor, com o XML gerado", [(p["nome"], p["estado"], "roar_fw_x" in p["xml"]) for p in lista["parsers"]] == [("fw_x", "pendente", True)]
              and "srcip" in lista["campos"], str(lista["parsers"])[:200])
    registrar("guiado ruim é recusado com o motivo", http.post("/api/parsers", json={"titulo": "x", "nome": "x", "modo": "guiado", "definicao": {"reconhecer": "programa", "valor": "a"}}).status_code == 422)
    registrar("nome repetido é recusado", http.post("/api/parsers", json={"titulo": "x", "nome": "fw_x", "modo": "guiado", "definicao": guiado}).status_code == 409)
    registrar("o nome não muda", http.put(f"/api/parsers/{pid}", json={"titulo": "x", "nome": "outro", "modo": "guiado", "definicao": guiado}).status_code == 422)
    mudou = http.put(f"/api/parsers/{pid}", json={"titulo": "Firewall X novo", "nome": "fw_x", "modo": "xml", "xml": '<decoder name="roar_fw_x"><program_name>FWX</program_name></decoder>'})
    registrar("muda para XML à mão", mudou.status_code == 204 and http.get("/api/parsers").json()["parsers"][0]["modo"] == "xml", mudou.text[:200])
    registrar("desliga o parser", http.post(f"/api/parsers/{pid}/ativo", params={"ligado": "false"}).status_code == 204
              and http.get("/api/parsers").json()["parsers"][0]["ativo"] is False)
    entrar(http, b)
    registrar("outra organização não vê nem mexe", http.get("/api/parsers").json()["parsers"] == [] and http.delete(f"/api/parsers/{pid}").status_code == 404)
    entrar(http, a)
    registrar("apaga o parser", http.delete(f"/api/parsers/{pid}").status_code == 204 and http.get("/api/parsers").json()["parsers"] == [])


def testar_listas(http, a, b):
    print("\n== Listas de observação", flush=True)
    from roar_api import listas
    from roar_ingestao import listas as listas_no_gerenciador
    n = listas.normalizar
    registrar("rede /24 vira prefixo, como o gerenciador compara", (n("ip", "10.20.30.0/24"), n("ip", " 203.0.113.9 "), n("ip", "2001:db8::1")) == ("10.20.30.", "203.0.113.9", "2001:db8::1"))
    for tipo, ruim in (("ip", "10.0.0.0/20"), ("ip", "x.y"), ("dominio", "não é domínio"), ("hash", "abc"), ("texto", 'com "aspas"')):
        try:
            n(tipo, ruim)
            registrar(f"item ruim é recusado: {ruim}", False)
        except listas.ItemInvalido:
            registrar(f"item ruim é recusado: {ruim}", True)
    registrar("domínio e hash ficam em minúsculas", (n("dominio", "Exemplo.COM.br."), n("hash", "A" * 64)) == ("exemplo.com.br", "a" * 64))
    registrar("chave com dois pontos vai entre aspas no arquivo", listas_no_gerenciador.chave("2001:db8::1") == '"2001:db8::1"' and listas_no_gerenciador.chave("10.0.0.") == "10.0.0.")
    from roar_ingestao import provisao
    base = "<ossec_config>\n  <ruleset>\n    <rule_dir>ruleset/rules</rule_dir>\n  </ruleset>\n</ossec_config>\n"
    conf = provisao.com_listas(base, listas_no_gerenciador.declaracoes({"bloqueados": "1.2.3.4:\n"}))
    registrar("a lista entra no ruleset que já existe, sem abrir outro", conf.count("<ruleset>") == 1
              and conf.index("<list>etc/lists/roar/bloqueados</list>") < conf.index("</ruleset>") and provisao.com_listas(base, "") == base, conf)
    registrar("o resumo muda com o conteúdo", listas_no_gerenciador.resumo({"bloqueados": "1.2.3.4:\n"}) != listas_no_gerenciador.resumo({"bloqueados": "1.2.3.5:\n"})
              and listas_no_gerenciador.resumo({}) == "")

    entrar(http, a)
    criada = http.post("/api/listas", json={"titulo": "IPs bloqueados", "nome": "ips-bloqueados", "tipo": "ip"})
    registrar("cria a lista", criada.status_code == 201, criada.text[:200])
    lista = criada.json()["id"]
    registrar("nome repetido é recusado", http.post("/api/listas", json={"titulo": "Outra", "nome": "ips-bloqueados", "tipo": "ip"}).status_code == 409)
    registrar("nome com caminho é recusado", http.post("/api/listas", json={"titulo": "x", "nome": "../etc", "tipo": "ip"}).status_code == 422)
    ruim = http.post(f"/api/listas/{lista}/itens", json={"itens": [{"valor": "10.0.0.1"}, {"valor": "nao-e-ip"}]})
    registrar("um item ruim recusa o pedido inteiro, com o motivo", ruim.status_code == 422 and "nao-e-ip" in ruim.json()["detail"], ruim.text[:200])
    ok = http.post(f"/api/listas/{lista}/itens", json={"itens": [{"valor": "10.0.0.1", "nota": "scanner"}, {"valor": "192.168.5.0/24"}, {"valor": "10.0.0.1", "nota": "repetido"}]})
    registrar("grava os itens, sem repetir", ok.status_code == 200 and ok.json()["gravados"] == 2, ok.text[:200])
    vista = http.get(f"/api/listas/{lista}").json()
    registrar("a lista mostra os itens e a regra pronta", [i["valor"] for i in vista["itens"]] == ["10.0.0.1", "192.168.5."]
              and "etc/lists/roar/ips-bloqueados" in vista["regra"] and vista["regra"].startswith("<rule") and 'lookup="address_match_key"' in vista["regra"], str(vista)[:300])
    registrar("a contagem aparece na lista de listas", [(x["nome"], x["itens"]) for x in http.get("/api/listas").json()["listas"]] == [("ips-bloqueados", 2)])
    registrar("tira um item", http.post(f"/api/listas/{lista}/itens/remover", json={"valores": ["10.0.0.1"]}).json()["removidos"] == 1)

    entrar(http, b)
    registrar("outra organização não vê a lista", http.get("/api/listas").json()["listas"] == [] and http.get(f"/api/listas/{lista}").status_code == 404)
    registrar("outra organização não mexe na lista", http.post(f"/api/listas/{lista}/itens", json={"itens": [{"valor": "1.1.1.1"}]}).status_code == 404
              and http.delete(f"/api/listas/{lista}").status_code == 404)
    entrar(http, a)
    registrar("apaga a lista com os itens", http.delete(f"/api/listas/{lista}").status_code == 204 and http.get("/api/listas").json()["listas"] == [])


def testar_chaves(http, a, b):
    print("\n== Chaves de API", flush=True)
    entrar(http, a)
    registrar("chave de administrador é recusada", http.post("/api/chaves", json={"nome": "x", "perfil": "administrador"}).status_code == 422)
    criada = http.post("/api/chaves", json={"nome": "SOAR externo", "perfil": "analista_n1", "dias": 30})
    registrar("chave é criada e o segredo sai uma vez", criada.status_code == 201 and criada.json()["chave"].startswith("roar_"), criada.text[:120])
    token, identificador = criada.json()["chave"], criada.json()["id"]
    lista = http.get("/api/chaves").json()["chaves"]
    registrar("a lista não mostra o segredo", lista and token not in json.dumps(lista) and lista[0]["estado"] == "ativa" and lista[0]["dono"] == "Analista a")
    openapi = http.get("/api/openapi.json").json()
    registrar("a documentação traz as rotas de dado e não as de conta", "/api/eventos" in openapi["paths"] and "/api/casos" in openapi["paths"]
              and not any(p.startswith(("/api/chaves", "/api/usuarios", "/api/minha-senha", "/api/mfa", "/api/entrar")) for p in openapi["paths"])
              and openapi["paths"]["/api/eventos"]["get"]["x-permissao"] == "ver")
    outro_evento = ADMIN.execute("SELECT id FROM eventos WHERE cliente_id = %s LIMIT 1", (b["id"],)).fetchone()[0]
    http.post("/api/sair")
    http.cookies.clear()

    chave = {"Authorization": f"Bearer {token}"}
    registrar("a chave lê os dados da organização", http.get("/api/fila", headers=chave).status_code == 200
              and http.get("/api/openapi.json", headers=chave).status_code == 200)
    caso = http.post("/api/casos", headers=chave, json={"titulo": "Aberto pela integração", "severidade": "media"})
    registrar("a chave age com o perfil escolhido, em nome de quem criou", caso.status_code == 201
              and http.get(f"/api/casos/{caso.json()['id']}", headers=chave).json()["caso"]["criado_por_nome"] == "Analista a (chave SOAR externo)")
    registrar("a chave não passa do perfil", http.get("/api/chaves", headers=chave).status_code == 403
              and http.request("PUT", "/api/organizacao/ofuscacao", headers=chave, json={"categorias": []}).status_code == 403)
    registrar("a chave não entra nas rotas de conta", http.get("/api/eu", headers=chave).status_code == 401
              and http.post("/api/minha-senha", headers=chave, json={"atual": "x", "nova": "y" * 20}).status_code == 401)
    registrar("a chave não vê outra organização", http.get(f"/api/eventos/{outro_evento}/ocsf", headers=chave).status_code == 404)
    registrar("chave inventada é recusada", http.get("/api/fila", headers={"Authorization": "Bearer roar_inventada_x"}).status_code == 401
              and http.get("/api/fila", headers={"Authorization": "Basic abc"}).status_code == 401)
    ADMIN.execute("UPDATE usuarios SET ativo = false WHERE cliente_id = %s", (a["id"],))
    registrar("dono desativado derruba a chave", http.get("/api/fila", headers=chave).status_code == 401)
    ADMIN.execute("UPDATE usuarios SET ativo = true WHERE cliente_id = %s", (a["id"],))
    ADMIN.execute("UPDATE chaves_api SET expira_em = now() - interval '1 minute' WHERE id = %s", (identificador,))
    registrar("chave vencida é recusada", http.get("/api/fila", headers=chave).status_code == 401)
    ADMIN.execute("UPDATE chaves_api SET expira_em = NULL WHERE id = %s", (identificador,))
    registrar("a chave registra o último uso", http.get("/api/fila", headers=chave).status_code == 200
              and ADMIN.execute("SELECT ultima_vez IS NOT NULL FROM chaves_api WHERE id = %s", (identificador,)).fetchone()[0])

    entrar(http, a)
    registrar("revogar a chave", http.request("DELETE", f"/api/chaves/{identificador}").status_code == 204
              and http.request("DELETE", f"/api/chaves/{identificador}").status_code == 404)
    registrar("criar e revogar ficam na auditoria", ADMIN.execute(
        "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao IN ('criar_chave_de_api', 'revogar_chave_de_api')", (a["id"],)).fetchone()[0] == 2)
    http.post("/api/sair")
    http.cookies.clear()
    registrar("chave revogada é recusada", http.get("/api/fila", headers=chave).status_code == 401)


def testar_caca(http, a):
    print("\n== Caça de indicadores", flush=True)
    entrar(http, a)
    registrar("caça sem indicador reconhecido é recusada", http.post("/api/inteligencia/cacar", json={"texto": "ola tudo bem"}).status_code == 422)
    r = http.post("/api/inteligencia/cacar", json={"texto": "203.0.113[.]5, 198.51.100.77; hxxps://mal[.]exemplo.com/x ola", "dias": 30})
    registrar("caça reconhece indicador desarmado", r.status_code == 200 and {(i["tipo"], i["valor"]) for i in r.json()["indicadores"]}
              == {("ip", "203.0.113.5"), ("ip", "198.51.100.77"), ("url", "https://mal.exemplo.com/x")} and r.json()["ignorados"] == ["ola"], r.text[:300])
    contagem = {i["valor"]: i["eventos"] for i in r.json()["indicadores"]}
    registrar("caça acha o evento da organização e só ele", contagem == {"203.0.113.5": 1, "198.51.100.77": 0, "https://mal.exemplo.com/x": 0}, str(contagem))
    registrar("o achado diz qual indicador bateu", [x["indicador"] for x in r.json()["achados"]] == ["203.0.113.5"])
    registrar("caça fica na auditoria", ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'cacar_indicadores'",
                                                      (a["id"],)).fetchone()[0] == 1)
    registrar("endereço interno não é vigiado", http.post("/api/inteligencia/vigiar", json={"indicadores": [{"tipo": "ip", "valor": "10.0.0.1"}]}).status_code == 422)
    v = http.post("/api/inteligencia/vigiar", json={"indicadores": [{"tipo": "ip", "valor": "185.220.101.4"}, {"tipo": "ip", "valor": "10.0.0.1"}]})
    registrar("indicador passa a ser vigiado na Lista manual", v.status_code == 201 and v.json() == {"vigiados": 1, "recusados": ["10.0.0.1"]}, v.text[:200])
    registrar("vigiar de novo não duplica", http.post("/api/inteligencia/vigiar", json={"indicadores": [{"tipo": "ip", "valor": "185.220.101.4"}]}).status_code == 201
              and ADMIN.execute("SELECT count(*) FROM intel_indicadores i JOIN intel_fontes f ON f.id = i.fonte_id WHERE f.cliente_id = %s AND f.tipo = 'manual'",
                                (a["id"],)).fetchone()[0] == 1)
    registrar("a caça mostra que já é vigiado", next(i["vigiado"] for i in http.post("/api/inteligencia/cacar", json={"texto": "185.220.101.4"}).json()["indicadores"]))
    manual = next(f for f in http.get("/api/inteligencia").json()["fontes"] if f["tipo"] == "manual")
    registrar("a Lista manual aparece nas fontes e não sincroniza", manual["indicadores"] == 1
              and http.post(f"/api/inteligencia/fontes/{manual['id']}/sincronizar").status_code == 404)
    http.post("/api/sair")
    http.cookies.clear()


def testar_casos(http, a, b):
    print("\n== Casos", flush=True)
    entrar(http, a)
    registrar("caso sem título é recusado", http.post("/api/casos", json={"titulo": " ", "severidade": "alta"}).status_code == 422)
    registrar("caso com item de outra organização é recusado",
              http.post("/api/casos", json={"titulo": "x", "severidade": "alta", "itens": [{"tipo": "grupo", "id": b["grupo"]}]}).status_code == 404)
    criado = http.post("/api/casos", json={"titulo": "Força bruta no servidor", "severidade": "alta", "nota": "começando",
                                           "itens": [{"tipo": "grupo", "id": a["grupo"]}, {"tipo": "risco", "id": a["alerta"]}]})
    registrar("caso é criado com itens e nota", criado.status_code == 201, criado.text[:160])
    caso = criado.json()["id"]
    detalhe = http.get(f"/api/casos/{caso}").json()
    registrar("caso traz os itens, a nota e o prazo da severidade",
              sorted(i["tipo"] for i in detalhe["itens"]) == ["grupo", "risco"] and detalhe["notas"][0]["texto"] == "começando"
              and 23.9 < (datetime.fromisoformat(detalhe["caso"]["prazo"]) - datetime.fromisoformat(detalhe["caso"]["criado_em"])).total_seconds() / 3600 < 24.1)
    registrar("a Fila sabe em que caso o alerta está",
              [c["id"] for c in http.get("/api/casos/do-item", params={"tipo": "grupo", "id": a["grupo"]}).json()["casos"]] == [caso])
    eu = next(r for r in detalhe["responsaveis"] if r["nome"] == "Analista a")
    registrar("responsável que não pode triar é recusado", http.patch(f"/api/casos/{caso}", json={"responsavel_id": str(uuid.uuid4())}).status_code == 422)
    r = http.patch(f"/api/casos/{caso}", json={"responsavel_id": eu["id"], "estado": "investigando", "severidade": "critica"})
    registrar("caso muda de responsável, estado e severidade", r.status_code == 204, r.text[:160])
    detalhe = http.get(f"/api/casos/{caso}").json()
    registrar("a severidade nova muda o prazo", 3.9 < (datetime.fromisoformat(detalhe["caso"]["prazo"])
                                                       - datetime.fromisoformat(detalhe["caso"]["criado_em"])).total_seconds() / 3600 < 4.1)
    registrar("cada mudança vira nota automática", sum(n["automatica"] for n in detalhe["notas"]) == 3, str(detalhe["notas"]))
    registrar("encerrar sem desfecho é recusado", http.patch(f"/api/casos/{caso}", json={"estado": "encerrado"}).status_code == 422)
    registrar("evento entra e sai do caso", http.post(f"/api/casos/{caso}/itens", json={"tipo": "evento", "id": ADMIN.execute(
        "SELECT id FROM eventos WHERE cliente_id = %s LIMIT 1", (a["id"],)).fetchone()[0]}).status_code == 204
              and len(http.get(f"/api/casos/{caso}").json()["itens"]) == 3
              and http.request("DELETE", f"/api/casos/{caso}/itens/risco/{a['alerta']}").status_code == 204)
    registrar("nota vazia é recusada", http.post(f"/api/casos/{caso}/notas", json={"texto": "  "}).status_code == 422)
    registrar("nota entra no histórico", http.post(f"/api/casos/{caso}/notas", json={"texto": "bloqueei o IP"}).status_code == 201)
    print("\n== Casos: fato, hipótese, plantão e evidências", flush=True)
    registrar("tipo de nota inventado é recusado", http.post(f"/api/casos/{caso}/notas", json={"texto": "x", "tipo": "palpite"}).status_code == 422)
    http.post(f"/api/casos/{caso}/notas", json={"texto": "a conta admin entrou de 203.0.113.9", "tipo": "fato"})
    http.post(f"/api/casos/{caso}/notas", json={"texto": "a senha vazou no phishing", "tipo": "hipotese"})
    notas = http.get(f"/api/casos/{caso}").json()["notas"]
    hipotese = next(n for n in notas if n["tipo"] == "hipotese")
    registrar("fato e hipótese ficam com o tipo, e a hipótese nasce aberta", any(n["tipo"] == "fato" for n in notas) and hipotese["situacao"] == "aberta")
    fato = next(n for n in notas if n["tipo"] == "fato")
    registrar("fato não tem situação para mudar", http.post(f"/api/casos/{caso}/notas/{fato['id']}/situacao", json={"situacao": "confirmada"}).status_code == 404)
    registrar("a hipótese é confirmada", http.post(f"/api/casos/{caso}/notas/{hipotese['id']}/situacao", json={"situacao": "confirmada"}).status_code == 204)
    notas = http.get(f"/api/casos/{caso}").json()["notas"]
    registrar("o texto da hipótese não muda, e a confirmação vai para o histórico",
              next(n for n in notas if n["id"] == hipotese["id"]) == {**hipotese, "situacao": "confirmada"}
              and any(n["automatica"] and n["texto"].startswith("Hipótese confirmada") for n in notas))
    registrar("passar sem dizer nada é recusado", http.post(f"/api/casos/{caso}/passagem", json={"para": eu["id"]}).status_code == 422)
    registrar("passar para quem não pode triar é recusado", http.post(f"/api/casos/{caso}/passagem", json={"para": str(uuid.uuid4()), "feito": "x"}).status_code == 422)
    registrar("passa o plantão", http.post(f"/api/casos/{caso}/passagem", json={"para": eu["id"], "feito": "bloqueei o IP", "pendente": "trocar a senha"}).status_code == 204)
    passagem = [n for n in http.get(f"/api/casos/{caso}").json()["notas"] if n["tipo"] == "passagem"]
    registrar("a passagem fica no histórico com o feito e o que falta", passagem and "Já feito: bloqueei o IP" in passagem[-1]["texto"] and "Falta: trocar a senha" in passagem[-1]["texto"])
    plantao = http.get("/api/casos-plantao", params={"horas": 12}).json()
    linha = next((c for c in plantao["abertos"] if c["id"] == caso), None)
    registrar("o resumo do plantão traz o caso, a última passagem e o texto para colar", linha and "Falta: trocar a senha" in (linha["ultima_passagem"] or "")
              and f"#{caso} Força bruta no servidor" in plantao["texto"] and plantao["novos"], str(linha)[:200])
    conteudo = b"print de tela \x00\x01"
    anexo = http.post(f"/api/casos/{caso}/evidencias/arquivo", json={"nome": "../print.png", "tipo_midia": "image/png", "descricao": "tela do phishing",
                                                                     "conteudo": base64.b64encode(conteudo).decode()})
    registrar("anexa um arquivo ao caso, com o resumo", anexo.status_code == 201 and anexo.json()["sha256"] == hashlib.sha256(conteudo).hexdigest(), anexo.text[:160])
    registrar("arquivo em base64 quebrado é recusado", http.post(f"/api/casos/{caso}/evidencias/arquivo", json={"nome": "x", "conteudo": "não é base64"}).status_code == 422)
    baixado = http.get(f"/api/casos/{caso}/evidencias/{anexo.json()['id']}")
    registrar("a evidência baixa igual, como anexo e com nome sem caminho", baixado.content == conteudo and "attachment" in baixado.headers["content-disposition"]
              and "/" not in baixado.headers["content-disposition"].split("filename=")[1], baixado.headers.get("content-disposition"))
    evidencias = http.get(f"/api/casos/{caso}").json()["evidencias"]
    registrar("o caso lista a evidência sem o conteúdo, e o histórico guarda o resumo", evidencias[0]["descricao"] == "tela do phishing" and "conteudo" not in evidencias[0]
              and any(hashlib.sha256(conteudo).hexdigest() in n["texto"] for n in http.get(f"/api/casos/{caso}").json()["notas"]))
    sem_selo = http.post(f"/api/casos/{caso}/evidencias/pacote")
    registrar("pacote de prova de evento que não está no índice é recusado com o motivo", sem_selo.status_code == 409 and sem_selo.json()["detail"], sem_selo.text[:160])
    registrar("caso encerra com desfecho", http.patch(f"/api/casos/{caso}", json={"estado": "encerrado", "desfecho": "incidente"}).status_code == 204)
    registrar("caso encerrado não é passado", http.post(f"/api/casos/{caso}/passagem", json={"para": eu["id"], "feito": "x"}).status_code == 409)
    registrar("caso encerrado sai dos abertos e vai para os encerrados",
              caso not in [c["id"] for c in http.get("/api/casos").json()["casos"]]
              and caso in [c["id"] for c in http.get("/api/casos", params={"estado": "encerrados"}).json()["casos"]])
    registrar("criar e mudar caso ficam na auditoria", ADMIN.execute(
        "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao IN ('criar_caso', 'alterar_caso')", (a["id"],)).fetchone()[0] == 3)
    http.post("/api/sair")
    http.cookies.clear()
    entrar(http, b)
    registrar("outra organização não vê o caso", http.get(f"/api/casos/{caso}").status_code == 404
              and http.post(f"/api/casos/{caso}/notas", json={"texto": "x"}).status_code == 404)
    registrar("nem a evidência dele", http.get(f"/api/casos/{caso}/evidencias/{anexo.json()['id']}").status_code == 404
              and http.post(f"/api/casos/{caso}/evidencias/arquivo", json={"nome": "x", "conteudo": "eA=="}).status_code == 404)
    http.post("/api/sair")
    http.cookies.clear()


def testar_triagem(http, a):
    print("\n== Triagem do risco e silêncios", flush=True)
    entrar(http, a)
    entidade = ADMIN.execute("SELECT entidade_id FROM alertas_risco WHERE id = %s", (a["alerta"],)).fetchone()[0]

    ADMIN.execute("INSERT INTO horas (cliente_id, entidade_id, hora, contagem) VALUES (%s, %s, 9, 40), (%s, %s, 14, 10)",
                  (a["id"], entidade, a["id"], entidade))
    ADMIN.execute("INSERT INTO vistos (cliente_id, entidade_id, dimensao, valor, primeira_vez, contagem) VALUES"
                  " (%s, %s, 'ip', '10.9.9.9', now(), 7), (%s, %s, 'privilegio', %s, now(), 2)",
                  (a["id"], entidade, a["id"], entidade, f"{a['ger']}:001:root"))
    normal = http.get(f"/api/entidades/{entidade}/normal").json()
    registrar("o normal traz as 24 horas e marca as incomuns", len(normal["horas"]) == 24 and normal["horario_conhecido"]
              and normal["horas"][3]["incomum"] and not normal["horas"][9]["incomum"] and normal["total_de_acessos"] == 50)
    registrar("o normal traz os IPs e privilégios já vistos", normal["ips"][0]["contagem"] == 7 and normal["privilegios"][0]["como"] == "root",
              str(normal["privilegios"]))
    registrar("o normal de entidade de outro cliente não aparece", http.get(f"/api/entidades/{2**40}/normal").status_code == 404)
    outro = ADMIN.execute("SELECT id FROM eventos WHERE cliente_id <> %s ORDER BY id DESC LIMIT 1", (a["id"],)).fetchone()[0]
    registrar("evento de outra organização não sai em OCSF", http.get(f"/api/eventos/{outro}/ocsf").status_code == 404)
    registrar("silêncio de sinal desconhecido é recusado", http.post("/api/silencios", json={"tipo": "inventado", "motivo": "x"}).status_code == 422)
    registrar("silêncio sem motivo é recusado", http.post("/api/silencios", json={"tipo": "primeiro_ip", "motivo": ""}).status_code == 422)
    criado = http.post("/api/silencios", json={"tipo": "primeiro_ip", "entidade_id": entidade, "motivo": "plantão", "dias": 7})
    registrar("silêncio é criado", criado.status_code == 201, criado.text[:160])
    registrar("silêncio aparece no risco", [s["tipo"] for s in http.get(f"/api/riscos/{a['alerta']}").json()["silencios"]] == ["primeiro_ip"])
    registrar("silêncio aparece na lista", any(s["id"] == criado.json()["id"] for s in http.get("/api/silencios").json()["silencios"]))
    registrar("silêncio de entidade de outro cliente não é criado",
              http.post("/api/silencios", json={"tipo": "primeiro_ip", "entidade_id": 2**40, "motivo": "x"}).status_code == 404)
    registrar("silêncio sai", http.request("DELETE", f"/api/silencios/{criado.json()['id']}").status_code == 204)
    registrar("silêncio que não existe não sai", http.request("DELETE", f"/api/silencios/{criado.json()['id']}").status_code == 404)

    registrar("motivo desconhecido é recusado", http.post(f"/api/riscos/{a['alerta']}/decisao", json={"motivo": "sei_la"}).status_code == 422)
    r = http.post(f"/api/riscos/{a['alerta']}/decisao", json={"motivo": "esperado", "nota": "mudou de equipe"})
    registrar("analista encerra o risco", r.status_code == 204, r.text[:160])
    alerta = http.get(f"/api/riscos/{a['alerta']}").json()["alerta"]
    registrar("risco guarda o motivo, a nota e quem decidiu",
              (alerta["estado"], alerta["motivo"], alerta["nota"], alerta["decidido_por_nome"]) == ("encerrado", "esperado", "mudou de equipe", "Analista a"), str(alerta))
    entidade_depois = ADMIN.execute("SELECT risco, risco_desde IS NOT NULL FROM entidades WHERE id = %s", (entidade,)).fetchone()
    registrar("o risco da pessoa zera", entidade_depois == (0.0, True), str(entidade_depois))
    registrar("o esperado vira normal para a pessoa",
              ADMIN.execute("SELECT count(*) FROM vistos WHERE entidade_id = %s AND dimensao = 'host' AND valor = 'h'", (entidade,)).fetchone()[0] == 1)
    registrar("risco encerrado não é encerrado de novo", http.post(f"/api/riscos/{a['alerta']}/decisao", json={"motivo": "resolvido"}).status_code == 409)
    registrar("risco encerrado sai da fila", a["alerta"] not in [x["id"] for x in http.get("/api/fila").json()["riscos"]])
    registrar("decisão fica na auditoria", ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'decidir_risco'",
                                                         (a["id"],)).fetchone()[0] == 1)
    http.post("/api/sair")
    http.cookies.clear()


def testar_ofuscacao(http, a):
    print("\n== Dado pessoal mascarado", flush=True)
    senha = secrets.token_urlsafe(18)
    n1 = {"email": f"n1-{uuid.uuid4().hex[:8]}@exemplo.test", "senha": senha}
    ADMIN.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista N1', %s, 'analista_n1')",
                  (a["id"], n1["email"], PasswordHasher().hash(senha)))
    evento = ADMIN.execute("SELECT id FROM eventos WHERE cliente_id = %s ORDER BY id LIMIT 1", (a["id"],)).fetchone()[0]
    ADMIN.execute("UPDATE eventos SET bruto = bruto || %s WHERE id = %s",
                  (Jsonb({"full_log": "login de fulano@exemplo.com.br, cpf 529.982.247-25", "data": {"srcuser": "fulano", "srcip": "203.0.113.5"}}), evento))
    entrar(http, n1)
    exportado = http.get("/api/eventos/ocsf", params={"dias": 30}).text
    registrar("N1 recebe a exportação em OCSF mascarada", "203.0.113.5" not in exportado and '"fulano"' not in exportado and "203.0.x.x" in exportado, exportado[:200])
    eu = http.get("/api/eu").json()
    registrar("N1 sabe que vê mascarado", eu["dados_mascarados"] is True and "usuario" in eu["ofuscar"])
    linha = next((e for e in http.get("/api/eventos").json()["eventos"] if e["id"] == evento), {})
    registrar("N1 vê o IP mascarado na lista", linha.get("ip_origem") == "203.0.x.x", str(linha)[:160])
    registrar("N1 vê o usuário como apelido", str(linha.get("usuario", "")).startswith("usuario-"))
    bruto = http.get(f"/api/eventos/{evento}/bruto").text
    registrar("N1 não vê CPF, e-mail nem usuário no bruto", "529.982.247-25" not in bruto and "fulano@" not in bruto and '"fulano"' not in bruto, bruto[:200])
    fila = http.get("/api/fila").json()
    registrar("N1 vê a entidade do risco como apelido", all(r["entidade"].startswith("usuario-") for r in fila["riscos"]), str(fila["riscos"])[:160])
    registrar("N1 não gera pacote de evidência", http.post("/api/integridade/evidencia", json={"fonte": "alertas", "ids": ["e1"]}).status_code == 403)
    registrar("N1 não muda o que é mascarado", http.request("PUT", "/api/organizacao/ofuscacao", json={"categorias": []}).status_code == 403)
    http.post("/api/sair")
    http.cookies.clear()

    entrar(http, a)
    registrar("administrador vê o original", "529.982.247-25" in http.get(f"/api/eventos/{evento}/bruto").text)
    um_evento = http.get(f"/api/eventos/{evento}/ocsf").json()
    registrar("evento em OCSF pela API", (um_evento["metadata"]["version"], um_evento["metadata"]["uid"], um_evento["src_endpoint"]["ip"])
              == ("1.3.0", str(evento), "203.0.113.5") and "bruto" not in um_evento and "raw_data" not in um_evento, str(um_evento)[:200])
    resposta = http.get("/api/eventos/ocsf", params={"dias": 30})
    linhas = [json.loads(l) for l in resposta.text.splitlines()]
    total = ADMIN.execute("SELECT count(*) FROM eventos WHERE cliente_id = %s AND ocorrido_em >= now() - interval '30 days'", (a["id"],)).fetchone()[0]
    registrar("exportação traz uma linha de OCSF por evento do filtro", resposta.headers["content-type"].startswith("application/x-ndjson")
              and len(linhas) == total == int(resposta.headers["x-eventos"]) and all(l["metadata"]["product"]["name"] == "Panthera Roar" for l in linhas))
    registrar("exportação respeita o filtro", http.get("/api/eventos/ocsf", params={"dias": 30, "regra": "nenhuma"}).text == "")
    registrar("categoria desconhecida é recusada", http.request("PUT", "/api/organizacao/ofuscacao", json={"categorias": ["senha"]}).status_code == 422)
    registrar("administrador desliga o IP", http.request("PUT", "/api/organizacao/ofuscacao", json={"categorias": ["usuario", "cpf"]}).status_code == 204)
    http.post("/api/sair")
    http.cookies.clear()

    entrar(http, n1)
    bruto = http.get(f"/api/eventos/{evento}/bruto").json()
    registrar("depois de desligar, N1 vê o IP", bruto["bruto"]["data"]["srcip"] == "203.0.113.5", str(bruto["bruto"].get("data")))
    registrar("o que continua ligado segue mascarado", bruto["bruto"]["data"]["srcuser"].startswith("usuario-") and "529.982.247-25" not in json.dumps(bruto))
    trilha = ADMIN.execute("SELECT alvo FROM auditoria WHERE cliente_id = %s AND acao = 'definir_ofuscacao'", (a["id"],)).fetchall()
    registrar("mudança fica na auditoria", trilha == [("cpf,usuario",)], str(trilha))
    http.post("/api/sair")
    http.cookies.clear()
    ADMIN.execute("UPDATE clientes SET ofuscar = DEFAULT WHERE id = %s", (a["id"],))


def main():
    testar_mascara_sem_banco()
    a, b = novo_cliente("a"), novo_cliente("b")
    with TestClient(app, base_url="https://testserver") as http:
        print("\n== Sem sessão", flush=True)
        for rota in ("/api/eu", "/api/fila", f"/api/riscos/{a['alerta']}", f"/api/grupos/{a['grupo']}"):
            registrar(f"{rota.split('/')[2]} exige sessão", http.get(rota).status_code == 401)
        http.cookies.set(COOKIE, "token-inventado")
        registrar("token inventado não entra", http.get("/api/eu").status_code == 401)
        http.cookies.clear()

        print("\n== Login", flush=True)
        registrar("senha errada é recusada", http.post("/api/entrar", json={"email": a["email"], "senha": "x"}).status_code == 401)
        resposta_inexistente = http.post("/api/entrar", json={"email": "ninguem@exemplo.test", "senha": "x"})
        resposta_errada = http.post("/api/entrar", json={"email": a["email"], "senha": "y"})
        registrar("não revela se o e-mail existe", resposta_inexistente.status_code == resposta_errada.status_code
                  and resposta_inexistente.text == resposta_errada.text)
        registrar("injeção no e-mail não entra", http.post(
            "/api/entrar", json={"email": "' OR 1=1 --", "senha": "x"}).status_code == 401)
        falhas_de_login.clear()

        r = entrar(http, a)
        cabecalho = r.headers.get("set-cookie", "").lower()
        registrar("login certo entra", r.status_code == 204)
        registrar("cookie protegido", all(x in cabecalho for x in ("httponly", "samesite=strict", "secure")), cabecalho[:0])
        token = http.cookies.get(COOKIE)
        registrar("banco guarda só o hash do token",
                  ADMIN.execute("SELECT count(*) FROM sessoes WHERE token_hash = %s", (token,)).fetchone()[0] == 0
                  and ADMIN.execute("SELECT count(*) FROM sessoes WHERE token_hash = %s",
                                    (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0] == 1)
        registrar("sessão identifica o cliente", http.get("/api/eu").json()["cliente"].startswith("a-"))

        print("\n== Isolamento entre clientes", flush=True)
        fila = http.get("/api/fila").json()
        registrar("fila só tem riscos do cliente", [x["id"] for x in fila["riscos"]] == [a["alerta"]])
        registrar("fila só tem alertas do cliente", [x["id"] for x in fila["grupos"]] == [a["grupo"]])
        registrar("risco de outro cliente não é encontrado", http.get(f"/api/riscos/{b['alerta']}").status_code == 404)
        registrar("alerta de outro cliente não é encontrado", http.get(f"/api/grupos/{b['grupo']}").status_code == 404)
        registrar("o próprio risco abre", http.get(f"/api/riscos/{a['alerta']}").status_code == 200)
        registrar("o próprio alerta abre", http.get(f"/api/grupos/{a['grupo']}").status_code == 200)
        registrar("cliente enviado na requisição é ignorado", [x["id"] for x in http.get(
            "/api/fila", params={"cliente": str(b["id"]), "cliente_id": str(b["id"])}).json()["riscos"]] == [a["alerta"]])

        print("\n== Panorama", flush=True)
        painel = http.get("/api/panorama", params={"dias": 7}).json()
        registrar("período tem um ponto por dia, mesmo sem dados", len(painel["por_dia"]) == 7)
        registrar("alerta de hoje entra no gráfico", sum(d["media"] for d in painel["por_dia"]) == 1, str(painel["por_dia"][-1]))
        registrar("gráfico de sinais tem os dados do cliente", painel["sinais"] == [{"tipo": "primeiro_host", "total": 1}])
        registrar("gráfico de origens sai sem máscara", painel["origens"] == [{"origem": "203.0.113.5", "total": 1}])
        registrar("gráfico de risco tem a entidade do cliente", [r["entidade"] for r in painel["riscos"]] == [XSS])
        registrar("período absurdo é contido", len(http.get("/api/panorama", params={"dias": 10**6}).json()["por_dia"]) == 90
                  and len(http.get("/api/panorama", params={"dias": -5}).json()["por_dia"]) == 1)
        registrar("panorama exige sessão", TestClient(app, base_url="https://testserver").get("/api/panorama").status_code == 401)
        fuso = ADMIN.execute("SELECT fuso FROM clientes WHERE id = %s", (a["id"],)).fetchone()[0]
        ADMIN.execute("UPDATE clientes SET fuso = 'Asia/Tokyo' WHERE id = %s", (a["id"],))
        dia_toquio = http.get("/api/panorama", params={"dias": 1}).json()["por_dia"][-1]["dia"]
        esperado = ADMIN.execute("SELECT (now() AT TIME ZONE 'Asia/Tokyo')::date::text").fetchone()[0]
        ADMIN.execute("UPDATE clientes SET fuso = %s WHERE id = %s", (fuso, a["id"]))
        registrar("dia segue o fuso do cliente", dia_toquio == esperado, dia_toquio)
        falhas_ruins = http.get("/api/panorama", params={"dias": "'; DROP TABLE eventos; --"})
        registrar("período com texto é recusado", falhas_ruins.status_code == 422)

        print("\n== Eventos e alerta bruto", flush=True)
        lista = http.get("/api/eventos").json()
        registrar("eventos só do cliente", len(lista["eventos"]) == 1 and lista["ha_mais"] is False)
        evento_a = lista["eventos"][0]["id"]
        registrar("lista de eventos não traz o bruto", "segredo_do_bruto" not in json.dumps(lista))
        registrar("busca encontra por IP", len(http.get("/api/eventos", params={"busca": "203.0.113.5"}).json()["eventos"]) == 1)
        registrar("busca sem resultado", http.get("/api/eventos", params={"busca": "naoexiste"}).json()["eventos"] == [])
        registrar("curinga na busca é tratado como texto", http.get("/api/eventos", params={"busca": "%"}).json()["eventos"] == [])
        registrar("injeção na busca não quebra", http.get("/api/eventos", params={"busca": "'; DROP TABLE eventos; --"}).status_code == 200)
        registrar("severidade inválida é ignorada", http.get("/api/eventos", params={"severidade": "' OR 1=1"}).status_code == 200)
        registrar("filtro de severidade funciona", http.get("/api/eventos", params={"severidade": "alta"}).json()["eventos"] == [])
        antes = ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'ver_bruto' AND alvo = %s", (a["id"], str(evento_a))).fetchone()[0]
        bruto = http.get(f"/api/eventos/{evento_a}/bruto")
        registrar("bruto abre com o conteúdo original", bruto.status_code == 200 and bruto.json()["bruto"]["segredo_do_bruto"] == "nao-sair")
        depois = ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'ver_bruto' AND alvo = %s",
                               (a["id"], str(evento_a))).fetchone()[0]
        registrar("ver o bruto fica registrado", depois == antes + 1)
        evento_b = ADMIN.execute("SELECT id FROM eventos WHERE cliente_id = %s LIMIT 1", (b["id"],)).fetchone()[0]
        registrar("bruto de outro cliente não é encontrado", http.get(f"/api/eventos/{evento_b}/bruto").status_code == 404)
        registrar("tentativa em outro cliente não vira registro nele", ADMIN.execute(
            "SELECT count(*) FROM auditoria WHERE cliente_id = %s", (b["id"],)).fetchone()[0] == 0)

        print("\n== Regras", flush=True)
        for cliente, regra, descricao, grupos, mitre in ((a, "5712", "Força bruta", ["authentication_failures"], ["T1110"]),
                                                         (a, "9999", "Regra sem disparo", ["outro"], []),
                                                         (b, "8888", "Regra só de B", ["segredo_b"], [])):
            ADMIN.execute("INSERT INTO regras (cliente_id, gerenciador_id, regra_id, nivel, descricao, grupos, mitre, arquivo)"
                          " VALUES (%s, %s, %s, 10, %s, %s, %s, 'x.xml')", (cliente["id"], cliente["ger"], regra, descricao, grupos, mitre))
        catalogo = http.get("/api/regras").json()
        registrar("regras só do cliente", {r["regra_id"] for r in catalogo["regras"]} == {"5712", "9999"})
        registrar("regra disparada vem primeiro com a contagem", catalogo["regras"][0]["regra_id"] == "5712" and catalogo["regras"][0]["disparos"] == 1)
        registrar("só as que dispararam", [r["regra_id"] for r in http.get("/api/regras", params={"so_disparadas": True}).json()["regras"]] == ["5712"])
        registrar("busca por técnica MITRE", [r["regra_id"] for r in http.get("/api/regras", params={"busca": "t1110"}).json()["regras"]] == ["5712"])
        registrar("busca não alcança regra de outro cliente", http.get("/api/regras", params={"busca": "segredo_b"}).json()["regras"] == [])
        sys.path.insert(0, str(RAIZ / "ueba"))
        from roar_ueba.motor import PESOS
        registrar("pesos da tela iguais aos do motor", {r["tipo"]: r["peso"] for r in catalogo["comportamento"]} == PESOS)
        from roar_ueba.motor import Parametros
        from roar_api import app as aplicacao
        p = Parametros()
        registrar("aprendizado e horário da tela iguais aos do motor",
                  (aplicacao.APRENDIZADO_DIAS, aplicacao.APRENDIZADO_SUCESSOS, aplicacao.HORARIO_MINIMO, aplicacao.HORARIO_PROBABILIDADE)
                  == (p.aprendizado_dias, p.aprendizado_sucessos, p.horario_minimo, p.horario_probabilidade))

        print("\n== Ativos, ataque e defesa, normas e arquivos", flush=True)
        for cliente, agente, nome in ((a, "001", "servidor-a"), (b, "001", "servidor-b")):
            ADMIN.execute("INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, estado, sca_nota) VALUES (%s, %s, %s, %s, 'active', 70)",
                          (cliente["id"], cliente["ger"], agente, nome))
        registrar("ativos só do cliente", [x["nome"] for x in http.get("/api/ativos").json()["ativos"]] == ["servidor-a"])
        # Dois gerenciadores da mesma organização numeram os agentes por conta própria.
        ADMIN.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES ('gersegundo', %s, 64000)", (a["id"],))
        ADMIN.execute("INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, estado) VALUES (%s, 'gersegundo', '001', 'servidor-a2', 'disconnected')", (a["id"],))
        lista = http.get("/api/ativos").json()["ativos"]
        registrar("mesmo número em dois gerenciadores se distingue", len({(x["gerenciador_id"], x["agente_id"]) for x in lista}) == 2)
        registrar("eventos de um agente não misturam gerenciadores", http.get("/api/eventos", params={"agente": "001", "gerenciador": "gersegundo"}).json()["eventos"] == [])
        ADMIN.execute("DELETE FROM ativos WHERE gerenciador_id = 'gersegundo'")
        ADMIN.execute("DELETE FROM gerenciadores WHERE id = 'gersegundo'")
        print("\n== Risco dos ativos", flush=True)
        from roar_api import risco_de_ativos as rda
        calmo = rda.nota()
        registrar("ativo sem nada pesando tem nota zero", (calmo["nota"], calmo["faixa"], calmo["motivos"]) == (0, "baixo", []))
        falhas = {"pontos": 40, "abertas": 4, "graves": 4, "exploradas": 1}
        normal, critico = rda.nota(falhas), rda.nota(falhas, criticidade="critica")
        registrar("a criticidade decide quanto do total vale", 0 < normal["nota"] < critico["nota"] <= 100, f"{normal['nota']} {critico['nota']}")
        registrar("indicador de ameaça visto pesa mais que alerta", rda.nota(ameacas=1)["nota"] > rda.nota(alertas=1)["nota"])
        registrar("mil falhas não passam de cem", rda.nota({"pontos": 100000, "abertas": 9999, "graves": 9999, "exploradas": 9999}, 100, 50, 500, "critica")["nota"] == 100)
        registrar("configuração segura ruim pesa, e sem checagem não pesa", rda.nota(configuracao=20)["nota"] > rda.nota(configuracao=90)["nota"] > 0
                  and rda.nota(configuracao=None)["nota"] == 0 and any("configuração" in m for m in rda.nota(configuracao=20)["motivos"]))
        registrar("a nota diz os motivos", any("explorada" in m for m in normal["motivos"]) and any("crítica" in m for m in normal["motivos"]), str(normal["motivos"]))
        cve_teste = "CVE-1999-0999999"
        ADMIN.execute("INSERT INTO cves (cve, prioridade, kev_desde, kev_ransomware) VALUES (%s, 'agora', '2024-01-01', true) ON CONFLICT DO NOTHING", (cve_teste,))
        for cliente, host in ((a, "servidor-a"), (a, "10.9.9.9"), (b, "servidor-b")):
            alvo = ADMIN.execute("INSERT INTO vuln_ativos (cliente_id, host, peso) VALUES (%s, %s, 5) RETURNING id", (cliente["id"], host)).fetchone()[0]
            ADMIN.execute("INSERT INTO vuln_achados (cliente_id, ativo_id, chave, fonte, titulo, cves, severidade) VALUES (%s, %s, 'teste|1', 'teste', 'Falha de teste', %s, 'critica')",
                          (cliente["id"], alvo, [cve_teste]))
        resposta = http.get("/api/ativos").json()
        servidor = next(x for x in resposta["ativos"] if x["nome"] == "servidor-a")["risco"]
        registrar("a falha explorada entra na nota do ativo com agente", servidor["nota"] > 0 and servidor["partes"]["falhas"] > 0
                  and any("explorada" in m for m in servidor["motivos"]), str(servidor))
        registrar("ativo só de varredura aparece à parte, com a criticidade do peso", [(x["host"], x["criticidade"]) for x in resposta["sem_agente"]] == [("10.9.9.9", "critica")]
                  and resposta["sem_agente"][0]["nota"] > servidor["nota"], str(resposta["sem_agente"])[:200])
        ADMIN.execute("DELETE FROM vuln_achados WHERE chave = 'teste|1' AND cliente_id = ANY(%s)", ([a["id"], b["id"]],))
        ADMIN.execute("DELETE FROM vuln_ativos WHERE cliente_id = ANY(%s)", ([a["id"], b["id"]],))
        ADMIN.execute("DELETE FROM cves WHERE cve = %s", (cve_teste,))
        ADMIN.execute("UPDATE regras SET mitre = '{T1110}' WHERE cliente_id = %s AND regra_id = '5712'", (a["id"],))
        ADMIN.execute("UPDATE eventos SET mitre = '{T1110.001}', regra_grupos = '{syscheck}', bruto = bruto || %s WHERE cliente_id = %s",
                      (Jsonb({"rule": {"mitre": {"id": ["T1110.001"], "technique": ["Password Guessing"], "tactic": ["Credential Access"]},
                                       "gdpr": ["IV_32.2"], "pci_dss": "nao-e-lista"},
                              "syscheck": {"path": "/etc/passwd", "event": "modified"}}), a["id"]))
        ADMIN.execute("UPDATE eventos SET mitre = '{T9999}', bruto = bruto || %s WHERE cliente_id = %s",
                      (Jsonb({"rule": {"gdpr": ["SEGREDO_B"]}}), b["id"]))
        ADMIN.execute("INSERT INTO tecnicas_defesa (tecnica, defesa_id, defesa_nome, tatica_defesa) VALUES"
                      " ('T1110', 'D3-TESTE', 'Defesa de teste', 'Harden') ON CONFLICT DO NOTHING")
        criar_attack = ADMIN.execute("SELECT count(*) FROM tecnicas_attack").fetchone()[0] == 0
        if criar_attack:
            ADMIN.execute("INSERT INTO taticas_attack VALUES ('credential-access', 'Credential Access', 0)")
            ADMIN.execute("INSERT INTO tecnicas_attack VALUES ('T1110', 'Brute Force', '{credential-access}', NULL, NULL, 'teste'),"
                          " ('T1110.001', 'Password Guessing', '{credential-access}', 'T1110', NULL, 'teste'),"
                          " ('T9999', 'Tecnica de B', '{credential-access}', NULL, NULL, 'teste')")
        matriz = http.get("/api/mitre/matriz").json()
        linha = next((t for t in matriz["tecnicas"] if t["tecnica"] == "T1110"), {})
        registrar("matriz soma a subtécnica na técnica mãe", linha.get("observados") == 1, str(linha)[:120])
        registrar("regra do cliente conta como cobertura", linha.get("regras") == 1)
        registrar("matriz não traz subtécnica como coluna", not any("." in t["tecnica"] for t in matriz["tecnicas"]))
        registrar("evento de B não aparece na matriz de A", next((t["observados"] for t in matriz["tecnicas"] if t["tecnica"] == "T9999"), 0) == 0)
        detalhe = http.get("/api/mitre/tecnicas/T1110").json()
        registrar("regra que deu match aparece", [m["regra_id"] for m in detalhe["match"]] == ["5712"], str(detalhe["match"])[:160])
        registrar("regra que cobre sem disparar aparece separada", detalhe["cobertura"] == [])
        registrar("defesa D3FEND aparece na técnica", any(d["defesa_id"] == "D3-TESTE" for d in detalhe["defesas"]))
        sub = http.get("/api/mitre/tecnicas/T1110.001").json()
        registrar("subtécnica herda a defesa da técnica mãe", any(d["defesa_id"] == "D3-TESTE" for d in sub["defesas"]))
        registrar("match de B não aparece em A", http.get("/api/mitre/tecnicas/T9999").json().get("match", []) == [])
        registrar("técnica inválida não é encontrada", http.get("/api/mitre/tecnicas/DROP%20TABLE").status_code == 404)
        risco = http.get(f"/api/riscos/{a['alerta']}").json()
        tecnica = risco["sinais"][0]["tecnica"] or {}
        registrar("sinal leva a subtécnica do próprio evento", tecnica.get("codigo") == "T1110.001" and tecnica.get("nome") == "Password Guessing", str(tecnica))
        registrar("técnica do sinal vem com a tática", tecnica.get("tatica") == "Credential Access")
        registrar("risco traz o risco depois de cada sinal", risco["sinais"][0]["risco_depois"] == 75.0)
        registrar("campo mitre cru não sai na linha do tempo", "mitre" not in risco["sinais"][0])
        ADMIN.execute("DELETE FROM tecnicas_defesa WHERE defesa_id = 'D3-TESTE'")
        if criar_attack:
            ADMIN.execute("DELETE FROM tecnicas_attack WHERE versao = 'teste'")
            ADMIN.execute("DELETE FROM taticas_attack WHERE tatica = 'credential-access'")
        registrar("controle da norma só do cliente", [c["controle"] for c in http.get("/api/normas", params={"norma": "gdpr"}).json()["controles"]] == ["IV_32.2"])
        registrar("o controle da norma vem com o nome", next(c for c in http.get("/api/normas", params={"norma": "gdpr"}).json()["controles"]
                                                            if c["controle"] == "IV_32.2")["nome"].startswith("Art. 32(2)"))
        lgpd = http.get("/api/normas").json()
        art46 = next((c for c in lgpd["controles"] if c["controle"] == "Art. 46"), {})
        registrar("a LGPD é a norma padrão e sai do GDPR", lgpd["norma"] == "lgpd" and lgpd["derivada_de"] == "GDPR" and lgpd["chave"] == "gdpr"
                  and art46.get("origens") == ["IV_32.2"] and art46.get("nome", "").startswith("Medidas de segurança"), str(art46))
        from roar_api.normas import CATALOGO, nome_do_controle
        registrar("controle sem nome próprio leva o do nível acima", (nome_do_controle("hipaa", "164.310.d"), nome_do_controle("nist_800_53", "RA.5"),
                  nome_do_controle("tsc", "cc6.8"), nome_do_controle("gpg13", "4.12")) == ("Salvaguardas físicas", "Avaliação de risco",
                  "Impedir ou detectar software não autorizado ou malicioso", "Estado de estações, servidores e dispositivos"))
        registrar("as duas grafias do HIPAA dão no mesmo controle", nome_do_controle("hipaa", "164.312.a.2.I") == nome_do_controle("hipaa", "164.312(a)(2)(i)")
                  == "Identificação única de cada usuário" and nome_do_controle("hipaa", "164.308(a)(3)(ii)(A)").startswith("Autorizar"))
        sem_nome = [(n, c) for n, c in ADMIN.execute(
            "SELECT DISTINCT n, c FROM regras, jsonb_object_keys(normas) n, jsonb_array_elements_text(normas -> n) c WHERE n = ANY(%s)", (list(CATALOGO),)).fetchall()
            if nome_do_controle(n, c) is None]
        registrar("todo controle das regras tem nome", not sem_nome, str(sem_nome[:10]))
        registrar("campo de norma fora do formato não quebra", http.get("/api/normas", params={"norma": "pci_dss"}).json()["controles"] == [])
        registrar("norma desconhecida é recusada", http.get("/api/normas", params={"norma": "'; DROP TABLE eventos; --"}).status_code == 422)
        registrar("mudança em arquivo aparece", http.get("/api/arquivos").json()["arquivos"][0]["caminho"] == "/etc/passwd")
        registrar("busca de arquivo funciona", http.get("/api/arquivos", params={"busca": "nao-existe"}).json()["arquivos"] == [])

        print("\n== Abrir e criar regras", flush=True)
        ADMIN.execute("UPDATE regras SET detalhes = %s, normas = %s WHERE cliente_id = %s AND regra_id = '5712'",
                      (Jsonb({"frequency": "8", "if_matched_sid": "5710"}), Jsonb({"gdpr": ["IV_32.2"]}), a["id"]))
        aberta = http.get("/api/regras/5712").json()
        registrar("regra abre com as condições", aberta["regra"]["detalhes"]["frequency"] == "8")
        registrar("regra mostra os disparos", aberta["disparos"]["total"] == 1 and len(aberta["recentes"]) == 1)
        registrar("detalhe da regra não traz o bruto", "segredo_do_bruto" not in json.dumps(aberta))
        registrar("regra de outro cliente não abre", http.get("/api/regras/8888").status_code == 404)
        registrar("número de regra inválido não abre", http.get("/api/regras/1%20OR%201=1").status_code == 404)

        guiada = {"formato": "guiada", "titulo": "Programa suspeito <b>", "origem": "windows_processo", "nivel": "high",
                  "tecnicas": ["T1059.001"], "condicoes": [{"campo": "Image", "operador": "termina", "valor": "\\mal.exe"},
                                                           {"campo": "CommandLine", "operador": "contem", "valor": "-enc"}]}
        previa = http.post("/api/regras/converter", json=guiada)
        registrar("prévia da regra guiada funciona", previa.status_code == 200 and "win.eventdata.image" in previa.json()["xml"], previa.text[:160])
        registrar("prévia não cria nada", ADMIN.execute("SELECT count(*) FROM regras_proprias WHERE cliente_id = %s", (a["id"],)).fetchone()[0] == 0)
        registrar("técnica entra na regra guiada", "T1059.001" in previa.json()["xml"])
        registrar("título hostil não vira marcação", "<b>" not in previa.json()["xml"])
        registrar("campo fora da lista é recusado", http.post("/api/regras/converter", json=dict(
            guiada, condicoes=[{"campo": "Inventado", "operador": "igual", "valor": "x"}])).status_code == 422)
        registrar("condição vazia é recusada", http.post("/api/regras/converter", json=dict(guiada, condicoes=[])).status_code == 422)
        registrar("regra sem valor é recusada", http.post("/api/regras/converter", json=dict(
            guiada, condicoes=[{"campo": "Image", "operador": "igual", "valor": " "}])).status_code == 422)
        registrar("origem desconhecida é recusada", http.post("/api/regras/converter", json=dict(guiada, origem="x")).status_code == 422)
        registrar("formato desconhecido é recusado", http.post("/api/regras/converter", json={"formato": "xml"}).status_code == 422)
        registrar("Sigma inválido é recusado com motivo", http.post(
            "/api/regras/converter", json={"formato": "sigma", "sigma": "isto: [nao e sigma"}).status_code == 422)
        sigma_cidr = ("title: t\nlogsource: {product: windows, service: security}\ndetection:\n  s: {IpAddress|cidr: 10.0.0.0/8}\n"
                      "  condition: s\nlevel: low\n")
        motivo = http.post("/api/regras/converter", json={"formato": "sigma", "sigma": sigma_cidr})
        registrar("o que não converte explica o motivo", motivo.status_code == 422 and "converter" in motivo.json()["detail"], motivo.text[:120])

        criada = http.post("/api/regras/proprias", json=guiada)
        registrar("regra é criada aguardando aplicação", criada.status_code == 201 and criada.json()["estado"] == "pendente")
        registrar("criação fica registrada", ADMIN.execute(
            "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'criar_regra'", (a["id"],)).fetchone()[0] == 1)
        proprias = http.get("/api/regras/proprias").json()["regras"]
        registrar("regra aparece na lista", [x["id"] for x in proprias] == [criada.json()["id"]])
        id_a = criada.json()["id"]
        http.post("/api/sair"); http.cookies.clear(); entrar(http, b)
        registrar("outro cliente não vê a regra", http.get("/api/regras/proprias").json()["regras"] == [])
        registrar("outro cliente não desativa a regra", http.post(f"/api/regras/proprias/{id_a}/desativar").status_code == 404)
        http.post("/api/sair"); http.cookies.clear(); entrar(http, a)
        registrar("o dono desativa a regra", http.post(f"/api/regras/proprias/{id_a}/desativar").status_code == 204
                  and http.get("/api/regras/proprias").json()["regras"][0]["estado"] == "desativada")

        print("\n== Regras à mão, importação, biblioteca e exportação", flush=True)
        manual = '<group name="teste,"><rule id="100001" level="10"><if_sid>5710</if_sid><description>Regra manual</description></rule></group>'
        registrar("XML à mão converte", http.post("/api/regras/converter", json={"formato": "xml", "xml": manual}).status_code == 200)
        registrar("XML à mão é criado", http.post("/api/regras/proprias", json={"formato": "xml", "xml": manual}).status_code == 201)
        for nome, ruim in (("XML quebrado", "<group><rule"), ("DOCTYPE", '<!DOCTYPE x [<!ENTITY a "b">]>' + manual),
                           ("substituir regra existente", manual.replace('level="10"', 'level="10" overwrite="yes"')),
                           ("sem nível", manual.replace(' level="10"', "")), ("sem descrição", manual.replace("<description>Regra manual</description>", ""))):
            registrar(f"XML recusado: {nome}", http.post("/api/regras/converter", json={"formato": "xml", "xml": ruim}).status_code == 422)

        boa = "title: Boa\nlogsource: {product: linux, service: syslog}\ndetection:\n  s: ['texto']\n  condition: s\nlevel: low\n"
        ruim = "title: Ruim\nlogsource: {product: windows, service: security}\ndetection:\n  s: {IpAddress|cidr: 10.0.0.0/8}\n  condition: s\nlevel: low\n"
        relatorio = http.post("/api/regras/importar", json={"formato": "sigma", "conteudo": boa + "---\n" + ruim}).json()
        registrar("importação separa o que entrou e o que não entrou", relatorio["criadas"] == ["Boa"] and relatorio["recusadas"][0]["titulo"] == "Ruim", str(relatorio)[:200])
        registrar("importação fica registrada", ADMIN.execute(
            "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'importar_regras'", (a["id"],)).fetchone()[0] == 1)
        registrar("XML ruim na importação vai para o relatório", http.post("/api/regras/importar", json={"formato": "xml", "conteudo": "<rule"}).json()["recusadas"] != [])

        identificador = "0b4a4a2e-2222-4c1c-9d2e-" + uuid.uuid4().hex[:12]
        ADMIN.execute("INSERT INTO biblioteca_regras (id, titulo, autor, conteudo, convertivel, versao) VALUES (%s, 'Regra pública', 'Autora', %s, true, 'teste')",
                      (identificador, boa.replace("Boa", "Publica").replace("level: low", "author: Autora\nlevel: low")))
        lista = http.get("/api/regras/biblioteca", params={"busca": "Regra pública"}).json()
        registrar("biblioteca mostra a autoria", lista["regras"][0]["autor"] == "Autora")
        registrar("regra da biblioteca é ativada", http.post(f"/api/regras/biblioteca/{identificador}/ativar").status_code == 201)
        registrar("ativar de novo avisa que já está ativa", http.post(f"/api/regras/biblioteca/{identificador}/ativar").status_code == 409)
        registrar("id inválido na biblioteca", http.post("/api/regras/biblioteca/zzz/ativar").status_code == 404)
        ADMIN.execute("DELETE FROM biblioteca_regras WHERE id = %s", (identificador,))
        previa_autor = http.post("/api/regras/converter", json={"formato": "sigma", "sigma": boa.replace("level: low", "author: Autora\nlevel: low")}).json()
        registrar("autoria vai para o alerta, como a licença pede", "autoria: Autora" in previa_autor["xml"])

        exportado = http.get("/api/regras/exportar")
        registrar("exportação baixa as regras do cliente", "attachment" in exportado.headers.get("content-disposition", "") and "Regra manual" in exportado.text)

        ADMIN.execute("INSERT INTO arquivos_de_regras (arquivo, conteudo) VALUES ('teste_roar.xml', %s) ON CONFLICT (arquivo) DO UPDATE SET conteudo = EXCLUDED.conteudo",
                      ('<group name="g,"><rule id="5712" level="10"><description>Original</description></rule></group>',))
        ADMIN.execute("UPDATE regras SET arquivo = 'teste_roar.xml' WHERE cliente_id = %s AND regra_id = '5712'", (a["id"],))
        registrar("regra abre com o XML original", "Original" in (http.get("/api/regras/5712").json()["xml"] or ""))
        registrar("arquivo do Wazuh é exportado", "Original" in http.get("/api/regras/arquivos/teste_roar.xml").text)
        registrar("caminho malicioso no arquivo é recusado", http.get("/api/regras/arquivos/..%2F..%2Fetc%2Fpasswd").status_code == 404)
        ADMIN.execute("DELETE FROM arquivos_de_regras WHERE arquivo = 'teste_roar.xml'")

        print("\n== Entradas e saídas", flush=True)
        registrar("id gigante não vira erro", http.get(f"/api/riscos/{2**70}").status_code == 404)
        registrar("id negativo não vira erro", http.get("/api/grupos/-1").status_code == 404)
        registrar("id com texto é recusado", http.get("/api/riscos/1%20OR%201=1").status_code == 422)
        registrar("limite absurdo é contido", http.get("/api/fila", params={"limite": 10**9}).status_code == 200)
        registrar("IP sai sem máscara de rede", http.get(f"/api/grupos/{a['grupo']}").json()["eventos"][0]["ip_origem"] == "203.0.113.5")
        agora = datetime.now(timezone.utc)
        ADMIN.execute(
            "INSERT INTO grupos_alerta (cliente_id, chave, dia, gerenciador_id, agente_id, nivel, severidade, regras,"
            " primeira_em, ultima_em) VALUES (%s, 'normal', %s, %s, '001', 3, 'baixa', '{5715}', %s, %s)",
            (a["id"], agora.date(), a["ger"], agora, agora))
        registrar("login normal não polui a fila", len(http.get("/api/fila").json()["grupos"]) == 1)
        tudo = "".join(http.get(r).text for r in ("/api/fila", f"/api/riscos/{a['alerta']}", f"/api/grupos/{a['grupo']}"))
        registrar("alerta bruto não sai pela API", "segredo_do_bruto" not in tudo)
        registrar("texto hostil sai só como dado JSON", json.loads(http.get(f"/api/riscos/{a['alerta']}").text)["alerta"]["entidade"] == XSS)
        registrar("resposta da API não fica em cache", http.get("/api/fila").headers.get("cache-control") == "no-store")
        registrar("rotas de documentação estão fechadas", http.get("/docs").status_code == 404 and http.get("/openapi.json").status_code == 404)

        print("\n== Tela", flush=True)
        inicio = http.get("/")
        politica = inicio.headers.get("content-security-policy", "")
        registrar("tela abre", inicio.status_code == 200 and "Panthera" in inicio.text)
        registrar("política de conteúdo bloqueia script de fora", "default-src 'self'" in politica and "unsafe" not in politica)
        registrar("tela não pode ser embutida", "frame-ancestors 'none'" in politica)
        registrar("endereço da tela devolve a mesma página", http.get("/fila").status_code == 200 and "Panthera" in http.get("/fila").text)
        registrar("rota de API desconhecida continua 404", http.get("/api/nao-existe").status_code == 404)
        antigo = http.get("/novo/ajuda/mfa", follow_redirects=False)
        registrar("endereço antigo leva ao novo", antigo.status_code in (302, 307) and antigo.headers["location"] == "/ajuda/mfa")
        registrar("endereço antigo não redireciona para fora", http.get("/novo//atacante.example", follow_redirects=False).headers["location"] == "/")
        registrar("a console antiga saiu", not (ESTATICO / "roar.js").exists() and not (ESTATICO / "index.html").exists())
        js = "".join(p.read_text(encoding="utf-8") for p in (RAIZ / "web/src").rglob("*.ts*"))
        registrar("tela nunca monta HTML com dado", not any(x in js for x in
                  ("dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(")))
        html = (ESTATICO / "console/index.html").read_text(encoding="utf-8")
        registrar("nenhum script embutido na página", "<script>" not in html and " onclick=" not in html)
        registrar("nenhum recurso externo", "http://" not in html and "https://" not in html and not re.search(r"""(?:fetch|import)\(\s*["'`]https?:""", js))
        texto = html + js
        registrar("tela não cita ferramentas", not any(x in texto.lower() for x in ("wazuh", "shuffle", "temporal", "opensearch")))

        print("\n== Requisição de outro site", flush=True)
        r = http.post("/api/sair", headers={"Origin": "https://atacante.example"})
        registrar("outro site não encerra a sessão", r.status_code == 403 and http.get("/api/eu").status_code == 200)

        print("\n== Fim da sessão", flush=True)
        antigo = http.cookies.get(COOKIE)
        registrar("sair responde", http.post("/api/sair").status_code == 204)
        http.cookies.set(COOKIE, antigo)
        registrar("token antigo não vale depois de sair", http.get("/api/eu").status_code == 401)
        http.cookies.clear()

        entrar(http, b)
        ADMIN.execute("UPDATE sessoes SET expira_em = now() - interval '1 minute' WHERE token_hash = %s",
                      (hashlib.sha256(http.cookies.get(COOKIE).encode()).hexdigest(),))
        registrar("sessão expirada não vale", http.get("/api/eu").status_code == 401)
        http.cookies.clear()
        entrar(http, b)
        ADMIN.execute("UPDATE usuarios SET ativo = false WHERE cliente_id = %s", (b["id"],))
        registrar("usuário desativado perde o acesso na hora", http.get("/api/eu").status_code == 401)
        registrar("usuário desativado não entra", entrar(http, b).status_code == 401)
        ADMIN.execute("UPDATE usuarios SET ativo = true WHERE cliente_id = %s", (b["id"],))
        http.cookies.clear()
        falhas_de_login.clear()

        testar_ofuscacao(http, a)
        falhas_de_login.clear()
        testar_triagem(http, a)
        falhas_de_login.clear()
        testar_casos(http, a, b)
        falhas_de_login.clear()
        testar_caca(http, a)
        falhas_de_login.clear()
        testar_chaves(http, a, b)
        falhas_de_login.clear()
        testar_listas(http, a, b)
        falhas_de_login.clear()
        testar_parsers(http, a, b)
        falhas_de_login.clear()
        testar_buscas_e_paineis(http, a, b)
        falhas_de_login.clear()
        testar_email(http, a, b)
        falhas_de_login.clear()
        testar_superficie(http, a, b)
        falhas_de_login.clear()
        testar_passkeys(http, a)
        falhas_de_login.clear()
        testar_sso(http, a, b)
        falhas_de_login.clear()
        testar_saml(http, a, b)
        falhas_de_login.clear()

        print("\n== Tentativas em série", flush=True)
        codigos = [http.post("/api/entrar", json={"email": a["email"], "senha": f"t{i}"}).status_code for i in range(6)]
        registrar("bloqueia depois de 5 tentativas", codigos == [401] * 5 + [429], str(codigos))
        registrar("nem a senha certa entra durante o bloqueio", entrar(http, a).status_code == 429)
        falhas_de_login.clear()

    print("\n== Papel da API no banco", flush=True)
    with psycopg.connect(URL_API, autocommit=True) as api:
        registrar("não lê usuários nem hashes", recusado(lambda: api.execute("SELECT senha_hash FROM usuarios")))
        registrar("não lê sessões", recusado(lambda: api.execute("SELECT * FROM sessoes")))
        registrar("não altera usuários", recusado(lambda: api.execute("UPDATE usuarios SET ativo = true")))
        registrar("não apaga a auditoria", recusado(lambda: api.execute("DELETE FROM auditoria")))
        registrar("não altera a auditoria", recusado(lambda: api.execute("UPDATE auditoria SET acao = 'x'")))
        registrar("não altera regras", recusado(lambda: api.execute("UPDATE regras SET nivel = 0")))
        registrar("não troca o próprio cliente pelo cadastro", recusado(lambda: api.execute("UPDATE clientes SET nome = 'x'")))

    testar_linha_do_tempo()
    testar_ocsf_sem_banco()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    try:
        codigo = main()
    finally:
        limpar()
    sys.exit(codigo)
