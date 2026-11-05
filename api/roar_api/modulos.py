"""O que está instalado. Módulo fora do perfil não aparece na tela nem responde na API.

Rota nova cai no SIEM por padrão: é o módulo que exige mais peças, e assim nada novo fica exposto sem querer.
"""

import os

SIEM = "siem"
VULNERABILIDADES = "vulnerabilidades"
PERFIS = {"completo": {SIEM, VULNERABILIDADES}, "siem": {SIEM}, "vulnerabilidades": {VULNERABILIDADES}}
ROTAS_DE_TODOS = ("/api/entrar", "/api/sair", "/api/eu", "/api/saude", "/api/minha-senha", "/api/mfa/", "/api/usuarios", "/api/organizacoes", "/api/organizacao/", "/api/auditoria", "/api/notificacoes",
                  "/api/chaves", "/api/openapi.json")
ROTAS_DE_VULNERABILIDADES = ("/api/vuln/", "/api/cves")


def do_ambiente():
    return PERFIS.get(os.getenv("ROAR_PERFIL", "completo"), PERFIS["completo"])


def _coincide(caminho, prefixo):
    return caminho.startswith(prefixo) if prefixo.endswith("/") else caminho == prefixo or caminho.startswith(prefixo + "/")


def rota_liberada(caminho, modulos):
    if not caminho.startswith("/api/"):
        return True
    if any(_coincide(caminho, p) for p in ROTAS_DE_TODOS):
        return True
    if any(_coincide(caminho, p) for p in ROTAS_DE_VULNERABILIDADES):
        return VULNERABILIDADES in modulos
    return SIEM in modulos
