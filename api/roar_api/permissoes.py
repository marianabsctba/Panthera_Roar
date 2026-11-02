"""O que cada perfil pode fazer. Permissão que não está aqui não existe para ninguém."""

VER = "ver"                          # Painéis, fila, eventos, regras, ativos, fontes, automação.
VER_BRUTO = "ver_bruto"              # Log e alerta como chegaram: podem ter dado pessoal.
GERIR_REGRAS = "gerir_regras"
GERIR_FONTES = "gerir_fontes"
INSTALAR_AGENTE = "instalar_agente"  # O comando traz a senha de inscrição do cliente.
GERIR_PLAYBOOKS = "gerir_playbooks"
APROVAR = "aprovar"
GERIR_USUARIOS = "gerir_usuarios"

PERFIS = {
    "administrador": {VER, VER_BRUTO, GERIR_REGRAS, GERIR_FONTES, INSTALAR_AGENTE, GERIR_PLAYBOOKS, APROVAR, GERIR_USUARIOS},
    "engenharia": {VER, VER_BRUTO, GERIR_REGRAS, GERIR_FONTES, INSTALAR_AGENTE, GERIR_PLAYBOOKS},
    "analista_n2": {VER, VER_BRUTO, APROVAR},
    "analista_n1": {VER, VER_BRUTO},
    "auditor": {VER},
}


def pode(perfil, permissao):
    return permissao in PERFIS.get(perfil, ())
