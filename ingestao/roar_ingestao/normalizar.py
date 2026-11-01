"""Transforma um alerta do Wazuh no evento do Roar.

Quase tudo no alerta pode ter sido escrito pelo atacante. Aqui nada é interpretado
como instrução, e o dono do evento nunca sai daqui: quem decide é o mapa de agentes.
"""

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone

LIMITE_BRUTO = 256 * 1024
LIMITE_TEXTO = 1024
AGENTE_DO_GERENCIADOR = "000"
CAMPOS_DE_USUARIO = (
    ("data", "srcuser"),
    ("data", "dstuser"),
    ("data", "win", "eventdata", "targetUserName"),
    ("data", "win", "eventdata", "subjectUserName"),
)


class AlertaInvalido(Exception):
    pass


@dataclass(frozen=True)
class Evento:
    origem_id: str
    ocorrido_em: datetime
    nivel: int
    severidade: str
    regra_id: str
    regra_descricao: str | None
    regra_grupos: list
    mitre: list
    agente_id: str
    agente_nome: str | None
    ip_origem: str | None
    usuario: str | None
    bruto: dict


def severidade_do_nivel(nivel):
    if nivel >= 15:
        return "critica"
    if nivel >= 12:
        return "alta"
    if nivel >= 7:
        return "media"
    return "baixa"


def limpar(valor):
    """O PostgreSQL recusa nulo e UTF-8 inválido, e um atacante controla esses campos."""
    if isinstance(valor, str):
        return valor.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    if isinstance(valor, list):
        return [limpar(v) for v in valor]
    if isinstance(valor, dict):
        return {limpar(k): limpar(v) for k, v in valor.items()}
    return valor


def limitar_bruto(alerta):
    texto = json.dumps(alerta, ensure_ascii=False, default=str)
    tamanho = len(texto.encode("utf-8", "replace"))
    if tamanho <= LIMITE_BRUTO:
        return alerta
    return {
        "roar_truncado": True,
        "tamanho": tamanho,
        "sha256": hashlib.sha256(texto.encode("utf-8", "replace")).hexdigest(),
        "agent": alerta.get("agent"),
        "rule": alerta.get("rule"),
        "timestamp": alerta.get("timestamp"),
    }


def bruto_seguro(alerta):
    """Nunca falha: um alerta impossível de guardar não pode travar a fila."""
    try:
        return limitar_bruto(limpar(alerta))
    except (RecursionError, TypeError, ValueError):
        return {"roar_invalido": True}


def _texto(valor):
    if not isinstance(valor, str):
        return None
    return valor.strip()[:LIMITE_TEXTO] or None


def _lista_de_textos(valor):
    if not isinstance(valor, list):
        return []
    return [t for t in (_texto(v) for v in valor[:50]) if t]


def _caminho(alerta, caminho):
    atual = alerta
    for parte in caminho:
        if not isinstance(atual, dict):
            return None
        atual = atual.get(parte)
    return atual


def _ip(valor):
    if not isinstance(valor, str):
        return None
    try:
        return str(ipaddress.ip_address(valor.strip()))
    except ValueError:
        return None


def _momento(valor):
    if not isinstance(valor, str):
        raise AlertaInvalido("sem_horario")
    try:
        momento = datetime.fromisoformat(valor)
    except ValueError:
        raise AlertaInvalido("horario_invalido")
    if momento.tzinfo is None:
        raise AlertaInvalido("horario_sem_fuso")
    return momento.astimezone(timezone.utc)


def agente_do_alerta(alerta):
    agente = alerta.get("agent") if isinstance(alerta, dict) else None
    identificador = agente.get("id") if isinstance(agente, dict) else None
    return identificador if isinstance(identificador, str) and identificador else None


def normalizar(origem_id, alerta):
    try:
        alerta = limpar(alerta)
        bruto = limitar_bruto(alerta)
    except RecursionError:
        raise AlertaInvalido("estrutura_invalida")
    agente_id = agente_do_alerta(alerta)
    if not agente_id:
        raise AlertaInvalido("sem_agente")

    regra = alerta.get("rule")
    if not isinstance(regra, dict):
        raise AlertaInvalido("sem_regra")
    regra_id = _texto(regra.get("id"))
    nivel = regra.get("level")
    if not regra_id:
        raise AlertaInvalido("sem_regra")
    if not isinstance(nivel, int) or isinstance(nivel, bool) or not 0 <= nivel <= 16:
        raise AlertaInvalido("nivel_invalido")

    usuario = next((u for u in (_texto(_caminho(alerta, c)) for c in CAMPOS_DE_USUARIO) if u), None)
    mitre = regra.get("mitre") if isinstance(regra.get("mitre"), dict) else {}

    return Evento(
        origem_id=origem_id,
        ocorrido_em=_momento(alerta.get("timestamp")),
        nivel=nivel,
        severidade=severidade_do_nivel(nivel),
        regra_id=regra_id,
        regra_descricao=_texto(regra.get("description")),
        regra_grupos=_lista_de_textos(regra.get("groups")),
        mitre=_lista_de_textos(mitre.get("id")),
        agente_id=agente_id,
        agente_nome=_texto(alerta["agent"].get("name")),
        ip_origem=_ip(_caminho(alerta, ("data", "srcip"))),
        usuario=usuario,
        bruto=bruto,
    )


def chave_do_grupo(evento):
    """Um ataque vira um grupo só: por ativo, origem e dia. Sem origem, separa por regra."""
    dia = evento.ocorrido_em.date().isoformat()
    partes = [evento.agente_id, evento.ip_origem or "", "" if evento.ip_origem else evento.regra_id, dia]
    return hashlib.sha256("|".join(partes).encode()).hexdigest()
