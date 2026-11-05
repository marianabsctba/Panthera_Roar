"""O evento do Roar no formato OCSF, para outro SIEM, um data lake ou o Amazon Security Lake lerem sem tradutor.

https://schema.ocsf.io/1.3.0. Cada evento vira uma classe só, escolhida pelos grupos da regra. O que não tem campo
no OCSF vai em "unmapped", sem se perder.
"""

import re
from datetime import datetime

VERSAO = "1.3.0"
PRODUTO = {"name": "Panthera Roar", "vendor_name": "Panthera Roar"}
SEVERIDADE = {"baixa": (2, "Low"), "media": (3, "Medium"), "alta": (4, "High"), "critica": (5, "Critical")}
CATEGORIAS = {1: "System Activity", 2: "Findings", 3: "Identity & Access Management"}
CLASSES = {
    1001: ("File System Activity", 1), 2003: ("Compliance Finding", 2), 2004: ("Detection Finding", 2), 3001: ("Account Change", 3),
    3002: ("Authentication", 3), 3003: ("Authorize Session", 3), 3006: ("Group Management", 3),
}
GRUPOS_SUCESSO = {"authentication_success"}
GRUPOS_FALHA = {"authentication_failed", "authentication_failures", "invalid_login"}
GRUPOS_DE_ADMINISTRACAO = {"group_changed", "win_group_changed"}
# Resultado da checagem de configuração do Wazuh no status de conformidade do OCSF.
RESULTADO_DA_CHECAGEM = {"passed": (1, "Pass"), "failed": (3, "Fail"), "not applicable": (99, "Other")}
MUDANCA_DE_ARQUIVO = {"added": (1, "Create"), "modified": (3, "Update"), "deleted": (4, "Delete")}
RESUMOS = (("md5_after", 1, "MD5"), ("sha1_after", 2, "SHA-1"), ("sha256_after", 3, "SHA-256"))
LINUX_GRUPO = re.compile(r"add '([^']+)' to (?:shadow )?group '([^']+)'")


def _ms(momento):
    return int(momento.timestamp() * 1000) if isinstance(momento, datetime) else None


def _sem_vazio(dado):
    """OCSF não quer campo nulo: quem lê confunde "não veio" com "veio vazio"."""
    if isinstance(dado, dict):
        limpo = {k: _sem_vazio(v) for k, v in dado.items()}
        return {k: v for k, v in limpo.items() if v not in (None, "", [], {})}
    if isinstance(dado, list):
        return [v for v in (_sem_vazio(i) for i in dado) if v not in (None, "", [], {})]
    return dado


def _classe(evento, bruto):
    grupos = set(evento.get("regra_grupos") or [])
    win = ((bruto.get("data") or {}).get("win") or {}) if isinstance(bruto.get("data"), dict) else {}
    id_windows = str((win.get("system") or {}).get("eventID") or "") if isinstance(win, dict) else ""
    texto = str(bruto.get("full_log") or "")
    if grupos & GRUPOS_SUCESSO:
        return 3002, 1, "Logon", 1
    if grupos & GRUPOS_FALHA:
        return 3002, 1, "Logon", 2
    if "syscheck" in grupos and isinstance(bruto.get("syscheck"), dict):
        atividade, nome = MUDANCA_DE_ARQUIVO.get(str(bruto["syscheck"].get("event")), (99, "Other"))
        return 1001, atividade, nome, None
    if id_windows == "4720" or "adduser" in grupos or "new user: name=" in texto:
        return 3001, 1, "Create", 1
    if id_windows in ("4728", "4732", "4756") or grupos & GRUPOS_DE_ADMINISTRACAO or LINUX_GRUPO.search(texto):
        return 3006, 3, "Add User", 1
    if "sudo" in grupos:
        return 3003, 1, "Assign Privileges", 1
    if "sca" in grupos and isinstance(bruto.get("data"), dict) and isinstance(bruto["data"].get("sca"), dict):
        return 2003, 1, "Create", None
    return 2004, 1, "Create", None


def _ataques(mitre, tecnicas):
    ataques = []
    for codigo in mitre or []:
        info = tecnicas.get(codigo) or tecnicas.get(codigo.split(".")[0]) or {}
        ataque = {"technique": {"uid": codigo, "name": info.get("nome")}, "version": "ATT&CK"}
        if info.get("tatica"):
            ataque["tactic"] = {"name": info["tatica"]}
        ataques.append(ataque)
    return ataques


def converter(evento, tecnicas=None):
    """Um evento do Roar (a linha da tabela eventos) em um objeto OCSF."""
    tecnicas = tecnicas or {}
    bruto = evento.get("bruto") if isinstance(evento.get("bruto"), dict) else {}
    dados = bruto.get("data") if isinstance(bruto.get("data"), dict) else {}
    classe, atividade, nome_da_atividade, situacao = _classe(evento, bruto)
    nome_da_classe, categoria = CLASSES[classe]
    severidade_id, severidade = SEVERIDADE.get(evento.get("severidade"), (0, "Unknown"))
    ip = evento.get("ip_origem")
    saida = {
        "class_uid": classe, "class_name": nome_da_classe, "category_uid": categoria, "category_name": CATEGORIAS[categoria],
        "activity_id": atividade, "activity_name": nome_da_atividade,
        "type_uid": classe * 100 + atividade, "type_name": f"{nome_da_classe}: {nome_da_atividade}",
        "time": _ms(evento.get("ocorrido_em")), "severity_id": severidade_id, "severity": severidade,
        "message": evento.get("regra_descricao"),
        "metadata": {
            "version": VERSAO, "product": PRODUTO, "uid": str(evento.get("id")) if evento.get("id") else None,
            "original_time": evento["ocorrido_em"].isoformat() if isinstance(evento.get("ocorrido_em"), datetime) else None,
            "logged_time": _ms(evento.get("recebido_em")), "labels": sorted(evento.get("regra_grupos") or []),
            "log_name": evento.get("origem"), "correlation_uid": evento.get("origem_id"),
        },
        "device": {"hostname": evento.get("agente_nome"), "uid": evento.get("agente_id"), "type_id": 0},
        "src_endpoint": {
            "ip": ip,
            "location": {"country": evento.get("pais"), "city": evento.get("cidade"), "region": evento.get("regiao")},
            "autonomous_system": {"name": evento.get("operadora"), "number": int(evento["asn"]) if str(evento.get("asn") or "").isdigit() else None},
        },
        "observables": [o for o in (
            {"name": "src_endpoint.ip", "type_id": 2, "type": "IP Address", "value": ip} if ip else None,
            {"name": "user.name", "type_id": 4, "type": "User Name", "value": evento.get("usuario")} if evento.get("usuario") else None,
            {"name": "device.hostname", "type_id": 1, "type": "Hostname", "value": evento.get("agente_nome")} if evento.get("agente_nome") else None,
        ) if o],
        "unmapped": {"regra_id": evento.get("regra_id"), "nivel": evento.get("nivel"), "gerenciador_id": evento.get("gerenciador_id")},
    }
    if situacao:
        saida.update(status_id=situacao, status="Success" if situacao == 1 else "Failure")
    usuario = {"name": evento.get("usuario")}

    if classe == 3002:
        saida.update(user=usuario, dst_endpoint={"hostname": evento.get("agente_nome")}, is_remote=bool(ip))
    elif classe == 1001:
        arquivo = bruto["syscheck"]
        caminho = str(arquivo.get("path") or "")
        saida["file"] = {
            "path": caminho, "name": re.split(r"[\\/]", caminho)[-1] if caminho else None, "type_id": 1, "size": arquivo.get("size_after"),
            "hashes": [{"algorithm_id": n, "algorithm": a, "value": arquivo[c]} for c, n, a in RESUMOS if arquivo.get(c)],
        }
        quem = ((arquivo.get("audit") or {}).get("login_user") or {}).get("name") if isinstance(arquivo.get("audit"), dict) else None
        saida["actor"] = {"user": {"name": quem}}
    elif classe in (3001, 3003):
        saida["user"] = {"name": dados.get("dstuser") or evento.get("usuario")}
        saida["actor"] = {"user": {"name": dados.get("srcuser")}}
    elif classe == 3006:
        achado = LINUX_GRUPO.search(str(bruto.get("full_log") or ""))
        win = (dados.get("win") or {}).get("eventdata") or {} if isinstance(dados.get("win"), dict) else {}
        saida["group"] = {"name": achado.group(2) if achado else win.get("targetUserName")}
        saida["user"] = {"name": achado.group(1) if achado else win.get("memberName") or win.get("memberSid")}
        saida["actor"] = {"user": {"name": win.get("subjectUserName")}}
    elif classe == 2003:
        sca = dados["sca"]
        checagem = sca.get("check") if isinstance(sca.get("check"), dict) else {}
        situacao_id, situacao_nome = RESULTADO_DA_CHECAGEM.get(str(checagem.get("result")), (0, "Unknown"))
        saida["finding_info"] = {"uid": str(evento.get("id")) if evento.get("id") else evento.get("origem_id"),
                                 "title": checagem.get("title") or evento.get("regra_descricao"), "desc": checagem.get("description")}
        saida["compliance"] = {
            "control": str(checagem.get("id")) if checagem.get("id") else None, "standards": [sca.get("policy")] if sca.get("policy") else [],
            "requirements": [f"{k}: {v}" for k, v in (checagem.get("compliance") or {}).items()] if isinstance(checagem.get("compliance"), dict) else [],
            "status_id": situacao_id if checagem else None, "status": situacao_nome if checagem else None,
        }
        saida["remediation"] = {"desc": checagem.get("remediation")}
        saida.update(status_id=1, status="New")
    else:
        saida["finding_info"] = {
            "uid": str(evento.get("id")) if evento.get("id") else evento.get("origem_id"), "title": evento.get("regra_descricao") or f"Regra {evento.get('regra_id')}",
            "types": sorted(evento.get("regra_grupos") or []), "analytic": {"uid": evento.get("regra_id"), "name": evento.get("regra_descricao"), "type_id": 1, "type": "Rule"},
            "attacks": _ataques(evento.get("mitre"), tecnicas),
        }
        saida.update(status_id=1, status="New", user=usuario)
    if classe != 2004 and evento.get("mitre"):
        saida["unmapped"]["mitre"] = list(evento["mitre"])
    return _sem_vazio(saida)
