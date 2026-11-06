"""Traz para o armazém de eventos o que só existe no indexador: os logs e alertas de antes do coletor (docs/clickhouse.md).

    python -m roar_ingestao.trazer_do_indexador [--gerenciador <id>]

Para cada gerenciador com armazém, copia o que o indexador tem com hora anterior ao primeiro evento que o coletor
gravou. Rodar de novo não repete: o limite passa a ser o mais antigo já copiado. As colunas saem do mesmo jeito que o
coletor monta (infra/wazuh/gerenciador/vector.yaml), e o país e a operadora vêm do que o indexador já tinha achado.
"""

import argparse
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

from . import armazem as armazem_de_eventos
from . import provisao
from .normalizar import CAMPOS_DE_IP_DE_DESTINO, CAMPOS_DE_IP_DE_ORIGEM, primeiro_campo

log = logging.getLogger("roar.trazer_do_indexador")
LOTE = 2000
TAMANHO_MAXIMO = armazem_de_eventos.TAMANHO_MAXIMO
CONJUNTOS = (("logs", provisao.indice_bruto_do), ("alertas", provisao.indice_do))


def _texto(valor):
    return valor if isinstance(valor, str) else ("" if valor is None else str(valor))


def _lista(valor):
    return [_texto(v) for v in valor] if isinstance(valor, list) else ([_texto(valor)] if valor else [])


def _caminho(doc, *partes):
    for parte in partes:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(parte)
    return doc


def linha_do_documento(gerenciador, identificador, documento):
    """A linha do armazém para um documento do indexador. O id sai do gerenciador e do _id: copiar de novo dá o mesmo."""
    original = {k: v for k, v in documento.items() if k not in ("GeoLocation", "Operadora")}
    bruto = json.dumps(original, ensure_ascii=False)
    regra, agente, dados = documento.get("rule") or {}, documento.get("agent") or {}, documento.get("data") or {}
    win = _caminho(dados, "win", "eventdata") or {}
    quando = datetime.fromisoformat(str(documento.get("timestamp", "")).replace("+0000", "+00:00")).astimezone(timezone.utc)
    usuario = next((_texto(v) for v in (dados.get("srcuser"), dados.get("dstuser"), win.get("targetUserName"), win.get("subjectUserName"),
                                         *(dados.get(c) for c in ("user_name", "source_user", "username", "user"))) if v), "")
    grande = len(bruto.encode()) > TAMANHO_MAXIMO
    lugar, rede = documento.get("GeoLocation") or {}, documento.get("Operadora") or {}
    return {
        "id": str(uuid.UUID(hashlib.sha256(f"{gerenciador}|{identificador}".encode()).hexdigest()[:32])),
        "ocorrido_em": quando.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "gerenciador": gerenciador, "origem_id": _texto(documento.get("id")),
        "agente_id": _texto(agente.get("id")), "agente_nome": _texto(agente.get("name")), "agente_ip": _texto(agente.get("ip")),
        "local": _texto(documento.get("location")), "decoder": _texto(_caminho(documento, "decoder", "name")),
        "regra_id": _texto(regra.get("id")), "nivel": int(regra.get("level") or 0) if str(regra.get("level") or 0).isdigit() else 0,
        "regra_descricao": _texto(regra.get("description")), "regra_grupos": _lista(regra.get("groups")),
        "mitre": _lista(_caminho(regra, "mitre", "id")), "mitre_tecnicas": _lista(_caminho(regra, "mitre", "technique")),
        "mitre_taticas": _lista(_caminho(regra, "mitre", "tactic")),
        "ip_origem": _texto(primeiro_campo(dados, CAMPOS_DE_IP_DE_ORIGEM)), "ip_destino": _texto(primeiro_campo(dados, CAMPOS_DE_IP_DE_DESTINO)), "usuario": usuario, "usuario_destino": _texto(dados.get("dstuser")),
        "full_log": _texto(documento.get("full_log"))[:4096] if grande else _texto(documento.get("full_log")),
        "dados": "" if grande else bruto, "tamanho_original": len(bruto.encode()),
        "resumo_do_original": hashlib.sha256(bruto.encode()).hexdigest() if grande else "",
        "pais": _texto(lugar.get("country_name")), "cidade": _texto(lugar.get("city_name")), "regiao": _texto(lugar.get("region_name")),
        "operadora": _texto(rede.get("organization_name")), "asn": _texto(rede.get("asn")),
    }


def trazer(indexer, adm, gerenciador, cliente):
    """Devolve {tabela: copiados}."""
    banco = armazem_de_eventos.banco_do(cliente)
    copiados = {}
    for tabela, prefixo_de in CONJUNTOS:
        primeiro = adm.linhas(f"SELECT toString(min(ocorrido_em)) AS m, count() AS n FROM {banco}.{tabela} WHERE gerenciador = {{g:String}}", {"g": gerenciador})[0]
        corpo = {"size": LOTE, "sort": [{"timestamp": "asc"}, {"_id": "asc"}], "track_total_hits": False}
        if int(primeiro["n"]):
            corpo["query"] = {"range": {"timestamp": {"lt": primeiro["m"].replace(" ", "T") + "Z"}}}
        total = 0
        while True:
            r = indexer.sessao.post(f"{indexer.url}/{prefixo_de(gerenciador)}*/_search?allow_no_indices=true&ignore_unavailable=true", json=corpo, timeout=120)
            r.raise_for_status()
            achados = r.json()["hits"]["hits"]
            linhas = []
            for h in achados:
                try:
                    linhas.append(linha_do_documento(gerenciador, h["_id"], h["_source"]))
                except (ValueError, TypeError):
                    log.warning("documento %s sem hora válida, fica só no indexador", h["_id"])
            if linhas:
                adm.executar(f"INSERT INTO {banco}.{tabela} SETTINGS date_time_input_format = 'best_effort' FORMAT JSONEachRow "
                             + "\n".join(json.dumps(l, ensure_ascii=False) for l in linhas))
                total += len(linhas)
            if len(achados) < LOTE:
                break
            corpo["search_after"] = achados[-1]["sort"]
        copiados[tabela] = total
        log.info("%s %s: %d trazidos do indexador", gerenciador, tabela, total)
    return copiados


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--gerenciador")
    a = args.parse_args()
    env = provisao.ler_env(provisao.DESTINO / ".env")
    indexer, adm = provisao.indexer_admin(env), armazem_de_eventos.admin(env)
    com_armazem = {l["name"] for l in adm.linhas("SELECT name FROM system.databases")}
    with provisao.banco_admin(env) as banco:
        gerenciadores = banco.execute("SELECT id, cliente_id FROM gerenciadores ORDER BY id").fetchall()
    for gerenciador, cliente in gerenciadores:
        if (a.gerenciador and gerenciador != a.gerenciador) or armazem_de_eventos.banco_do(cliente) not in com_armazem:
            continue
        print(gerenciador, trazer(indexer, adm, gerenciador, cliente))


if __name__ == "__main__":
    main()
