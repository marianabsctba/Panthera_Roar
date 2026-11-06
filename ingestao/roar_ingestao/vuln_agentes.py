"""Vulnerabilidades vistas pelo próprio agente: o inventário de pacotes cruzado com a base do Wazuh, sem varredura.

O detector do Wazuh roda em cada gerenciador e grava só no índice dele. Aqui os achados entram em Vulnerabilidades
como mais uma fonte, com o mesmo ciclo das varreduras: abre, reabre se voltar e fecha quando some.
Agente desconectado não fecha nada: não ver não é o mesmo que estar corrigido.
"""

import logging

from .vulnerabilidades import TAMANHO_DA_EVIDENCIA, _ativo, _historico, severidade_do_cvss

log = logging.getLogger("roar.vuln_agentes")
FONTE = "agente"
PREFIXO = "wazuh-states-vulnerabilities-"
LOTE = 1000
SEVERIDADES = {"critical": "critica", "high": "alta", "medium": "media", "low": "baixa"}


def indice_do(gerenciador_id):
    # O detector põe no nome o host do gerenciador, que é gerenciador-<id> (infra/wazuh/gerenciador/docker-compose.yml).
    return f"{PREFIXO}gerenciador-{gerenciador_id}"


def ler(indexer_get, url, gerenciador_id):
    """Tudo o que o detector achou neste gerenciador, de lote em lote. Índice que ainda não existe é lista vazia."""
    achados, depois = [], None
    while True:
        consulta = {"size": LOTE, "sort": [{"_id": "asc"}], "_source": ["agent", "package", "vulnerability", "host"]}
        if depois:
            consulta["search_after"] = depois
        r = indexer_get(f"{url}/{indice_do(gerenciador_id)}*/_search?allow_no_indices=true&ignore_unavailable=true", json=consulta, timeout=60)
        r.raise_for_status()
        lote = r.json()["hits"]["hits"]
        achados.extend(h["_source"] for h in lote)
        if len(lote) < LOTE:
            return achados
        depois = lote[-1]["sort"]


def _titulo(v, pacote):
    nome = f"{pacote.get('name', '')} {pacote.get('version', '')}".strip()
    return f"{v.get('id', 'Vulnerabilidade')} em {nome}" if nome else v.get("id", "Vulnerabilidade")


def _severidade(v):
    nota = (v.get("score") or {}).get("base")
    if isinstance(nota, (int, float)) and nota > 0:
        return float(nota), severidade_do_cvss(float(nota))
    return None, SEVERIDADES.get(str(v.get("severity", "")).lower(), "informativa")


def gravar(con, cliente, gerenciador_id, documentos, agentes):
    """Precisa rodar em transação, com roar.cliente definido.

    agentes: {agente_id: (endereço, nome, conectado)}, da tabela de ativos deste gerenciador. Devolve (novos, reabertos, corrigidos).
    """
    novos = reabertos = 0
    ativos_vistos = {}
    for agente_id, (endereco, nome, conectado) in agentes.items():
        if conectado:
            ativos_vistos[agente_id] = _ativo(con, cliente, endereco or nome, nome)
    for d in documentos:
        agente_id = str((d.get("agent") or {}).get("id", ""))
        if agente_id not in agentes:
            continue
        endereco, nome, _ = agentes[agente_id]
        ativo = ativos_vistos.get(agente_id) or _ativo(con, cliente, endereco or nome, nome)
        v, pacote = d.get("vulnerability") or {}, d.get("package") or {}
        cvss, severidade = _severidade(v)
        identificador = str(v.get("id", ""))
        chave = f"{FONTE}|{pacote.get('name', '')}|{identificador}"
        cves = [identificador.upper()] if identificador.upper().startswith("CVE-") else []
        evidencia = f"Pacote {pacote.get('name', '')} {pacote.get('version', '')} instalado em {nome}."[:TAMANHO_DA_EVIDENCIA]
        referencias = v.get("reference") or ""
        solucao = (f"Atualize o pacote {pacote.get('name', '')}. Referências: {referencias}" if referencias else f"Atualize o pacote {pacote.get('name', '')}.")[:TAMANHO_DA_EVIDENCIA]
        valores = (_titulo(v, pacote)[:500], cves, cvss, severidade, evidencia, solucao)
        existente = con.execute("SELECT id, estado FROM vuln_achados WHERE ativo_id = %s AND chave = %s", (ativo, chave)).fetchone()
        if existente is None:
            achado = con.execute(
                """INSERT INTO vuln_achados (cliente_id, ativo_id, chave, fonte, titulo, cves, cvss, severidade, evidencia, solucao, autenticada)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, true) RETURNING id""", (cliente, ativo, chave, FONTE, *valores)).fetchone()[0]
            _historico(con, cliente, achado, None, "aberto", None, "O agente encontrou o pacote vulnerável.")
            novos += 1
            continue
        achado, estado = existente
        # Aceito e falso positivo ficam: a decisão foi de uma pessoa.
        voltou = estado in ("corrigido", "correcao_informada")
        con.execute("""UPDATE vuln_achados SET titulo = %s, cves = %s, cvss = %s, severidade = %s, evidencia = %s, solucao = %s, ultima_vez = now(),
                         estado = CASE WHEN %s THEN 'aberto' ELSE estado END, corrigido_em = CASE WHEN %s THEN NULL ELSE corrigido_em END WHERE id = %s""",
                    (*valores, voltou, voltou, achado))
        if voltou:
            _historico(con, cliente, achado, estado, "aberto", None, "O agente ainda encontra o pacote vulnerável." if estado == "correcao_informada" else "O agente voltou a encontrar.")
            reabertos += 1
    # Só fecha o que é de agente conectado neste gerenciador e não apareceu nesta volta. A hora é a do banco:
    # dentro da transação, now() é sempre a mesma, então o que foi visto agora tem ultima_vez igual a ela.
    corrigidos = con.execute(
        """UPDATE vuln_achados SET estado = 'corrigido', corrigido_em = now()
           WHERE cliente_id = %s AND fonte = %s AND estado IN ('aberto', 'correcao_informada') AND ativo_id = ANY(%s) AND ultima_vez < now()
           RETURNING id""", (cliente, FONTE, list(ativos_vistos.values()))).fetchall()
    for (achado,) in corrigidos:
        _historico(con, cliente, achado, None, "corrigido", None, "O agente deixou de encontrar: o pacote foi atualizado ou removido.")
    return novos, reabertos, len(corrigidos)


def ciclo(banco, indexer_get, url):
    """Uma volta por gerenciador. Um com problema não para os outros."""
    for gerenciador_id, cliente in banco.gerenciadores():
        try:
            documentos = ler(indexer_get, url, gerenciador_id)
            with banco.con.transaction():
                banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
                agentes = {l[0]: (l[1], l[2], l[3] == "active") for l in banco.con.execute(
                    "SELECT agente_id, ip, coalesce(nome, agente_id), estado FROM ativos WHERE gerenciador_id = %s AND agente_id <> '000'",
                    (gerenciador_id,)).fetchall()}
                novos, reabertos, corrigidos = gravar(banco.con, cliente, gerenciador_id, documentos, agentes)
            if novos or reabertos or corrigidos:
                log.info("gerenciador %s: %d novos, %d reabertos, %d corrigidos", gerenciador_id, novos, reabertos, corrigidos)
        except Exception:
            log.exception("vulnerabilidades dos agentes do gerenciador %s", gerenciador_id)
