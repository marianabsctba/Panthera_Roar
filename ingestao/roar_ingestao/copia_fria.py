"""Traz dias da cópia fria de volta ao índice, e apaga quando o prazo de consulta vence.

Os nomes dos índices saem dos gerenciadores da própria organização: um pedido nunca alcança índice de outra.
O que volta fica fora da retenção automática, para não ser apagado na hora por ser antigo: quem apaga é este módulo.
"""

import logging
import time
from datetime import datetime, timedelta

from . import provisao

log = logging.getLogger("roar.copia_fria")
MAXIMO_DE_INDICES_RECUPERADOS = 200


def indices_da_copia(indexer):
    """Para cada índice guardado, a cópia mais nova que o tem."""
    r = indexer.sessao.get(f"{indexer.url}/_snapshot/{provisao.ARQUIVO}/_all", timeout=120)
    if not r.ok:
        return {}
    onde = {}
    for copia in sorted(r.json().get("snapshots", []), key=lambda c: c.get("end_time_in_millis", 0)):
        if copia.get("state") == "SUCCESS":
            for indice in copia.get("indices", []):
                onde[indice] = copia["snapshot"]
    return onde


def indices_do_periodo(gerenciadores, de, ate, tipo):
    prefixos = []
    for g in gerenciadores:
        if tipo in ("alertas", "ambos"):
            prefixos.append(provisao.indice_do(g))
        if tipo in ("logs", "ambos"):
            prefixos.append(provisao.indice_bruto_do(g))
    dias = [de + timedelta(days=i) for i in range((ate - de).days + 1)]
    return [f"{p}{d:%Y.%m.%d}" for p in prefixos for d in dias]


def recuperar(indexer, gerenciadores, de, ate, tipo):
    """Devolve os índices que voltaram. O que já está no índice fica como está."""
    vivos = set(indexer.sessao.get(f"{indexer.url}/_cat/indices/wazuh-*?h=index", timeout=60).text.split())
    onde = indices_da_copia(indexer)
    por_copia = {}
    for indice in indices_do_periodo(gerenciadores, de, ate, tipo):
        if indice not in vivos and indice in onde:
            por_copia.setdefault(onde[indice], []).append(indice)
    voltaram = []
    for copia, indices in por_copia.items():
        r = indexer.sessao.post(
            f"{indexer.url}/_snapshot/{provisao.ARQUIVO}/{copia}/_restore?wait_for_completion=true",
            # O índice guardado leva a política de retenção junto: sem tirar, ele voltaria já vencido e sairia na hora.
            json={"indices": ",".join(indices), "include_global_state": False,
                  "ignore_index_settings": ["index.plugins.index_state_management.policy_id", "index.opendistro.index_state_management.policy_id"],
                  "index_settings": {"index.plugins.index_state_management.auto_manage": False}},
            timeout=3600)
        if not r.ok:
            raise RuntimeError(f"restaurar {copia} devolveu {r.status_code}: {r.text[:300]}")
        voltaram.extend(indices)
        tirar_retencao(indexer, indices)
    return voltaram


def tirar_retencao(indexer, indices, tentativas=15, esperar=time.sleep):
    """O indexador prende a política de retenção ao índice novo de forma assíncrona, e às vezes isso chega depois da
    remoção. Confere e tira de novo até ela não estar mais lá, para o dia que voltou não sair na hora."""
    for _ in range(tentativas):
        indexer.sessao.post(f"{indexer.url}/_plugins/_ism/remove/{','.join(indices)}", timeout=60)
        esperar(2)
        explicado = indexer.sessao.get(f"{indexer.url}/_plugins/_ism/explain/{','.join(indices)}", timeout=60).json()
        if not any((explicado.get(i) or {}).get("index.plugins.index_state_management.policy_id") or (explicado.get(i) or {}).get("policy_id") for i in indices):
            return True
    log.warning("a retenção continua presa a %s", indices)
    return False


def devolver(indexer, indices):
    for indice in indices:
        # Só índice com nome de gerenciador: nada além do que este módulo trouxe.
        if indice.startswith((provisao.PREFIXO, provisao.PREFIXO_BRUTO)):
            indexer.sessao.delete(f"{indexer.url}/{indice}", timeout=120)


def processar(env):
    """Uma volta: atende um pedido e apaga o que venceu. Devolve True se fez algo."""
    indexer = provisao.indexer_admin(env)
    feito = False
    with provisao.banco_admin(env) as b:
        vencidos = b.execute("""UPDATE recuperacoes SET estado = 'devolvido'
                                WHERE estado = 'devolver' OR (estado = 'pronto' AND expira_em < now())
                                RETURNING id, indices""").fetchall()
    for _, indices in vencidos:
        devolver(indexer, indices)
        feito = True
    with provisao.banco_admin(env) as b:
        linha = b.execute("""UPDATE recuperacoes SET estado = 'em_andamento' WHERE id = (
                               SELECT id FROM recuperacoes WHERE estado = 'pendente' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
                             RETURNING id, cliente_id, de, ate, tipo, dias_de_consulta""").fetchone()
        if not linha:
            return feito
        pedido, cliente, de, ate, tipo, dias = linha
        gerenciadores = [g[0] for g in b.execute("SELECT id FROM gerenciadores WHERE cliente_id = %s", (cliente,)).fetchall()]
        ja_de_volta = b.execute("SELECT coalesce(sum(cardinality(indices)), 0) FROM recuperacoes WHERE cliente_id = %s AND estado = 'pronto'", (cliente,)).fetchone()[0]
    estado, mensagem, voltaram = "pronto", None, []
    try:
        if ja_de_volta + len(indices_do_periodo(gerenciadores, de, ate, tipo)) > MAXIMO_DE_INDICES_RECUPERADOS:
            estado, mensagem = "falhou", "Já há muitos dias de volta. Devolva algum antes de pedir mais."
        else:
            voltaram = recuperar(indexer, gerenciadores, de, ate, tipo)
            if not voltaram:
                estado, mensagem = "falhou", "Nenhum dia desse período está na cópia fria fora do índice."
    except Exception:
        log.exception("recuperação %s", pedido)
        devolver(indexer, voltaram)
        estado, mensagem, voltaram = "falhou", "Não foi possível recuperar. Veja o registro do serviço de organizações.", []
    with provisao.banco_admin(env) as b:
        b.execute("""UPDATE recuperacoes SET estado = %s, mensagem = %s, indices = %s, pronto_em = now(),
                     expira_em = CASE WHEN %s = 'pronto' THEN now() + make_interval(days => dias_de_consulta) END WHERE id = %s""",
                  (estado, mensagem, voltaram, estado, pedido))
    return True


def dias_disponiveis(ler, url, gerenciadores):
    """Para a tela: os dias de cada tipo que estão na cópia e não no índice. Só leitura, com a sessão de leitor da API."""
    r = ler(f"{url}/_snapshot/{provisao.ARQUIVO}/_all", timeout=60)
    if not r.ok:
        return None
    guardados = {i for c in r.json().get("snapshots", []) if c.get("state") == "SUCCESS" for i in c.get("indices", [])}
    if not gerenciadores:
        return {"alertas": [], "logs": []}
    # A leitura de tamanho é o que o leitor da API pode fazer nesses índices, e já diz quais estão vivos.
    padroes = ",".join(f"{p}*" for g in gerenciadores for p in (provisao.indice_do(g), provisao.indice_bruto_do(g)))
    vivos_r = ler(f"{url}/{padroes}/_stats/store?allow_no_indices=true&ignore_unavailable=true", timeout=60)
    if not vivos_r.ok:
        return None
    vivos = set(vivos_r.json().get("indices", {}))
    dias = {"alertas": set(), "logs": set()}
    for g in gerenciadores:
        for tipo, prefixo in (("alertas", provisao.indice_do(g)), ("logs", provisao.indice_bruto_do(g))):
            for indice in guardados - vivos:
                if indice.startswith(prefixo):
                    try:
                        dias[tipo].add(datetime.strptime(indice[len(prefixo):], "%Y.%m.%d").date())
                    except ValueError:
                        pass
    return {t: sorted(d.isoformat() for d in v) for t, v in dias.items()}
