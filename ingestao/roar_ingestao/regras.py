"""Copia o catálogo de regras de cada gerenciador para o banco, sob o RLS do cliente.

    python -m roar_ingestao.regras

A tela só lê o banco, então não precisa de credencial nenhuma dos gerenciadores.
"""

import logging
import re
import time
from pathlib import Path

import requests
import urllib3
from psycopg.types.json import Jsonb

from .ciclo import conexoes, ler_env
from .normalizar import limpar

PASTA_GERENCIADORES = Path("/opt/panthera-roar/gerenciadores")
TAMANHO_DA_PAGINA = 500
NORMAS = ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13")
URL_D3FEND = "https://d3fend.mitre.org/api/offensive-technique/attack"
log = logging.getLogger("roar.regras")


def _api_do_gerenciador(gerenciador_id):
    env = ler_env(PASTA_GERENCIADORES / gerenciador_id / ".env")
    return f"https://127.0.0.1:{env['PORTA_API']}", env["API_SENHA"]


def _pedir(gerenciador_id, rota, parametros=None):
    # Conexão local com a API do próprio contêiner, cujo certificado é autoassinado.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    base, senha = _api_do_gerenciador(gerenciador_id)
    token = requests.post(f"{base}/security/user/authenticate?raw=true", auth=("roar", senha), verify=False, timeout=30)
    token.raise_for_status()
    r = requests.get(base + rota, headers={"Authorization": f"Bearer {token.text}"}, verify=False, timeout=60,
                     params=parametros)
    r.raise_for_status()
    return r.json()


def buscar_regras(gerenciador_id):
    regras, deslocamento = [], 0
    while True:
        dados = _pedir(gerenciador_id, "/rules", {"limit": TAMANHO_DA_PAGINA, "offset": deslocamento})["data"]
        regras += dados["affected_items"]
        deslocamento += TAMANHO_DA_PAGINA
        if deslocamento >= dados["total_affected_items"]:
            return regras


def _textos(valor):
    return [str(v) for v in valor] if isinstance(valor, list) else []


def linha_da_regra(regra):
    regra = limpar(regra)
    normas = {n: _textos(regra.get(n)) for n in NORMAS if regra.get(n)}
    return (str(regra["id"]), int(regra.get("level") or 0), regra.get("description"),
            _textos(regra.get("groups")), _textos(regra.get("mitre")), regra.get("filename"),
            regra.get("status", "enabled") == "enabled", Jsonb(normas))


def gravar_regras(banco, gerenciador_id, cliente, regras):
    linhas = [linha_da_regra(r) for r in regras]
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        with banco.con.cursor() as c:
            c.executemany(
                """INSERT INTO regras (cliente_id, gerenciador_id, regra_id, nivel, descricao, grupos, mitre, arquivo, ativa, normas)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (gerenciador_id, regra_id) DO UPDATE SET nivel = EXCLUDED.nivel,
                     descricao = EXCLUDED.descricao, grupos = EXCLUDED.grupos, mitre = EXCLUDED.mitre,
                     arquivo = EXCLUDED.arquivo, ativa = EXCLUDED.ativa, normas = EXCLUDED.normas, atualizado_em = now()""",
                [(cliente, gerenciador_id, *linha) for linha in linhas])
        # Regra que saiu do gerenciador não pode seguir aparecendo.
        banco.con.execute("DELETE FROM regras WHERE gerenciador_id = %s AND NOT (regra_id = ANY(%s))",
                          (gerenciador_id, [l[0] for l in linhas]))
    return len(linhas)


def buscar_ativos(gerenciador_id):
    """Agentes com a nota da avaliação de configuração segura, quando houver."""
    agentes = _pedir(gerenciador_id, "/agents", {"limit": 500})["data"]["affected_items"]
    for agente in agentes:
        agente["_sca"] = None
        if agente.get("id") == "000" or agente.get("status") == "never_connected":
            continue
        try:
            politicas = _pedir(gerenciador_id, f"/sca/{agente['id']}", {"limit": 1})["data"]["affected_items"]
            agente["_sca"] = politicas[0] if politicas else None
        except requests.RequestException:
            log.warning("sem avaliação do agente %s", agente["id"])
    return agentes


def gravar_ativos(banco, gerenciador_id, cliente, agentes):
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        vistos = []
        for bruto in agentes:
            a = limpar(bruto)
            sca = a.get("_sca") or {}
            sistema = a.get("os") if isinstance(a.get("os"), dict) else {}
            vistos.append(str(a["id"]))
            banco.con.execute(
                """INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, ip, sistema, versao, estado, grupos,
                     ultima_conexao, sca_politica, sca_nota, sca_aprovados, sca_reprovados)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (gerenciador_id, agente_id) DO UPDATE SET nome = EXCLUDED.nome, ip = EXCLUDED.ip,
                     sistema = EXCLUDED.sistema, versao = EXCLUDED.versao, estado = EXCLUDED.estado,
                     grupos = EXCLUDED.grupos, ultima_conexao = EXCLUDED.ultima_conexao, sca_politica = EXCLUDED.sca_politica,
                     sca_nota = EXCLUDED.sca_nota, sca_aprovados = EXCLUDED.sca_aprovados,
                     sca_reprovados = EXCLUDED.sca_reprovados, atualizado_em = now()""",
                (cliente, gerenciador_id, str(a["id"]), a.get("name"), a.get("ip"),
                 " ".join(x for x in (sistema.get("name"), sistema.get("version")) if x) or None, a.get("version"),
                 a.get("status"), _textos(a.get("group")), a.get("lastKeepAlive"), sca.get("name"), sca.get("score"),
                 sca.get("pass"), sca.get("fail")))
        banco.con.execute("DELETE FROM ativos WHERE gerenciador_id = %s AND NOT (agente_id = ANY(%s))",
                          (gerenciador_id, vistos))
    return len(vistos)


def sincronizar_defesas(banco, tecnicas, pausa=0.2):
    """Consulta no MITRE D3FEND as técnicas que ainda não têm resposta guardada."""
    with banco.con.transaction():
        conhecidas = {t for (t,) in banco.con.execute("SELECT tecnica FROM tecnicas_consultadas").fetchall()}
    novas = 0
    for tecnica in sorted(set(tecnicas) - conhecidas):
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", tecnica):
            continue
        r = requests.get(f"{URL_D3FEND}/{tecnica}.json", timeout=30)
        if r.status_code == 404:
            ligacoes = []
        else:
            r.raise_for_status()
            ligacoes = r.json().get("off_to_def", {}).get("results", {}).get("bindings", [])
        with banco.con.transaction():
            for b in ligacoes:
                if "def_tech_id" in b and "def_tech_label" in b:
                    banco.con.execute(
                        """INSERT INTO tecnicas_defesa (tecnica, defesa_id, defesa_nome, tatica_defesa)
                           VALUES (%s, %s, %s, %s) ON CONFLICT (tecnica, defesa_id) DO UPDATE SET
                             defesa_nome = EXCLUDED.defesa_nome, tatica_defesa = EXCLUDED.tatica_defesa, atualizado_em = now()""",
                        (tecnica, b["def_tech_id"]["value"], b["def_tech_label"]["value"],
                         b.get("def_tactic_label", {}).get("value")))
            banco.con.execute("INSERT INTO tecnicas_consultadas (tecnica) VALUES (%s) ON CONFLICT DO NOTHING", (tecnica,))
        novas += 1
        time.sleep(pausa)
    return novas


def sincronizar(banco):
    """Falha em um gerenciador não impede os outros."""
    total, falhas, tecnicas = 0, {}, set()
    for gerenciador_id, cliente in banco.gerenciadores():
        if not (PASTA_GERENCIADORES / gerenciador_id).is_dir():
            continue
        try:
            regras = buscar_regras(gerenciador_id)
            total += gravar_regras(banco, gerenciador_id, cliente, regras)
            tecnicas |= {t for r in regras for t in _textos(r.get("mitre"))}
            gravar_ativos(banco, gerenciador_id, cliente, buscar_ativos(gerenciador_id))
        except Exception as erro:
            falhas[gerenciador_id] = erro
            log.exception("sincronização do gerenciador %s falhou", gerenciador_id)
    try:
        sincronizar_defesas(banco, tecnicas)
    except requests.RequestException:
        # Base pública fora do ar não atrapalha a detecção: tenta de novo no próximo ciclo.
        log.warning("MITRE D3FEND indisponível", exc_info=True)
    return total, falhas


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _, banco, _ = conexoes()
    total, falhas = sincronizar(banco)
    log.info("%d regras sincronizadas", total)
    raise SystemExit(1 if falhas else 0)


if __name__ == "__main__":
    main()
