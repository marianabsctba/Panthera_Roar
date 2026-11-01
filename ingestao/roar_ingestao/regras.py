"""Copia o catálogo de regras de cada gerenciador para o banco, sob o RLS do cliente.

    python -m roar_ingestao.regras

A tela só lê o banco, então não precisa de credencial nenhuma dos gerenciadores.
"""

import logging
from pathlib import Path

import requests
import urllib3

from .ciclo import conexoes, ler_env
from .normalizar import limpar

PASTA_GERENCIADORES = Path("/opt/panthera-roar/gerenciadores")
TAMANHO_DA_PAGINA = 500
log = logging.getLogger("roar.regras")


def _api_do_gerenciador(gerenciador_id):
    env = ler_env(PASTA_GERENCIADORES / gerenciador_id / ".env")
    return f"https://127.0.0.1:{env['PORTA_API']}", env["API_SENHA"]


def buscar_regras(gerenciador_id):
    # Conexão local com a API do próprio contêiner, cujo certificado é autoassinado.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    base, senha = _api_do_gerenciador(gerenciador_id)
    resposta = requests.post(f"{base}/security/user/authenticate?raw=true", auth=("roar", senha),
                             verify=False, timeout=30)
    resposta.raise_for_status()
    cabecalho = {"Authorization": f"Bearer {resposta.text}"}

    regras, deslocamento = [], 0
    while True:
        r = requests.get(f"{base}/rules", headers=cabecalho, verify=False, timeout=60,
                         params={"limit": TAMANHO_DA_PAGINA, "offset": deslocamento})
        r.raise_for_status()
        dados = r.json()["data"]
        regras += dados["affected_items"]
        deslocamento += TAMANHO_DA_PAGINA
        if deslocamento >= dados["total_affected_items"]:
            return regras


def _textos(valor):
    return [str(v) for v in valor] if isinstance(valor, list) else []


def linha_da_regra(regra):
    regra = limpar(regra)
    mitre = regra.get("mitre") if isinstance(regra.get("mitre"), dict) else {}
    return (str(regra["id"]), int(regra.get("level") or 0), regra.get("description"),
            _textos(regra.get("groups")), _textos(mitre.get("id")), regra.get("filename"),
            regra.get("status", "enabled") == "enabled")


def gravar_regras(banco, gerenciador_id, cliente, regras):
    linhas = [linha_da_regra(r) for r in regras]
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        with banco.con.cursor() as c:
            c.executemany(
                """INSERT INTO regras (cliente_id, gerenciador_id, regra_id, nivel, descricao, grupos, mitre, arquivo, ativa)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (gerenciador_id, regra_id) DO UPDATE SET nivel = EXCLUDED.nivel,
                     descricao = EXCLUDED.descricao, grupos = EXCLUDED.grupos, mitre = EXCLUDED.mitre,
                     arquivo = EXCLUDED.arquivo, ativa = EXCLUDED.ativa, atualizado_em = now()""",
                [(cliente, gerenciador_id, *linha) for linha in linhas])
        # Regra que saiu do gerenciador não pode seguir aparecendo.
        banco.con.execute("DELETE FROM regras WHERE gerenciador_id = %s AND NOT (regra_id = ANY(%s))",
                          (gerenciador_id, [l[0] for l in linhas]))
    return len(linhas)


def sincronizar(banco):
    """Falha em um gerenciador não impede os outros."""
    total, falhas = 0, {}
    for gerenciador_id, cliente in banco.gerenciadores():
        if not (PASTA_GERENCIADORES / gerenciador_id).is_dir():
            continue
        try:
            total += gravar_regras(banco, gerenciador_id, cliente, buscar_regras(gerenciador_id))
        except Exception as erro:
            falhas[gerenciador_id] = erro
            log.exception("regras do gerenciador %s falharam", gerenciador_id)
    return total, falhas


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _, banco, _ = conexoes()
    total, falhas = sincronizar(banco)
    log.info("%d regras sincronizadas", total)
    raise SystemExit(1 if falhas else 0)


if __name__ == "__main__":
    main()
