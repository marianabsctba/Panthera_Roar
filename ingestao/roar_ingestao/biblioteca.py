"""Carrega a base pública SigmaHQ, em versão fixa, para a biblioteca de regras.

    python -m roar_ingestao.biblioteca /opt/panthera-roar/sigma-base

As regras são distribuídas pela Detection Rule License 1.1: autor e endereço ficam visíveis
na tela, e o autor vai também na descrição dos alertas.
"""

import logging
import subprocess
import sys
from pathlib import Path

import yaml

from .ciclo import conexoes
from .sigma import converter_textos

ENDERECO_BASE = "https://github.com/SigmaHQ/sigma/blob/{versao}/{caminho}"
log = logging.getLogger("roar.biblioteca")


def _uma_regra(arquivo, raiz, versao):
    texto = arquivo.read_text(encoding="utf-8")
    dados = yaml.safe_load(texto)
    if not isinstance(dados, dict) or not dados.get("id") or not dados.get("title"):
        return None
    origem = dados.get("logsource") or {}
    tecnicas = sorted({t.split(".", 1)[1].upper() for t in dados.get("tags") or []
                       if isinstance(t, str) and t.lower().startswith("attack.t")})
    resultado = converter_textos([texto])[0]
    return (str(dados["id"]), str(dados["title"])[:300], str(dados.get("description") or "")[:2000] or None,
            str(dados.get("author") or "")[:300] or None, dados.get("level"),
            " / ".join(str(origem[k]) for k in ("product", "category", "service") if origem.get(k)) or None, tecnicas,
            ENDERECO_BASE.format(versao=versao, caminho=arquivo.relative_to(raiz).as_posix()), texto,
            bool(resultado.xml), resultado.motivo, versao)


def carregar(banco, raiz):
    raiz = Path(raiz)
    versao = subprocess.run(["git", "-C", str(raiz), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    linhas = [r for r in (_uma_regra(a, raiz, versao) for a in sorted((raiz / "rules").rglob("*.yml"))) if r]
    with banco.con.transaction():
        banco.con.execute("DELETE FROM biblioteca_regras")
        with banco.con.cursor() as c:
            c.executemany(
                """INSERT INTO biblioteca_regras (id, titulo, descricao, autor, nivel, origem, tecnicas, endereco, conteudo,
                     convertivel, motivo, versao) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (id) DO NOTHING""", linhas)
    return len(linhas), sum(1 for l in linhas if l[9])


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _, banco, _ = conexoes()
    total, convertiveis = carregar(banco, sys.argv[1] if len(sys.argv) > 1 else "/opt/panthera-roar/sigma-base")
    log.info("%d regras na biblioteca, %d convertíveis", total, convertiveis)


if __name__ == "__main__":
    main()
