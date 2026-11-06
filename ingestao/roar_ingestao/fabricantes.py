"""Decodificadores e regras do Panthera Roar para equipamentos que o Wazuh não conhece (fabricantes/*.xml).

Valem para todo gerenciador, de qualquer organização: são do produto, não da organização (os parsers da organização ficam em
parsers.py). Roda no ciclo das fontes. Instala só quando o conteúdo muda; se o gerenciador recusar, volta ao anterior e
os parsers da organização continuam valendo.
"""

import hashlib
import logging
from pathlib import Path

from .regras import PASTA_GERENCIADORES

log = logging.getLogger("roar.fabricantes")
PASTA = Path(__file__).resolve().parent / "fabricantes"
DECODIFICADORES = "roar_fabricantes.xml"
REGRAS = "roar_fabricantes_regras.xml"


def conteudo():
    return (PASTA / "decodificadores.xml").read_text(encoding="utf-8"), (PASTA / "regras.xml").read_text(encoding="utf-8")


def aplicar(gerenciador_id, provisao=None):
    """True quando instalou agora."""
    if provisao is None:
        from . import provisao
    decodificadores, regras = conteudo()
    resumo = hashlib.sha256((decodificadores + regras).encode()).hexdigest()
    marca = PASTA_GERENCIADORES / gerenciador_id / "fabricantes.aplicado"
    if marca.exists() and marca.read_text() == resumo:
        return False
    # Primeiro o decodificador, sem reiniciar: a regra cita o nome dele, e o reinício vem com a regra.
    ok, detalhe = provisao.aplicar_regras(gerenciador_id, DECODIFICADORES, decodificadores, reiniciar=False, tipo="decoders")
    if ok:
        ok, detalhe = provisao.aplicar_regras(gerenciador_id, REGRAS, regras)
        if not ok:
            provisao.remover_regras(gerenciador_id, DECODIFICADORES, tipo="decoders")
    if not ok:
        log.error("decodificadores de fabricantes recusados em %s: %s", gerenciador_id, str(detalhe)[:400])
        return False
    marca.write_text(resumo)
    return True
