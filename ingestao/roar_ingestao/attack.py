"""Carrega a matriz Enterprise do MITRE ATT&CK, em versão fixa, para o banco.

    python -m roar_ingestao.attack

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of
The MITRE Corporation.
"""

import logging

import requests

from .ciclo import conexoes
from .regras import sincronizar_defesas

VERSAO = "20.0"
URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       f"enterprise-attack/enterprise-attack-{VERSAO}.json")
log = logging.getLogger("roar.attack")


def interpretar(pacote):
    """Devolve (táticas em ordem, técnicas), sem o que o próprio MITRE aposentou."""
    objetos = pacote["objects"]
    por_id = {o["id"]: o for o in objetos if o["type"] == "x-mitre-tactic"}
    matriz = next(o for o in objetos if o["type"] == "x-mitre-matrix")
    taticas = [(por_id[i]["x_mitre_shortname"], por_id[i]["name"], ordem) for ordem, i in enumerate(matriz["tactic_refs"])]
    tecnicas = []
    for o in objetos:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next((e for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
        if not ref:
            continue
        identificador = ref["external_id"]
        tecnicas.append((identificador, o["name"], [f["phase_name"] for f in o.get("kill_chain_phases", [])],
                         identificador.split(".")[0] if "." in identificador else None, ref.get("url"), VERSAO))
    return taticas, tecnicas


def sincronizar_attack(banco, forcar=False):
    """Só baixa de novo se a versão fixada mudou: o arquivo tem 55 MB."""
    with banco.con.transaction():
        atual = banco.con.execute("SELECT count(*) FROM tecnicas_attack WHERE versao = %s", (VERSAO,)).fetchone()[0]
    if atual and not forcar:
        return atual
    r = requests.get(URL, timeout=300)
    r.raise_for_status()
    taticas, tecnicas = interpretar(r.json())
    with banco.con.transaction():
        banco.con.execute("DELETE FROM tecnicas_attack")
        banco.con.execute("DELETE FROM taticas_attack")
        with banco.con.cursor() as c:
            c.executemany("INSERT INTO taticas_attack (tatica, nome, ordem) VALUES (%s, %s, %s)", taticas)
            c.executemany("INSERT INTO tecnicas_attack (tecnica, nome, taticas, pai, endereco, versao)"
                          " VALUES (%s, %s, %s, %s, %s, %s)", tecnicas)
    return len(tecnicas)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _, banco, _ = conexoes()
    total = sincronizar_attack(banco)
    log.info("%d técnicas do ATT&CK %s", total, VERSAO)
    with banco.con.transaction():
        tecnicas = [t for (t,) in banco.con.execute("SELECT tecnica FROM tecnicas_attack").fetchall()]
    log.info("%d técnicas novas consultadas no D3FEND", sincronizar_defesas(banco, tecnicas))


if __name__ == "__main__":
    main()
