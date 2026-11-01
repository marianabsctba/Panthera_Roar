#!/usr/bin/env python3
"""Regras criadas na tela, instaladas num gerenciador Wazuh real. Requer infra/subir.sh e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_regras_aplicadas.py
"""

import re
import sys
import time
import uuid
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "testes/fase1"), str(RAIZ / "testes/fase4")]

from roar_ingestao.regras import aplicar_regras_proprias, buscar_regras, sincronizar_arquivos  # noqa: E402
from roar_ingestao.sigma import sigma_da_regra_guiada  # noqa: E402
from roar_ingestao.xml_proprio import trecho_da_regra  # noqa: E402
from testar_ingestao import Ambiente, esperar_gerenciador  # noqa: E402
from testar_sigma import regra_disparada, sysmon  # noqa: E402

RESULTADOS = []
SYSLOG = "/var/log/syslog"


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def main():
    amb = Ambiente()
    try:
        g = amb.gerenciador("regras-aplicadas")
        registrar("gerenciador no ar", esperar_gerenciador(g))
        usuario = uuid.uuid4()

        def criar(titulo, formato, origem):
            return amb.um(
                "INSERT INTO regras_proprias (cliente_id, gerenciador_id, titulo, formato, origem, criada_por)"
                " VALUES (%s, %s, %s, %s, %s, %s) RETURNING id", g["cliente"], g["id"], titulo, formato, origem, usuario)

        def estado(i):
            return amb.admin.execute("SELECT estado, mensagem FROM regras_proprias WHERE id = %s", (i,)).fetchone()

        def aplicar():
            n = aplicar_regras_proprias(amb.banco, g["id"], g["cliente"])
            time.sleep(25)
            esperar_gerenciador(g, 240)
            return n

        def dispara(texto, titulo, espera=20):
            marca = f"marca{uuid.uuid4().hex}"
            linha = f"Nov  1 12:00:00 servidor aplicacao[7]: {texto} {marca}"
            descricoes, _ = regra_disparada(g, linha, marca, local=SYSLOG, espera=espera)
            return titulo in descricoes, descricoes

        print("\n== Regra guiada, Sigma e XML à mão", flush=True)
        sigma_guiada = sigma_da_regra_guiada("Guiada de teste", "linux_syslog", "high", [{"valor": "palavra-guiada"}])
        guiada = criar("Guiada de teste", "guiada", sigma_guiada)
        manual = criar("Manual de teste", "xml",
                       '<group name="teste,"><rule id="100001" level="10"><if_group>syslog</if_group>'
                       "<match>palavra-manual</match><description>Manual de teste</description></rule></group>")
        windows = criar("Guiada de Windows", "guiada", sigma_da_regra_guiada(
            "Guiada de Windows", "windows_processo", "high",
            [{"campo": "Image", "operador": "termina", "valor": "\\roarteste.exe"},
             {"campo": "CommandLine", "operador": "contem", "valor": "alfa"},
             {"campo": "CommandLine", "operador": "contem", "valor": "beta"}]))
        ruim = criar("Regra ruim", "xml",
                     '<group name="teste,"><rule id="100002" level="10"><if_group>syslog</if_group>'
                     '<field name="x" type="pcre2">(</field><description>Regra ruim</description></rule></group>')
        aceitas = aplicar()
        registrar("regras boas são instaladas", aceitas == 3 and estado(guiada)[0] == "ativa" and estado(manual)[0] == "ativa"
                  and estado(windows)[0] == "ativa", f"{aceitas} aceitas")

        def processo(linha):
            marca = f"marca{uuid.uuid4().hex}"
            evento = sysmon("C:\\Temp\\roarteste.exe", "C:\\Windows\\explorer.exe", linha, marca=marca)
            return regra_disparada(g, evento, marca)[0]

        registrar("regra guiada de Windows dispara", "Guiada de Windows" in processo("roarteste alfa beta"))
        registrar("com duas condições no campo, as duas precisam valer", "Guiada de Windows" not in processo("roarteste alfa"))
        registrar("regra ruim é recusada com motivo", estado(ruim)[0] == "recusada" and estado(ruim)[1], str(estado(ruim))[:200])
        registrar("regra ruim não derruba as outras nem o gerenciador", esperar_gerenciador(g, 60))
        ok, vistos = dispara("texto com palavra-guiada", "Guiada de teste")
        registrar("regra guiada dispara", ok, str(vistos))
        ok, vistos = dispara("texto com palavra-manual", "Manual de teste")
        registrar("regra escrita à mão dispara", ok, str(vistos))
        ok, _ = dispara("texto sem nada", "Manual de teste", espera=6)
        registrar("log comum não dispara", not ok)

        print("\n== Reaplicar não reinicia à toa", flush=True)
        registrar("sem mudança nada é refeito", aplicar_regras_proprias(amb.banco, g["id"], g["cliente"]) == 0)

        print("\n== Copiar uma regra do Wazuh e personalizar", flush=True)
        regras = buscar_regras(g["id"])
        sincronizar_arquivos(amb.banco, g["id"], [r for r in regras if r["id"] == 5710])
        arquivo = next(r["filename"] for r in regras if r["id"] == 5710)
        original = amb.um("SELECT conteudo FROM arquivos_de_regras WHERE arquivo = %s", arquivo)
        trecho = trecho_da_regra(original, 5710)
        registrar("XML original da regra é encontrado", trecho and 'id="5710"' in trecho, (trecho or "")[:80])
        # Quem personaliza quase sempre muda a descrição e deixa a condição como está.
        personalizada = trecho.replace('level="5"', 'level="11"')
        personalizada = re.sub(r"<description>[^<]*</description>", "<description>Personalizada de teste</description>", personalizada)
        copia = criar("Personalizada de teste", "xml", f'<group name="personalizadas,">{personalizada}</group>')
        aplicar()
        registrar("cópia personalizada é aceita", estado(copia)[0] == "ativa", str(estado(copia))[:300])
        marca = f"marca{uuid.uuid4().hex}"
        linha = f"Nov  1 12:00:00 servidor sshd[7]: Failed password for invalid user {marca} from 203.0.113.9 port 4 ssh2"
        descricoes, _ = regra_disparada(g, linha, marca, local=SYSLOG)
        # A cópia tem nível maior e passa à frente da original, que segue instalada para os outros casos.
        registrar("cópia personalizada dispara no lugar da original", descricoes == ["Personalizada de teste"], str(descricoes))

        print("\n== Desativar", flush=True)
        amb.admin.execute("UPDATE regras_proprias SET estado = 'desativada' WHERE id = %s", (manual,))
        aplicar()
        ok, _ = dispara("texto com palavra-manual", "Manual de teste", espera=8)
        registrar("regra desativada para de disparar", not ok)
        ok, vistos = dispara("texto com palavra-guiada", "Guiada de teste")
        registrar("as outras continuam ativas", ok, str(vistos))
    finally:
        amb.admin.execute("DELETE FROM arquivos_de_regras WHERE arquivo LIKE '%%sshd%%'")
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
