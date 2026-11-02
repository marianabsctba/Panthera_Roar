#!/usr/bin/env python3
"""Regras criadas na tela, instaladas num gerenciador Wazuh real. Requer infra/subir.sh e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_regras_aplicadas.py
"""

import re
import secrets
import sys
import time
import uuid
from pathlib import Path

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "testes/fase1"), str(RAIZ / "testes/fase4")]

from roar_api.app import app  # noqa: E402
from roar_ingestao.regras import aplicar_regras_proprias, buscar_regras, sincronizar_arquivos  # noqa: E402
from roar_ingestao.sigma import sigma_da_regra_guiada  # noqa: E402
from roar_ingestao.xml_proprio import trecho_da_regra  # noqa: E402
from testar_ingestao import Ambiente, api_do, esperar_gerenciador  # noqa: E402
from testar_sigma import regra_disparada, sysmon  # noqa: E402

RESULTADOS = []
SYSLOG = "/var/log/syslog"


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def testar_catalogo(amb, g, email, email2, senha, senha2, aplicar, estado, regra_disparada):
    """Editar, desativar e restaurar uma regra do catálogo, vendo o que o gerenciador alerta de fato."""
    print("\n== Regra do catálogo", flush=True)
    linha = amb.admin.execute("SELECT regra_id FROM regras WHERE gerenciador_id = %s AND regra_id = '5710'", (g["id"],)).fetchone()
    if not linha:
        amb.admin.execute("INSERT INTO regras (cliente_id, gerenciador_id, regra_id, nivel, descricao, arquivo) "
                          "SELECT %s, %s, '5710', 5, 'sshd: login inexistente', arquivo FROM arquivos_de_regras "
                          "WHERE conteudo LIKE '%%id=\"5710\"%%' LIMIT 1", (g["cliente"], g["id"]))

    def alerta():
        marca = f"marca{uuid.uuid4().hex}"
        texto = f"Nov  1 12:00:00 servidor sshd[7]: Failed password for invalid user {marca} from 203.0.113.9 port 4 ssh2"
        return regra_disparada(g, texto, marca, local=SYSLOG, espera=10)

    def regras_ativas():
        return sh_regras(g, "5710")

    with TestClient(app, base_url="https://testserver") as http:
        http.post("/api/entrar", json={"email": email2, "senha": senha2})
        registrar("outro cliente não acha a regra para desligar", http.post("/api/regras/5710/desligar").status_code == 404)
        http.post("/api/sair")
        http.cookies.clear()
        http.post("/api/entrar", json={"email": email, "senha": senha})
        original = http.get("/api/regras/5710").json()["xml"]
        registrar("regra do catálogo abre com o texto", original and 'id="5710"' in original)

        for nome, xml in (("outro número", original.replace('id="5710"', 'id="5711"')),
                          ("dependência alterada", re.sub(r"<if_sid>[^<]*</if_sid>", "<if_sid>1</if_sid>", original)),
                          ("duas regras", original + original),
                          ("sem descrição", re.sub(r"<description>.*?</description>", "", original)),
                          ("com DOCTYPE", '<!DOCTYPE a [<!ENTITY b "c">]>' + original)):
            registrar(f"edição recusada: {nome}", http.put("/api/regras/5710/versao", json={"xml": xml}).status_code == 422)
        registrar("não edita regra que não existe", http.put("/api/regras/99999999/versao", json={"xml": original}).status_code == 404)

        print("-- editar", flush=True)
        editada = re.sub(r"<description>[^<]*</description>", "<description>Descricao editada</description>", original)
        r = http.put("/api/regras/5710/versao", json={"xml": editada})
        registrar("edição aceita", r.status_code == 200, r.text[:120])
        aplicar()
        ajuste = http.get("/api/regras/5710").json()["ajuste"]
        registrar("edição é instalada", ajuste and ajuste["estado"] == "ativa", str(ajuste)[:240])
        descricoes, _ = alerta()
        registrar("alerta sai com a versão editada, e não como regra nova", "Descricao editada" in descricoes, str(descricoes))
        registrar("a versão editada tem o número da original", amb.um(
            "SELECT count(*) FROM regras_proprias WHERE substitui = '5710' AND estado = 'ativa'") == 1 and "Descricao editada" in regras_ativas(), str(regras_ativas()))

        print("-- desativar", flush=True)
        registrar("desativar responde", http.post("/api/regras/5710/desligar").status_code == 200)
        registrar("lista marca a regra", any(x["regra_id"] == "5710" and x["ajuste"] == "desligada" for x in http.get("/api/regras", params={"busca": "5710"}).json()["regras"]))
        aplicar()
        registrar("desativação é instalada", http.get("/api/regras/5710").json()["ajuste"]["estado"] == "ativa")
        descricoes, _ = alerta()
        registrar("regra desativada para de alertar", "Descricao editada" not in descricoes and not any("non-existent" in d for d in descricoes), str(descricoes))

        print("-- restaurar", flush=True)
        registrar("restaurar responde", http.post("/api/regras/5710/restaurar").status_code == 204)
        aplicar()
        descricoes, _ = alerta()
        registrar("a original volta a alertar", any("non-existent" in d for d in descricoes), str(descricoes))
        registrar("restaurar duas vezes não encontra nada", http.post("/api/regras/5710/restaurar").status_code == 404)
        registrar("ajustes ficam na auditoria", amb.um(
            "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao LIKE '%%regra_do_catalogo'", g["cliente"]) == 3)


def sh_regras(g, regra):
    # A API lista a original e a versão que passou a valer, as duas com o mesmo número.
    return [i["description"] for i in api_do(g, "GET", "/rules", params={"rule_ids": regra})["data"]["affected_items"]]


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
        # Evento de Windows que não casa nada não gera alerta, e aí nada prova que foi avaliado.
        # A sentinela tem nível menor que a regra em teste: só aparece se a regra calou.
        sentinela = criar("Sentinela do Sysmon", "xml",
                          '<group name="teste,"><rule id="100003" level="3"><if_group>sysmon_event1</if_group>'
                          '<field name="win.eventdata.processGuid">^marca</field><description>Sentinela do Sysmon</description></rule></group>')
        ruim = criar("Regra ruim", "xml",
                     '<group name="teste,"><rule id="100002" level="10"><if_group>syslog</if_group>'
                     '<field name="x" type="pcre2">(</field><description>Regra ruim</description></rule></group>')
        aceitas = aplicar()
        registrar("regras boas são instaladas", aceitas == 4 and estado(guiada)[0] == "ativa" and estado(manual)[0] == "ativa"
                  and estado(windows)[0] == "ativa" and estado(sentinela)[0] == "ativa", f"{aceitas} aceitas")

        def processo(linha):
            marca = f"marca{uuid.uuid4().hex}"
            evento = sysmon("C:\\Temp\\roarteste.exe", "C:\\Windows\\explorer.exe", linha, marca=marca)
            return regra_disparada(g, evento, marca)[0]

        vistos = processo("roarteste alfa beta")
        registrar("regra guiada de Windows dispara", "Guiada de Windows" in vistos, str(vistos))
        vistos = processo("roarteste alfa")
        registrar("com duas condições no campo, as duas precisam valer", vistos and "Guiada de Windows" not in vistos, str(vistos))
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

        print("\n== Editar pela tela", flush=True)
        senha, email = secrets.token_urlsafe(18), f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
        amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash) VALUES (%s, %s, 'Analista', %s)",
                          (g["cliente"], email, PasswordHasher().hash(senha)))
        outro = amb.admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"outro-{uuid.uuid4().hex[:8]}",)).fetchone()[0]
        senha2, email2 = secrets.token_urlsafe(18), f"outro-{uuid.uuid4().hex[:8]}@exemplo.test"
        amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash) VALUES (%s, %s, 'Outro', %s)",
                          (outro, email2, PasswordHasher().hash(senha2)))
        editada = ('<group name="teste,"><rule id="100001" level="10"><if_group>syslog</if_group>'
                   "<match>palavra-editada</match><description>Manual de teste</description></rule></group>")
        try:
            with TestClient(app, base_url="https://testserver") as http:
                http.post("/api/entrar", json={"email": email2, "senha": senha2})
                registrar("outro cliente não edita a regra", http.put(f"/api/regras/proprias/{manual}", json={"formato": "xml", "xml": editada}).status_code == 404)
                http.post("/api/sair")
                http.cookies.clear()
                http.post("/api/entrar", json={"email": email, "senha": senha})
                registrar("regra aberta traz o texto para editar", any(r["id"] == manual and "palavra-manual" in r["origem"] for r in http.get("/api/regras/proprias").json()["regras"]))
                registrar("edição inválida é recusada e nada muda", http.put(f"/api/regras/proprias/{manual}", json={"formato": "xml", "xml": "<rule>"}).status_code == 422
                          and estado(manual)[0] == "ativa")
                r = http.put(f"/api/regras/proprias/{manual}", json={"formato": "xml", "xml": editada})
                registrar("edição volta a pendente", r.status_code == 200 and estado(manual)[0] == "pendente", r.text[:120])
            aplicar()
            registrar("versão editada é aceita", estado(manual)[0] == "ativa", str(estado(manual)))
            ok, vistos = dispara("texto com palavra-editada", "Manual de teste")
            registrar("versão editada dispara", ok, str(vistos))
            ok, _ = dispara("texto com palavra-manual", "Manual de teste", espera=8)
            registrar("versão antiga para de disparar", not ok)
            # A cópia de nível maior passaria à frente e esconderia o que este teste quer ver.
            amb.admin.execute("UPDATE regras_proprias SET estado = 'desativada' WHERE id = %s", (copia,))
            aplicar()
            testar_catalogo(amb, g, email, email2, senha, senha2, aplicar, estado, regra_disparada)
        finally:
            amb.admin.execute("DELETE FROM auditoria WHERE cliente_id = ANY(%s)", ([g["cliente"], outro],))
            amb.admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", ([g["cliente"], outro],))
            amb.admin.execute("DELETE FROM clientes WHERE id = %s", (outro,))

        print("\n== Desativar", flush=True)
        amb.admin.execute("UPDATE regras_proprias SET estado = 'desativada' WHERE id = %s", (manual,))
        aplicar()
        ok, _ = dispara("texto com palavra-manual", "Manual de teste", espera=8)
        registrar("regra desativada para de disparar", not ok)
        ok, vistos = dispara("texto com palavra-guiada", "Guiada de teste")
        registrar("as outras continuam ativas", ok, str(vistos))

        print("\n== Tirar a última regra", flush=True)
        amb.admin.execute("UPDATE regras_proprias SET estado = 'desativada' WHERE gerenciador_id = %s", (g["id"],))
        aplicar()
        ok, _ = dispara("texto com palavra-guiada", "Guiada de teste", espera=8)
        registrar("sem nenhuma regra própria, a última para de disparar", not ok)
        registrar("gerenciador continua no ar", esperar_gerenciador(g, 60))
    finally:
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
