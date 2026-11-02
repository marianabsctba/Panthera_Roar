#!/usr/bin/env python3
"""Biblioteca YARA com o pacote real, gerenciador real e um Ubuntu real com o agente oficial.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_biblioteca_yara.py

Guarda a biblioteca instalada, troca por versões de teste e devolve no final. Apaga tudo o que criou.
"""

import hashlib
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import requests
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "testes/fase1")]

from roar_api.app import app  # noqa: E402
from roar_ingestao import biblioteca, fontes, provisao, yara_regras  # noqa: E402
from roar_ingestao.regras import buscar_ativos, gravar_ativos  # noqa: E402
from testar_ingestao import SUFIXO, Ambiente, agente_ativo, esperar_gerenciador  # noqa: E402

RESULTADOS = []
MARCA = f"ROAR-BIBLIOTECA-{uuid.uuid4().hex}"
IMAGEM = "roar-teste-yara"
DOCKERFILE = """FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq curl lsb-release adduser sudo >/dev/null
RUN curl -so /agente.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.9-1_amd64.deb
CMD ["sleep", "infinity"]
"""
EXTRA = f'''
/*
 * YARA Rule Set
 * Repository Name: Prova do Roar
 * Repository: https://exemplo.test/regras
 */
rule ROAR_PROVA : FILE
{{
	meta:
		description = "Marca de prova"
		author = "Autora da Prova"
		license = "BSD 2-Clause"
		source_url = "https://exemplo.test/regras/prova.yar"
		score = 80

	strings:
		$a = "{MARCA}"

	condition:
		$a
}}
rule ROAR_BASE
{{
	strings:
		$a = "{MARCA}-BASE"

	condition:
		$a
}}
rule ROAR_DEPENDE
{{
	condition:
		ROAR_BASE
}}
'''
SEGUNDA = f'''
rule ROAR_PROVA_DOIS
{{
	strings:
		$a = "{MARCA}-DOIS"

	condition:
		$a
}}
'''


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def sh(*args, limite=600):
    r = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=limite)
    return (r.stdout + r.stderr).strip()


def esperar(condicao, limite=120, passo=5):
    fim_ = time.time() + limite
    valor = condicao()
    while not valor and time.time() < fim_:
        time.sleep(passo)
        valor = condicao()
    return valor


def criar_usuario(amb, cliente):
    senha, email = secrets.token_urlsafe(18), f"analista-{uuid.uuid4().hex[:8]}@exemplo.test"
    amb.admin.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista', %s, 'administrador')",
                      (cliente, email, PasswordHasher().hash(senha)))
    return {"email": email, "senha": senha}


def pacote_pequeno(n=1200):
    return "\n".join(f'rule roar_{i}\n{{\n\tstrings:\n\t\t$a = "roar-marca-unica-{i}-{MARCA}"\n\n\tcondition:\n\t\t$a\n}}' for i in range(n))


def recusa(texto, antes=None):
    try:
        yara_regras.conferir_pacote(texto, antes)
        return ""
    except yara_regras.RegraInvalida as erro:
        return str(erro)


def testar_portao():
    print("== Portão de uma versão nova", flush=True)
    pequeno = pacote_pequeno()
    registrar("pacote bom passa", yara_regras.conferir_pacote(pequeno) == 1200)
    registrar("cortado é recusado", "menos" in recusa(pacote_pequeno(50)), recusa(pacote_pequeno(50)))
    registrar("encolheu de repente é recusado", "menos" in recusa(pequeno, 5000))
    registrar("encolher pouco passa", recusa(pequeno, 1500) == "")
    registrar("que não compila é recusado", "não compila" in recusa(pequeno + "\nrule {"))
    registrar("com include é recusado", "não compila" in recusa('include "/etc/shadow"\n' + pequeno))
    registrar("com regra global é recusado", "global" in recusa(pequeno + "\nglobal rule g { condition: filesize > 1 }"))
    registrar("que bate com tudo é recusado", "qualquer arquivo" in recusa(pequeno + "\nrule tudo { condition: true }"))
    registrar("grande demais é recusado", "tamanho" in recusa(pequeno + "\n//" + "x" * yara_regras.MAXIMO_DO_PACOTE))
    pasta = Path(tempfile.mkdtemp(prefix="roar-yara-comuns-"))
    for i in range(50):
        (pasta / f"programa{i}").write_text("comum roar-marca-unica-7-" + MARCA)
    original = yara_regras._programas_do_sistema
    yara_regras._programas_do_sistema = lambda: [str(p) for p in pasta.iterdir()]
    try:
        registrar("que acusa programas comuns é recusado", "programas comuns" in recusa(pequeno), recusa(pequeno))
    finally:
        yara_regras._programas_do_sistema = original

    print("\n== Leitura do pacote", flush=True)
    regras = {r["nome"]: r for r in yara_regras.regras_do_pacote(EXTRA + "\nprivate rule ROAR_PRIVADA\n{\n\tcondition:\n\t\ttrue\n}\n")}
    registrar("acha as regras", set(regras) == {"ROAR_PROVA", "ROAR_BASE", "ROAR_DEPENDE", "ROAR_PRIVADA"}, str(sorted(regras)))
    p = regras["ROAR_PROVA"]
    registrar("lê autor, licença, origem e pontuação", p["autor"] == "Autora da Prova" and p["licenca"] == "BSD 2-Clause" and p["repositorio"] == "Prova do Roar" and p["pontuacao"] == 80 and p["endereco"].endswith("prova.yar"), str(p)[:200])
    registrar("marca a privada", regras["ROAR_PRIVADA"]["privada"] and not p["privada"])
    sem = yara_regras.sem_regras(EXTRA, ["ROAR_DEPENDE"])
    registrar("tira só a regra pedida", "ROAR_DEPENDE" not in sem and "ROAR_BASE" in sem and "ROAR_PROVA" in sem)
    registrar("o que sobra compila", yara_regras.yara.compile(source=sem, includes=False))
    registrar("nome sem regra não muda nada", yara_regras.sem_regras(EXTRA, ["NAO_EXISTE"]) == EXTRA)


class Guardado:
    """A biblioteca é pública e única: o teste a troca e precisa devolver."""

    def __init__(self, admin):
        self.admin = admin
        self.pacotes = admin.execute("SELECT versao, conteudo, regras, sha256, publicado_em FROM yara_pacotes").fetchall()
        self.catalogo = admin.execute("SELECT nome, privada, descricao, autor, repositorio, licenca, endereco, pontuacao, conteudo FROM yara_biblioteca").fetchall()
        self.estado = admin.execute("SELECT nome, versao, atualizada_em, tentativa_em, erro FROM bibliotecas_estado WHERE nome = 'yara'").fetchall()

    def esvaziar(self):
        self.admin.execute("DELETE FROM yara_biblioteca; DELETE FROM yara_pacotes; DELETE FROM bibliotecas_estado WHERE nome = 'yara'")

    def devolver(self):
        self.esvaziar()
        with self.admin.cursor() as c:
            c.executemany("INSERT INTO yara_pacotes (versao, conteudo, regras, sha256, publicado_em) VALUES (%s, %s, %s, %s, %s)", self.pacotes)
            c.executemany("INSERT INTO yara_biblioteca (nome, privada, descricao, autor, repositorio, licenca, endereco, pontuacao, conteudo) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", self.catalogo)
            c.executemany("INSERT INTO bibliotecas_estado (nome, versao, atualizada_em, tentativa_em, erro) VALUES (%s, %s, %s, %s, %s)", self.estado)


def main():
    testar_portao()
    amb = Ambiente()
    guardado = Guardado(amb.admin)
    nome = f"roar-teste-yara-{SUFIXO}"
    try:
        base = next((p[1] for p in guardado.pacotes), None)
        if not base:
            biblioteca.atualizar_yara(amb.banco)
            base = amb.admin.execute("SELECT conteudo FROM yara_pacotes ORDER BY publicado_em DESC LIMIT 1").fetchone()[0]
            guardado = Guardado(amb.admin)
        guardado.esvaziar()

        print("\n== Atualização", flush=True)
        v1, v2, v3 = f"prova-1-{SUFIXO}", f"prova-2-{SUFIXO}", f"prova-3-{SUFIXO}"
        total = biblioteca.publicar_yara(amb.banco, v1, base + EXTRA)
        registrar("publica o pacote real inteiro", total > 1000, str(total))
        registrar("o catálogo fica pesquisável", amb.um("SELECT count(*) FROM yara_biblioteca") >= total - 10)
        registrar("o estado registra a versão", amb.um("SELECT versao FROM bibliotecas_estado WHERE nome = 'yara'") == v1)
        try:
            biblioteca.publicar_yara(amb.banco, "ruim", pacote_pequeno(50))
            registrar("versão ruim é recusada", False)
        except yara_regras.RegraInvalida:
            registrar("versão ruim é recusada", amb.um("SELECT versao FROM bibliotecas_estado WHERE nome = 'yara'") == v1 and amb.um("SELECT count(*) FROM yara_pacotes WHERE versao = 'ruim'") == 0)
        original = biblioteca.requests.get

        def fora_do_ar(*a, **k):
            raise requests.ConnectionError("sem rede")

        biblioteca.requests.get = fora_do_ar
        try:
            registrar("sem rede o ciclo não derruba o serviço", biblioteca.ciclo(amb.banco) is False)
        finally:
            biblioteca.requests.get = original
        linha = amb.admin.execute("SELECT versao, erro FROM bibliotecas_estado WHERE nome = 'yara'").fetchone()
        registrar("sem rede a versão atual continua e a tela sabe", linha[0] == v1 and "continua valendo" in (linha[1] or ""), str(linha))
        registrar("o erro não vaza detalhe", "sem rede" not in (linha[1] or ""))
        sigma_antes = amb.um("SELECT count(*) FROM biblioteca_regras")
        pasta_sigma = Path(tempfile.mkdtemp(prefix="roar-sigma-")) / "rules"
        pasta_sigma.mkdir()
        (pasta_sigma / "a.yml").write_text("title: x\nid: 11111111-1111-1111-1111-111111111111\nlogsource: {product: linux}\ndetection: {s: {a: b}, condition: s}\n")
        try:
            biblioteca.carregar_sigma(amb.banco, pasta_sigma.parent, "cortada")
            registrar("Sigma cortada é recusada", False)
        except biblioteca.BaseEstranha:
            registrar("Sigma cortada é recusada e a atual fica", amb.um("SELECT count(*) FROM biblioteca_regras") == sigma_antes)

        a, b = amb.gerenciador("ybib-a"), amb.gerenciador("ybib-b")
        registrar("gerenciadores no ar", esperar_gerenciador(a) and esperar_gerenciador(b))
        ger = f"roar-ger-{a['id']}-gerenciador-1"
        ua, ub = criar_usuario(amb, a["cliente"]), criar_usuario(amb, b["cliente"])
        pasta = Path(tempfile.mkdtemp(prefix="roar-yara-"))
        (pasta / "Dockerfile").write_text(DOCKERFILE)
        sh("docker", "build", "-q", "-t", IMAGEM, str(pasta))
        sh("docker", "run", "-d", "--name", nome, "--hostname", nome, "--network", provisao.REDE, IMAGEM)
        amb.conteineres.append(nome)
        sh("docker", "exec", "-e", f"WAZUH_MANAGER={a['host']}", "-e", f"WAZUH_REGISTRATION_SERVER={a['host']}",
           "-e", f"WAZUH_REGISTRATION_PASSWORD={a['senha_inscricao']}", "-e", f"WAZUH_AGENT_NAME={nome}", nome, "dpkg", "-i", "/agente.deb")
        sh("docker", "exec", nome, "/var/ossec/bin/wazuh-control", "start")
        agente = agente_ativo(a, nome, 180)
        registrar("Ubuntu com o agente oficial fica ativo", agente, str(agente))
        gravar_ativos(amb.banco, a["id"], a["cliente"], buscar_ativos(a["id"]))
        no_agente = lambda: sh("docker", "exec", nome, "cat", "/var/ossec/etc/shared/roar_yara.yar")  # noqa: E731

        with TestClient(app, base_url="https://testserver") as http:
            http.post("/api/entrar", json=ua)

            print("\n== Pela tela", flush=True)
            visao = http.get("/api/yara").json()
            registrar("a tela mostra a biblioteca disponível", visao["biblioteca"]["versao"] == v1 and visao["biblioteca"]["regras"] == total, str(visao["biblioteca"])[:160])
            registrar("não vem ligada", visao["assinatura"] is None)
            registrar("o comando do Windows aparece", "yara64.exe" in visao["comando_windows"] and yara_regras.YARA_WINDOWS_SHA256 in visao["comando_windows"])
            registrar("o comando do Windows confere a assinatura do runtime", "Get-AuthenticodeSignature" in visao["comando_windows"] and "vcruntime140.dll" in visao["comando_windows"])
            registrar("o script do Windows lê acentos direito", yara_regras.SCRIPT_WINDOWS.startswith("\ufeff"))
            registrar("o script do Windows não usa param", "param(" not in yara_regras.SCRIPT_WINDOWS and "$args[0]" in yara_regras.SCRIPT_WINDOWS)
            registrar("escolher regra antes de ativar pede para ativar", http.post("/api/yara/biblioteca/regras/ROAR_PROVA/nao-usar").status_code == 409)
            r = http.get("/api/yara/biblioteca/regras", params={"busca": "ROAR_PROVA"}).json()
            registrar("a busca traz autor, origem e licença", r["regras"] and r["regras"][0]["autor"] == "Autora da Prova" and r["regras"][0]["repositorio"] == "Prova do Roar" and r["regras"][0]["licenca"] == "BSD 2-Clause", str(r)[:220])
            registrar("o catálogo tem página", len(http.get("/api/yara/biblioteca/regras").json()["regras"]) < total)

            registrar("ativar responde", http.post("/api/yara/biblioteca", json={"ativa": True}).status_code == 200)
            registrar("fica na auditoria", amb.um("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'mudar_biblioteca_yara'", a["cliente"]) == 1)
            http.post("/api/fim/caminhos", json={"caminho": "/srv/yara-teste", "sistema": "linux", "modo": "tempo_real"})
            sh("docker", "exec", nome, "mkdir", "-p", "/srv/yara-teste")
            fontes.ciclo(amb.banco)
            assinatura = http.get("/api/yara").json()["assinatura"]
            registrar("fica aplicada, na versão certa", assinatura["estado"] == "aplicada" and assinatura["versao"] == v1, str(assinatura))
            registrar("gerenciador volta", esperar_gerenciador(a, 240))
            registrar("o outro cliente não recebe nada", "roar_yara" not in sh("docker", "exec", f"roar-ger-{b['id']}-gerenciador-1", "ls", "/var/ossec/etc/shared/default"))
            inicio = time.time()
            registrar("o pacote inteiro chega ao agente", esperar(lambda: MARCA in no_agente(), limite=300), f"{time.time() - inicio:.0f} s")
            registrar("o agente volta depois de receber", agente_ativo(a, nome, 180))
            comando = http.get("/api/yara").json()["comando"]
            saida = sh("docker", "exec", "-e", "DEBIAN_FRONTEND=noninteractive", nome, "sh", "-c", f"apt-get update -qq >/dev/null; {comando}")
            registrar("o comando da tela instala", "Pronto" in saida, saida[-120:])

            def pronto():
                amb.ciclo(a)
                return next(s for s in http.get("/api/yara").json()["servidores"] if s["agente_id"] == agente)["pronto_em"]

            registrar("o servidor confirma", esperar(pronto, limite=300))

            print("\n== Arquivos de verdade", flush=True)
            time.sleep(50)
            sh("docker", "exec", nome, "sh", "-c", f'echo "x {MARCA} y" > /srv/yara-teste/primeiro.bin')

            def achou(arquivo, regra):
                def olhar():
                    amb.ciclo(a)
                    return [x for x in http.get("/api/yara").json()["achados"] if arquivo in (x["arquivo"] or "") and x["regra"] == regra]
                return olhar

            achados = esperar(achou("primeiro.bin", "ROAR_PROVA"), limite=240)
            registrar("regra da biblioteca vira alerta", achados, str(achados[:1])[:240])
            registrar("o alerta dá crédito à autora", achados and achados[0]["autor"] == "Autora da Prova" and achados[0]["licenca"] == "BSD 2-Clause")
            compilado = sh("docker", "exec", nome, "ls", "-la", "/var/ossec/var/roar_yara.yarc")
            registrar("o agente compilou uma vez e guardou", "roar_yara.yarc" in compilado and "root" in compilado, compilado[:90])
            antes = sh("docker", "exec", nome, "stat", "-c", "%Y", "/var/ossec/var/roar_yara.yarc")
            sh("docker", "exec", nome, "sh", "-c", f'echo "x {MARCA} y" > /srv/yara-teste/segundo.bin')
            registrar("o segundo arquivo também vira alerta", esperar(achou("segundo.bin", "ROAR_PROVA"), limite=180))
            registrar("sem mudar as regras, não recompila", sh("docker", "exec", nome, "stat", "-c", "%Y", "/var/ossec/var/roar_yara.yarc") == antes)

            print("\n== Regra nova na atualização automática", flush=True)
            biblioteca.publicar_yara(amb.banco, v2, base + EXTRA + SEGUNDA)
            fontes.ciclo(amb.banco)
            registrar("a organização passa para a versão nova sozinha", http.get("/api/yara").json()["assinatura"]["versao"] == v2)
            registrar("a versão nova chega ao agente", esperar(lambda: "ROAR_PROVA_DOIS" in no_agente(), limite=300))
            registrar("o agente volta", agente_ativo(a, nome, 180))
            time.sleep(50)
            sh("docker", "exec", nome, "sh", "-c", f'echo "{MARCA}-DOIS" > /srv/yara-teste/terceiro.bin')
            registrar("recompila sozinho e a regra nova vale", esperar(achou("terceiro.bin", "ROAR_PROVA_DOIS"), limite=240))

            print("\n== Atualização automática desligada", flush=True)
            http.post("/api/yara/biblioteca", json={"ativa": True, "automatica": False})
            fontes.ciclo(amb.banco)
            biblioteca.publicar_yara(amb.banco, v3, base + EXTRA + SEGUNDA + "\nrule ROAR_PROVA_TRES\n{\n\tstrings:\n\t\t$a = \"" + MARCA + "-TRES\"\n\n\tcondition:\n\t\t$a\n}\n")
            fontes.ciclo(amb.banco)
            assinatura = http.get("/api/yara").json()["assinatura"]
            registrar("fica na versão escolhida", assinatura["versao"] == v2, str(assinatura))
            registrar("a nova não chega ao gerenciador", "ROAR_PROVA_TRES" not in sh("docker", "exec", ger, "cat", "/var/ossec/etc/shared/default/roar_yara.yar"))
            registrar("a tela sabe que há versão mais nova", http.get("/api/yara").json()["biblioteca"]["versao"] == v3)
            registrar("atualizar agora responde", http.post("/api/yara/biblioteca/atualizar").status_code == 202)
            fontes.ciclo(amb.banco)
            registrar("passa para a nova só agora", http.get("/api/yara").json()["assinatura"]["versao"] == v3 and "ROAR_PROVA_TRES" in sh("docker", "exec", ger, "cat", "/var/ossec/etc/shared/default/roar_yara.yar"))

            print("\n== Escolher regras", flush=True)
            registrar("regra inexistente", http.post("/api/yara/biblioteca/regras/NAO_EXISTE/nao-usar").status_code == 404)
            registrar("ação inventada", http.post("/api/yara/biblioteca/regras/ROAR_PROVA/apagar").status_code == 404)
            privada = amb.admin.execute("SELECT nome FROM yara_biblioteca WHERE privada LIMIT 1").fetchone()
            if privada:
                registrar("regra privada não sai sozinha", http.post(f"/api/yara/biblioteca/regras/{privada[0]}/nao-usar").status_code == 422)
            registrar("tirar uma regra responde", http.post("/api/yara/biblioteca/regras/ROAR_PROVA_DOIS/nao-usar").status_code == 204)
            registrar("tirar duas vezes não duplica", http.post("/api/yara/biblioteca/regras/ROAR_PROVA_DOIS/nao-usar").status_code == 204 and http.get("/api/yara").json()["assinatura"]["excluidas"] == 1)
            registrar("a busca mostra que saiu", not http.get("/api/yara/biblioteca/regras", params={"busca": "ROAR_PROVA_DOIS"}).json()["regras"][0]["em_uso"])
            fontes.ciclo(amb.banco)
            conteudo = sh("docker", "exec", ger, "cat", "/var/ossec/etc/shared/default/roar_yara.yar")
            registrar("sai do que vai aos servidores", "ROAR_PROVA_DOIS" not in conteudo and "ROAR_PROVA_TRES" in conteudo)
            registrar("usar de novo responde", http.post("/api/yara/biblioteca/regras/ROAR_PROVA_DOIS/usar").status_code == 204)
            fontes.ciclo(amb.banco)
            registrar("volta aos servidores", "ROAR_PROVA_DOIS" in sh("docker", "exec", ger, "cat", "/var/ossec/etc/shared/default/roar_yara.yar"))

            print("\n== Tirar uma regra de que outra depende", flush=True)
            antes = hashlib.sha256(sh("docker", "exec", ger, "cat", "/var/ossec/etc/shared/default/roar_yara.yar").encode()).hexdigest()
            http.post("/api/yara/biblioteca/regras/ROAR_BASE/nao-usar")
            fontes.ciclo(amb.banco)
            assinatura = http.get("/api/yara").json()["assinatura"]
            registrar("é recusada e explica", assinatura["estado"] == "recusada" and "depender" in (assinatura["mensagem"] or ""), str(assinatura))
            registrar("os servidores não recebem nada quebrado", hashlib.sha256(sh("docker", "exec", ger, "cat", "/var/ossec/etc/shared/default/roar_yara.yar").encode()).hexdigest() == antes)
            http.post("/api/yara/biblioteca/regras/ROAR_BASE/usar")
            fontes.ciclo(amb.banco)
            registrar("desfazer conserta", http.get("/api/yara").json()["assinatura"]["estado"] == "aplicada")

            print("\n== Regras próprias junto da biblioteca", flush=True)
            r = http.post("/api/yara/regras", json={"nome": "Mesmo nome", "fonte": 'rule ROAR_PROVA { strings: $a = "outra coisa" condition: $a }'})
            registrar("nome igual ao da biblioteca é recusado na hora", r.status_code == 422 and "conflita" in r.json()["detail"], r.text[:140])
            r = http.post("/api/yara/regras", json={"nome": "Própria", "fonte": f'rule roar_propria {{ strings: $a = "{MARCA}-PROPRIA" condition: $a }}'})
            registrar("regra própria convive", r.status_code == 201, r.text[:100])
            fontes.ciclo(amb.banco)
            conteudo = sh("docker", "exec", ger, "cat", "/var/ossec/etc/shared/default/roar_yara.yar")
            registrar("vão as duas", "roar_propria" in conteudo and "ROAR_PROVA" in conteudo)

            print("\n== Isolamento", flush=True)
            http.post("/api/sair")
            http.cookies.clear()
            http.post("/api/entrar", json=ub)
            visto = http.get("/api/yara").json()
            registrar("outro cliente não vê a escolha", visto["assinatura"] is None and visto["regras"] == [] and visto["achados"] == [])
            registrar("o catálogo público aparece", visto["biblioteca"]["versao"] == v3)
            registrar("outro cliente não muda a escolha", http.post("/api/yara/biblioteca/regras/ROAR_PROVA/nao-usar").status_code == 409)
            registrar("a escolha de um não afeta o outro", amb.um("SELECT count(*) FROM yara_assinatura WHERE cliente_id = %s", b["cliente"]) == 0)
            http.post("/api/sair")
            http.cookies.clear()

            print("\n== Parar de usar", flush=True)
            http.post("/api/entrar", json=ua)
            for regra in http.get("/api/yara").json()["regras"]:
                http.post(f"/api/yara/regras/{regra['id']}/desativar")
            registrar("parar responde", http.post("/api/yara/biblioteca", json={"ativa": False}).status_code == 200)
            fontes.ciclo(amb.banco)
            registrar("a pasta dos agentes esvazia", "roar_yara" not in sh("docker", "exec", ger, "ls", "/var/ossec/etc/shared/default"))
            registrar("gerenciador volta sem a resposta", esperar_gerenciador(a, 240) and "roar_yara" not in sh("docker", "exec", ger, "cat", "/var/ossec/etc/ossec.conf"))
    finally:
        clientes = [g["cliente"] for g in amb.gerenciadores]
        amb.admin.execute("DELETE FROM usuarios WHERE cliente_id = ANY(%s)", (clientes,))
        try:
            amb.limpar()
        finally:
            import psycopg
            admin = psycopg.connect(f"postgresql://roar_admin:{amb.env['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
            guardado.admin = admin
            guardado.devolver()
            admin.close()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
