#!/usr/bin/env python3
"""Fase 4, primeira parte: login e fila de alertas. Requer infra/subir.sh já executado e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_api.py

Usa o banco de verdade e apaga no final tudo o que criou.
"""

import hashlib
import json
import random
import re
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api")]

ENV = {}
for linha in Path("/opt/panthera-roar/.env").read_text().splitlines():
    if "=" in linha and not linha.startswith("#"):
        k, v = linha.split("=", 1)
        ENV[k] = v
ADMIN = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
URL_API = f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar"

from roar_api.app import COOKIE, ESTATICO, app, falhas_de_login  # noqa: E402

XSS = '<img src=x onerror="alert(1)">'
RESULTADOS = []
CRIADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def recusado(funcao):
    try:
        funcao()
        return False
    except psycopg.Error:
        return True


def novo_cliente(nome):
    sufixo = uuid.uuid4().hex[:10]
    cliente = ADMIN.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"{nome}-{sufixo}",)).fetchone()[0]
    ger = f"t{sufixo}"
    ADMIN.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)",
                  (ger, cliente, random.randint(40000, 60000)))
    senha = secrets.token_urlsafe(18)
    email = f"analista-{sufixo}@exemplo.test"
    ADMIN.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, %s, %s, 'administrador')",
                  (cliente, email, f"Analista {nome}", PasswordHasher().hash(senha)))
    agora = datetime.now(timezone.utc)
    entidade = ADMIN.execute(
        "INSERT INTO entidades (cliente_id, tipo, chave, nome, primeira_vista, ultima_vista, risco)"
        " VALUES (%s, 'usuario', %s, %s, %s, %s, 75) RETURNING id", (cliente, f"maria{sufixo}", XSS, agora, agora)).fetchone()[0]
    ADMIN.execute("UPDATE entidades SET risco_em = %s WHERE id = %s", (agora, entidade))
    grupo = ADMIN.execute(
        "INSERT INTO grupos_alerta (cliente_id, chave, dia, gerenciador_id, agente_id, nivel, severidade, regras,"
        " primeira_em, ultima_em) VALUES (%s, 'k', %s, %s, '001', 10, 'media', '{5712}', %s, %s) RETURNING id",
        (cliente, agora.date(), ger, agora, agora)).fetchone()[0]
    evento = ADMIN.execute(
        "INSERT INTO eventos (cliente_id, grupo_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel, severidade,"
        " regra_id, regra_descricao, agente_id, agente_nome, ip_origem, usuario, bruto)"
        " VALUES (%s, %s, %s, 'wazuh', 'e1', %s, 10, 'media', '5712', %s, '001', 'servidor', '203.0.113.5', %s, %s)"
        " RETURNING id", (cliente, grupo, ger, agora, XSS, XSS, Jsonb({"segredo_do_bruto": "nao-sair"}))).fetchone()[0]
    ADMIN.execute(
        "INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id, detalhes)"
        " VALUES (%s, %s, 'primeiro_host', 'h', %s, 15, %s, %s, %s)",
        (cliente, entidade, agora.date(), agora, evento, Jsonb({"host": XSS})))
    alerta = ADMIN.execute(
        "INSERT INTO alertas_risco (cliente_id, entidade_id, severidade, risco_maximo, aberto_em)"
        " VALUES (%s, %s, 'alta', 75, %s) RETURNING id", (cliente, entidade, agora)).fetchone()[0]
    dados = {"id": cliente, "ger": ger, "email": email, "senha": senha, "alerta": alerta, "grupo": grupo}
    CRIADOS.append(dados)
    return dados


def limpar():
    ids = [c["id"] for c in CRIADOS]
    for tabela in ("chaves_api", "relatorios_gerados", "notificacoes", "intel_ocorrencias", "intel_indicadores", "intel_fontes", "casos_notas", "casos_itens", "casos", "regras_proprias", "ativos", "auditoria", "regras", "sinais", "alertas_risco", "vistos", "horas", "silencios", "pares", "entidades", "eventos", "grupos_alerta",
                   "gerenciadores", "usuarios"):
        ADMIN.execute(f"DELETE FROM {tabela} WHERE cliente_id = ANY(%s)", (ids,))
    ADMIN.execute("DELETE FROM clientes WHERE id = ANY(%s)", (ids,))


def entrar(http, cliente):
    return http.post("/api/entrar", json={"email": cliente["email"], "senha": cliente["senha"]})


def testar_linha_do_tempo():
    print("\n== Linha do tempo do risco", flush=True)
    from roar_api.app import LIMITE_DO_RISCO_ALTO, LIMITE_DO_RISCO_CRITICO, MEIA_VIDA_DO_RISCO_HORAS, _linha_do_tempo
    sys.path.insert(0, str(RAIZ / "ueba"))
    from roar_ueba.motor import Parametros
    p = Parametros()
    registrar("a tela usa os mesmos números do motor", (MEIA_VIDA_DO_RISCO_HORAS, LIMITE_DO_RISCO_ALTO, LIMITE_DO_RISCO_CRITICO)
              == (p.meia_vida_horas, p.limite_alerta, p.limite_critico))
    inicio = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tecnicas = {"T1110": {"nome": "Brute Force", "tatica": "Credential Access"}, "T1078": {"nome": "Valid Accounts", "tatica": "Initial Access"}}
    sinais = [
        {"tipo": "primeiro_ip", "peso": 10, "ocorrido_em": inicio + timedelta(hours=24), "mitre": []},
        {"tipo": "sucesso_apos_falhas", "peso": 40, "ocorrido_em": inicio, "mitre": ["T9999"]},
        {"tipo": "primeiro_host", "peso": 15, "ocorrido_em": inicio + timedelta(days=7, hours=12), "mitre": None},
    ]
    linha = _linha_do_tempo(sinais, tecnicas)
    registrar("sinais saem em ordem de acontecimento", [s["tipo"] for s in linha] == ["sucesso_apos_falhas", "primeiro_ip", "primeiro_host"])
    registrar("risco decai pela meia-vida", [s["risco_depois"] for s in linha][:2] == [40.0, 30.0], str([s["risco_depois"] for s in linha]))
    registrar("sinal fora da janela não soma", linha[2]["risco_depois"] == round(15 + 10 * 0.5 ** 6.5, 1), str(linha[2]["risco_depois"]))
    registrar("técnica desconhecida do evento cai na do sinal", linha[0]["tecnica"] == {"codigo": "T1110", **tecnicas["T1110"]})
    registrar("sinal sem técnica conhecida fica sem", linha[2]["tecnica"] is None)


def testar_mascara_sem_banco():
    print("\n== Máscara de dado pessoal", flush=True)
    from roar_api.ofuscacao import CATEGORIAS, Mascara
    m = Mascara(CATEGORIAS, b"chave", "cliente")
    texto = m.texto("cpf 529.982.247-25 cnpj 11.222.333/0001-81 cartao 4111 1111 1111 1111 tel (41) 99876-5432 mail fulano@exemplo.com.br de 203.0.113.5")
    registrar("CPF, CNPJ, cartão, telefone, e-mail e IP somem do texto",
              texto == "cpf ***.***.***-** cnpj **.***.***/****-** cartao **** **** **** 1111 tel (**) *****-**** mail f***@exemplo.com.br de 203.0.x.x", texto)
    intacto = "versão 1.2.3.4.5, dia 2026-11-05 10:20:30, número 12345678901, cartão 4111 1111 1111 1112"
    registrar("versão, data e número que não passam na conferência ficam", m.texto(intacto) == intacto, m.texto(intacto))
    dado = m.dado({"usuario": "maria.silva", "bruto": {"full_log": "senha errada para maria.silva", "data": {"srcuser": "Maria.Silva"}},
                   "riscos": [{"entidade": "maria.silva", "entidade_tipo": "usuario"}, {"entidade": "web-01", "entidade_tipo": "ativo"}], "peso": 15})
    apelido = dado["usuario"]
    registrar("usuário vira apelido", apelido.startswith("usuario-") and "maria" not in json.dumps(dado).lower(), json.dumps(dado))
    registrar("o mesmo usuário tem o mesmo apelido em todo lugar", dado["bruto"]["data"]["srcuser"] == dado["riscos"][0]["entidade"] == apelido
              and dado["bruto"]["full_log"] == f"senha errada para {apelido}")
    registrar("ativo não é mascarado como usuário", dado["riscos"][1]["entidade"] == "web-01" and dado["peso"] == 15)
    registrar("apelido muda de uma organização para outra", Mascara(CATEGORIAS, b"chave", "outro").apelido("maria.silva") != apelido)
    so_ip = Mascara(["ip"], b"chave", "cliente").dado({"usuario": "maria", "ip_origem": "2001:db8::1", "texto": "maria@x.com"})
    registrar("só o que está ligado é mascarado", so_ip == {"usuario": "maria", "ip_origem": "2001:x:x", "texto": "maria@x.com"}, str(so_ip))


def testar_ocsf_sem_banco():
    print("\n== OCSF", flush=True)
    from roar_api.ocsf import converter
    agora = datetime.now(timezone.utc)
    base = {"id": 7, "ocorrido_em": agora, "recebido_em": agora, "severidade": "media", "regra_id": "5715", "agente_nome": "srv", "agente_id": "001",
            "ip_origem": "203.0.113.9", "usuario": "ana"}
    login = converter({**base, "regra_grupos": ["sshd", "authentication_success"], "bruto": {}})
    registrar("login vira Authentication com sucesso", (login["class_uid"], login["type_uid"], login["status_id"], login["user"]["name"])
              == (3002, 300201, 1, "ana"), str(login)[:200])
    falha = converter({**base, "regra_grupos": ["authentication_failed"], "bruto": {}})
    registrar("falha de login vira Authentication com falha", (falha["class_uid"], falha["status"]) == (3002, "Failure"))
    arquivo = converter({**base, "usuario": None, "regra_grupos": ["ossec", "syscheck"],
                         "bruto": {"syscheck": {"path": "/etc/shadow", "event": "modified", "sha256_after": "ab" * 32}}})
    registrar("integridade vira File System Activity com o resumo", (arquivo["class_uid"], arquivo["activity_name"], arquivo["file"]["name"],
              arquivo["file"]["hashes"][0]["algorithm"]) == (1001, "Update", "shadow", "SHA-256"), str(arquivo.get("file")))
    grupo = converter({**base, "regra_grupos": ["windows"], "bruto": {"data": {"win": {"system": {"eventID": "4732"}, "eventdata": {
        "targetUserName": "Administrators", "memberName": "bob", "subjectUserName": "ana"}}}}})
    registrar("entrada em grupo vira Group Management", (grupo["class_uid"], grupo["group"]["name"], grupo["user"]["name"], grupo["actor"]["user"]["name"])
              == (3006, "Administrators", "bob", "ana"))
    registrar("sudo vira Authorize Session", converter({**base, "regra_grupos": ["sudo"], "bruto": {}})["class_uid"] == 3003)
    achado = converter({**base, "regra_grupos": ["web", "attack"], "mitre": ["T1190"], "bruto": {}},
                       {"T1190": {"nome": "Exploit Public-Facing Application", "tatica": "Initial Access"}})
    registrar("o resto vira Detection Finding com a técnica do ATT&CK", (achado["class_uid"], achado["finding_info"]["attacks"][0]["technique"]["name"],
              achado["finding_info"]["attacks"][0]["tactic"]["name"], achado["severity_id"]) == (2004, "Exploit Public-Facing Application", "Initial Access", 3))
    sca = converter({**base, "usuario": None, "regra_grupos": ["sca"], "bruto": {"data": {"sca": {"type": "check", "policy": "CIS Debian 12",
                    "check": {"id": "28500", "title": "Garantir /tmp separado", "result": "failed", "compliance": {"cis": "1.1.2"}}}}}})
    registrar("checagem de configuração vira Compliance Finding", (sca["class_uid"], sca["compliance"]["status"], sca["compliance"]["standards"],
              sca["finding_info"]["title"]) == (2003, "Fail", ["CIS Debian 12"], "Garantir /tmp separado"), str(sca)[:200])
    registrar("campo vazio não aparece", "status" not in converter({**base, "regra_grupos": [], "bruto": {}, "usuario": None}).get("user", {}))


def testar_chaves(http, a, b):
    print("\n== Chaves de API", flush=True)
    entrar(http, a)
    registrar("chave de administrador é recusada", http.post("/api/chaves", json={"nome": "x", "perfil": "administrador"}).status_code == 422)
    criada = http.post("/api/chaves", json={"nome": "SOAR externo", "perfil": "analista_n1", "dias": 30})
    registrar("chave é criada e o segredo sai uma vez", criada.status_code == 201 and criada.json()["chave"].startswith("roar_"), criada.text[:120])
    token, identificador = criada.json()["chave"], criada.json()["id"]
    lista = http.get("/api/chaves").json()["chaves"]
    registrar("a lista não mostra o segredo", lista and token not in json.dumps(lista) and lista[0]["estado"] == "ativa" and lista[0]["dono"] == "Analista a")
    openapi = http.get("/api/openapi.json").json()
    registrar("a documentação traz as rotas de dado e não as de conta", "/api/eventos" in openapi["paths"] and "/api/casos" in openapi["paths"]
              and not any(p.startswith(("/api/chaves", "/api/usuarios", "/api/minha-senha", "/api/mfa", "/api/entrar")) for p in openapi["paths"])
              and openapi["paths"]["/api/eventos"]["get"]["x-permissao"] == "ver")
    outro_evento = ADMIN.execute("SELECT id FROM eventos WHERE cliente_id = %s LIMIT 1", (b["id"],)).fetchone()[0]
    http.post("/api/sair")
    http.cookies.clear()

    chave = {"Authorization": f"Bearer {token}"}
    registrar("a chave lê os dados da organização", http.get("/api/fila", headers=chave).status_code == 200
              and http.get("/api/openapi.json", headers=chave).status_code == 200)
    caso = http.post("/api/casos", headers=chave, json={"titulo": "Aberto pela integração", "severidade": "media"})
    registrar("a chave age com o perfil escolhido, em nome de quem criou", caso.status_code == 201
              and http.get(f"/api/casos/{caso.json()['id']}", headers=chave).json()["caso"]["criado_por_nome"] == "Analista a (chave SOAR externo)")
    registrar("a chave não passa do perfil", http.get("/api/chaves", headers=chave).status_code == 403
              and http.request("PUT", "/api/organizacao/ofuscacao", headers=chave, json={"categorias": []}).status_code == 403)
    registrar("a chave não entra nas rotas de conta", http.get("/api/eu", headers=chave).status_code == 401
              and http.post("/api/minha-senha", headers=chave, json={"atual": "x", "nova": "y" * 20}).status_code == 401)
    registrar("a chave não vê outra organização", http.get(f"/api/eventos/{outro_evento}/ocsf", headers=chave).status_code == 404)
    registrar("chave inventada é recusada", http.get("/api/fila", headers={"Authorization": "Bearer roar_inventada_x"}).status_code == 401
              and http.get("/api/fila", headers={"Authorization": "Basic abc"}).status_code == 401)
    ADMIN.execute("UPDATE usuarios SET ativo = false WHERE cliente_id = %s", (a["id"],))
    registrar("dono desativado derruba a chave", http.get("/api/fila", headers=chave).status_code == 401)
    ADMIN.execute("UPDATE usuarios SET ativo = true WHERE cliente_id = %s", (a["id"],))
    ADMIN.execute("UPDATE chaves_api SET expira_em = now() - interval '1 minute' WHERE id = %s", (identificador,))
    registrar("chave vencida é recusada", http.get("/api/fila", headers=chave).status_code == 401)
    ADMIN.execute("UPDATE chaves_api SET expira_em = NULL WHERE id = %s", (identificador,))
    registrar("a chave registra o último uso", http.get("/api/fila", headers=chave).status_code == 200
              and ADMIN.execute("SELECT ultima_vez IS NOT NULL FROM chaves_api WHERE id = %s", (identificador,)).fetchone()[0])

    entrar(http, a)
    registrar("revogar a chave", http.request("DELETE", f"/api/chaves/{identificador}").status_code == 204
              and http.request("DELETE", f"/api/chaves/{identificador}").status_code == 404)
    registrar("criar e revogar ficam na auditoria", ADMIN.execute(
        "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao IN ('criar_chave_de_api', 'revogar_chave_de_api')", (a["id"],)).fetchone()[0] == 2)
    http.post("/api/sair")
    http.cookies.clear()
    registrar("chave revogada é recusada", http.get("/api/fila", headers=chave).status_code == 401)


def testar_caca(http, a):
    print("\n== Caça de indicadores", flush=True)
    entrar(http, a)
    registrar("caça sem indicador reconhecido é recusada", http.post("/api/inteligencia/cacar", json={"texto": "ola tudo bem"}).status_code == 422)
    r = http.post("/api/inteligencia/cacar", json={"texto": "203.0.113[.]5, 198.51.100.77; hxxps://mal[.]exemplo.com/x ola", "dias": 30})
    registrar("caça reconhece indicador desarmado", r.status_code == 200 and {(i["tipo"], i["valor"]) for i in r.json()["indicadores"]}
              == {("ip", "203.0.113.5"), ("ip", "198.51.100.77"), ("url", "https://mal.exemplo.com/x")} and r.json()["ignorados"] == ["ola"], r.text[:300])
    contagem = {i["valor"]: i["eventos"] for i in r.json()["indicadores"]}
    registrar("caça acha o evento da organização e só ele", contagem == {"203.0.113.5": 1, "198.51.100.77": 0, "https://mal.exemplo.com/x": 0}, str(contagem))
    registrar("o achado diz qual indicador bateu", [x["indicador"] for x in r.json()["achados"]] == ["203.0.113.5"])
    registrar("caça fica na auditoria", ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'cacar_indicadores'",
                                                      (a["id"],)).fetchone()[0] == 1)
    registrar("endereço interno não é vigiado", http.post("/api/inteligencia/vigiar", json={"indicadores": [{"tipo": "ip", "valor": "10.0.0.1"}]}).status_code == 422)
    v = http.post("/api/inteligencia/vigiar", json={"indicadores": [{"tipo": "ip", "valor": "185.220.101.4"}, {"tipo": "ip", "valor": "10.0.0.1"}]})
    registrar("indicador passa a ser vigiado na Lista manual", v.status_code == 201 and v.json() == {"vigiados": 1, "recusados": ["10.0.0.1"]}, v.text[:200])
    registrar("vigiar de novo não duplica", http.post("/api/inteligencia/vigiar", json={"indicadores": [{"tipo": "ip", "valor": "185.220.101.4"}]}).status_code == 201
              and ADMIN.execute("SELECT count(*) FROM intel_indicadores i JOIN intel_fontes f ON f.id = i.fonte_id WHERE f.cliente_id = %s AND f.tipo = 'manual'",
                                (a["id"],)).fetchone()[0] == 1)
    registrar("a caça mostra que já é vigiado", next(i["vigiado"] for i in http.post("/api/inteligencia/cacar", json={"texto": "185.220.101.4"}).json()["indicadores"]))
    manual = next(f for f in http.get("/api/inteligencia").json()["fontes"] if f["tipo"] == "manual")
    registrar("a Lista manual aparece nas fontes e não sincroniza", manual["indicadores"] == 1
              and http.post(f"/api/inteligencia/fontes/{manual['id']}/sincronizar").status_code == 404)
    http.post("/api/sair")
    http.cookies.clear()


def testar_casos(http, a, b):
    print("\n== Casos", flush=True)
    entrar(http, a)
    registrar("caso sem título é recusado", http.post("/api/casos", json={"titulo": " ", "severidade": "alta"}).status_code == 422)
    registrar("caso com item de outra organização é recusado",
              http.post("/api/casos", json={"titulo": "x", "severidade": "alta", "itens": [{"tipo": "grupo", "id": b["grupo"]}]}).status_code == 404)
    criado = http.post("/api/casos", json={"titulo": "Força bruta no servidor", "severidade": "alta", "nota": "começando",
                                           "itens": [{"tipo": "grupo", "id": a["grupo"]}, {"tipo": "risco", "id": a["alerta"]}]})
    registrar("caso é criado com itens e nota", criado.status_code == 201, criado.text[:160])
    caso = criado.json()["id"]
    detalhe = http.get(f"/api/casos/{caso}").json()
    registrar("caso traz os itens, a nota e o prazo da severidade",
              sorted(i["tipo"] for i in detalhe["itens"]) == ["grupo", "risco"] and detalhe["notas"][0]["texto"] == "começando"
              and 23.9 < (datetime.fromisoformat(detalhe["caso"]["prazo"]) - datetime.fromisoformat(detalhe["caso"]["criado_em"])).total_seconds() / 3600 < 24.1)
    registrar("a Fila sabe em que caso o alerta está",
              [c["id"] for c in http.get("/api/casos/do-item", params={"tipo": "grupo", "id": a["grupo"]}).json()["casos"]] == [caso])
    eu = next(r for r in detalhe["responsaveis"] if r["nome"] == "Analista a")
    registrar("responsável que não pode triar é recusado", http.patch(f"/api/casos/{caso}", json={"responsavel_id": str(uuid.uuid4())}).status_code == 422)
    r = http.patch(f"/api/casos/{caso}", json={"responsavel_id": eu["id"], "estado": "investigando", "severidade": "critica"})
    registrar("caso muda de responsável, estado e severidade", r.status_code == 204, r.text[:160])
    detalhe = http.get(f"/api/casos/{caso}").json()
    registrar("a severidade nova muda o prazo", 3.9 < (datetime.fromisoformat(detalhe["caso"]["prazo"])
                                                       - datetime.fromisoformat(detalhe["caso"]["criado_em"])).total_seconds() / 3600 < 4.1)
    registrar("cada mudança vira nota automática", sum(n["automatica"] for n in detalhe["notas"]) == 3, str(detalhe["notas"]))
    registrar("encerrar sem desfecho é recusado", http.patch(f"/api/casos/{caso}", json={"estado": "encerrado"}).status_code == 422)
    registrar("evento entra e sai do caso", http.post(f"/api/casos/{caso}/itens", json={"tipo": "evento", "id": ADMIN.execute(
        "SELECT id FROM eventos WHERE cliente_id = %s LIMIT 1", (a["id"],)).fetchone()[0]}).status_code == 204
              and len(http.get(f"/api/casos/{caso}").json()["itens"]) == 3
              and http.request("DELETE", f"/api/casos/{caso}/itens/risco/{a['alerta']}").status_code == 204)
    registrar("nota vazia é recusada", http.post(f"/api/casos/{caso}/notas", json={"texto": "  "}).status_code == 422)
    registrar("nota entra no histórico", http.post(f"/api/casos/{caso}/notas", json={"texto": "bloqueei o IP"}).status_code == 201)
    registrar("caso encerra com desfecho", http.patch(f"/api/casos/{caso}", json={"estado": "encerrado", "desfecho": "incidente"}).status_code == 204)
    registrar("caso encerrado sai dos abertos e vai para os encerrados",
              caso not in [c["id"] for c in http.get("/api/casos").json()["casos"]]
              and caso in [c["id"] for c in http.get("/api/casos", params={"estado": "encerrados"}).json()["casos"]])
    registrar("criar e mudar caso ficam na auditoria", ADMIN.execute(
        "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao IN ('criar_caso', 'alterar_caso')", (a["id"],)).fetchone()[0] == 3)
    http.post("/api/sair")
    http.cookies.clear()
    entrar(http, b)
    registrar("outra organização não vê o caso", http.get(f"/api/casos/{caso}").status_code == 404
              and http.post(f"/api/casos/{caso}/notas", json={"texto": "x"}).status_code == 404)
    http.post("/api/sair")
    http.cookies.clear()


def testar_triagem(http, a):
    print("\n== Triagem do risco e silêncios", flush=True)
    entrar(http, a)
    entidade = ADMIN.execute("SELECT entidade_id FROM alertas_risco WHERE id = %s", (a["alerta"],)).fetchone()[0]

    ADMIN.execute("INSERT INTO horas (cliente_id, entidade_id, hora, contagem) VALUES (%s, %s, 9, 40), (%s, %s, 14, 10)",
                  (a["id"], entidade, a["id"], entidade))
    ADMIN.execute("INSERT INTO vistos (cliente_id, entidade_id, dimensao, valor, primeira_vez, contagem) VALUES"
                  " (%s, %s, 'ip', '10.9.9.9', now(), 7), (%s, %s, 'privilegio', %s, now(), 2)",
                  (a["id"], entidade, a["id"], entidade, f"{a['ger']}:001:root"))
    normal = http.get(f"/api/entidades/{entidade}/normal").json()
    registrar("o normal traz as 24 horas e marca as incomuns", len(normal["horas"]) == 24 and normal["horario_conhecido"]
              and normal["horas"][3]["incomum"] and not normal["horas"][9]["incomum"] and normal["total_de_acessos"] == 50)
    registrar("o normal traz os IPs e privilégios já vistos", normal["ips"][0]["contagem"] == 7 and normal["privilegios"][0]["como"] == "root",
              str(normal["privilegios"]))
    registrar("o normal de entidade de outro cliente não aparece", http.get(f"/api/entidades/{2**40}/normal").status_code == 404)
    outro = ADMIN.execute("SELECT id FROM eventos WHERE cliente_id <> %s ORDER BY id DESC LIMIT 1", (a["id"],)).fetchone()[0]
    registrar("evento de outra organização não sai em OCSF", http.get(f"/api/eventos/{outro}/ocsf").status_code == 404)
    registrar("silêncio de sinal desconhecido é recusado", http.post("/api/silencios", json={"tipo": "inventado", "motivo": "x"}).status_code == 422)
    registrar("silêncio sem motivo é recusado", http.post("/api/silencios", json={"tipo": "primeiro_ip", "motivo": ""}).status_code == 422)
    criado = http.post("/api/silencios", json={"tipo": "primeiro_ip", "entidade_id": entidade, "motivo": "plantão", "dias": 7})
    registrar("silêncio é criado", criado.status_code == 201, criado.text[:160])
    registrar("silêncio aparece no risco", [s["tipo"] for s in http.get(f"/api/riscos/{a['alerta']}").json()["silencios"]] == ["primeiro_ip"])
    registrar("silêncio aparece na lista", any(s["id"] == criado.json()["id"] for s in http.get("/api/silencios").json()["silencios"]))
    registrar("silêncio de entidade de outro cliente não é criado",
              http.post("/api/silencios", json={"tipo": "primeiro_ip", "entidade_id": 2**40, "motivo": "x"}).status_code == 404)
    registrar("silêncio sai", http.request("DELETE", f"/api/silencios/{criado.json()['id']}").status_code == 204)
    registrar("silêncio que não existe não sai", http.request("DELETE", f"/api/silencios/{criado.json()['id']}").status_code == 404)

    registrar("motivo desconhecido é recusado", http.post(f"/api/riscos/{a['alerta']}/decisao", json={"motivo": "sei_la"}).status_code == 422)
    r = http.post(f"/api/riscos/{a['alerta']}/decisao", json={"motivo": "esperado", "nota": "mudou de equipe"})
    registrar("analista encerra o risco", r.status_code == 204, r.text[:160])
    alerta = http.get(f"/api/riscos/{a['alerta']}").json()["alerta"]
    registrar("risco guarda o motivo, a nota e quem decidiu",
              (alerta["estado"], alerta["motivo"], alerta["nota"], alerta["decidido_por_nome"]) == ("encerrado", "esperado", "mudou de equipe", "Analista a"), str(alerta))
    entidade_depois = ADMIN.execute("SELECT risco, risco_desde IS NOT NULL FROM entidades WHERE id = %s", (entidade,)).fetchone()
    registrar("o risco da pessoa zera", entidade_depois == (0.0, True), str(entidade_depois))
    registrar("o esperado vira normal para a pessoa",
              ADMIN.execute("SELECT count(*) FROM vistos WHERE entidade_id = %s AND dimensao = 'host' AND valor = 'h'", (entidade,)).fetchone()[0] == 1)
    registrar("risco encerrado não é encerrado de novo", http.post(f"/api/riscos/{a['alerta']}/decisao", json={"motivo": "resolvido"}).status_code == 409)
    registrar("risco encerrado sai da fila", a["alerta"] not in [x["id"] for x in http.get("/api/fila").json()["riscos"]])
    registrar("decisão fica na auditoria", ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'decidir_risco'",
                                                         (a["id"],)).fetchone()[0] == 1)
    http.post("/api/sair")
    http.cookies.clear()


def testar_ofuscacao(http, a):
    print("\n== Dado pessoal mascarado", flush=True)
    senha = secrets.token_urlsafe(18)
    n1 = {"email": f"n1-{uuid.uuid4().hex[:8]}@exemplo.test", "senha": senha}
    ADMIN.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil) VALUES (%s, %s, 'Analista N1', %s, 'analista_n1')",
                  (a["id"], n1["email"], PasswordHasher().hash(senha)))
    evento = ADMIN.execute("SELECT id FROM eventos WHERE cliente_id = %s ORDER BY id LIMIT 1", (a["id"],)).fetchone()[0]
    ADMIN.execute("UPDATE eventos SET bruto = bruto || %s WHERE id = %s",
                  (Jsonb({"full_log": "login de fulano@exemplo.com.br, cpf 529.982.247-25", "data": {"srcuser": "fulano", "srcip": "203.0.113.5"}}), evento))
    entrar(http, n1)
    exportado = http.get("/api/eventos/ocsf", params={"dias": 30}).text
    registrar("N1 recebe a exportação em OCSF mascarada", "203.0.113.5" not in exportado and '"fulano"' not in exportado and "203.0.x.x" in exportado, exportado[:200])
    eu = http.get("/api/eu").json()
    registrar("N1 sabe que vê mascarado", eu["dados_mascarados"] is True and "usuario" in eu["ofuscar"])
    linha = next((e for e in http.get("/api/eventos").json()["eventos"] if e["id"] == evento), {})
    registrar("N1 vê o IP mascarado na lista", linha.get("ip_origem") == "203.0.x.x", str(linha)[:160])
    registrar("N1 vê o usuário como apelido", str(linha.get("usuario", "")).startswith("usuario-"))
    bruto = http.get(f"/api/eventos/{evento}/bruto").text
    registrar("N1 não vê CPF, e-mail nem usuário no bruto", "529.982.247-25" not in bruto and "fulano@" not in bruto and '"fulano"' not in bruto, bruto[:200])
    fila = http.get("/api/fila").json()
    registrar("N1 vê a entidade do risco como apelido", all(r["entidade"].startswith("usuario-") for r in fila["riscos"]), str(fila["riscos"])[:160])
    registrar("N1 não gera pacote de evidência", http.post("/api/integridade/evidencia", json={"fonte": "alertas", "ids": ["e1"]}).status_code == 403)
    registrar("N1 não muda o que é mascarado", http.request("PUT", "/api/organizacao/ofuscacao", json={"categorias": []}).status_code == 403)
    http.post("/api/sair")
    http.cookies.clear()

    entrar(http, a)
    registrar("administrador vê o original", "529.982.247-25" in http.get(f"/api/eventos/{evento}/bruto").text)
    um_evento = http.get(f"/api/eventos/{evento}/ocsf").json()
    registrar("evento em OCSF pela API", (um_evento["metadata"]["version"], um_evento["metadata"]["uid"], um_evento["src_endpoint"]["ip"])
              == ("1.3.0", str(evento), "203.0.113.5") and "bruto" not in um_evento and "raw_data" not in um_evento, str(um_evento)[:200])
    resposta = http.get("/api/eventos/ocsf", params={"dias": 30})
    linhas = [json.loads(l) for l in resposta.text.splitlines()]
    total = ADMIN.execute("SELECT count(*) FROM eventos WHERE cliente_id = %s AND ocorrido_em >= now() - interval '30 days'", (a["id"],)).fetchone()[0]
    registrar("exportação traz uma linha de OCSF por evento do filtro", resposta.headers["content-type"].startswith("application/x-ndjson")
              and len(linhas) == total == int(resposta.headers["x-eventos"]) and all(l["metadata"]["product"]["name"] == "Panthera Roar" for l in linhas))
    registrar("exportação respeita o filtro", http.get("/api/eventos/ocsf", params={"dias": 30, "regra": "nenhuma"}).text == "")
    registrar("categoria desconhecida é recusada", http.request("PUT", "/api/organizacao/ofuscacao", json={"categorias": ["senha"]}).status_code == 422)
    registrar("administrador desliga o IP", http.request("PUT", "/api/organizacao/ofuscacao", json={"categorias": ["usuario", "cpf"]}).status_code == 204)
    http.post("/api/sair")
    http.cookies.clear()

    entrar(http, n1)
    bruto = http.get(f"/api/eventos/{evento}/bruto").json()
    registrar("depois de desligar, N1 vê o IP", bruto["bruto"]["data"]["srcip"] == "203.0.113.5", str(bruto["bruto"].get("data")))
    registrar("o que continua ligado segue mascarado", bruto["bruto"]["data"]["srcuser"].startswith("usuario-") and "529.982.247-25" not in json.dumps(bruto))
    trilha = ADMIN.execute("SELECT alvo FROM auditoria WHERE cliente_id = %s AND acao = 'definir_ofuscacao'", (a["id"],)).fetchall()
    registrar("mudança fica na auditoria", trilha == [("cpf,usuario",)], str(trilha))
    http.post("/api/sair")
    http.cookies.clear()
    ADMIN.execute("UPDATE clientes SET ofuscar = DEFAULT WHERE id = %s", (a["id"],))


def main():
    testar_mascara_sem_banco()
    a, b = novo_cliente("a"), novo_cliente("b")
    with TestClient(app, base_url="https://testserver") as http:
        print("\n== Sem sessão", flush=True)
        for rota in ("/api/eu", "/api/fila", f"/api/riscos/{a['alerta']}", f"/api/grupos/{a['grupo']}"):
            registrar(f"{rota.split('/')[2]} exige sessão", http.get(rota).status_code == 401)
        http.cookies.set(COOKIE, "token-inventado")
        registrar("token inventado não entra", http.get("/api/eu").status_code == 401)
        http.cookies.clear()

        print("\n== Login", flush=True)
        registrar("senha errada é recusada", http.post("/api/entrar", json={"email": a["email"], "senha": "x"}).status_code == 401)
        resposta_inexistente = http.post("/api/entrar", json={"email": "ninguem@exemplo.test", "senha": "x"})
        resposta_errada = http.post("/api/entrar", json={"email": a["email"], "senha": "y"})
        registrar("não revela se o e-mail existe", resposta_inexistente.status_code == resposta_errada.status_code
                  and resposta_inexistente.text == resposta_errada.text)
        registrar("injeção no e-mail não entra", http.post(
            "/api/entrar", json={"email": "' OR 1=1 --", "senha": "x"}).status_code == 401)
        falhas_de_login.clear()

        r = entrar(http, a)
        cabecalho = r.headers.get("set-cookie", "").lower()
        registrar("login certo entra", r.status_code == 204)
        registrar("cookie protegido", all(x in cabecalho for x in ("httponly", "samesite=strict", "secure")), cabecalho[:0])
        token = http.cookies.get(COOKIE)
        registrar("banco guarda só o hash do token",
                  ADMIN.execute("SELECT count(*) FROM sessoes WHERE token_hash = %s", (token,)).fetchone()[0] == 0
                  and ADMIN.execute("SELECT count(*) FROM sessoes WHERE token_hash = %s",
                                    (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0] == 1)
        registrar("sessão identifica o cliente", http.get("/api/eu").json()["cliente"].startswith("a-"))

        print("\n== Isolamento entre clientes", flush=True)
        fila = http.get("/api/fila").json()
        registrar("fila só tem riscos do cliente", [x["id"] for x in fila["riscos"]] == [a["alerta"]])
        registrar("fila só tem alertas do cliente", [x["id"] for x in fila["grupos"]] == [a["grupo"]])
        registrar("risco de outro cliente não é encontrado", http.get(f"/api/riscos/{b['alerta']}").status_code == 404)
        registrar("alerta de outro cliente não é encontrado", http.get(f"/api/grupos/{b['grupo']}").status_code == 404)
        registrar("o próprio risco abre", http.get(f"/api/riscos/{a['alerta']}").status_code == 200)
        registrar("o próprio alerta abre", http.get(f"/api/grupos/{a['grupo']}").status_code == 200)
        registrar("cliente enviado na requisição é ignorado", [x["id"] for x in http.get(
            "/api/fila", params={"cliente": str(b["id"]), "cliente_id": str(b["id"])}).json()["riscos"]] == [a["alerta"]])

        print("\n== Panorama", flush=True)
        painel = http.get("/api/panorama", params={"dias": 7}).json()
        registrar("período tem um ponto por dia, mesmo sem dados", len(painel["por_dia"]) == 7)
        registrar("alerta de hoje entra no gráfico", sum(d["media"] for d in painel["por_dia"]) == 1, str(painel["por_dia"][-1]))
        registrar("gráfico de sinais tem os dados do cliente", painel["sinais"] == [{"tipo": "primeiro_host", "total": 1}])
        registrar("gráfico de origens sai sem máscara", painel["origens"] == [{"origem": "203.0.113.5", "total": 1}])
        registrar("gráfico de risco tem a entidade do cliente", [r["entidade"] for r in painel["riscos"]] == [XSS])
        registrar("período absurdo é contido", len(http.get("/api/panorama", params={"dias": 10**6}).json()["por_dia"]) == 90
                  and len(http.get("/api/panorama", params={"dias": -5}).json()["por_dia"]) == 1)
        registrar("panorama exige sessão", TestClient(app, base_url="https://testserver").get("/api/panorama").status_code == 401)
        fuso = ADMIN.execute("SELECT fuso FROM clientes WHERE id = %s", (a["id"],)).fetchone()[0]
        ADMIN.execute("UPDATE clientes SET fuso = 'Asia/Tokyo' WHERE id = %s", (a["id"],))
        dia_toquio = http.get("/api/panorama", params={"dias": 1}).json()["por_dia"][-1]["dia"]
        esperado = ADMIN.execute("SELECT (now() AT TIME ZONE 'Asia/Tokyo')::date::text").fetchone()[0]
        ADMIN.execute("UPDATE clientes SET fuso = %s WHERE id = %s", (fuso, a["id"]))
        registrar("dia segue o fuso do cliente", dia_toquio == esperado, dia_toquio)
        falhas_ruins = http.get("/api/panorama", params={"dias": "'; DROP TABLE eventos; --"})
        registrar("período com texto é recusado", falhas_ruins.status_code == 422)

        print("\n== Eventos e alerta bruto", flush=True)
        lista = http.get("/api/eventos").json()
        registrar("eventos só do cliente", len(lista["eventos"]) == 1 and lista["ha_mais"] is False)
        evento_a = lista["eventos"][0]["id"]
        registrar("lista de eventos não traz o bruto", "segredo_do_bruto" not in json.dumps(lista))
        registrar("busca encontra por IP", len(http.get("/api/eventos", params={"busca": "203.0.113.5"}).json()["eventos"]) == 1)
        registrar("busca sem resultado", http.get("/api/eventos", params={"busca": "naoexiste"}).json()["eventos"] == [])
        registrar("curinga na busca é tratado como texto", http.get("/api/eventos", params={"busca": "%"}).json()["eventos"] == [])
        registrar("injeção na busca não quebra", http.get("/api/eventos", params={"busca": "'; DROP TABLE eventos; --"}).status_code == 200)
        registrar("severidade inválida é ignorada", http.get("/api/eventos", params={"severidade": "' OR 1=1"}).status_code == 200)
        registrar("filtro de severidade funciona", http.get("/api/eventos", params={"severidade": "alta"}).json()["eventos"] == [])
        antes = ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'ver_bruto' AND alvo = %s", (a["id"], str(evento_a))).fetchone()[0]
        bruto = http.get(f"/api/eventos/{evento_a}/bruto")
        registrar("bruto abre com o conteúdo original", bruto.status_code == 200 and bruto.json()["bruto"]["segredo_do_bruto"] == "nao-sair")
        depois = ADMIN.execute("SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'ver_bruto' AND alvo = %s",
                               (a["id"], str(evento_a))).fetchone()[0]
        registrar("ver o bruto fica registrado", depois == antes + 1)
        evento_b = ADMIN.execute("SELECT id FROM eventos WHERE cliente_id = %s LIMIT 1", (b["id"],)).fetchone()[0]
        registrar("bruto de outro cliente não é encontrado", http.get(f"/api/eventos/{evento_b}/bruto").status_code == 404)
        registrar("tentativa em outro cliente não vira registro nele", ADMIN.execute(
            "SELECT count(*) FROM auditoria WHERE cliente_id = %s", (b["id"],)).fetchone()[0] == 0)

        print("\n== Regras", flush=True)
        for cliente, regra, descricao, grupos, mitre in ((a, "5712", "Força bruta", ["authentication_failures"], ["T1110"]),
                                                         (a, "9999", "Regra sem disparo", ["outro"], []),
                                                         (b, "8888", "Regra só de B", ["segredo_b"], [])):
            ADMIN.execute("INSERT INTO regras (cliente_id, gerenciador_id, regra_id, nivel, descricao, grupos, mitre, arquivo)"
                          " VALUES (%s, %s, %s, 10, %s, %s, %s, 'x.xml')", (cliente["id"], cliente["ger"], regra, descricao, grupos, mitre))
        catalogo = http.get("/api/regras").json()
        registrar("regras só do cliente", {r["regra_id"] for r in catalogo["regras"]} == {"5712", "9999"})
        registrar("regra disparada vem primeiro com a contagem", catalogo["regras"][0]["regra_id"] == "5712" and catalogo["regras"][0]["disparos"] == 1)
        registrar("só as que dispararam", [r["regra_id"] for r in http.get("/api/regras", params={"so_disparadas": True}).json()["regras"]] == ["5712"])
        registrar("busca por técnica MITRE", [r["regra_id"] for r in http.get("/api/regras", params={"busca": "t1110"}).json()["regras"]] == ["5712"])
        registrar("busca não alcança regra de outro cliente", http.get("/api/regras", params={"busca": "segredo_b"}).json()["regras"] == [])
        sys.path.insert(0, str(RAIZ / "ueba"))
        from roar_ueba.motor import PESOS
        registrar("pesos da tela iguais aos do motor", {r["tipo"]: r["peso"] for r in catalogo["comportamento"]} == PESOS)
        from roar_ueba.motor import Parametros
        from roar_api import app as aplicacao
        p = Parametros()
        registrar("aprendizado e horário da tela iguais aos do motor",
                  (aplicacao.APRENDIZADO_DIAS, aplicacao.APRENDIZADO_SUCESSOS, aplicacao.HORARIO_MINIMO, aplicacao.HORARIO_PROBABILIDADE)
                  == (p.aprendizado_dias, p.aprendizado_sucessos, p.horario_minimo, p.horario_probabilidade))

        print("\n== Ativos, ataque e defesa, normas e arquivos", flush=True)
        for cliente, agente, nome in ((a, "001", "servidor-a"), (b, "001", "servidor-b")):
            ADMIN.execute("INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, estado, sca_nota) VALUES (%s, %s, %s, %s, 'active', 70)",
                          (cliente["id"], cliente["ger"], agente, nome))
        registrar("ativos só do cliente", [x["nome"] for x in http.get("/api/ativos").json()["ativos"]] == ["servidor-a"])
        # Dois gerenciadores da mesma organização numeram os agentes por conta própria.
        ADMIN.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES ('gersegundo', %s, 64000)", (a["id"],))
        ADMIN.execute("INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, estado) VALUES (%s, 'gersegundo', '001', 'servidor-a2', 'disconnected')", (a["id"],))
        lista = http.get("/api/ativos").json()["ativos"]
        registrar("mesmo número em dois gerenciadores se distingue", len({(x["gerenciador_id"], x["agente_id"]) for x in lista}) == 2)
        registrar("eventos de um agente não misturam gerenciadores", http.get("/api/eventos", params={"agente": "001", "gerenciador": "gersegundo"}).json()["eventos"] == [])
        ADMIN.execute("DELETE FROM ativos WHERE gerenciador_id = 'gersegundo'")
        ADMIN.execute("DELETE FROM gerenciadores WHERE id = 'gersegundo'")
        ADMIN.execute("UPDATE regras SET mitre = '{T1110}' WHERE cliente_id = %s AND regra_id = '5712'", (a["id"],))
        ADMIN.execute("UPDATE eventos SET mitre = '{T1110.001}', regra_grupos = '{syscheck}', bruto = bruto || %s WHERE cliente_id = %s",
                      (Jsonb({"rule": {"mitre": {"id": ["T1110.001"], "technique": ["Password Guessing"], "tactic": ["Credential Access"]},
                                       "gdpr": ["IV_32.2"], "pci_dss": "nao-e-lista"},
                              "syscheck": {"path": "/etc/passwd", "event": "modified"}}), a["id"]))
        ADMIN.execute("UPDATE eventos SET mitre = '{T9999}', bruto = bruto || %s WHERE cliente_id = %s",
                      (Jsonb({"rule": {"gdpr": ["SEGREDO_B"]}}), b["id"]))
        ADMIN.execute("INSERT INTO tecnicas_defesa (tecnica, defesa_id, defesa_nome, tatica_defesa) VALUES"
                      " ('T1110', 'D3-TESTE', 'Defesa de teste', 'Harden') ON CONFLICT DO NOTHING")
        criar_attack = ADMIN.execute("SELECT count(*) FROM tecnicas_attack").fetchone()[0] == 0
        if criar_attack:
            ADMIN.execute("INSERT INTO taticas_attack VALUES ('credential-access', 'Credential Access', 0)")
            ADMIN.execute("INSERT INTO tecnicas_attack VALUES ('T1110', 'Brute Force', '{credential-access}', NULL, NULL, 'teste'),"
                          " ('T1110.001', 'Password Guessing', '{credential-access}', 'T1110', NULL, 'teste'),"
                          " ('T9999', 'Tecnica de B', '{credential-access}', NULL, NULL, 'teste')")
        matriz = http.get("/api/mitre/matriz").json()
        linha = next((t for t in matriz["tecnicas"] if t["tecnica"] == "T1110"), {})
        registrar("matriz soma a subtécnica na técnica mãe", linha.get("observados") == 1, str(linha)[:120])
        registrar("regra do cliente conta como cobertura", linha.get("regras") == 1)
        registrar("matriz não traz subtécnica como coluna", not any("." in t["tecnica"] for t in matriz["tecnicas"]))
        registrar("evento de B não aparece na matriz de A", next((t["observados"] for t in matriz["tecnicas"] if t["tecnica"] == "T9999"), 0) == 0)
        detalhe = http.get("/api/mitre/tecnicas/T1110").json()
        registrar("regra que deu match aparece", [m["regra_id"] for m in detalhe["match"]] == ["5712"], str(detalhe["match"])[:160])
        registrar("regra que cobre sem disparar aparece separada", detalhe["cobertura"] == [])
        registrar("defesa D3FEND aparece na técnica", any(d["defesa_id"] == "D3-TESTE" for d in detalhe["defesas"]))
        sub = http.get("/api/mitre/tecnicas/T1110.001").json()
        registrar("subtécnica herda a defesa da técnica mãe", any(d["defesa_id"] == "D3-TESTE" for d in sub["defesas"]))
        registrar("match de B não aparece em A", http.get("/api/mitre/tecnicas/T9999").json().get("match", []) == [])
        registrar("técnica inválida não é encontrada", http.get("/api/mitre/tecnicas/DROP%20TABLE").status_code == 404)
        risco = http.get(f"/api/riscos/{a['alerta']}").json()
        tecnica = risco["sinais"][0]["tecnica"] or {}
        registrar("sinal leva a subtécnica do próprio evento", tecnica.get("codigo") == "T1110.001" and tecnica.get("nome") == "Password Guessing", str(tecnica))
        registrar("técnica do sinal vem com a tática", tecnica.get("tatica") == "Credential Access")
        registrar("risco traz o risco depois de cada sinal", risco["sinais"][0]["risco_depois"] == 15.0)
        registrar("campo mitre cru não sai na linha do tempo", "mitre" not in risco["sinais"][0])
        ADMIN.execute("DELETE FROM tecnicas_defesa WHERE defesa_id = 'D3-TESTE'")
        if criar_attack:
            ADMIN.execute("DELETE FROM tecnicas_attack WHERE versao = 'teste'")
            ADMIN.execute("DELETE FROM taticas_attack WHERE tatica = 'credential-access'")
        registrar("controle da norma só do cliente", [c["controle"] for c in http.get("/api/normas", params={"norma": "gdpr"}).json()["controles"]] == ["IV_32.2"])
        registrar("o controle da norma vem com o nome", next(c for c in http.get("/api/normas", params={"norma": "gdpr"}).json()["controles"]
                                                            if c["controle"] == "IV_32.2")["nome"].startswith("Art. 32(2)"))
        lgpd = http.get("/api/normas").json()
        art46 = next((c for c in lgpd["controles"] if c["controle"] == "Art. 46"), {})
        registrar("a LGPD é a norma padrão e sai do GDPR", lgpd["norma"] == "lgpd" and lgpd["derivada_de"] == "GDPR" and lgpd["chave"] == "gdpr"
                  and art46.get("origens") == ["IV_32.2"] and art46.get("nome", "").startswith("Medidas de segurança"), str(art46))
        from roar_api.normas import CATALOGO, nome_do_controle
        registrar("controle sem nome próprio leva o do nível acima", (nome_do_controle("hipaa", "164.310.d"), nome_do_controle("nist_800_53", "RA.5"),
                  nome_do_controle("tsc", "cc6.8"), nome_do_controle("gpg13", "4.12")) == ("Salvaguardas físicas", "Avaliação de risco",
                  "Impedir ou detectar software não autorizado ou malicioso", "Estado de estações, servidores e dispositivos"))
        registrar("as duas grafias do HIPAA dão no mesmo controle", nome_do_controle("hipaa", "164.312.a.2.I") == nome_do_controle("hipaa", "164.312(a)(2)(i)")
                  == "Identificação única de cada usuário" and nome_do_controle("hipaa", "164.308(a)(3)(ii)(A)").startswith("Autorizar"))
        sem_nome = [(n, c) for n, c in ADMIN.execute(
            "SELECT DISTINCT n, c FROM regras, jsonb_object_keys(normas) n, jsonb_array_elements_text(normas -> n) c WHERE n = ANY(%s)", (list(CATALOGO),)).fetchall()
            if nome_do_controle(n, c) is None]
        registrar("todo controle das regras tem nome", not sem_nome, str(sem_nome[:10]))
        registrar("campo de norma fora do formato não quebra", http.get("/api/normas", params={"norma": "pci_dss"}).json()["controles"] == [])
        registrar("norma desconhecida é recusada", http.get("/api/normas", params={"norma": "'; DROP TABLE eventos; --"}).status_code == 422)
        registrar("mudança em arquivo aparece", http.get("/api/arquivos").json()["arquivos"][0]["caminho"] == "/etc/passwd")
        registrar("busca de arquivo funciona", http.get("/api/arquivos", params={"busca": "nao-existe"}).json()["arquivos"] == [])

        print("\n== Abrir e criar regras", flush=True)
        ADMIN.execute("UPDATE regras SET detalhes = %s, normas = %s WHERE cliente_id = %s AND regra_id = '5712'",
                      (Jsonb({"frequency": "8", "if_matched_sid": "5710"}), Jsonb({"gdpr": ["IV_32.2"]}), a["id"]))
        aberta = http.get("/api/regras/5712").json()
        registrar("regra abre com as condições", aberta["regra"]["detalhes"]["frequency"] == "8")
        registrar("regra mostra os disparos", aberta["disparos"]["total"] == 1 and len(aberta["recentes"]) == 1)
        registrar("detalhe da regra não traz o bruto", "segredo_do_bruto" not in json.dumps(aberta))
        registrar("regra de outro cliente não abre", http.get("/api/regras/8888").status_code == 404)
        registrar("número de regra inválido não abre", http.get("/api/regras/1%20OR%201=1").status_code == 404)

        guiada = {"formato": "guiada", "titulo": "Programa suspeito <b>", "origem": "windows_processo", "nivel": "high",
                  "tecnicas": ["T1059.001"], "condicoes": [{"campo": "Image", "operador": "termina", "valor": "\\mal.exe"},
                                                           {"campo": "CommandLine", "operador": "contem", "valor": "-enc"}]}
        previa = http.post("/api/regras/converter", json=guiada)
        registrar("prévia da regra guiada funciona", previa.status_code == 200 and "win.eventdata.image" in previa.json()["xml"], previa.text[:160])
        registrar("prévia não cria nada", ADMIN.execute("SELECT count(*) FROM regras_proprias WHERE cliente_id = %s", (a["id"],)).fetchone()[0] == 0)
        registrar("técnica entra na regra guiada", "T1059.001" in previa.json()["xml"])
        registrar("título hostil não vira marcação", "<b>" not in previa.json()["xml"])
        registrar("campo fora da lista é recusado", http.post("/api/regras/converter", json=dict(
            guiada, condicoes=[{"campo": "Inventado", "operador": "igual", "valor": "x"}])).status_code == 422)
        registrar("condição vazia é recusada", http.post("/api/regras/converter", json=dict(guiada, condicoes=[])).status_code == 422)
        registrar("regra sem valor é recusada", http.post("/api/regras/converter", json=dict(
            guiada, condicoes=[{"campo": "Image", "operador": "igual", "valor": " "}])).status_code == 422)
        registrar("origem desconhecida é recusada", http.post("/api/regras/converter", json=dict(guiada, origem="x")).status_code == 422)
        registrar("formato desconhecido é recusado", http.post("/api/regras/converter", json={"formato": "xml"}).status_code == 422)
        registrar("Sigma inválido é recusado com motivo", http.post(
            "/api/regras/converter", json={"formato": "sigma", "sigma": "isto: [nao e sigma"}).status_code == 422)
        sigma_cidr = ("title: t\nlogsource: {product: windows, service: security}\ndetection:\n  s: {IpAddress|cidr: 10.0.0.0/8}\n"
                      "  condition: s\nlevel: low\n")
        motivo = http.post("/api/regras/converter", json={"formato": "sigma", "sigma": sigma_cidr})
        registrar("o que não converte explica o motivo", motivo.status_code == 422 and "converter" in motivo.json()["detail"], motivo.text[:120])

        criada = http.post("/api/regras/proprias", json=guiada)
        registrar("regra é criada aguardando aplicação", criada.status_code == 201 and criada.json()["estado"] == "pendente")
        registrar("criação fica registrada", ADMIN.execute(
            "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'criar_regra'", (a["id"],)).fetchone()[0] == 1)
        proprias = http.get("/api/regras/proprias").json()["regras"]
        registrar("regra aparece na lista", [x["id"] for x in proprias] == [criada.json()["id"]])
        id_a = criada.json()["id"]
        http.post("/api/sair"); http.cookies.clear(); entrar(http, b)
        registrar("outro cliente não vê a regra", http.get("/api/regras/proprias").json()["regras"] == [])
        registrar("outro cliente não desativa a regra", http.post(f"/api/regras/proprias/{id_a}/desativar").status_code == 404)
        http.post("/api/sair"); http.cookies.clear(); entrar(http, a)
        registrar("o dono desativa a regra", http.post(f"/api/regras/proprias/{id_a}/desativar").status_code == 204
                  and http.get("/api/regras/proprias").json()["regras"][0]["estado"] == "desativada")

        print("\n== Regras à mão, importação, biblioteca e exportação", flush=True)
        manual = '<group name="teste,"><rule id="100001" level="10"><if_sid>5710</if_sid><description>Regra manual</description></rule></group>'
        registrar("XML à mão converte", http.post("/api/regras/converter", json={"formato": "xml", "xml": manual}).status_code == 200)
        registrar("XML à mão é criado", http.post("/api/regras/proprias", json={"formato": "xml", "xml": manual}).status_code == 201)
        for nome, ruim in (("XML quebrado", "<group><rule"), ("DOCTYPE", '<!DOCTYPE x [<!ENTITY a "b">]>' + manual),
                           ("substituir regra existente", manual.replace('level="10"', 'level="10" overwrite="yes"')),
                           ("sem nível", manual.replace(' level="10"', "")), ("sem descrição", manual.replace("<description>Regra manual</description>", ""))):
            registrar(f"XML recusado: {nome}", http.post("/api/regras/converter", json={"formato": "xml", "xml": ruim}).status_code == 422)

        boa = "title: Boa\nlogsource: {product: linux, service: syslog}\ndetection:\n  s: ['texto']\n  condition: s\nlevel: low\n"
        ruim = "title: Ruim\nlogsource: {product: windows, service: security}\ndetection:\n  s: {IpAddress|cidr: 10.0.0.0/8}\n  condition: s\nlevel: low\n"
        relatorio = http.post("/api/regras/importar", json={"formato": "sigma", "conteudo": boa + "---\n" + ruim}).json()
        registrar("importação separa o que entrou e o que não entrou", relatorio["criadas"] == ["Boa"] and relatorio["recusadas"][0]["titulo"] == "Ruim", str(relatorio)[:200])
        registrar("importação fica registrada", ADMIN.execute(
            "SELECT count(*) FROM auditoria WHERE cliente_id = %s AND acao = 'importar_regras'", (a["id"],)).fetchone()[0] == 1)
        registrar("XML ruim na importação vai para o relatório", http.post("/api/regras/importar", json={"formato": "xml", "conteudo": "<rule"}).json()["recusadas"] != [])

        identificador = "0b4a4a2e-2222-4c1c-9d2e-" + uuid.uuid4().hex[:12]
        ADMIN.execute("INSERT INTO biblioteca_regras (id, titulo, autor, conteudo, convertivel, versao) VALUES (%s, 'Regra pública', 'Autora', %s, true, 'teste')",
                      (identificador, boa.replace("Boa", "Publica").replace("level: low", "author: Autora\nlevel: low")))
        lista = http.get("/api/regras/biblioteca", params={"busca": "Regra pública"}).json()
        registrar("biblioteca mostra a autoria", lista["regras"][0]["autor"] == "Autora")
        registrar("regra da biblioteca é ativada", http.post(f"/api/regras/biblioteca/{identificador}/ativar").status_code == 201)
        registrar("ativar de novo avisa que já está ativa", http.post(f"/api/regras/biblioteca/{identificador}/ativar").status_code == 409)
        registrar("id inválido na biblioteca", http.post("/api/regras/biblioteca/zzz/ativar").status_code == 404)
        ADMIN.execute("DELETE FROM biblioteca_regras WHERE id = %s", (identificador,))
        previa_autor = http.post("/api/regras/converter", json={"formato": "sigma", "sigma": boa.replace("level: low", "author: Autora\nlevel: low")}).json()
        registrar("autoria vai para o alerta, como a licença pede", "autoria: Autora" in previa_autor["xml"])

        exportado = http.get("/api/regras/exportar")
        registrar("exportação baixa as regras do cliente", "attachment" in exportado.headers.get("content-disposition", "") and "Regra manual" in exportado.text)

        ADMIN.execute("INSERT INTO arquivos_de_regras (arquivo, conteudo) VALUES ('teste_roar.xml', %s) ON CONFLICT (arquivo) DO UPDATE SET conteudo = EXCLUDED.conteudo",
                      ('<group name="g,"><rule id="5712" level="10"><description>Original</description></rule></group>',))
        ADMIN.execute("UPDATE regras SET arquivo = 'teste_roar.xml' WHERE cliente_id = %s AND regra_id = '5712'", (a["id"],))
        registrar("regra abre com o XML original", "Original" in (http.get("/api/regras/5712").json()["xml"] or ""))
        registrar("arquivo do Wazuh é exportado", "Original" in http.get("/api/regras/arquivos/teste_roar.xml").text)
        registrar("caminho malicioso no arquivo é recusado", http.get("/api/regras/arquivos/..%2F..%2Fetc%2Fpasswd").status_code == 404)
        ADMIN.execute("DELETE FROM arquivos_de_regras WHERE arquivo = 'teste_roar.xml'")

        print("\n== Entradas e saídas", flush=True)
        registrar("id gigante não vira erro", http.get(f"/api/riscos/{2**70}").status_code == 404)
        registrar("id negativo não vira erro", http.get("/api/grupos/-1").status_code == 404)
        registrar("id com texto é recusado", http.get("/api/riscos/1%20OR%201=1").status_code == 422)
        registrar("limite absurdo é contido", http.get("/api/fila", params={"limite": 10**9}).status_code == 200)
        registrar("IP sai sem máscara de rede", http.get(f"/api/grupos/{a['grupo']}").json()["eventos"][0]["ip_origem"] == "203.0.113.5")
        agora = datetime.now(timezone.utc)
        ADMIN.execute(
            "INSERT INTO grupos_alerta (cliente_id, chave, dia, gerenciador_id, agente_id, nivel, severidade, regras,"
            " primeira_em, ultima_em) VALUES (%s, 'normal', %s, %s, '001', 3, 'baixa', '{5715}', %s, %s)",
            (a["id"], agora.date(), a["ger"], agora, agora))
        registrar("login normal não polui a fila", len(http.get("/api/fila").json()["grupos"]) == 1)
        tudo = "".join(http.get(r).text for r in ("/api/fila", f"/api/riscos/{a['alerta']}", f"/api/grupos/{a['grupo']}"))
        registrar("alerta bruto não sai pela API", "segredo_do_bruto" not in tudo)
        registrar("texto hostil sai só como dado JSON", json.loads(http.get(f"/api/riscos/{a['alerta']}").text)["alerta"]["entidade"] == XSS)
        registrar("resposta da API não fica em cache", http.get("/api/fila").headers.get("cache-control") == "no-store")
        registrar("rotas de documentação estão fechadas", http.get("/docs").status_code == 404 and http.get("/openapi.json").status_code == 404)

        print("\n== Tela", flush=True)
        inicio = http.get("/")
        politica = inicio.headers.get("content-security-policy", "")
        registrar("tela abre", inicio.status_code == 200 and "Panthera" in inicio.text)
        registrar("política de conteúdo bloqueia script de fora", "default-src 'self'" in politica and "unsafe" not in politica)
        registrar("tela não pode ser embutida", "frame-ancestors 'none'" in politica)
        registrar("endereço da tela devolve a mesma página", http.get("/fila").status_code == 200 and "Panthera" in http.get("/fila").text)
        registrar("rota de API desconhecida continua 404", http.get("/api/nao-existe").status_code == 404)
        antigo = http.get("/novo/ajuda/mfa", follow_redirects=False)
        registrar("endereço antigo leva ao novo", antigo.status_code in (302, 307) and antigo.headers["location"] == "/ajuda/mfa")
        registrar("endereço antigo não redireciona para fora", http.get("/novo//atacante.example", follow_redirects=False).headers["location"] == "/")
        registrar("a console antiga saiu", not (ESTATICO / "roar.js").exists() and not (ESTATICO / "index.html").exists())
        js = "".join(p.read_text(encoding="utf-8") for p in (RAIZ / "web/src").rglob("*.ts*"))
        registrar("tela nunca monta HTML com dado", not any(x in js for x in
                  ("dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(")))
        html = (ESTATICO / "console/index.html").read_text(encoding="utf-8")
        registrar("nenhum script embutido na página", "<script>" not in html and " onclick=" not in html)
        registrar("nenhum recurso externo", "http://" not in html and "https://" not in html and not re.search(r"""(?:fetch|import)\(\s*["'`]https?:""", js))
        texto = html + js
        registrar("tela não cita ferramentas", not any(x in texto.lower() for x in ("wazuh", "shuffle", "temporal", "opensearch")))

        print("\n== Requisição de outro site", flush=True)
        r = http.post("/api/sair", headers={"Origin": "https://atacante.example"})
        registrar("outro site não encerra a sessão", r.status_code == 403 and http.get("/api/eu").status_code == 200)

        print("\n== Fim da sessão", flush=True)
        antigo = http.cookies.get(COOKIE)
        registrar("sair responde", http.post("/api/sair").status_code == 204)
        http.cookies.set(COOKIE, antigo)
        registrar("token antigo não vale depois de sair", http.get("/api/eu").status_code == 401)
        http.cookies.clear()

        entrar(http, b)
        ADMIN.execute("UPDATE sessoes SET expira_em = now() - interval '1 minute' WHERE token_hash = %s",
                      (hashlib.sha256(http.cookies.get(COOKIE).encode()).hexdigest(),))
        registrar("sessão expirada não vale", http.get("/api/eu").status_code == 401)
        http.cookies.clear()
        entrar(http, b)
        ADMIN.execute("UPDATE usuarios SET ativo = false WHERE cliente_id = %s", (b["id"],))
        registrar("usuário desativado perde o acesso na hora", http.get("/api/eu").status_code == 401)
        registrar("usuário desativado não entra", entrar(http, b).status_code == 401)
        ADMIN.execute("UPDATE usuarios SET ativo = true WHERE cliente_id = %s", (b["id"],))
        http.cookies.clear()
        falhas_de_login.clear()

        testar_ofuscacao(http, a)
        falhas_de_login.clear()
        testar_triagem(http, a)
        falhas_de_login.clear()
        testar_casos(http, a, b)
        falhas_de_login.clear()
        testar_caca(http, a)
        falhas_de_login.clear()
        testar_chaves(http, a, b)
        falhas_de_login.clear()

        print("\n== Tentativas em série", flush=True)
        codigos = [http.post("/api/entrar", json={"email": a["email"], "senha": f"t{i}"}).status_code for i in range(6)]
        registrar("bloqueia depois de 5 tentativas", codigos == [401] * 5 + [429], str(codigos))
        registrar("nem a senha certa entra durante o bloqueio", entrar(http, a).status_code == 429)
        falhas_de_login.clear()

    print("\n== Papel da API no banco", flush=True)
    with psycopg.connect(URL_API, autocommit=True) as api:
        registrar("não lê usuários nem hashes", recusado(lambda: api.execute("SELECT senha_hash FROM usuarios")))
        registrar("não lê sessões", recusado(lambda: api.execute("SELECT * FROM sessoes")))
        registrar("não altera usuários", recusado(lambda: api.execute("UPDATE usuarios SET ativo = true")))
        registrar("não apaga a auditoria", recusado(lambda: api.execute("DELETE FROM auditoria")))
        registrar("não altera a auditoria", recusado(lambda: api.execute("UPDATE auditoria SET acao = 'x'")))
        registrar("não altera regras", recusado(lambda: api.execute("UPDATE regras SET nivel = 0")))
        registrar("não troca o próprio cliente pelo cadastro", recusado(lambda: api.execute("UPDATE clientes SET nome = 'x'")))

    testar_linha_do_tempo()
    testar_ocsf_sem_banco()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    try:
        codigo = main()
    finally:
        limpar()
    sys.exit(codigo)
