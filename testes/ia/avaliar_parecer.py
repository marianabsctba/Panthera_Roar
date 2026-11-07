#!/usr/bin/env python3
"""Mede o acerto do parecer da IA local num conjunto de casos montados, metade ataque e metade uso normal.

    /opt/panthera-roar/venv/bin/python testes/ia/avaliar_parecer.py [--casos nome1,nome2] [--saida arquivo.json]

Cada caso monta seus alertas, o risco das pessoas, os ativos e os fluxos de rede numa organização de teste, roda a
investigação (investigacao.py) e pede o parecer (parecer.py) do jeito que a tela pede. A resposta certa vem anotada:

- ataque: acerta com "ataque" ou "suspeito"; "benigno" é o pior erro (deixar passar um ataque);
- normal: acerta com "benigno"; "inconclusivo" não é erro, mas não ajuda; "ataque" é alarme falso.

Os casos ficam separados no tempo (três dias entre um e outro) e cada um tem seus endereços, contas e ativos, para a
janela de 24 horas da investigação de um não ver o outro. Apaga no final tudo o que criou.
"""

import argparse
import json
import secrets
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "motor"), str(RAIZ / "ingestao"), str(RAIZ / "ueba")]

from roar_api import investigacao, parecer  # noqa: E402
from roar_ingestao import armazem  # noqa: E402

ENV = dict(l.strip().split("=", 1) for l in open("/opt/panthera-roar/.env", encoding="utf-8") if "=" in l and not l.startswith("#"))
SUFIXO = uuid.uuid4().hex[:8]
AGORA = datetime.now(timezone.utc).replace(microsecond=0)
FALHA, SUCESSO = ["authentication_failed"], ["authentication_success"]

# Um evento: (minutos depois do começo do caso, regra, descrição, nível, grupos, agente, nome do agente, endereço, conta,
# é o alerta julgado, arquivo mexido). Os dois últimos são opcionais.
CASOS = [
    # ------------------------------------------------------------------ ataques
    {"nome": "forca_bruta_com_entrada_e_root", "esperado": "ataque",
     "pessoas": [("bruno", 70, [("10.1.0.5", 40, 200)])], "ativos": [("101", "srv-web", "critica")],
     "eventos": [*[(i, "5710", "sshd: login recusado", 5, FALHA, "101", "srv-web", "45.33.20.7", "bruno") for i in range(10)],
                 (11, "5712", "sshd: força bruta", 10, ["authentication_failures"], "101", "srv-web", "45.33.20.7", "bruno", True),
                 (15, "5715", "sshd: login com sucesso", 3, SUCESSO, "101", "srv-web", "45.33.20.7", "bruno"),
                 (18, "5402", "Virou root com sudo", 12, ["sudo"], "101", "srv-web", None, "bruno")],
     "sinais": [("bruno", "sucesso_apos_falhas", 70, 15, 11)]},
    {"nome": "forca_bruta_que_deu_certo", "esperado": "ataque",
     "pessoas": [("carla", 40, [("10.2.0.8", 60, 300)])], "ativos": [("102", "srv-vpn", "alta")],
     "eventos": [*[(i, "5710", "sshd: login recusado", 5, FALHA, "102", "srv-vpn", "103.44.8.9", "carla") for i in range(12)],
                 (13, "5712", "sshd: força bruta", 10, ["authentication_failures"], "102", "srv-vpn", "103.44.8.9", "carla", True),
                 (20, "5715", "sshd: login com sucesso", 3, SUCESSO, "102", "srv-vpn", "103.44.8.9", "carla")],
     "sinais": [("carla", "sucesso_apos_falhas", 40, 20, 13)]},
    {"nome": "pulverizacao_de_senhas", "esperado": "ataque",
     "pessoas": [], "ativos": [("103", "srv-ad", "critica")],
     "eventos": [*[(i, "60122", "Windows: logon recusado", 5, FALHA, "103", "srv-ad", "91.240.118.3", f"usuario{i}") for i in range(14)],
                 (15, "60204", "Windows: muitas falhas de logon de origens diferentes", 10, ["authentication_failures"], "103", "srv-ad", "91.240.118.3", "usuario14", True)]},
    {"nome": "endereco_novo_e_privilegio", "esperado": "ataque",
     "pessoas": [("diego", 65, [("10.3.0.4", 90, 500)])], "ativos": [("104", "srv-erp", "alta")],
     "eventos": [(0, "5715", "sshd: login com sucesso", 3, SUCESSO, "104", "srv-erp", "185.199.10.4", "diego"),
                 (4, "5402", "Virou root com sudo", 12, ["sudo"], "104", "srv-erp", "185.199.10.4", "diego", True),
                 (9, "550", "Integridade: arquivo do sistema alterado", 7, ["syscheck"], "104", "srv-erp", None, None)],
     "sinais": [("diego", "primeiro_ip", 25, 0, 0), ("diego", "primeiro_privilegio", 40, 4, 1)]},
    {"nome": "okta_mfa_negado_e_entrada", "esperado": "ataque",
     "pessoas": [("elisa", 55, [("189.40.10.2", 120, 800)])], "ativos": [],
     "eventos": [*[(i, "100933", "Okta: segundo fator negado", 7, FALHA, "000", "gerenciador", "45.155.205.9", "elisa") for i in range(6)],
                 (7, "100937", "Okta: muitas tentativas recusadas vindas do mesmo endereço", 10, ["authentication_failures"], "000", "gerenciador", "45.155.205.9", "elisa", True),
                 (9, "100931", "Okta: entrou", 3, SUCESSO, "000", "gerenciador", "45.155.205.9", "elisa")],
     "sinais": [("elisa", "sucesso_apos_falhas", 55, 9, 7)]},
    {"nome": "workspace_admin_apos_login_suspeito", "esperado": "ataque",
     "pessoas": [("fabio", 60, [("200.150.3.3", 200, 900)])], "ativos": [],
     "eventos": [(0, "100943", "Google Workspace: o Google apontou risco no login", 10, ["attack"], "000", "gerenciador", "5.188.62.11", "fabio"),
                 (6, "100945", "Google Workspace: mudança de administração (ASSIGN_ROLE)", 10, ["account_changed"], "000", "gerenciador", "5.188.62.11", "fabio", True),
                 (8, "100946", "Google Workspace: arquivo do Drive aberto para fora", 7, ["data_exfiltration"], "000", "gerenciador", "5.188.62.11", "fabio")],
     "sinais": [("fabio", "primeiro_ip", 25, 0, 0), ("fabio", "regra_disparada", 35, 6, 1)]},
    {"nome": "malware_com_varios_alertas_graves", "esperado": "ataque",
     "pessoas": [], "ativos": [("105", "estacao-rh", "normal")],
     "eventos": [(0, "92052", "Windows: PowerShell com comando codificado", 12, ["windows"], "105", "estacao-rh", None, None),
                 (3, "61138", "Windows: serviço novo instalado", 10, ["windows"], "105", "estacao-rh", None, None),
                 (5, "100200", "YARA: arquivo bateu com regra de ransomware", 13, ["yara"], "105", "estacao-rh", None, None, True),
                 (8, "87105", "Muitos arquivos alterados em pouco tempo", 12, ["syscheck"], "105", "estacao-rh", None, None)]},
    {"nome": "varredura_de_fora_em_ssh_e_rdp", "esperado": "ataque",
     "pessoas": [], "ativos": [("106", "srv-arquivos", "alta"), ("107", "srv-banco", "critica")],
     "eventos": [*[(i, "5710", "sshd: login recusado", 5, FALHA, a, n, "193.32.162.40", u) for i, (a, n, u) in
                   enumerate([("106", "srv-arquivos", "root"), ("107", "srv-banco", "admin"), ("106", "srv-arquivos", "oracle"), ("107", "srv-banco", "postgres")] * 3)],
                 (13, "5712", "sshd: força bruta", 10, ["authentication_failures"], "107", "srv-banco", "193.32.162.40", "admin", True)],
     "fluxos": [("193.32.162.40", "10.7.0.", 22, 60, 120), ("193.32.162.40", "10.7.0.", 3389, 60, 80)]},
    {"nome": "saida_grande_para_fora", "esperado": "ataque",
     "pessoas": [("gustavo", 45, [("10.8.0.15", 100, 700)])], "ativos": [("108", "estacao-financeiro", "alta")],
     "eventos": [(0, "550", "Integridade: arquivo sensível lido e copiado", 10, ["syscheck"], "108", "estacao-financeiro", "10.8.0.15", "gustavo", True),
                 (5, "100110", "Contato com endereço de indicador de ameaça", 12, ["ioc"], "108", "estacao-financeiro", "10.8.0.15", "gustavo")],
     "fluxos": [("10.8.0.15", "146.70.1.9", 443, 900_000_000, 40)],
     "sinais": [("gustavo", "ioc_tocado", 45, 5, 1)]},
    {"nome": "conta_criada_e_posta_em_admins", "esperado": "ataque",
     "pessoas": [("helena", 62, [("10.9.0.3", 150, 600)])], "ativos": [("109", "srv-dc", "critica")],
     "eventos": [(0, "60109", "Windows: conta criada", 8, ["adduser"], "109", "srv-dc", "10.9.0.77", "helena"),
                 (2, "60110", "Windows: conta posta no grupo Domain Admins", 12, ["account_changed"], "109", "srv-dc", "10.9.0.77", "helena", True)],
     "sinais": [("helena", "conta_criada", 30, 0, 0), ("helena", "grupo_administrativo", 32, 2, 1)]},
    {"nome": "viagem_impossivel", "esperado": "ataque",
     "pessoas": [("igor", 68, [("177.10.20.30", 300, 1200)])], "ativos": [("110", "srv-email", "alta")],
     "eventos": [(0, "5715", "Login com sucesso", 3, SUCESSO, "110", "srv-email", "177.10.20.30", "igor"),
                 (30, "5715", "Login com sucesso", 3, SUCESSO, "110", "srv-email", "36.110.50.2", "igor"),
                 (32, "100020", "Comportamento: viagem impossível", 10, ["ueba"], "110", "srv-email", "36.110.50.2", "igor", True)],
     "sinais": [("igor", "viagem_impossivel", 50, 30, 1), ("igor", "primeiro_ip", 18, 30, 1)]},
    {"nome": "movimento_lateral", "esperado": "ataque",
     "pessoas": [("julia", 72, [("10.11.0.4", 200, 900)])], "ativos": [("111", "srv-a", "alta"), ("112", "srv-b", "alta"), ("113", "srv-c", "critica")],
     "eventos": [(0, "5715", "Login com sucesso", 3, SUCESSO, "111", "srv-a", "10.11.0.99", "julia"),
                 (3, "5715", "Login com sucesso", 3, SUCESSO, "112", "srv-b", "10.11.0.99", "julia"),
                 (6, "5715", "Login com sucesso", 3, SUCESSO, "113", "srv-c", "10.11.0.99", "julia"),
                 (8, "5402", "Virou root com sudo", 12, ["sudo"], "113", "srv-c", "10.11.0.99", "julia", True)],
     "sinais": [("julia", "primeiro_host", 20, 3, 1), ("julia", "primeiro_host", 20, 6, 2), ("julia", "primeiro_privilegio", 32, 8, 3)]},
    {"nome": "ransomware_no_servidor_de_arquivos", "esperado": "ataque",
     "pessoas": [], "ativos": [("114", "srv-arquivos2", "critica")],
     "eventos": [(i // 13, "100300", "Possible ransomware activity", 12, ["syscheck"], "114", "srv-arquivos2", None, None, i == 39,
                  f"/srv/arquivos/financeiro/planilha-{i:02d}.xlsx.locked") for i in range(40)]},
    # ------------------------------------------------------------------ uso normal
    {"nome": "errou_a_senha_uma_vez", "esperado": "normal",
     "pessoas": [("karen", 0, [("10.20.0.9", 200, 900)])], "ativos": [("201", "estacao-karen", "normal")],
     "eventos": [(0, "5710", "Login recusado", 5, FALHA, "201", "estacao-karen", "10.20.0.9", "karen", True)]},
    {"nome": "errou_tres_vezes_e_entrou", "esperado": "normal",
     "pessoas": [("lucas", 3, [("10.21.0.4", 300, 1500)])], "ativos": [("202", "estacao-lucas", "normal")],
     "eventos": [(0, "5710", "Login recusado", 5, FALHA, "202", "estacao-lucas", "10.21.0.4", "lucas"),
                 (1, "5710", "Login recusado", 5, FALHA, "202", "estacao-lucas", "10.21.0.4", "lucas"),
                 (2, "5710", "Login recusado", 5, FALHA, "202", "estacao-lucas", "10.21.0.4", "lucas", True),
                 (3, "5715", "Login com sucesso", 3, SUCESSO, "202", "estacao-lucas", "10.21.0.4", "lucas")]},
    {"nome": "monitoramento_com_senha_vencida", "esperado": "normal",
     "pessoas": [("svc-zabbix", 0, [("10.22.0.50", 400, 50000)])], "ativos": [("203", "srv-banco-relatorio", "normal")],
     "eventos": [*[(i * 5, "5710", "Login recusado", 5, FALHA, "203", "srv-banco-relatorio", "10.22.0.50", "svc-zabbix") for i in range(6)],
                 (31, "5712", "Muitos logins recusados", 10, ["authentication_failures"], "203", "srv-banco-relatorio", "10.22.0.50", "svc-zabbix", True)]},
    {"nome": "admin_entrou_do_lugar_de_sempre", "esperado": "normal",
     "pessoas": [("marcos", 5, [("10.23.0.2", 500, 3000)])], "ativos": [("204", "srv-web2", "alta")],
     "eventos": [(0, "5715", "Login com sucesso", 3, SUCESSO, "204", "srv-web2", "10.23.0.2", "marcos"),
                 (2, "5402", "Virou root com sudo", 7, ["sudo"], "204", "srv-web2", "10.23.0.2", "marcos", True)]},
    {"nome": "okta_errou_o_codigo_uma_vez", "esperado": "normal",
     "pessoas": [("natalia", 0, [("189.40.11.5", 250, 1100)])], "ativos": [],
     "eventos": [(0, "100933", "Okta: segundo fator negado", 7, FALHA, "000", "gerenciador", "189.40.11.5", "natalia", True),
                 (2, "100931", "Okta: entrou", 3, SUCESSO, "000", "gerenciador", "189.40.11.5", "natalia")]},
    {"nome": "workspace_compartilhou_com_link", "esperado": "normal",
     "pessoas": [("otavio", 0, [("200.150.9.9", 365, 4000)])], "ativos": [],
     "eventos": [(0, "100941", "Google Workspace: entrou", 3, SUCESSO, "000", "gerenciador", "200.150.9.9", "otavio"),
                 (40, "100946", "Google Workspace: arquivo do Drive aberto para fora (people_with_link)", 7, ["data_exfiltration"], "000", "gerenciador", "200.150.9.9", "otavio", True)]},
    {"nome": "atualizacao_de_pacotes", "esperado": "normal",
     "pessoas": [], "ativos": [("205", "srv-app", "normal")],
     "eventos": [(0, "2902", "Pacote novo instalado", 7, ["dpkg"], "205", "srv-app", None, None, True),
                 (1, "2903", "Pacote atualizado", 3, ["dpkg"], "205", "srv-app", None, None)]},
    {"nome": "copia_noturna_para_nuvem", "esperado": "normal",
     "pessoas": [("svc-backup", 0, [("10.24.0.40", 700, 9000)])], "ativos": [("206", "srv-backup", "alta")],
     "eventos": [(0, "5715", "Login com sucesso", 3, SUCESSO, "206", "srv-backup", "10.24.0.40", "svc-backup", True)],
     "fluxos": [("10.24.0.40", "52.217.110.68", 443, 400_000_000, 8)]},
    {"nome": "varredura_interna_autorizada_sem_entrada", "esperado": "normal",
     "pessoas": [], "ativos": [("207", "srv-impressao", "baixa")],
     "eventos": [(0, "40111", "Varredura de portas detectada", 7, ["recon"], "207", "srv-impressao", "10.25.0.200", None, True)]},
    {"nome": "atualizacao_do_sistema_troca_arquivos", "esperado": "normal",
     "pessoas": [], "ativos": [("211", "srv-app2", "normal")],
     "eventos": [(0, "2902", "Pacote novo instalado: roar-portal 4.2.1", 7, ["dpkg"], "211", "srv-app2", None, None),
                 *[(1, "550", "Integridade: arquivo alterado", 7, ["syscheck"], "211", "srv-app2", None, None, i == 29,
                    f"/var/www/portal/assets/modulo-{i:02d}.js") for i in range(30)]]},
    {"nome": "uma_falha_de_fora_sem_mais_nada", "esperado": "normal",
     "pessoas": [], "ativos": [("208", "srv-site", "normal")],
     "eventos": [(0, "5710", "sshd: login recusado com usuário que não existe", 5, FALHA, "208", "srv-site", "64.62.197.10", "test", True)]},
    {"nome": "troca_de_senha_pelo_proprio", "esperado": "normal",
     "pessoas": [("paula", 2, [("10.26.0.7", 180, 800)])], "ativos": [("209", "estacao-paula", "normal")],
     "eventos": [(0, "5715", "Login com sucesso", 3, SUCESSO, "209", "estacao-paula", "10.26.0.7", "paula"),
                 (5, "5555", "Senha da conta trocada", 7, ["account_changed"], "209", "estacao-paula", "10.26.0.7", "paula", True)]},
    {"nome": "login_fora_do_horario_do_lugar_de_sempre", "esperado": "normal",
     "pessoas": [("rafael", 10, [("10.27.0.3", 400, 2000)])], "ativos": [("210", "srv-monitor", "normal")],
     "eventos": [(0, "5715", "Login com sucesso", 3, SUCESSO, "210", "srv-monitor", "10.27.0.3", "rafael"),
                 (1, "100021", "Comportamento: horário fora do padrão", 5, ["ueba"], "210", "srv-monitor", "10.27.0.3", "rafael", True)],
     "sinais": [("rafael", "horario_incomum", 10, 1, 1)]},
]


def montar(admin, armazem_admin, banco, cliente, gerenciador, k, caso):
    """Os alertas, as pessoas, os ativos e os fluxos de um caso, começando três dias antes do caso seguinte."""
    inicio = AGORA - timedelta(days=3 * (len(CASOS) - k), hours=2)
    ids = []
    for chave, risco, ips in caso.get("pessoas", []):
        e = admin.execute("""INSERT INTO entidades (cliente_id, tipo, chave, nome, primeira_vista, ultima_vista, risco, risco_em)
                             VALUES (%s, 'usuario', %s, %s, %s, %s, %s, %s) RETURNING id""",
                          (cliente, chave, chave, inicio - timedelta(days=800), inicio, risco, inicio)).fetchone()[0]
        for ip, dias, vezes in ips:
            admin.execute("INSERT INTO vistos (cliente_id, entidade_id, dimensao, valor, primeira_vez, contagem) VALUES (%s, %s, 'ip', %s, %s, %s)",
                          (cliente, e, ip, inicio - timedelta(days=dias), vezes))
    for agente, nome, criticidade in caso.get("ativos", []):
        admin.execute("INSERT INTO ativos (cliente_id, gerenciador_id, agente_id, nome, criticidade, sca_nota) VALUES (%s, %s, %s, %s, %s, 70)",
                      (cliente, gerenciador, agente, nome, criticidade))
    alvo = None
    for ev in caso["eventos"]:
        minutos, regra, descricao, nivel, grupos, agente, agente_nome, ip, usuario = ev[:9]
        severidade = "critica" if nivel >= 12 else "alta" if nivel >= 10 else "media" if nivel >= 7 else "baixa"
        i = admin.execute(
            """INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao, regra_grupos,
                                    gerenciador_id, agente_id, agente_nome, ip_origem, usuario, bruto)
               VALUES (%s, 'avaliacao', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (cliente, uuid.uuid4().hex, inicio + timedelta(minutes=minutos, seconds=len(ids)), nivel, severidade, regra, descricao, grupos, gerenciador, agente,
             agente_nome, ip, usuario, Jsonb({"rule": {"id": regra}, **({"syscheck": {"path": ev[10]}} if len(ev) > 10 else {})}))).fetchone()[0]
        ids.append(i)
        if len(ev) > 9 and ev[9]:
            alvo = i
    for chave, tipo, peso, minutos, n in caso.get("sinais", []):
        entidade = admin.execute("SELECT id FROM entidades WHERE cliente_id = %s AND chave = %s", (cliente, chave)).fetchone()[0]
        quando = inicio + timedelta(minutes=minutos)
        admin.execute("""INSERT INTO sinais (cliente_id, entidade_id, tipo, valor, dia, peso, ocorrido_em, evento_id, detalhes)
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '{}') ON CONFLICT DO NOTHING""",
                      (cliente, entidade, tipo, f"{tipo}-{minutos}", quando.date(), peso, quando, ids[n]))
    for origem, destino, porta, bytes_, n in caso.get("fluxos", []):
        momento = (inicio + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        # Destino terminado em ponto: uma máquina diferente da rede por fluxo.
        para = f"concat('{destino}', toString(10 + number % 40))" if destino.endswith(".") else f"'{destino}'"
        armazem_admin.executar(f"""INSERT INTO {banco}.fluxos (ocorrido_em, exportador, origem, destino, porta_origem, porta_destino, protocolo, bytes, pacotes)
                                   SELECT toDateTime64('{momento}', 3, 'UTC') + toIntervalSecond(number), '10.0.0.1', '{origem}', {para}, 40000 + number % 20000,
                                          {porta}, 'tcp', {bytes_ // n}, greatest(1, {bytes_ // n // 1200}) FROM numbers({n})""")
    return alvo


def acertou(esperado, veredito):
    if esperado == "ataque":
        return veredito in ("ataque", "suspeito")
    return veredito == "benigno"


def main():
    argumentos = argparse.ArgumentParser()
    argumentos.add_argument("--casos", default="")
    argumentos.add_argument("--saida", default="")
    opcoes = argumentos.parse_args()
    escolhidos = [c for c in CASOS if not opcoes.casos or c["nome"] in opcoes.casos.split(",")]
    ia = parecer.configuracao(ENV)
    if not ia:
        print("A IA local não está ligada (IA_MODELO no .env).")
        return 1
    admin = psycopg.connect(f"postgresql://roar_admin:{ENV['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    api = psycopg.connect(f"postgresql://roar_api:{ENV['ROAR_API_SENHA']}@127.0.0.1:5433/roar", autocommit=True)
    armazem_admin = armazem.admin(ENV)
    cliente = str(admin.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (f"avaliacao-ia-{SUFIXO}",)).fetchone()[0])
    gerenciador = f"aval{SUFIXO}"
    admin.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)", (gerenciador, cliente, 41000 + secrets.randbelow(19000)))
    banco = armazem.criar_organizacao(armazem_admin, cliente, 400, 400)
    leitor = armazem.leitor(ENV)
    resultados = []
    try:
        alvos = [(caso, montar(admin, armazem_admin, banco, cliente, gerenciador, CASOS.index(caso), caso)) for caso in escolhidos]
        api.row_factory = psycopg.rows.dict_row
        for caso, alvo in alvos:
            with api.transaction():
                api.execute("SELECT set_config('roar.cliente', %s, true)", (cliente,))
                pacote = investigacao.investigar(api, alvo, leitor, banco)
            inicio = time.monotonic()
            p = parecer.dar(pacote, *ia)
            certo = acertou(caso["esperado"], p["veredito"])
            resultados.append({"caso": caso["nome"], "esperado": caso["esperado"], "veredito": p["veredito"], "confianca": p["confianca"], "acertou": certo,
                               "segundos": round(time.monotonic() - inicio, 1), "motivos": len(p["motivos"]), "avisos": p["avisos"], "resumo": p["resumo"],
                               "agrava": sum(1 for x in pacote["perguntas"] if x["tom"] == "agrava"),
                               "passos": p["proximos_passos"], "passos_genericos": p.get("passos_genericos", 0)})
            print(f"{'ACERTOU' if certo else 'ERROU  '} {caso['nome']:<45} esperado {caso['esperado']:<6} → {p['veredito']:<12} ({p['confianca']}, "
                  f"{resultados[-1]['segundos']} s){' AVISO: ' + ' | '.join(p['avisos']) if p['avisos'] else ''}", flush=True)
    finally:
        armazem_admin.executar(f"DROP DATABASE IF EXISTS {banco}")
        for tabela in ("pareceres", "sinais", "vistos", "alertas_risco", "notificacoes", "pares", "eventos", "auditoria", "ativos", "horas", "falhas_por_hora",
                       "entidades", "ueba_cursor"):
            admin.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM gerenciadores WHERE cliente_id = %s", (cliente,))
        admin.execute("DELETE FROM clientes WHERE id = %s", (cliente,))

    ataques = [r for r in resultados if r["esperado"] == "ataque"]
    normais = [r for r in resultados if r["esperado"] == "normal"]
    deixou_passar = [r["caso"] for r in ataques if r["veredito"] == "benigno"]
    alarme_falso = [r["caso"] for r in normais if r["veredito"] in ("ataque", "suspeito")]
    inconclusivos = [r["caso"] for r in resultados if r["veredito"] == "inconclusivo"]
    resumo = {
        "modelo": ia[1], "quando": AGORA.isoformat(), "casos": len(resultados),
        "acertos": sum(r["acertou"] for r in resultados),
        "ataques_reconhecidos": f"{sum(r['acertou'] for r in ataques)} de {len(ataques)}",
        "normais_reconhecidos": f"{sum(r['acertou'] for r in normais)} de {len(normais)}",
        "ataques_deixados_passar": deixou_passar, "alarmes_falsos": alarme_falso, "inconclusivos": inconclusivos,
        "segundos_medios": round(sum(r["segundos"] for r in resultados) / max(1, len(resultados)), 1),
        "com_aviso": sum(1 for r in resultados if r["avisos"]),
        # O óbvio que a IA escreveu e o Roar tirou: quanto menor, menos a peneira precisou trabalhar.
        "passos_genericos_tirados": sum(r["passos_genericos"] for r in resultados),
        "passos_que_ficaram": sum(len(r["passos"]) for r in resultados),
    }
    print("\n" + json.dumps(resumo, ensure_ascii=False, indent=1))
    if opcoes.saida:
        Path(opcoes.saida).write_text(json.dumps({"resumo": resumo, "casos": resultados}, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
