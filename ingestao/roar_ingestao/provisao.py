"""Prepara o indexer e cria o gerenciador do Wazuh de cada cliente.

    python -m roar_ingestao.provisao preparar
    python -m roar_ingestao.provisao criar --nome acme
    python -m roar_ingestao.provisao remover --id <id>
"""

import argparse
import json
import os
import re
import secrets
import shutil
import stat
import string
import subprocess
import time
from pathlib import Path

import psycopg
import requests
import urllib3

from .ciclo import ler_env
from .fonte_wazuh import Indexer

DESTINO = Path("/opt/panthera-roar")
RAIZ = Path(__file__).resolve().parents[2]
WAZUH_VERSAO = "4.14.9"
IMAGEM = f"wazuh/wazuh-manager:{WAZUH_VERSAO}"
CERTIFICADOS = DESTINO / "wazuh/single-node/config/wazuh_indexer_ssl_certs"
CONF_BASE = DESTINO / "wazuh/single-node/config/wazuh_cluster/wazuh_manager.conf"
REDE = "panthera-roar-wazuh_default"
PREFIXO = "wazuh-alerts-4.x-"
PREFIXO_BRUTO = "wazuh-archives-4.x-"
PORTA_INICIAL = 21000
LEITOR = "roar_leitor"


def gerar(tamanho=32):
    alfabeto = string.ascii_letters + string.digits
    return "".join(secrets.choice(alfabeto) for _ in range(tamanho))


def senha_forte():
    # A API do Wazuh exige maiúscula, minúscula, número e símbolo.
    return gerar(28) + "Aa1.-"


def indice_do(gerenciador_id):
    return f"{PREFIXO}{gerenciador_id}-"


def indice_bruto_do(gerenciador_id):
    return f"{PREFIXO_BRUTO}{gerenciador_id}-"


def indexer_admin(env):
    return Indexer("https://127.0.0.1:9200", env["WAZUH_INDEXER_USERNAME"], env["WAZUH_INDEXER_PASSWORD"],
                   str(CERTIFICADOS / "root-ca.pem"))


def banco_admin(env):
    return psycopg.connect(f"postgresql://roar_admin:{env['BANCO_SENHA']}@127.0.0.1:5433/roar", autocommit=True)


def _na_imagem(*comando):
    r = subprocess.run(["docker", "run", "--rm", "--entrypoint", comando[0], IMAGEM, *comando[1:]],
                       check=True, capture_output=True, text=True)
    return r.stdout


def _pedir(indexer, metodo, rota, corpo=None):
    r = indexer.sessao.request(metodo, f"{indexer.url}/{rota}", json=corpo, timeout=60)
    if not r.ok:
        raise RuntimeError(f"{metodo} {rota} devolveu {r.status_code}: {r.text[:300]}")
    return r


def _esperar(indexer):
    for _ in range(90):
        try:
            if indexer.sessao.get(f"{indexer.url}/_cluster/health", timeout=5).ok:
                return
        except requests.RequestException:
            pass
        time.sleep(5)
    raise RuntimeError("indexer não respondeu")


def preparar():
    """Tudo o que os gerenciadores não têm permissão de fazer sozinhos."""
    env = ler_env(DESTINO / ".env")
    indexer = indexer_admin(env)
    _esperar(indexer)

    versao = _na_imagem("filebeat", "version").split()[2]
    for conjunto in ("alerts", "archives"):
        pipeline = json.loads(_na_imagem("cat", f"/usr/share/filebeat/module/wazuh/{conjunto}/ingest/pipeline.json"))
        # O processador original escolhe o índice por um campo enviado pelo gerenciador. Cada
        # gerenciador já grava direto no próprio índice, então o índice fica sendo o da requisição.
        pipeline["processors"] = [p for p in pipeline["processors"] if "date_index_name" not in p]
        _pedir(indexer, "PUT", f"_ingest/pipeline/filebeat-{versao}-wazuh-{conjunto}-pipeline", pipeline)

    # Sem isso os índices crescem até encher o disco, principalmente os de log bruto.
    dias = int(env.get("RETENCAO_DIAS", "90"))
    politica = {"policy": {
        "description": "Retenção dos índices de alertas e logs brutos",
        "default_state": "quente",
        "states": [
            {"name": "quente", "actions": [],
             "transitions": [{"state_name": "apagar", "conditions": {"min_index_age": f"{dias}d"}}]},
            {"name": "apagar", "actions": [{"delete": {}}], "transitions": []},
        ],
        "ism_template": [{"index_patterns": [f"{PREFIXO}*", f"{PREFIXO_BRUTO}*"], "priority": 100}],
    }}
    atual = indexer.sessao.get(f"{indexer.url}/_plugins/_ism/policies/roar-retencao", timeout=30)
    if atual.ok:
        dados = atual.json()
        _pedir(indexer, "PUT", f"_plugins/_ism/policies/roar-retencao?if_seq_no={dados['_seq_no']}"
                               f"&if_primary_term={dados['_primary_term']}", politica)
    else:
        _pedir(indexer, "PUT", "_plugins/_ism/policies/roar-retencao", politica)

    modelo = json.loads(_na_imagem("cat", "/var/ossec/data_tmp/exclusion/etc/filebeat/wazuh-template.json"))
    _pedir(indexer, "PUT", "_template/wazuh", modelo)

    _pedir(indexer, "PUT", f"_plugins/_security/api/roles/{LEITOR}", {
        "cluster_permissions": ["cluster_monitor"],
        "index_permissions": [{"index_patterns": [f"{PREFIXO}*", f"{PREFIXO_BRUTO}*"], "allowed_actions": ["read", "indices:monitor/stats"]}],
    })
    _pedir(indexer, "PUT", f"_plugins/_security/api/internalusers/{LEITOR}",
           {"password": env["ROAR_LEITOR_SENHA"], "opendistro_security_roles": [LEITOR]})
    print("Indexer preparado.")


def _permissoes_do_indexer(indexer, gerenciador_id, senha):
    usuario = f"roar_ger_{gerenciador_id}"
    _pedir(indexer, "PUT", f"_plugins/_security/api/roles/{usuario}", {
        "cluster_permissions": ["cluster_monitor", "cluster:admin/ingest/pipeline/get", "indices:data/write/bulk"],
        "index_permissions": [{
            "index_patterns": [f"{indice_do(gerenciador_id)}*", f"{indice_bruto_do(gerenciador_id)}*"],
            "allowed_actions": ["indices:admin/create", "indices:admin/mapping/put",
                                "indices:data/write/index", "indices:data/write/bulk*"],
        }],
    })
    _pedir(indexer, "PUT", f"_plugins/_security/api/internalusers/{usuario}",
           {"password": senha, "opendistro_security_roles": [usuario]})
    return usuario


def _compose(pasta, gerenciador_id, *comando):
    return subprocess.run(["docker", "compose", "--project-directory", str(pasta),
                           "--project-name", f"roar-ger-{gerenciador_id}", *comando],
                          check=True, capture_output=True, text=True)


def configuracao_do_gerenciador(conf):
    """Exige senha na inscrição e desliga o que usaria índices compartilhados entre clientes."""
    conf = conf.replace("<use_password>no</use_password>", "<use_password>yes</use_password>")
    # Guarda também o que não virou alerta: é o log bruto que investigação e auditoria pedem.
    conf = conf.replace("<logall_json>no</logall_json>", "<logall_json>yes</logall_json>")
    for bloco in ("vulnerability-detection", "indexer"):
        conf = re.sub(rf"(<{bloco}>\s*<enabled>)yes(</enabled>)", lambda m: f"{m[1]}no{m[2]}", conf)
    return conf + _RESPOSTAS_COM_PRAZO


# Cada prazo vira o comando firewall-drop<segundos>, que o ativo desfaz sozinho ao vencer.
# O grupo não existe em regra nenhuma: o bloqueio só sai quando um playbook pede, nunca por regra.
SEGUNDOS_DE_BLOQUEIO = (3600, 86400, 604800)
# netsh e win_route-null são os equivalentes de Windows.
RESPOSTAS_COM_PRAZO = ("firewall-drop", "host-deny", "route-null", "netsh", "win_route-null", "disable-account")
_RESPOSTAS_COM_PRAZO = "\n<ossec_config>\n" + "".join(
    f"  <active-response>\n    <disabled>no</disabled>\n    <command>{c}</command>\n    <location>local</location>\n"
    f"    <rules_group>roar_so_por_playbook</rules_group>\n    <timeout>{s}</timeout>\n  </active-response>\n"
    for c in RESPOSTAS_COM_PRAZO for s in SEGUNDOS_DE_BLOQUEIO
) + "</ossec_config>\n"


def criar(nome, endereco_portas="127.0.0.1"):
    """Devolve o que é preciso para inscrever agentes. Só a senha de inscrição sai daqui."""
    env = ler_env(DESTINO / ".env")
    indexer = indexer_admin(env)
    gerenciador_id = secrets.token_hex(6)
    pasta = DESTINO / "gerenciadores" / gerenciador_id

    with banco_admin(env) as banco:
        cliente = banco.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (nome,)).fetchone()[0]
        porta = banco.execute("SELECT coalesce(max(porta_base) + 4, %s) FROM gerenciadores",
                              (PORTA_INICIAL,)).fetchone()[0]
        banco.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)",
                      (gerenciador_id, cliente, porta))

    senha_indexer, senha_api, senha_inscricao = senha_forte(), senha_forte(), gerar()
    usuario = _permissoes_do_indexer(indexer, gerenciador_id, senha_indexer)
    with banco_admin(env) as banco:
        banco.execute("INSERT INTO inscricao_de_agentes (gerenciador_id, cliente_id, senha) VALUES (%s, %s, %s)",
                      (gerenciador_id, cliente, senha_inscricao))

    pasta.mkdir(parents=True, mode=0o700)
    origem = RAIZ / "infra/wazuh/gerenciador"
    shutil.copy(origem / "docker-compose.yml", pasta / "docker-compose.yml")
    shutil.copy(origem / "1-roar-filebeat", pasta / "1-roar-filebeat")
    (pasta / "1-roar-filebeat").chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

    (pasta / "ossec.conf").write_text(configuracao_do_gerenciador(CONF_BASE.read_text()))
    (pasta / "authd.pass").write_text(senha_inscricao + "\n")
    (pasta / "authd.pass").chmod(0o640)

    variaveis = {
        "WAZUH_VERSAO": WAZUH_VERSAO, "GERENCIADOR_ID": gerenciador_id, "REDE": REDE,
        "PORTAS_ENDERECO": endereco_portas, "PORTA_EVENTOS": porta, "PORTA_INSCRICAO": porta + 1,
        "PORTA_API": porta + 2, "PORTA_SYSLOG": porta + 3, "INDEXER_USUARIO": usuario, "INDEXER_SENHA": senha_indexer,
        "API_SENHA": senha_api, "INDICE": indice_do(gerenciador_id),
        "INDICE_BRUTO": indice_bruto_do(gerenciador_id), "CERTIFICADOS": CERTIFICADOS,
    }
    (pasta / ".env").write_text("".join(f"{k}={v}\n" for k, v in variaveis.items()))
    (pasta / ".env").chmod(0o600)

    _compose(pasta, gerenciador_id, "up", "-d")
    _worker_do_cliente(cliente, ["enable", "--now"])
    return {"id": gerenciador_id, "cliente": cliente, "porta_eventos": porta, "porta_inscricao": porta + 1,
            "porta_api": porta + 2, "senha_inscricao": senha_inscricao, "senha_api": senha_api,
            "indexer_usuario": usuario, "indexer_senha": senha_indexer,
            "host": f"gerenciador-{gerenciador_id}"}


def _api_do_gerenciador(gerenciador_id, metodo, rota, **kwargs):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    env = ler_env(DESTINO / "gerenciadores" / gerenciador_id / ".env")
    base = f"https://127.0.0.1:{env['PORTA_API']}"
    token = requests.post(f"{base}/security/user/authenticate?raw=true", auth=("roar", env["API_SENHA"]),
                          verify=False, timeout=30)
    token.raise_for_status()
    r = requests.request(metodo, base + rota, headers={"Authorization": f"Bearer {token.text}"}, verify=False, timeout=120, **kwargs)
    r.raise_for_status()
    return r.json()


def _configuracao_valida(gerenciador_id, programas=("wazuh-analysisd",)):
    # Usa o binário do Wazuh: a validação pela API estoura o tempo com milhares de regras.
    # Na dúvida, reprova: quem chama volta ao arquivo anterior e não reinicia nada.
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    for programa in programas:
        r = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                            "exec", "-T", "gerenciador", f"/var/ossec/bin/{programa}", "-t"],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            return False, {"status": "erro", "saida": (r.stderr or r.stdout)[-400:]}
    return True, {"status": "OK", "saida": ""}


def aplicar_regras(gerenciador_id, nome, xml, reiniciar=True):
    """Instala um arquivo de regras. Se a validação reprovar, volta ao anterior e não reinicia.

    Copia direto para o contêiner porque a API do Wazuh estoura o tempo com arquivos grandes.
    """
    if not re.fullmatch(r"roar_[a-z0-9_]+\.xml", nome):
        raise ValueError("nome de arquivo de regras inválido")
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    caminho = f"/var/ossec/etc/rules/{nome}"
    novo, anterior = pasta / nome, pasta / f"{nome}.anterior"

    copia = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name",
                            f"roar-ger-{gerenciador_id}", "exec", "-T", "gerenciador", "cat", caminho],
                           capture_output=True)
    tinha_anterior = copia.returncode == 0
    if tinha_anterior:
        anterior.write_bytes(copia.stdout)

    def instalar(arquivo):
        _compose(pasta, gerenciador_id, "cp", str(arquivo), f"gerenciador:{caminho}")
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chown", "wazuh:wazuh", caminho)
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chmod", "660", caminho)

    novo.write_text(xml, encoding="utf-8")
    instalar(novo)
    valida, detalhe = _configuracao_valida(gerenciador_id)
    if not valida:
        if tinha_anterior:
            instalar(anterior)
        else:
            _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "rm", "-f", caminho)
        return False, detalhe
    if reiniciar:
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "/var/ossec/bin/wazuh-control", "restart")
    return True, detalhe


def aplicar_agent_conf(gerenciador_id, conteudo, grupo="default"):
    """Configuração que o gerenciador distribui aos agentes, validada pelo programa dele. Reprovou: volta ao anterior."""
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    caminho = f"/var/ossec/etc/shared/{grupo}/agent.conf"
    anterior, novo = pasta / "agent.conf.anterior", pasta / "agent.conf.novo"
    copia = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                            "exec", "-T", "gerenciador", "cat", caminho], capture_output=True)
    anterior.write_bytes(copia.stdout if copia.returncode == 0 else b"<agent_config>\n</agent_config>\n")

    def instalar(arquivo):
        _compose(pasta, gerenciador_id, "cp", str(arquivo), f"gerenciador:{caminho}")
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chown", "wazuh:wazuh", caminho)
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chmod", "660", caminho)

    novo.write_text(conteudo, encoding="utf-8")
    instalar(novo)
    r = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                        "exec", "-T", "gerenciador", "/var/ossec/bin/verify-agent-conf", "-f", caminho], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        instalar(anterior)
        return False, {"status": "erro", "saida": (r.stderr or r.stdout)[-400:]}
    return True, {"status": "OK", "saida": ""}


def aplicar_yara(gerenciador_id, regras, script, decodificadores, deteccoes, nome_das_deteccoes, grupo="default"):
    """Decodificador e detecção ficam mesmo sem regras: sozinhos não fazem nada. Sem regras, a pasta dos agentes esvazia."""
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    compartilhada = f"/var/ossec/etc/shared/{grupo}"
    copia = pasta / "yara.tmp"

    def copiar(conteudo, caminho):
        copia.write_text(conteudo, encoding="utf-8")
        _compose(pasta, gerenciador_id, "cp", str(copia), f"gerenciador:{caminho}")
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chown", "wazuh:wazuh", caminho)
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chmod", "660", caminho)

    if not regras:
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "rm", "-f", f"{compartilhada}/roar_yara.yar", f"{compartilhada}/roar_yara.sh")
        return True, {"status": "OK", "saida": ""}
    copiar(decodificadores, "/var/ossec/etc/decoders/roar_yara.xml")
    ok, detalhe = aplicar_regras(gerenciador_id, nome_das_deteccoes, deteccoes, reiniciar=False)
    if ok:
        copiar(regras, f"{compartilhada}/roar_yara.yar")
        copiar(script, f"{compartilhada}/roar_yara.sh")
    else:
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "rm", "-f", "/var/ossec/etc/decoders/roar_yara.xml")
    copia.unlink(missing_ok=True)
    return ok, detalhe


def enviar_eventos(gerenciador_id, eventos):
    """Entrega ao analisador do gerenciador, que aplica as mesmas regras de qualquer outro log."""
    return _api_do_gerenciador(gerenciador_id, "POST", "/events", json={"events": eventos})


def remover_regras(gerenciador_id, nome):
    """Tira um arquivo de regras. Se nunca foi instalado, não reinicia nada."""
    if not re.fullmatch(r"roar_[a-z0-9_]+\.xml", nome):
        raise ValueError("nome de arquivo de regras inválido")
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    caminho = f"/var/ossec/etc/rules/{nome}"
    existe = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                             "exec", "-T", "gerenciador", "test", "-f", caminho], capture_output=True)
    if existe.returncode != 0:
        return True, {"status": "OK", "saida": ""}
    _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "rm", "-f", caminho)
    valida, detalhe = _configuracao_valida(gerenciador_id)
    if valida:
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "/var/ossec/bin/wazuh-control", "restart")
    return valida, detalhe


def _instalar_credenciais(pasta, gerenciador_id, arquivos):
    """Troca o conjunto inteiro: credencial de fonte removida não pode continuar no gerenciador."""
    _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "sh", "-c",
             "rm -rf /var/ossec/etc/roar-credenciais /root/.aws/credentials; mkdir -p /var/ossec/etc/roar-credenciais /root/.aws; "
             "chown root:wazuh /var/ossec/etc/roar-credenciais; chmod 750 /var/ossec/etc/roar-credenciais; chmod 700 /root/.aws")
    temporario = pasta / "credencial.tmp"
    for caminho, conteudo in arquivos.items():
        descritor = os.open(temporario, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descritor, "w", encoding="utf-8") as f:
            f.write(conteudo)
        _compose(pasta, gerenciador_id, "cp", str(temporario), f"gerenciador:{caminho}")
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chown", "root:wazuh", caminho)
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chmod", "640", caminho)
    temporario.unlink(missing_ok=True)


def aplicar_configuracao(gerenciador_id, fragmento, arquivos=None):
    """Troca o trecho das fontes de dados. Se reprovar, volta ao arquivo anterior e não reinicia."""
    arquivos = arquivos or {}
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    caminho = "/var/ossec/etc/ossec.conf"
    montado, anterior = pasta / "ossec.conf", pasta / "ossec.conf.anterior"
    anterior.write_bytes(subprocess.run(
        ["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
         "exec", "-T", "gerenciador", "cat", caminho], capture_output=True, check=True).stdout)
    guardados = pasta / "credenciais.json"
    arquivos_anteriores = json.loads(guardados.read_text()) if guardados.exists() else {}

    def instalar(arquivo):
        _compose(pasta, gerenciador_id, "cp", str(arquivo), f"gerenciador:{caminho}")
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chown", "root:wazuh", caminho)
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chmod", "660", caminho)

    novo = pasta / "ossec.conf.novo"
    novo.write_text(configuracao_do_gerenciador(CONF_BASE.read_text()) + fragmento)
    instalar(novo)
    _instalar_credenciais(pasta, gerenciador_id, arquivos)
    # O analisador sozinho aprova um syslog inválido, que só derrubaria o recebimento ao reiniciar.
    valida, detalhe = _configuracao_valida(gerenciador_id, ("wazuh-analysisd", "wazuh-remoted", "wazuh-modulesd"))
    if not valida:
        instalar(anterior)
        _instalar_credenciais(pasta, gerenciador_id, arquivos_anteriores)
        return False, detalhe

    def reiniciar():
        return subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                               "exec", "-T", "gerenciador", "/var/ossec/bin/wazuh-control", "restart"],
                              capture_output=True, text=True, timeout=600)

    resultado = reiniciar()
    if resultado.returncode != 0:
        # A coleta do cliente não pode ficar parada: volta ao que funcionava e sobe de novo.
        instalar(anterior)
        _instalar_credenciais(pasta, gerenciador_id, arquivos_anteriores)
        reiniciar()
        return False, {"status": "erro", "saida": (resultado.stderr or resultado.stdout)[-400:]}
    # O arquivo montado é o que o contêiner copia ao ser recriado.
    shutil.copy(novo, montado)
    novo.unlink()
    montado.chmod(0o640)
    descritor = os.open(guardados, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descritor, "w", encoding="utf-8") as f:
        json.dump(arquivos, f)
    return True, detalhe


def remover(gerenciador_id, apagar_dados=True):
    env = ler_env(DESTINO / ".env")
    indexer = indexer_admin(env)
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    if pasta.is_dir():
        _compose(pasta, gerenciador_id, "down", "-v")
        shutil.rmtree(pasta)
    usuario = f"roar_ger_{gerenciador_id}"
    for rota in (f"_plugins/_security/api/internalusers/{usuario}", f"_plugins/_security/api/roles/{usuario}"):
        indexer.sessao.delete(f"{indexer.url}/{rota}", timeout=60)
    if apagar_dados:
        indexer.sessao.delete(f"{indexer.url}/{indice_do(gerenciador_id)}*", timeout=60)
        indexer.sessao.delete(f"{indexer.url}/{indice_bruto_do(gerenciador_id)}*", timeout=60)
        with banco_admin(env) as banco:
            cliente = banco.execute("SELECT cliente_id FROM gerenciadores WHERE id = %s",
                                    (gerenciador_id,)).fetchone()
            banco.execute("DELETE FROM sinais WHERE evento_id IN (SELECT id FROM eventos WHERE gerenciador_id = %s)",
                          (gerenciador_id,))
            banco.execute("DELETE FROM aprovacoes WHERE execucao_id IN (SELECT id FROM execucoes WHERE gerenciador_id = %s)",
                          (gerenciador_id,))
            for tabela in ("quarentena", "eventos", "grupos_alerta", "regras", "ativos", "regras_proprias", "entrada_webhook", "fontes",
                           "inscricao_de_agentes", "execucoes", "fim_base", "fim_varreduras", "fim_caminhos"):
                banco.execute(f"DELETE FROM {tabela} WHERE gerenciador_id = %s", (gerenciador_id,))
            banco.execute("DELETE FROM checkpoints WHERE fonte = %s", (gerenciador_id,))
            banco.execute("DELETE FROM gerenciadores WHERE id = %s", (gerenciador_id,))
            restantes = cliente and banco.execute("SELECT count(*) FROM gerenciadores WHERE cliente_id = %s",
                                                  (cliente[0],)).fetchone()[0]
            if cliente and not restantes:
                _worker_do_cliente(cliente[0], ["disable", "--now"])
                for tabela in ("vuln_historico", "vuln_achados", "vuln_ativos", "vuln_varreduras", "vuln_alvos", "vuln_modelos"):
                    banco.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente[0],))
                for tabela in ("sinais", "alertas_risco", "falhas_por_hora", "horas", "vistos", "entidades", "ueba_cursor",
                               "auditoria", "aprovacoes", "execucoes", "playbooks", "soar_cursor", "segredos"):
                    banco.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente[0],))
                banco.execute("DELETE FROM clientes WHERE id = %s", (cliente[0],))


def _worker_do_cliente(cliente, acao):
    """Em ambiente sem o serviço instalado, como nos testes, não há o que ligar."""
    try:
        subprocess.run(["systemctl", *acao, f"roar-worker@{cliente}"], capture_output=True, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        pass


def primeiro_acesso(organizacao, email):
    """Sem isto, uma instalação nova não tem como entrar. Só age se ainda não há ninguém."""
    from argon2 import PasswordHasher

    env = ler_env(DESTINO / ".env")
    with banco_admin(env) as banco:
        if banco.execute("SELECT count(*) FROM usuarios").fetchone()[0]:
            return None
        cliente = banco.execute("SELECT id FROM clientes ORDER BY criado_em LIMIT 1").fetchone()
    if cliente is None:
        # Sem SIEM não há gerenciador para criar: basta a organização.
        if (DESTINO / "perfil").is_file() and (DESTINO / "perfil").read_text().strip() == "vulnerabilidades":
            with banco_admin(env) as banco:
                banco.execute("INSERT INTO clientes (nome) VALUES (%s)", (organizacao,))
        else:
            criar(organizacao)
    senha = secrets.token_urlsafe(18)
    with banco_admin(env) as banco:
        cliente = banco.execute("SELECT id FROM clientes ORDER BY criado_em LIMIT 1").fetchone()[0]
        banco.execute("INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil, trocar_senha) VALUES (%s, %s, 'Administração', %s, 'administrador', true)",
                      (cliente, email.strip().lower(), PasswordHasher().hash(senha)))
    # Em arquivo só do root, e nunca na tela: terminal fica em histórico e em log de instalação.
    arquivo = DESTINO / "primeiro-acesso.txt"
    descritor = os.open(arquivo, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descritor, "w") as f:
        f.write(f"{email}\n{senha}\n")
    return arquivo


def main():
    args = argparse.ArgumentParser()
    comandos = args.add_subparsers(dest="comando", required=True)
    comandos.add_parser("preparar")
    p = comandos.add_parser("primeiro-acesso")
    p.add_argument("--organizacao", required=True)
    p.add_argument("--email", required=True)
    c = comandos.add_parser("criar")
    c.add_argument("--nome", required=True)
    c.add_argument("--endereco-portas", default="127.0.0.1")
    r = comandos.add_parser("remover")
    r.add_argument("--id", required=True)
    a = args.parse_args()

    if a.comando == "preparar":
        preparar()
    elif a.comando == "primeiro-acesso":
        arquivo = primeiro_acesso(a.organizacao, a.email)
        print(f"Primeiro acesso em {arquivo}. A senha é temporária: apague o arquivo depois de entrar." if arquivo else "Já existem usuários: nada a fazer.")
    elif a.comando == "criar":
        g = criar(a.nome, a.endereco_portas)
        print(f"Gerenciador {g['id']} criado. Eventos na porta {g['porta_eventos']}, inscrição na {g['porta_inscricao']}.")
        print(f"Senha de inscrição dos agentes: {DESTINO}/gerenciadores/{g['id']}/authd.pass")
    else:
        remover(a.id)
        print("Gerenciador removido, com os dados.")


if __name__ == "__main__":
    main()
