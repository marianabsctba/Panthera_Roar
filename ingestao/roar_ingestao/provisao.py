"""Prepara o indexer e cria o gerenciador do Wazuh de cada cliente.

    python -m roar_ingestao.provisao preparar
    python -m roar_ingestao.provisao criar --nome acme
    python -m roar_ingestao.provisao remover --id <id>
"""

import argparse
import json
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
        "index_permissions": [{"index_patterns": [f"{PREFIXO}*", f"{PREFIXO_BRUTO}*"], "allowed_actions": ["read"]}],
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
    return conf


def criar(nome, endereco_portas="127.0.0.1"):
    """Devolve o que é preciso para inscrever agentes. Só a senha de inscrição sai daqui."""
    env = ler_env(DESTINO / ".env")
    indexer = indexer_admin(env)
    gerenciador_id = secrets.token_hex(6)
    pasta = DESTINO / "gerenciadores" / gerenciador_id

    with banco_admin(env) as banco:
        cliente = banco.execute("INSERT INTO clientes (nome) VALUES (%s) RETURNING id", (nome,)).fetchone()[0]
        porta = banco.execute("SELECT coalesce(max(porta_base) + 3, %s) FROM gerenciadores",
                              (PORTA_INICIAL,)).fetchone()[0]
        banco.execute("INSERT INTO gerenciadores (id, cliente_id, porta_base) VALUES (%s, %s, %s)",
                      (gerenciador_id, cliente, porta))

    senha_indexer, senha_api, senha_inscricao = senha_forte(), senha_forte(), gerar()
    usuario = _permissoes_do_indexer(indexer, gerenciador_id, senha_indexer)

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
        "PORTA_API": porta + 2, "INDEXER_USUARIO": usuario, "INDEXER_SENHA": senha_indexer,
        "API_SENHA": senha_api, "INDICE": indice_do(gerenciador_id),
        "INDICE_BRUTO": indice_bruto_do(gerenciador_id), "CERTIFICADOS": CERTIFICADOS,
    }
    (pasta / ".env").write_text("".join(f"{k}={v}\n" for k, v in variaveis.items()))
    (pasta / ".env").chmod(0o600)

    _compose(pasta, gerenciador_id, "up", "-d")
    return {"id": gerenciador_id, "cliente": cliente, "porta_eventos": porta, "porta_inscricao": porta + 1,
            "porta_api": porta + 2, "senha_inscricao": senha_inscricao, "senha_api": senha_api,
            "indexer_usuario": usuario, "indexer_senha": senha_indexer,
            "host": f"gerenciador-{gerenciador_id}"}


def _api_do_gerenciador(gerenciador_id, metodo, rota):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    env = ler_env(DESTINO / "gerenciadores" / gerenciador_id / ".env")
    base = f"https://127.0.0.1:{env['PORTA_API']}"
    token = requests.post(f"{base}/security/user/authenticate?raw=true", auth=("roar", env["API_SENHA"]),
                          verify=False, timeout=30)
    token.raise_for_status()
    r = requests.request(metodo, base + rota, headers={"Authorization": f"Bearer {token.text}"}, verify=False, timeout=120)
    r.raise_for_status()
    return r.json()


def _configuracao_valida(gerenciador_id):
    # Usa o binário do Wazuh: a validação pela API estoura o tempo com milhares de regras.
    # Na dúvida, reprova: quem chama volta ao arquivo anterior e não reinicia nada.
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    r = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                        "exec", "-T", "gerenciador", "/var/ossec/bin/wazuh-analysisd", "-t"],
                       capture_output=True, text=True, timeout=600)
    return r.returncode == 0, {"status": "OK" if r.returncode == 0 else "erro", "saida": (r.stderr or r.stdout)[-400:]}


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
            for tabela in ("quarentena", "eventos", "grupos_alerta", "regras", "ativos", "regras_proprias"):
                banco.execute(f"DELETE FROM {tabela} WHERE gerenciador_id = %s", (gerenciador_id,))
            banco.execute("DELETE FROM checkpoints WHERE fonte = %s", (gerenciador_id,))
            banco.execute("DELETE FROM gerenciadores WHERE id = %s", (gerenciador_id,))
            restantes = cliente and banco.execute("SELECT count(*) FROM gerenciadores WHERE cliente_id = %s",
                                                  (cliente[0],)).fetchone()[0]
            if cliente and not restantes:
                for tabela in ("sinais", "alertas_risco", "falhas_por_hora", "horas", "vistos", "entidades", "ueba_cursor",
                               "auditoria"):
                    banco.execute(f"DELETE FROM {tabela} WHERE cliente_id = %s", (cliente[0],))
                banco.execute("DELETE FROM clientes WHERE id = %s", (cliente[0],))


def main():
    args = argparse.ArgumentParser()
    comandos = args.add_subparsers(dest="comando", required=True)
    comandos.add_parser("preparar")
    c = comandos.add_parser("criar")
    c.add_argument("--nome", required=True)
    c.add_argument("--endereco-portas", default="127.0.0.1")
    r = comandos.add_parser("remover")
    r.add_argument("--id", required=True)
    a = args.parse_args()

    if a.comando == "preparar":
        preparar()
    elif a.comando == "criar":
        g = criar(a.nome, a.endereco_portas)
        print(f"Gerenciador {g['id']} criado. Eventos na porta {g['porta_eventos']}, inscrição na {g['porta_inscricao']}.")
        print(f"Senha de inscrição dos agentes: {DESTINO}/gerenciadores/{g['id']}/authd.pass")
    else:
        remover(a.id)
        print("Gerenciador removido, com os dados.")


if __name__ == "__main__":
    main()
