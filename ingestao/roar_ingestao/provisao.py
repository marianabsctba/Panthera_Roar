"""Prepara o indexer e cria o gerenciador do Wazuh de cada cliente.

    python -m roar_ingestao.provisao preparar
    python -m roar_ingestao.provisao criar --nome acme
    python -m roar_ingestao.provisao remover --id <id>
"""

import argparse
import fcntl
import json
import logging
import os
import re
import secrets
import shutil
import stat
import string
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import psycopg
import requests
import urllib3

from . import armazem
from .ciclo import ler_env
from .fonte_wazuh import Indexer

log = logging.getLogger("roar.provisao")

DESTINO = Path("/opt/panthera-roar")
RAIZ = Path(__file__).resolve().parents[2]
WAZUH_VERSAO = "4.14.9"
# O mesmo da instalação (infra/.env.exemplo): seis meses, o que o Marco Civil pede a provedor de aplicação.
RETENCAO_PADRAO = "180"
# Muda quando a configuração base do gerenciador muda: faz cada gerenciador já existente receber a nova uma vez.
VERSAO_DA_CONFIGURACAO = "3"
ARQUIVO, PASTA_DO_ARQUIVO, ARQUIVO_PADRAO = "roar-arquivo", "/mnt/roar-arquivo", "365"
IMAGEM = f"wazuh/wazuh-manager:{WAZUH_VERSAO}"
CERTIFICADOS = DESTINO / "wazuh/single-node/config/wazuh_indexer_ssl_certs"
CONF_BASE = DESTINO / "wazuh/single-node/config/wazuh_cluster/wazuh_manager.conf"
REDE = "panthera-roar-wazuh_default"
PREFIXO = "wazuh-alerts-4.x-"
PREFIXO_BRUTO = "wazuh-archives-4.x-"
PORTA_INICIAL = 21000
LEITOR = "roar_leitor"
# O portão (roar_ingestao.portao) fica no gateway da rede dos contêineres: os gerenciadores chegam nele sem nome novo.
PORTAO_PASTA = DESTINO / "portao"
PORTAO_PORTA = 9201
DIAS_DO_CERTIFICADO = 730


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


# Os selos são prova e só recebem acréscimo; o pedido de remoção é o registro de que a organização saiu.
GUARDADAS = ("selos", "selo_folhas", "selo_ancoras", "selo_verificacoes", "organizacoes_pedidos")


def varrer(b, cliente):
    """Apaga a organização de toda tabela que tem o campo dela, menos as que guardam prova.

    Lista escrita à mão esquece a tabela criada no ano que vem. Aqui ela entra sozinha. A ordem das chaves estrangeiras
    não está escrita em lugar nenhum: tenta de novo o que falhou, até não sobrar nada ou não andar mais.
    """
    tabelas = [l[0] for l in b.execute(
        """SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t USING (table_schema, table_name)
           WHERE c.table_schema = 'public' AND c.column_name = 'cliente_id' AND t.table_type = 'BASE TABLE'
             AND c.table_name <> ALL(%s) ORDER BY 1""", (list(GUARDADAS),)).fetchall()]
    while tabelas:
        faltam = []
        for tabela in tabelas:
            try:
                with b.transaction():
                    b.execute(f'DELETE FROM "{tabela}" WHERE cliente_id = %s', (cliente,))
            except psycopg.errors.ForeignKeyViolation:
                faltam.append(tabela)
        if len(faltam) == len(tabelas):
            raise RuntimeError(f"não deu para apagar a organização de: {', '.join(faltam)}")
        tabelas = faltam


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


def ip_do_portao():
    """O gateway da rede dos contêineres: só eles alcançam, e nada fora do servidor."""
    r = subprocess.run(["docker", "network", "inspect", REDE, "--format", "{{(index .IPAM.Config 0).Gateway}}"],
                       check=True, capture_output=True, text=True)
    return r.stdout.strip()


def _certificado_do_portao(ip):
    """Emitido pela autoridade que os gerenciadores já confiam. Renova perto de vencer ou se o IP mudar."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    certificado, chave = PORTAO_PASTA / "portao.pem", PORTAO_PASTA / "portao-key.pem"
    agora = datetime.datetime.now(datetime.timezone.utc)
    if certificado.exists():
        atual = x509.load_pem_x509_certificate(certificado.read_bytes())
        nomes = atual.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if atual.not_valid_after_utc - agora > datetime.timedelta(days=30) and ipaddress.ip_address(ip) in nomes.get_values_for_type(x509.IPAddress):
            return False
    autoridade = x509.load_pem_x509_certificate((CERTIFICADOS / "root-ca-manager.pem").read_bytes())
    chave_da_autoridade = serialization.load_pem_private_key((CERTIFICADOS / "root-ca-manager.key").read_bytes(), password=None)
    privada = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "roar-portao")])
    novo = (x509.CertificateBuilder().subject_name(nome).issuer_name(autoridade.subject).public_key(privada.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(agora - datetime.timedelta(minutes=5))
            .not_valid_after(agora + datetime.timedelta(days=DIAS_DO_CERTIFICADO))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("roar-portao"), x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(chave_da_autoridade, hashes.SHA256()))
    PORTAO_PASTA.mkdir(mode=0o700, exist_ok=True)
    descritor = os.open(chave, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descritor, "wb") as f:
        f.write(privada.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    certificado.write_bytes(novo.public_bytes(serialization.Encoding.PEM))
    # O portão roda como roar-svc: a chave é dele, e de mais ninguém.
    try:
        import pwd
        dono = pwd.getpwnam("roar-svc")
        for caminho in (PORTAO_PASTA, chave, certificado):
            os.chown(caminho, dono.pw_uid, dono.pw_gid)
    except KeyError:
        pass
    return True


def _modelos_de_estado(indexer):
    """Os modelos que o conector do Wazuh tentaria criar. Criados aqui, com a credencial de administração."""
    criados = 0
    for arquivo in _na_imagem("ls", "/var/ossec/templates").split():
        modelo = json.loads(_na_imagem("cat", f"/var/ossec/templates/{arquivo}")) if arquivo.endswith(".json") else {}
        # A pasta também traz atualizações de mapeamento, que não são modelo: só entra o que diz a quais índices vale.
        if "index_patterns" in modelo:
            _pedir(indexer, "PUT", f"_index_template/roar-{arquivo.removesuffix('.json')}", modelo)
            criados += 1
    return criados


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
        # Para cada campo de onde sai o local do endereço, sai também a operadora, da base que já vem no indexador.
        pipeline["processors"] += [
            {"geoip": {"field": p["geoip"]["field"], "database_file": "GeoLite2-ASN.mmdb", "target_field": "Operadora",
                       "properties": ["asn", "organization_name"], "ignore_missing": True, "ignore_failure": True}}
            for p in pipeline["processors"] if "geoip" in p]
        _pedir(indexer, "PUT", f"_ingest/pipeline/filebeat-{versao}-wazuh-{conjunto}-pipeline", pipeline)

    # Sem isso os índices crescem até encher o disco, principalmente os de log bruto.
    # Vale até a organização ter a própria política: cada gerenciador ganha uma, com prioridade maior.
    _gravar_politica(indexer, "roar-retencao", "Retenção padrão dos índices de alertas e logs brutos",
                     [f"{PREFIXO}*", f"{PREFIXO_BRUTO}*"], int(env.get("RETENCAO_DIAS", RETENCAO_PADRAO)), 100)

    modelo = json.loads(_na_imagem("cat", "/var/ossec/data_tmp/exclusion/etc/filebeat/wazuh-template.json"))
    _pedir(indexer, "PUT", "_template/wazuh", modelo)
    # Log bruto é lido bem menos que alerta: vale gastar CPU ao gravar para ocupar menos disco. Só vale para índice novo.
    _pedir(indexer, "PUT", "_template/roar-compressao", {"index_patterns": [f"{PREFIXO_BRUTO}*"], "order": 10,
                                                        "settings": {"index.codec": "best_compression"}})

    preparar_arquivo(indexer, int(env.get("ROAR_ARQUIVO_DIAS", ARQUIVO_PADRAO)))

    _modelos_de_estado(indexer)
    _certificado_do_portao(ip_do_portao())
    # Gerenciador de antes do portão ganha os próprios índices de estado; a configuração nova chega pelo serviço de fontes.
    with banco_admin(env) as banco:
        for (gerenciador_id,) in banco.execute("SELECT id FROM gerenciadores").fetchall():
            _papel_do_gerenciador(indexer, gerenciador_id)

    _pedir(indexer, "PUT", f"_plugins/_security/api/roles/{LEITOR}", {
        # Ler a lista de cópias frias deixa a tela mostrar quando foi a última.
        "cluster_permissions": ["cluster_monitor", "cluster:admin/snapshot/get", "cluster:admin/repository/get"],
        "index_permissions": [{"index_patterns": [f"{PREFIXO}*", f"{PREFIXO_BRUTO}*", "wazuh-states-vulnerabilities-*"], "allowed_actions": ["read", "indices:monitor/stats"]}],
    })
    _pedir(indexer, "PUT", f"_plugins/_security/api/internalusers/{LEITOR}",
           {"password": env["ROAR_LEITOR_SENHA"], "opendistro_security_roles": [LEITOR]})
    print("Indexer preparado.")

    armazem.preparar(armazem.admin(env), env["ARMAZEM_LEITOR_SENHA"])
    with banco_admin(env) as banco:
        gerenciadores = [g for (g,) in banco.execute("SELECT id FROM gerenciadores").fetchall()]
    for gerenciador_id in gerenciadores:
        if (DESTINO / "gerenciadores" / gerenciador_id).is_dir():
            ligar_coletor(gerenciador_id)
    print("Armazém preparado.")


def _dias_do_cliente(banco, cliente):
    padrao = int(ler_env(DESTINO / ".env").get("RETENCAO_DIAS", RETENCAO_PADRAO))
    linha = banco.execute("SELECT retencao_alertas_dias, retencao_logs_dias FROM clientes WHERE id = %s", (cliente,)).fetchone()
    return (linha[0] or padrao, linha[1] or padrao) if linha else (padrao, padrao)


GEOIP = DESTINO / "geoip"
BASES_DE_LOCALIZACAO = ("GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb")


def _bases_de_localizacao():
    """As bases GeoLite2 que vêm com o indexador: o coletor localiza o endereço com as mesmas, e o país não muda de um lado
    para o outro. Copiadas uma vez; o indexador novo traz a versão nova, e a cópia é refeita em preparar."""
    GEOIP.mkdir(mode=0o755, exist_ok=True)
    conteiner = subprocess.run(["docker", "ps", "--format", "{{.Names}}", "--filter", "name=wazuh.indexer"],
                               capture_output=True, text=True, check=True).stdout.split()
    for base in BASES_DE_LOCALIZACAO:
        if conteiner and (not (GEOIP / base).exists() or os.environ.get("ROAR_GEOIP_RENOVAR") == "1"):
            subprocess.run(["docker", "cp", f"{conteiner[0]}:/usr/share/wazuh-indexer/modules/ingest-geoip/{base}", str(GEOIP / base)], check=True)
            (GEOIP / base).chmod(0o644)
    return GEOIP


def _syslog_do_coletor(pasta, fontes, desvio=False):
    """A parte do coletor que recebe o syslog: sem ela, a pasta que o compose monta fica vazia e o syslog não tem destino."""
    from . import coletor_syslog, syslog_cifrado
    from .fontes import redes_de_syslog

    coletor_syslog.gravar(pasta, coletor_syslog.configuracao(redes_de_syslog(fontes), desvio, syslog_cifrado.chave_do_repasse()))


def ligar_coletor(gerenciador_id):
    """Banco da organização, usuário do coletor e o coletor do gerenciador no ar. Pode rodar de novo sem estrago:
    é assim que os gerenciadores criados antes do armazém ganham o seu."""
    env = ler_env(DESTINO / ".env")
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    with banco_admin(env) as banco:
        cliente = banco.execute("SELECT cliente_id FROM gerenciadores WHERE id = %s", (gerenciador_id,)).fetchone()[0]
        dias_alertas, dias_logs = _dias_do_cliente(banco, cliente)
        desvio = banco.execute("SELECT desvio_de_volume FROM clientes WHERE id = %s", (cliente,)).fetchone()[0]
        fontes_de_syslog = [{"tipo": "syslog", "config": c} for (c,) in banco.execute(
            "SELECT config FROM fontes WHERE gerenciador_id = %s AND tipo = 'syslog' AND estado IN ('pendente', 'ativa')", (gerenciador_id,)).fetchall()]
    adm = armazem.admin(env)
    nome_do_banco = armazem.criar_organizacao(adm, cliente, dias_alertas, dias_logs, int(env.get("ARMAZEM_DIAS_QUENTES", armazem.DIAS_QUENTES_PADRAO)))
    variaveis = ler_env(pasta / ".env")
    senha = variaveis.get("ARMAZEM_SENHA") or senha_forte()
    usuario = armazem.criar_gravador(adm, gerenciador_id, cliente, senha)
    variaveis.update({"ARMAZEM_USUARIO": usuario, "ARMAZEM_SENHA": senha, "ARMAZEM_BANCO": nome_do_banco, "GEOIP": str(_bases_de_localizacao()),

                      # Só o armazém recebe logs e alertas: o Filebeat do gerenciador não sobe (teste do caminho antigo liga de volta pelo ambiente).
                      "ROAR_SO_ARMAZEM": os.environ.get("ROAR_SO_ARMAZEM", env.get("ROAR_SO_ARMAZEM", "0"))})
    (pasta / ".env").write_text("".join(f"{k}={v}\n" for k, v in variaveis.items()))
    (pasta / ".env").chmod(0o600)
    origem = RAIZ / "infra/wazuh/gerenciador"
    # O compose é sempre o modelo com variáveis: copiar de novo só acrescenta o coletor aos gerenciadores antigos.
    shutil.copy(origem / "docker-compose.yml", pasta / "docker-compose.yml")
    shutil.copy(origem / "1-roar-filebeat", pasta / "1-roar-filebeat")
    (pasta / "1-roar-filebeat").chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    # O Vector não troca variáveis de ambiente dentro da configuração: os valores entram aqui, num arquivo só do root.
    texto = (origem / "vector.yaml").read_text()
    for chave, valor in (("ARMAZEM_BANCO", nome_do_banco), ("ARMAZEM_USUARIO", usuario), ("ARMAZEM_SENHA", senha)):
        texto = texto.replace("{{" + chave + "}}", valor)
    destino = pasta / "vector.yaml"
    destino.touch(mode=0o600)
    destino.chmod(0o600)
    destino.write_text(texto)
    _syslog_do_coletor(pasta, fontes_de_syslog, desvio)
    # Os dois: no gerenciador antigo, a porta de syslog passa para o coletor (o compose só recria o que mudou).
    _compose(pasta, gerenciador_id, "up", "-d")


def preparar_arquivo(indexer, dias):
    """Cópia fria diária de alertas e logs brutos. O índice ao vivo some no prazo da organização; a cópia, no prazo da instalação."""
    r = indexer.sessao.put(f"{indexer.url}/_snapshot/{ARQUIVO}", json={"type": "fs", "settings": {"location": PASTA_DO_ARQUIVO, "compress": True}}, timeout=60)
    if not r.ok:
        # Instalação antiga, sem a pasta declarada no indexador: segue sem cópia fria até rodar o instalador de novo.
        print(f"Cópia fria desligada: o indexador não aceitou a pasta ({r.status_code}).")
        return False
    politica = {
        "description": "Cópia fria diária dos índices de alertas e logs brutos",
        "creation": {"schedule": {"cron": {"expression": "30 1 * * *", "timezone": "UTC"}}},
        # Guarda ao menos uma semana de cópias, mesmo se o prazo for curto.
        "deletion": {"schedule": {"cron": {"expression": "30 3 * * *", "timezone": "UTC"}}, "condition": {"max_age": f"{dias}d", "min_count": 7}},
        "snapshot_config": {"indices": f"{PREFIXO}*,{PREFIXO_BRUTO}*", "repository": ARQUIVO, "ignore_unavailable": True, "include_global_state": False},
    }
    atual = indexer.sessao.get(f"{indexer.url}/_plugins/_sm/policies/{ARQUIVO}", timeout=30)
    if atual.ok:
        dados = atual.json()
        _pedir(indexer, "PUT", f"_plugins/_sm/policies/{ARQUIVO}?if_seq_no={dados['_seq_no']}&if_primary_term={dados['_primary_term']}", politica)
    else:
        _pedir(indexer, "POST", f"_plugins/_sm/policies/{ARQUIVO}", politica)
    return True


def _gravar_politica(indexer, nome, descricao, padroes, dias, prioridade):
    politica = {"policy": {
        "description": descricao,
        "default_state": "quente",
        "states": [
            {"name": "quente", "actions": [],
             "transitions": [{"state_name": "apagar", "conditions": {"min_index_age": f"{dias}d"}}]},
            {"name": "apagar", "actions": [{"delete": {}}], "transitions": []},
        ],
        "ism_template": [{"index_patterns": padroes, "priority": prioridade}],
    }}
    atual = indexer.sessao.get(f"{indexer.url}/_plugins/_ism/policies/{nome}", timeout=30)
    if atual.ok:
        dados = atual.json()
        _pedir(indexer, "PUT", f"_plugins/_ism/policies/{nome}?if_seq_no={dados['_seq_no']}&if_primary_term={dados['_primary_term']}", politica)
    else:
        _pedir(indexer, "PUT", f"_plugins/_ism/policies/{nome}", politica)


def aplicar_retencao(gerenciador_id, dias_alertas, dias_logs):
    """Cada gerenciador com a retenção da própria organização. Índice novo pega pela prioridade; o que já existe troca aqui."""
    env = ler_env(DESTINO / ".env")
    indexer = indexer_admin(env)
    with banco_admin(env) as banco:
        cliente = banco.execute("SELECT cliente_id FROM gerenciadores WHERE id = %s", (gerenciador_id,)).fetchone()
    if cliente:
        armazem.aplicar_retencao(armazem.admin(env), cliente[0], dias_alertas, dias_logs, int(env.get("ARMAZEM_DIAS_QUENTES", armazem.DIAS_QUENTES_PADRAO)))
    for tipo, prefixo, dias in (("alertas", indice_do(gerenciador_id), dias_alertas), ("logs", indice_bruto_do(gerenciador_id), dias_logs)):
        nome = f"roar-retencao-{tipo}-{gerenciador_id}"
        _gravar_politica(indexer, nome, f"Retenção de {tipo} de um gerenciador", [f"{prefixo}*"], dias, 200)
        # Sem índice ainda, o indexador recusa a troca em vez de não fazer nada: o primeiro já nasce com a política certa.
        if not _pedir(indexer, "GET", f"_cat/indices/{prefixo}*?h=index").text.split():
            continue
        # Trocar de política só valeria ao fim da etapa atual, que dura o prazo inteiro: tira a antiga e põe a nova.
        # A idade conta da criação do índice, então nada ganha prazo extra com a troca.
        _pedir(indexer, "POST", f"_plugins/_ism/remove/{prefixo}*")
        _pedir(indexer, "POST", f"_plugins/_ism/add/{prefixo}*", {"policy_id": nome})


def apagar_retencao(indexer, gerenciador_id):
    for tipo in ("alertas", "logs"):
        indexer.sessao.delete(f"{indexer.url}/_plugins/_ism/policies/roar-retencao-{tipo}-{gerenciador_id}", timeout=60)


def indices_de_estado_do(gerenciador_id):
    """Vulnerabilidades e inventário que o próprio gerenciador mantém. O nome leva o host dele."""
    return f"wazuh-states-*-gerenciador-{gerenciador_id}*"


def _papel_do_gerenciador(indexer, gerenciador_id):
    usuario = f"roar_ger_{gerenciador_id}"
    _pedir(indexer, "PUT", f"_plugins/_security/api/roles/{usuario}", {
        # Continuar e fechar uma busca paginada são permissões do cluster, mas só valem com o identificador da busca,
        # que é aberta dentro dos índices permitidos abaixo.
        "cluster_permissions": ["cluster_monitor", "cluster:admin/ingest/pipeline/get", "indices:data/write/bulk",
                                "indices:data/read/scroll", "indices:data/read/scroll/clear"],
        "index_permissions": [{
            "index_patterns": [f"{indice_do(gerenciador_id)}*", f"{indice_bruto_do(gerenciador_id)}*"],
            "allowed_actions": ["indices:admin/create", "indices:admin/mapping/put",
                                "indices:data/write/index", "indices:data/write/bulk*"],
        }, {
            # O detector apaga o que foi corrigido e lê para comparar: só nos índices de estado dele.
            "index_patterns": [indices_de_estado_do(gerenciador_id)],
            "allowed_actions": ["indices:admin/create", "indices:admin/get", "indices:admin/mapping/put", "indices:admin/mappings/get",
                                "indices:admin/refresh*", "indices:data/write/*", "indices:data/read/*", "indices:monitor/*"],
        }],
    })
    return usuario


def _permissoes_do_indexer(indexer, gerenciador_id, senha):
    usuario = _papel_do_gerenciador(indexer, gerenciador_id)
    _pedir(indexer, "PUT", f"_plugins/_security/api/internalusers/{usuario}",
           {"password": senha, "opendistro_security_roles": [usuario]})
    return usuario


SEGUNDOS_PARA_A_API_SUBIR = 90


def _garantir_api(pasta, gerenciador_id, esperar=time.sleep):
    """Reinícios seguidos às vezes deixam a API antiga viva e sem dono, presa na porta: a nova não sobe e o
    wazuh-control já não enxerga a antiga. Sem a API param os webhooks e a sincronização das regras."""
    def no_ar():
        estado = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                                 "exec", "-T", "gerenciador", "/var/ossec/bin/wazuh-control", "status"], capture_output=True, text=True)
        return "wazuh-apid is running" in estado.stdout

    for _ in range(SEGUNDOS_PARA_A_API_SUBIR // 5):
        if no_ar():
            return True
        esperar(5)
    log.warning("a API do gerenciador %s não subiu: encerrando a antiga e subindo de novo", gerenciador_id)
    subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                    "exec", "-T", "gerenciador", "sh", "-c", "pkill -f wazuh_apid.py; sleep 3; /var/ossec/bin/wazuh-control start"],
                   capture_output=True, text=True, timeout=300)
    for _ in range(SEGUNDOS_PARA_A_API_SUBIR // 5):
        if no_ar():
            return True
        esperar(5)
    log.error("a API do gerenciador %s continua fora do ar", gerenciador_id)
    return False


def _compose(pasta, gerenciador_id, *comando):
    return subprocess.run(["docker", "compose", "--project-directory", str(pasta),
                           "--project-name", f"roar-ger-{gerenciador_id}", *comando],
                          check=True, capture_output=True, text=True)


def configuracao_do_gerenciador(conf, guardar_logs=True):
    """Exige senha na inscrição, e liga o detector de vulnerabilidades gravando só nos índices deste gerenciador."""
    conf = conf.replace("<use_password>no</use_password>", "<use_password>yes</use_password>")
    # Guarda também o que não virou alerta: é o log bruto que investigação e auditoria pedem.
    # A organização pode abrir mão para economizar disco, e aí só os alertas ficam selados.
    if guardar_logs:
        conf = conf.replace("<logall_json>no</logall_json>", "<logall_json>yes</logall_json>")
    else:
        conf = conf.replace("<logall_json>yes</logall_json>", "<logall_json>no</logall_json>")
    # O detector de vulnerabilidades e o inventário gravam nos índices de estado deste gerenciador, pelo portão.
    for bloco in ("vulnerability-detection", "indexer"):
        conf = re.sub(rf"(<{bloco}>\s*<enabled>)no(</enabled>)", lambda m: f"{m[1]}yes{m[2]}", conf)
    # O gerenciador vigiava o próprio contêiner: medição de disco a cada seis minutos, varreduras e inventário dele.
    # Eram quase metade dos logs brutos, sem nada a investigar. Os agentes têm configuração própria e não mudam.
    conf = re.sub(r"(<sca>\s*<enabled>)yes(</enabled>)", lambda m: f"{m[1]}no{m[2]}", conf)
    conf = re.sub(r"(<rootcheck>\s*<disabled>)no(</disabled>)", lambda m: f"{m[1]}yes{m[2]}", conf)
    conf = re.sub(r'(<wodle name="syscollector">\s*<disabled>)no(</disabled>)', lambda m: f"{m[1]}yes{m[2]}", conf)
    conf = re.sub(r"\s*<localfile>\s*<log_format>(?:full_)?command</log_format>.*?</localfile>", "", conf, flags=re.S)
    # O conector pede, sem parar, para criar modelos de índice, e essa permissão afetaria todos os clientes.
    # O portão responde esses pedidos; o resto vai ao indexador com a credencial deste gerenciador.
    conf = re.sub(r"(<indexer>.*?<host>)[^<]*(</host>)", rf"\g<1>https://{ip_do_portao()}:{PORTAO_PORTA}\g<2>", conf, count=1, flags=re.S)
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
        # O compose declara também o coletor: sem a pasta das bases de localização, nem o gerenciador sobe.
        "GEOIP": _bases_de_localizacao(),
    }
    (pasta / ".env").write_text("".join(f"{k}={v}\n" for k, v in variaveis.items()))
    (pasta / ".env").chmod(0o600)

    _syslog_do_coletor(pasta, [])

    _compose(pasta, gerenciador_id, "up", "-d", "gerenciador")
    ligar_coletor(gerenciador_id)
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


@contextmanager
def trava(gerenciador_id):
    """Uma coisa por vez no gerenciador: o teste de parser grava um decodificador provisório, que não pode estar
    lá quando a configuração é validada ou o gerenciador reinicia. Vale entre serviços: é um arquivo travado."""
    caminho = DESTINO / "gerenciadores" / gerenciador_id / "gerenciador.trava"
    with open(caminho, "a") as arquivo:
        fcntl.flock(arquivo, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(arquivo, fcntl.LOCK_UN)


def _configuracao_valida(gerenciador_id, programas=("wazuh-analysisd",)):
    # Usa o binário do Wazuh: a validação pela API estoura o tempo com milhares de regras.
    # Na dúvida, reprova: quem chama volta ao arquivo anterior e não reinicia nada.
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    with trava(gerenciador_id):
        for programa in programas:
            r = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                                "exec", "-T", "gerenciador", f"/var/ossec/bin/{programa}", "-t"],
                               capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                return False, {"status": "erro", "saida": (r.stderr or r.stdout)[-400:]}
    return True, {"status": "OK", "saida": ""}


def _reiniciar(pasta, gerenciador_id):
    with trava(gerenciador_id):
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "/var/ossec/bin/wazuh-control", "restart")
    _garantir_api(pasta, gerenciador_id)


DECODIFICADOR_DE_TESTE = "/var/ossec/etc/decoders/roar_teste_parser.xml"


def testar_log(gerenciador_id, log, xml=None):
    """Roda um log no teste do gerenciador, que lê os decodificadores do disco a cada sessão. Com xml, o
    decodificador fica no disco só durante o teste, com o gerenciador travado. Devolve a saída do teste."""
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    with trava(gerenciador_id):
        if xml:
            subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                            "exec", "-T", "gerenciador", "sh", "-c",
                            f"cat > {DECODIFICADOR_DE_TESTE} && chown wazuh:wazuh {DECODIFICADOR_DE_TESTE} && chmod 660 {DECODIFICADOR_DE_TESTE}"],
                           input=xml, capture_output=True, text=True, check=True, timeout=60)
        try:
            dados = _api_do_gerenciador(gerenciador_id, "PUT", "/logtest", json={"event": log, "log_format": "syslog", "location": "roar-teste"})["data"]
        finally:
            if xml:
                _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "rm", "-f", DECODIFICADOR_DE_TESTE)
    try:
        _api_do_gerenciador(gerenciador_id, "DELETE", f"/logtest/sessions/{dados['token']}")
    except (requests.RequestException, KeyError):
        pass  # A sessão expira sozinha.
    return {"saida": dados.get("output") or {}, "mensagens": [m for m in dados.get("messages", []) if "WARNING" in m or "ERROR" in m][:10]}


def aplicar_regras(gerenciador_id, nome, xml, reiniciar=True, tipo="rules"):
    """Instala um arquivo de regras, ou de decodificadores com tipo="decoders". Se a validação reprovar, volta ao
    anterior e não reinicia.

    Copia direto para o contêiner porque a API do Wazuh estoura o tempo com arquivos grandes.
    """
    if not re.fullmatch(r"roar_[a-z0-9_]+\.xml", nome) or tipo not in ("rules", "decoders"):
        raise ValueError("nome de arquivo de regras inválido")
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    caminho = f"/var/ossec/etc/{tipo}/{nome}"
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
        _reiniciar(pasta, gerenciador_id)
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


def aplicar_yara(gerenciador_id, regras, scripts, decodificadores, deteccoes, nome_das_deteccoes, grupo="default"):
    """Decodificador e detecção ficam mesmo sem regras: sozinhos não fazem nada. Sem regras, a pasta dos agentes esvazia."""
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    compartilhada = f"/var/ossec/etc/shared/{grupo}"
    copia = pasta / "yara.tmp"

    def copiar(conteudo, caminho):
        copia.write_bytes(conteudo.encode("utf-8"))
        _compose(pasta, gerenciador_id, "cp", str(copia), f"gerenciador:{caminho}")
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chown", "wazuh:wazuh", caminho)
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chmod", "660", caminho)

    if not regras:
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "rm", "-f", f"{compartilhada}/roar_yara.yar", *(f"{compartilhada}/{nome}" for nome in scripts))
        return True, {"status": "OK", "saida": ""}
    copiar(decodificadores, "/var/ossec/etc/decoders/roar_yara.xml")
    ok, detalhe = aplicar_regras(gerenciador_id, nome_das_deteccoes, deteccoes, reiniciar=False)
    if ok:
        copiar(regras, f"{compartilhada}/roar_yara.yar")
        for nome, conteudo in scripts.items():
            copiar(conteudo, f"{compartilhada}/{nome}")
    else:
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "rm", "-f", "/var/ossec/etc/decoders/roar_yara.xml")
    copia.unlink(missing_ok=True)
    return ok, detalhe


PASTA_DAS_LISTAS = "/var/ossec/etc/lists/roar"


def instalar_listas(gerenciador_id, arquivos):
    """Grava as listas de observação. Só acrescenta e troca: a configuração em uso ainda pode citar uma lista
    apagada, e lista citada que falta derruba o analisador ao reiniciar. O que sobrou sai com remover_listas."""
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "sh", "-c",
             f"mkdir -p {PASTA_DAS_LISTAS} && chown wazuh:wazuh {PASTA_DAS_LISTAS} && chmod 770 {PASTA_DAS_LISTAS}")
    copia = pasta / "lista.tmp"
    for nome, conteudo in arquivos.items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", nome):
            raise ValueError("nome de lista inválido")
        copia.write_bytes(conteudo.encode("utf-8"))
        caminho = f"{PASTA_DAS_LISTAS}/{nome}"
        _compose(pasta, gerenciador_id, "cp", str(copia), f"gerenciador:{caminho}")
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chown", "wazuh:wazuh", caminho)
        _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "chmod", "660", caminho)
    copia.unlink(missing_ok=True)


def remover_listas(gerenciador_id, manter):
    """Depois que a configuração nova entrou: tira as listas que ela não cita mais, com o arquivo compilado junto."""
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    existentes = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                                 "exec", "-T", "gerenciador", "ls", "-1", PASTA_DAS_LISTAS], capture_output=True, text=True).stdout.split()
    sobrando = {n.removesuffix(".cdb") for n in existentes} - set(manter)
    for nome in sobrando:
        if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", nome):
            _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "rm", "-f", f"{PASTA_DAS_LISTAS}/{nome}", f"{PASTA_DAS_LISTAS}/{nome}.cdb")
    return len(sobrando)


def enviar_eventos(gerenciador_id, eventos):
    """Entrega ao analisador do gerenciador, que aplica as mesmas regras de qualquer outro log."""
    return _api_do_gerenciador(gerenciador_id, "POST", "/events", json={"events": eventos})


def remover_regras(gerenciador_id, nome, tipo="rules"):
    """Tira um arquivo de regras ou de decodificadores. Se nunca foi instalado, não reinicia nada."""
    if not re.fullmatch(r"roar_[a-z0-9_]+\.xml", nome) or tipo not in ("rules", "decoders"):
        raise ValueError("nome de arquivo de regras inválido")
    pasta = DESTINO / "gerenciadores" / gerenciador_id
    caminho = f"/var/ossec/etc/{tipo}/{nome}"
    existe = subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                             "exec", "-T", "gerenciador", "test", "-f", caminho], capture_output=True)
    if existe.returncode != 0:
        return True, {"status": "OK", "saida": ""}
    _compose(pasta, gerenciador_id, "exec", "-T", "gerenciador", "rm", "-f", caminho)
    valida, detalhe = _configuracao_valida(gerenciador_id)
    if valida:
        _reiniciar(pasta, gerenciador_id)
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


def com_listas(conf, declaracoes):
    """As listas entram no <ruleset> que já existe: um segundo bloco faz o analisador não carregar lista nenhuma."""
    if not declaracoes:
        return conf
    if conf.count("</ruleset>") != 1:
        raise ValueError("a configuração base precisa ter um único <ruleset>")
    return conf.replace("</ruleset>", declaracoes + "  </ruleset>")


def aplicar_configuracao(gerenciador_id, fragmento, arquivos=None, guardar_logs=True, listas=""):
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
    novo.write_text(com_listas(configuracao_do_gerenciador(CONF_BASE.read_text(), guardar_logs), listas) + fragmento)
    instalar(novo)
    _instalar_credenciais(pasta, gerenciador_id, arquivos)
    # O analisador sozinho aprova um syslog inválido, que só derrubaria o recebimento ao reiniciar.
    valida, detalhe = _configuracao_valida(gerenciador_id, ("wazuh-analysisd", "wazuh-remoted", "wazuh-modulesd"))
    if not valida:
        instalar(anterior)
        _instalar_credenciais(pasta, gerenciador_id, arquivos_anteriores)
        return False, detalhe

    def reiniciar():
        with trava(gerenciador_id):
            return subprocess.run(["docker", "compose", "--project-directory", str(pasta), "--project-name", f"roar-ger-{gerenciador_id}",
                                   "exec", "-T", "gerenciador", "/var/ossec/bin/wazuh-control", "restart"],
                                  capture_output=True, text=True, timeout=600)

    resultado = reiniciar()
    if resultado.returncode != 0:
        # A coleta do cliente não pode ficar parada: volta ao que funcionava e sobe de novo.
        instalar(anterior)
        _instalar_credenciais(pasta, gerenciador_id, arquivos_anteriores)
        reiniciar()
        _garantir_api(pasta, gerenciador_id)
        return False, {"status": "erro", "saida": (resultado.stderr or resultado.stdout)[-400:]}
    _garantir_api(pasta, gerenciador_id)
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
    adm = armazem.admin(env)
    armazem.remover_gravador(adm, gerenciador_id)
    usuario = f"roar_ger_{gerenciador_id}"
    for rota in (f"_plugins/_security/api/internalusers/{usuario}", f"_plugins/_security/api/roles/{usuario}"):
        indexer.sessao.delete(f"{indexer.url}/{rota}", timeout=60)
    if apagar_dados:
        apagar_retencao(indexer, gerenciador_id)
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
                armazem.remover_organizacao(adm, cliente[0])
                # A mesma varredura da remoção de organização: tabela nova não fica para trás.
                varrer(banco, cliente[0])
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
