"""O armazém de eventos no ClickHouse: um banco por organização, com os logs e os alertas.

Quem grava é o coletor (Vector) de cada gerenciador, com um usuário que só insere no banco daquela organização. Quem lê
usa o usuário de leitura, e o banco consultado sai sempre da organização da sessão, nunca do pedido. A conversa é pela
interface HTTP, com parâmetros: nenhum valor vindo de fora é colado no SQL. Desenho em docs/clickhouse.md.
"""

import hashlib
import json
import re

import requests

TEMPO = 120
ADMIN = "roar_admin"
LEITOR = "roar_leitor"
PERFIL_DO_LEITOR = "roar_leitura"
# Log hostil ou gigante não pode derrubar a tela: o mesmo limite de 256 KiB da ingestão antiga, cortado no coletor.
TAMANHO_MAXIMO = 262144
DIAS_QUENTES_PADRAO = 30
NOME_DE_GERENCIADOR = re.compile(r"[a-z0-9]{6,32}")
TABELAS = ("logs", "alertas")
# O resumo por hora de cada origem: o bastante para comparar com as semanas anteriores.
DIAS_DO_RESUMO = 35

COLUNAS = """
    id UUID,
    ocorrido_em DateTime64(3, 'UTC'),
    recebido_em DateTime64(3, 'UTC') DEFAULT now64(3),
    gerenciador LowCardinality(String),
    origem_id String,
    agente_id LowCardinality(String),
    agente_nome LowCardinality(String),
    agente_ip String,
    local String,
    decoder LowCardinality(String),
    regra_id LowCardinality(String),
    nivel UInt8,
    regra_descricao String,
    regra_grupos Array(LowCardinality(String)),
    mitre Array(LowCardinality(String)),
    ip_origem String,
    ip_destino String,
    usuario String,
    usuario_destino String,
    full_log String CODEC(ZSTD(3)),
    dados String CODEC(ZSTD(3)),
    tamanho_original UInt32,
    resumo_do_original String,
    INDEX ix_ip_origem ip_origem TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX ix_usuario usuario TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX ix_regra regra_id TYPE set(1000) GRANULARITY 4,
    INDEX ix_texto lower(full_log) TYPE ngrambf_v1(4, 65536, 3, 0) GRANULARITY 4
"""


# Colunas que vieram depois da primeira versão: entram também nas tabelas que já existem, sem recriar nada.
COLUNAS_NOVAS = (
    ("pais", "LowCardinality(String)"), ("cidade", "LowCardinality(String)"), ("regiao", "LowCardinality(String)"),
    ("operadora", "LowCardinality(String)"), ("asn", "LowCardinality(String)"),
    ("mitre_tecnicas", "Array(LowCardinality(String))"), ("mitre_taticas", "Array(LowCardinality(String))"),
)


class ArmazemRecusou(Exception):
    pass


class Armazem:
    def __init__(self, usuario, senha, url, sessao=None):
        self.url, self.usuario, self.senha = url, usuario, senha
        self.sessao = sessao or requests.Session()

    def executar(self, sql, parametros=None, formato=None):
        """Roda uma instrução. Os parâmetros vão separados ({nome:Tipo} no SQL), e o ClickHouse é quem os encaixa."""
        corpo = sql + (f" FORMAT {formato}" if formato else "")
        dados = {f"param_{k}": v for k, v in (parametros or {}).items()}
        r = self.sessao.post(self.url, params=dados, data=corpo.encode(), auth=(self.usuario, self.senha), timeout=TEMPO)
        if r.status_code != 200:
            raise ArmazemRecusou(r.text[:500])
        return r

    def linhas(self, sql, parametros=None):
        return [json.loads(linha) for linha in self.executar(sql, parametros, "JSONEachRow").text.splitlines() if linha]


def url(env):
    # A porta muda quando a máquina já tem outro ClickHouse na 8123 (ARMAZEM_PORTA no .env).
    return f"http://127.0.0.1:{int(env.get('ARMAZEM_PORTA') or 8123)}"


def leitor(env):
    """Quem só lê, para a API e os serviços. Sem a senha no ambiente (instalação antiga), não há armazém para ler."""
    return Armazem(LEITOR, env["ARMAZEM_LEITOR_SENHA"], url(env)) if env.get("ARMAZEM_LEITOR_SENHA") else None


def admin(env):
    return Armazem(ADMIN, env["ARMAZEM_SENHA"], url(env))


def _hash_da_senha(senha):
    # Só o hash vai ao ClickHouse, e ele é hexadecimal: pode entrar no texto do comando sem risco.
    return hashlib.sha256(senha.encode()).hexdigest()


def banco_do(cliente_id):
    """O nome do banco sai do id da organização (uuid), nunca de um texto livre."""
    nome = str(cliente_id).replace("-", "").lower()
    if not re.fullmatch(r"[0-9a-f]{32}", nome):
        raise ValueError("id de organização inválido")
    return f"roar_c_{nome}"


def usuario_do(gerenciador_id):
    if not NOME_DE_GERENCIADOR.fullmatch(gerenciador_id):
        raise ValueError("id de gerenciador inválido")
    return f"roar_ger_{gerenciador_id}"


def ttl(dias, dias_quentes):
    """Os dias mais novos ficam no disco rápido; depois vão para o frio, e somem ao fim da retenção."""
    dias, dias_quentes = int(dias), int(dias_quentes)
    partes = []
    if dias_quentes < dias:
        partes.append(f"toDateTime(ocorrido_em) + INTERVAL {dias_quentes} DAY TO VOLUME 'frio'")
    partes.append(f"toDateTime(ocorrido_em) + INTERVAL {dias} DAY DELETE")
    return ", ".join(partes)


def preparar(armazem, senha_do_leitor):
    """O que vale para todas as organizações: o perfil e o usuário de leitura."""
    # Cota de quem lê: uma busca pesada de uma organização não trava a tela das outras.
    armazem.executar(f"""CREATE SETTINGS PROFILE OR REPLACE {PERFIL_DO_LEITOR} SETTINGS readonly = 1, max_execution_time = 60,
                         max_memory_usage = 4000000000, max_result_rows = 100000, max_threads = 8""")
    armazem.executar(f"CREATE USER IF NOT EXISTS {LEITOR} IDENTIFIED WITH sha256_hash BY '{_hash_da_senha(senha_do_leitor)}' SETTINGS PROFILE {PERFIL_DO_LEITOR}")
    armazem.executar(f"ALTER USER {LEITOR} IDENTIFIED WITH sha256_hash BY '{_hash_da_senha(senha_do_leitor)}' SETTINGS PROFILE {PERFIL_DO_LEITOR}")
    # O disco ocupado por dia, para a tela de Armazenamento. Só estas colunas; o banco consultado sai da sessão, na API.
    armazem.executar(f"GRANT SELECT(database, table, partition, bytes_on_disk, active) ON system.parts TO {LEITOR}")


def criar_organizacao(armazem, cliente_id, dias_alertas, dias_logs, dias_quentes=DIAS_QUENTES_PADRAO):
    """Banco e tabelas da organização. Pode rodar de novo: o que já existe fica, e a retenção é reaplicada."""
    banco = banco_do(cliente_id)
    armazem.executar(f"CREATE DATABASE IF NOT EXISTS {banco}")
    for tabela, dias in (("logs", dias_logs), ("alertas", dias_alertas)):
        armazem.executar(f"""CREATE TABLE IF NOT EXISTS {banco}.{tabela} ({COLUNAS})
                             ENGINE = MergeTree
                             PARTITION BY toYYYYMMDD(ocorrido_em)
                             ORDER BY (toStartOfHour(ocorrido_em), agente_id, ocorrido_em)
                             TTL {ttl(dias, dias_quentes)}
                             SETTINGS storage_policy = 'roar', ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000""")
        for coluna, tipo in COLUNAS_NOVAS:
            armazem.executar(f"ALTER TABLE {banco}.{tabela} ADD COLUMN IF NOT EXISTS {coluna} {tipo}")
    criar_resumo_das_origens(armazem, banco)
    aplicar_retencao(armazem, cliente_id, dias_alertas, dias_logs, dias_quentes)
    armazem.executar(f"GRANT SELECT ON {banco}.* TO {LEITOR}")
    return banco


def criar_resumo_das_origens(armazem, banco):
    """Eventos por hora de cada origem (o endereço do equipamento no syslog, o módulo na nuvem, o arquivo no agente):
    quantos chegaram, quantos o gerenciador entendeu e o último. A saúde das fontes lê daqui, sem varrer os logs. A visão
    soma cada gravação do coletor; na primeira vez, o que já estava gravado entra de uma vez."""
    novo = armazem.linhas("SELECT count() AS n FROM system.tables WHERE database = {b:String} AND name = 'origens_por_hora'", {"b": banco})[0]["n"] in (0, "0")
    armazem.executar(f"""CREATE TABLE IF NOT EXISTS {banco}.origens_por_hora (
                             hora DateTime('UTC'),
                             gerenciador LowCardinality(String),
                             agente_id LowCardinality(String),
                             local String,
                             eventos SimpleAggregateFunction(sum, UInt64),
                             entendidos SimpleAggregateFunction(sum, UInt64),
                             ultimo SimpleAggregateFunction(max, DateTime64(3, 'UTC')))
                         ENGINE = AggregatingMergeTree
                         PARTITION BY toYYYYMM(hora)
                         ORDER BY (gerenciador, local, agente_id, hora)
                         TTL hora + INTERVAL {DIAS_DO_RESUMO} DAY""")
    selecao = f"""SELECT toStartOfHour(ocorrido_em) AS hora, gerenciador, agente_id, local, count() AS eventos,
                         countIf(notEmpty(decoder)) AS entendidos, max(ocorrido_em) AS ultimo FROM {banco}.logs"""
    # A visão roda a cada gravação do coletor, e o coletor não lê nada: ela usa a permissão de quem a criou. Sem isso, o
    # armazém grava os logs mas devolve erro ao coletor, que descarta o lote achando que falhou.
    armazem.executar(f"""CREATE MATERIALIZED VIEW IF NOT EXISTS {banco}.origens_por_hora_visao TO {banco}.origens_por_hora
                         DEFINER = CURRENT_USER SQL SECURITY DEFINER AS {selecao} GROUP BY hora, gerenciador, agente_id, local""")
    armazem.executar(f"ALTER TABLE {banco}.origens_por_hora_visao MODIFY DEFINER = CURRENT_USER SQL SECURITY DEFINER")
    if novo:
        # Só o que chegou antes da visão existir: o que chega depois, ela mesma soma.
        corte = armazem.linhas("SELECT toString(now64(3)) AS t")[0]["t"]
        armazem.executar(f"""INSERT INTO {banco}.origens_por_hora {selecao}
                             WHERE ocorrido_em >= now64(3) - INTERVAL {DIAS_DO_RESUMO} DAY AND recebido_em < toDateTime64({{c:String}}, 3)
                             GROUP BY hora, gerenciador, agente_id, local""", {"c": corte})


def aplicar_retencao(armazem, cliente_id, dias_alertas, dias_logs, dias_quentes=DIAS_QUENTES_PADRAO):
    banco = banco_do(cliente_id)
    # Organização sem gerenciador ainda não tem banco: a regra entra quando ele for criado.
    if armazem.linhas("SELECT count() AS n FROM system.databases WHERE name = {banco:String}", {"banco": banco})[0]["n"] in (0, "0"):
        return
    for tabela, dias in (("logs", dias_logs), ("alertas", dias_alertas)):
        # Só troca a regra: o ClickHouse aplica aos poucos, nas próximas junções, sem reescrever tudo agora.
        armazem.executar(f"ALTER TABLE {banco}.{tabela} MODIFY TTL {ttl(dias, dias_quentes)} SETTINGS materialize_ttl_after_modify = 0")


def criar_gravador(armazem, gerenciador_id, cliente_id, senha):
    """O usuário do coletor de um gerenciador: só insere nas tabelas da própria organização, e não lê nada."""
    banco, usuario = banco_do(cliente_id), usuario_do(gerenciador_id)
    armazem.executar(f"CREATE USER IF NOT EXISTS {usuario} IDENTIFIED WITH sha256_hash BY '{_hash_da_senha(senha)}'")
    armazem.executar(f"ALTER USER {usuario} IDENTIFIED WITH sha256_hash BY '{_hash_da_senha(senha)}'")
    armazem.executar(f"REVOKE ALL ON *.* FROM {usuario}")
    for tabela in TABELAS:
        armazem.executar(f"GRANT INSERT ON {banco}.{tabela} TO {usuario}")
    return usuario


def remover_gravador(armazem, gerenciador_id):
    armazem.executar(f"DROP USER IF EXISTS {usuario_do(gerenciador_id)}")


def documento_original(linha):
    """O log exatamente como o gerenciador gravou (o JSON do Wazuh), sem o que o armazém acrescentou. É o que os selos
    selam e o que a perícia entrega. Log grande demais ficou só com o começo e o resumo do original."""
    if linha.get("dados"):
        try:
            documento = json.loads(linha["dados"])
            if isinstance(documento, dict):
                return documento
        except ValueError:
            pass
    return {"full_log": linha.get("full_log", ""), "resumo_do_original": linha.get("resumo_do_original", "")}


def remover_organizacao(armazem, cliente_id):
    armazem.executar(f"DROP DATABASE IF EXISTS {banco_do(cliente_id)}")
