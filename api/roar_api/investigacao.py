"""Investigação de um alerta: as perguntas que um analista faria, respondidas pelo próprio Roar, sem IA.

Cada pergunta roda uma consulta fixa nos alertas, no risco das pessoas, nos ativos e, quando a organização lê do armazém,
nos logs e nos fluxos de rede. A resposta vem com o tom (agrava, atenua ou só informa) e os alertas que a provam, para
o analista conferir com um clique. A janela é de 24 horas antes e depois do alerta.

A primeira pergunta é sobre o próprio alerta: quantos eventos ele juntou, em quanto tempo, a técnica e os arquivos. As
outras só aparecem quando cabem (sem origem, sem conta, alerta do próprio gerenciador): melhor nenhuma resposta que uma
vazia. Uma IA que vier depois lê este mesmo pacote, e só pode citar o que estiver nele.
"""

import ipaddress
from collections import Counter
from datetime import timedelta

from roar_ueba.identidade import chave_do_usuario

JANELA = timedelta(hours=24)
LIMITE_DE_ALERTAS = 500
CITADOS = 5
# Mesmos grupos do motor de risco (ueba/roar_ueba/motor.py).
GRUPOS_SUCESSO = {"authentication_success"}
GRUPOS_FALHA = {"authentication_failed", "authentication_failures", "invalid_login"}
NIVEL_GRAVE = 7
# Instalação e atualização de pacotes (Debian, Red Hat, Windows): trocam muitos arquivos de uma vez.
GRUPOS_PACOTE = {"dpkg", "yum", "rpm", "apt", "msi", "windows_update"}
# A partir de quantas contas tentadas pelo mesmo endereço o padrão é de pulverização de senhas.
CONTAS_DE_PULVERIZACAO = 5
# Volume que sai da rede para um endereço de fora a partir do qual vale olhar: 50 MB.
SAIDA_GRANDE = 50 * 1024 * 1024
AGENTE_DO_GERENCIADOR = "000"
# Os mesmos nomes da tela (web/src/formato.ts, SINAIS e CRITICIDADES).
SINAIS = {
    "sucesso_apos_falhas": "acesso depois de várias falhas", "viagem_impossivel": "viagem impossível", "primeiro_privilegio": "primeiro uso de um privilégio",
    "pico_de_falhas": "pico de falhas de acesso", "primeiro_host": "ativo nunca usado", "horario_incomum": "horário fora do padrão", "primeiro_ip": "endereço nunca usado",
    "host_raro_no_cliente": "ativo incomum na organização", "ioc_tocado": "contato com indicador de ameaça", "grupo_administrativo": "entrada em grupo administrativo",
    "arquivo_sensivel": "arquivo sensível alterado", "conta_criada": "conta criada", "pessoa_em_risco": "pessoa em risco entrou",
    "ativo_em_risco": "entrada em ativo em risco", "regra_disparada": "regra disparada", "taticas_em_sequencia": "várias táticas do ATT&CK",
}
CRITICIDADES = {"baixa": "baixa", "normal": "normal", "alta": "alta", "critica": "crítica"}


def _citar(alertas):
    """Os mais graves primeiro e, entre eles, os mais antigos: é o começo da história."""
    escolhidos = sorted(alertas, key=lambda a: (-a["nivel"], a["ocorrido_em"]))[:CITADOS]
    return [{"id": a["id"], "quando": a["ocorrido_em"].isoformat(), "descricao": a["regra_descricao"] or a["regra_id"],
             "ip": a["ip"], "usuario": a["usuario"], "ativo": a["agente_nome"]} for a in sorted(escolhidos, key=lambda a: a["ocorrido_em"])]


def _plural(n, um, varios):
    return f"{n} {um if n == 1 else varios}"


def _bytes(n):
    for unidade in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unidade == "TB":
            return f"{n:.0f} {unidade}" if unidade == "bytes" else f"{n:.1f} {unidade}".replace(".", ",")
        n /= 1024


def _interno(ip):
    try:
        endereco = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return endereco.is_private or endereco.is_loopback or endereco.is_link_local


def _pergunta(chave, pergunta, resposta, tom, como, eventos=None):
    return {"id": chave, "pergunta": pergunta, "resposta": resposta, "tom": tom, "como": como, "eventos": eventos or []}


def _alertas(con, coluna, valor, alerta, extra=""):
    return con.execute(
        f"""SELECT id, ocorrido_em, nivel, regra_id, regra_descricao, regra_grupos, agente_id, agente_nome, host(ip_origem) AS ip, usuario, pais
            FROM eventos WHERE {coluna} = %s AND ocorrido_em BETWEEN %s AND %s AND id <> %s {extra}
            ORDER BY ocorrido_em LIMIT {LIMITE_DE_ALERTAS}""",
        (valor, alerta["ocorrido_em"] - JANELA, alerta["ocorrido_em"] + JANELA, alerta["id"])).fetchall()


def _enderecos_conhecidos(con, usuario, antes):
    """Os endereços de onde a conta já entrava pelo menos um dia antes do alerta, pelo risco das pessoas."""
    chave = chave_do_usuario(usuario) if usuario else None
    if not chave:
        return set()
    return {l["valor"] for l in con.execute(
        """SELECT v.valor FROM vistos v JOIN entidades e ON e.id = v.entidade_id
           WHERE e.tipo = 'usuario' AND e.chave = %s AND v.dimensao = 'ip' AND v.primeira_vez < %s""",
        (chave, antes - timedelta(days=1))).fetchall()}


def do_alerta(con, alerta):
    """O que o próprio alerta juntou: quantos eventos, em quanto tempo, a técnica de ataque e os arquivos mexidos."""
    if alerta["grupo_id"]:
        irmaos = con.execute(
            """SELECT id, ocorrido_em, nivel, regra_id, regra_descricao, agente_nome, host(ip_origem) AS ip, usuario, bruto #>> '{syscheck,path}' AS arquivo
               FROM eventos WHERE grupo_id = %s ORDER BY ocorrido_em LIMIT 2000""", (alerta["grupo_id"],)).fetchall()
        como = "Os eventos que o Roar juntou neste mesmo alerta, na Fila."
    else:
        irmaos = con.execute(
            """SELECT id, ocorrido_em, nivel, regra_id, regra_descricao, agente_nome, host(ip_origem) AS ip, usuario, bruto #>> '{syscheck,path}' AS arquivo
               FROM eventos WHERE regra_id = %s AND gerenciador_id = %s AND agente_id = %s AND ocorrido_em BETWEEN %s AND %s
               ORDER BY ocorrido_em LIMIT 2000""",
            (alerta["regra_id"], alerta["gerenciador_id"], alerta["agente_id"], alerta["ocorrido_em"] - timedelta(hours=1), alerta["ocorrido_em"] + timedelta(hours=1))).fetchall()
        como = "Eventos da mesma regra no mesmo ativo, uma hora antes e depois."
    if not irmaos:
        return []
    minutos = round((irmaos[-1]["ocorrido_em"] - irmaos[0]["ocorrido_em"]).total_seconds() / 60)
    duracao = "em menos de um minuto" if minutos < 1 else f"em {_plural(minutos, 'minuto', 'minutos')}"
    partes = [f"{_plural(len(irmaos), 'evento', 'eventos')}" + (f" {duracao}" if len(irmaos) > 1 else ""),
              f"nível {alerta['nivel']}"]
    if alerta["mitre"]:
        partes.append(f"técnica {', '.join(alerta['mitre'][:3])}")
    arquivos = sorted({i["arquivo"] for i in irmaos if i["arquivo"]})
    resposta = (alerta["regra_descricao"] or alerta["regra_id"]).rstrip(". ") + ": " + ", ".join(partes) + "."
    citados = list(irmaos)
    atualizacao = None
    if arquivos:
        resposta += f" {_plural(len(arquivos), 'arquivo mexido', 'arquivos diferentes mexidos')}, como {', '.join(arquivos[:3])}."
        # Arquivos trocados logo depois de instalar ou atualizar um pacote no mesmo ativo: é o que a atualização faz.
        atualizacao = con.execute(
            """SELECT id, ocorrido_em, nivel, regra_id, regra_descricao, agente_nome, host(ip_origem) AS ip, usuario FROM eventos
               WHERE gerenciador_id = %s AND agente_id = %s AND regra_grupos && %s AND ocorrido_em BETWEEN %s AND %s
               ORDER BY ocorrido_em DESC LIMIT 1""",
            (alerta["gerenciador_id"], alerta["agente_id"], list(GRUPOS_PACOTE), irmaos[0]["ocorrido_em"] - timedelta(hours=1),
             irmaos[-1]["ocorrido_em"])).fetchone()
        if atualizacao:
            resposta += (f" Pouco antes, o ativo instalou ou atualizou um pacote ({(atualizacao['regra_descricao'] or atualizacao['regra_id']).rstrip('. ')}),"
                         " o que costuma trocar muitos arquivos de uma vez.")
            citados.append(atualizacao)
    tom = "informa" if atualizacao and alerta["nivel"] < 12 else "agrava" if alerta["nivel"] >= 12 or len(arquivos) >= 20 else "informa"
    return [_pergunta("alerta", "O que o próprio alerta mostra?", resposta, tom, como, _citar(citados))]


def da_origem(con, alerta):
    ip = alerta["ip"]
    vizinhos = _alertas(con, "ip_origem", ip, alerta)
    como = f"Alertas vindos de {ip} entre 24 horas antes e 24 horas depois deste."
    perguntas = []
    if not vizinhos:
        perguntas.append(_pergunta("origem", "O que mais veio desse endereço?", "Nenhum outro alerta desse endereço nas 24 horas antes e depois.", "atenua", como))
    else:
        ativos = {a["agente_nome"] or a["agente_id"] for a in vizinhos}
        contas = {a["usuario"] for a in vizinhos if a["usuario"]}
        regras = Counter((a["regra_descricao"] or a["regra_id"]).rstrip(". ") for a in vizinhos)
        partes = [f"{_plural(len(vizinhos), 'outro alerta', 'outros alertas')} desse endereço", f"em {_plural(len(ativos), 'ativo', 'ativos')}"]
        if contas:
            partes.append(f"contra {_plural(len(contas), 'conta', 'contas')}")
        resposta = " ".join(partes) + f". O mais comum: {regras.most_common(1)[0][0]} ({regras.most_common(1)[0][1]})."
        falhas = [a for a in vizinhos if set(a["regra_grupos"]) & GRUPOS_FALHA]
        contas_com_falha = {a["usuario"] for a in falhas if a["usuario"]}
        if len(contas_com_falha) >= CONTAS_DE_PULVERIZACAO:
            resposta += (f" O mesmo endereço errou a senha em {len(contas_com_falha)} contas diferentes: é o padrão de quem testa uma"
                         " senha em muitas contas (pulverização de senhas).")
        if len(vizinhos) >= LIMITE_DE_ALERTAS:
            resposta = "Mais de " + resposta[0].lower() + resposta[1:]
        espalhado = len(ativos) > 1 or len(contas) > 2 or any(a["nivel"] >= NIVEL_GRAVE for a in vizinhos)
        perguntas.append(_pergunta("origem", "O que mais veio desse endereço?", resposta, "agrava" if espalhado else "informa", como, _citar(vizinhos)))

    falhou = bool(set(alerta["regra_grupos"]) & GRUPOS_FALHA)
    entradas = [a for a in vizinhos if set(a["regra_grupos"]) & GRUPOS_SUCESSO]
    depois = [a for a in entradas if a["ocorrido_em"] >= alerta["ocorrido_em"]]
    como = f"Logins com sucesso vindos de {ip} na mesma janela."
    if falhou and depois:
        contas = sorted({a["usuario"] for a in depois if a["usuario"]})
        # A própria pessoa errando a senha e acertando depois, da máquina de sempre, é o caso mais comum de todos.
        de_sempre = alerta["usuario"] and contas == [alerta["usuario"]] and ip in _enderecos_conhecidos(con, alerta["usuario"], alerta["ocorrido_em"])
        if de_sempre:
            resposta = (f"Sim, a própria conta {contas[0]}, desse mesmo endereço, que ela já usava antes: "
                        "parece alguém errando a senha e acertando depois.")
        else:
            resposta = (f"Sim. Depois das falhas, {_plural(len(depois), 'login deu certo', 'logins deram certo')} desse endereço"
                        + (f", na conta {', '.join(contas[:3])}" if contas else "") + ".")
        perguntas.append(_pergunta("entrou", "Alguém conseguiu entrar a partir desse endereço?", resposta, "informa" if de_sempre else "agrava", como, _citar(depois)))
    elif falhou:
        perguntas.append(_pergunta("entrou", "Alguém conseguiu entrar a partir desse endereço?",
                                   "Não há login com sucesso desse endereço depois das falhas.", "atenua", como))
    elif entradas:
        perguntas.append(_pergunta("entrou", "Alguém conseguiu entrar a partir desse endereço?",
                                   f"{_plural(len(entradas), 'login com sucesso', 'logins com sucesso')} desse endereço na janela.", "informa", como, _citar(entradas)))
    return perguntas


def da_conta(con, alerta):
    usuario = alerta["usuario"]
    perguntas = []
    vizinhos = _alertas(con, "usuario", usuario, alerta)
    como = f"Alertas da conta {usuario} entre 24 horas antes e 24 horas depois deste."
    if vizinhos:
        ips = {a["ip"] for a in vizinhos if a["ip"]}
        paises = {a["pais"] for a in vizinhos if a["pais"]}
        falhas = [a for a in vizinhos if set(a["regra_grupos"]) & GRUPOS_FALHA]
        partes = [f"{_plural(len(vizinhos), 'outro alerta', 'outros alertas')} dessa conta"]
        if ips:
            partes.append(f"de {_plural(len(ips), 'endereço', 'endereços')}")
        if len(paises) > 1:
            partes.append(f"em {len(paises)} países ({', '.join(sorted(paises)[:4])})")
        resposta = " ".join(partes) + "." + (f" {_plural(len(falhas), 'é login recusado', 'são logins recusados')}." if falhas else "")
        conhecidos = _enderecos_conhecidos(con, usuario, alerta["ocorrido_em"])
        # Muitas falhas só dos endereços de sempre da conta: senha vencida num serviço, não alguém de fora tentando.
        falhas_de_fora = [a for a in falhas if a["ip"] not in conhecidos]
        if falhas and not falhas_de_fora and conhecidos:
            resposta += " Todas as falhas vieram de endereços que a conta já usava antes."
        graves = [a for a in vizinhos if a["nivel"] >= NIVEL_GRAVE and not (set(a["regra_grupos"]) & GRUPOS_FALHA and a["ip"] in conhecidos)]
        tom = "agrava" if len(paises) > 1 or len(falhas_de_fora) >= 5 or graves else "informa"
        perguntas.append(_pergunta("conta", "O que mais aconteceu com essa conta?", resposta, tom, como, _citar(vizinhos)))
    else:
        perguntas.append(_pergunta("conta", "O que mais aconteceu com essa conta?", "Nenhum outro alerta dessa conta nas 24 horas antes e depois.", "informa", como))

    chave = chave_do_usuario(usuario)
    entidade = con.execute("SELECT id, risco, primeira_vista FROM entidades WHERE tipo = 'usuario' AND chave = %s", (chave,)).fetchone() if chave else None
    if not entidade:
        return perguntas
    if alerta["ip"]:
        visto = con.execute("SELECT primeira_vez, contagem FROM vistos WHERE entidade_id = %s AND dimensao = 'ip' AND valor = %s",
                            (entidade["id"], alerta["ip"])).fetchone()
        conhecidos = con.execute("SELECT count(*) AS n FROM vistos WHERE entidade_id = %s AND dimensao = 'ip'", (entidade["id"],)).fetchone()["n"]
        como = "Os endereços de onde essa conta já entrou, guardados pelo risco das pessoas."
        if visto and visto["primeira_vez"] < alerta["ocorrido_em"] - timedelta(days=1):
            perguntas.append(_pergunta("endereco_conhecido", "Essa conta costuma vir desse endereço?",
                                       f"Sim: desde {visto['primeira_vez']:%d/%m/%Y}, {_plural(visto['contagem'], 'vez', 'vezes')}.", "atenua", como))
        elif conhecidos:
            perguntas.append(_pergunta("endereco_conhecido", "Essa conta costuma vir desse endereço?",
                                       f"Não. É novo para essa conta, que já veio de {_plural(conhecidos, 'outro endereço', 'outros endereços')}.", "agrava", como))
    sinais = con.execute(
        """SELECT s.tipo, s.peso, s.ocorrido_em, s.evento_id FROM sinais s WHERE s.entidade_id = %s AND s.ocorrido_em BETWEEN %s AND %s
           ORDER BY s.peso DESC, s.ocorrido_em LIMIT 20""",
        (entidade["id"], alerta["ocorrido_em"] - timedelta(days=7), alerta["ocorrido_em"] + JANELA)).fetchall()
    risco = round(entidade["risco"])
    citados = []
    ids = [s["evento_id"] for s in sinais if s["evento_id"]][:CITADOS]
    if ids:
        citados = _citar(con.execute(
            """SELECT id, ocorrido_em, nivel, regra_id, regra_descricao, agente_nome, host(ip_origem) AS ip, usuario FROM eventos
               WHERE id = ANY(%s) AND ocorrido_em BETWEEN %s AND %s""",
            (ids, alerta["ocorrido_em"] - timedelta(days=8), alerta["ocorrido_em"] + JANELA)).fetchall())
    tipos = Counter(SINAIS.get(s["tipo"], s["tipo"].replace("_", " ")) for s in sinais)
    resposta = f"Risco atual {risco} de 100." + (f" Sinais na última semana: {', '.join(f'{t} ({n})' for t, n in tipos.most_common(4))}." if sinais else " Nenhum sinal na última semana.")
    perguntas.append(_pergunta("risco", "Essa pessoa já vinha se comportando diferente?", resposta,
                               "agrava" if risco >= 60 else "informa" if sinais else "atenua", "Os sinais do risco das pessoas dos 7 dias antes até 24 horas depois.", citados))
    return perguntas


def do_ativo(con, alerta):
    if alerta["agente_id"] == AGENTE_DO_GERENCIADOR:
        return []
    ativo = con.execute("SELECT nome, criticidade, sca_nota FROM ativos WHERE gerenciador_id = %s AND agente_id = %s",
                        (alerta["gerenciador_id"], alerta["agente_id"])).fetchone()
    nome = (ativo and ativo["nome"]) or alerta["agente_nome"] or alerta["agente_id"]
    graves = con.execute(
        f"""SELECT id, ocorrido_em, nivel, regra_id, regra_descricao, agente_nome, host(ip_origem) AS ip, usuario FROM eventos
            WHERE gerenciador_id = %s AND agente_id = %s AND nivel >= {NIVEL_GRAVE} AND ocorrido_em BETWEEN %s AND %s AND id <> %s
              AND regra_id <> %s
            ORDER BY ocorrido_em LIMIT {LIMITE_DE_ALERTAS}""",
        (alerta["gerenciador_id"], alerta["agente_id"], alerta["ocorrido_em"] - JANELA, alerta["ocorrido_em"] + JANELA, alerta["id"],
         # A mesma regra no mesmo ativo é o próprio alerta repetido, e já está na pergunta do alerta.
         alerta["regra_id"])).fetchall()
    critico = bool(ativo) and ativo["criticidade"] in ("alta", "critica")
    partes = []
    if graves:
        regras = Counter((a["regra_descricao"] or a["regra_id"]).rstrip(". ") for a in graves)
        partes.append(f"{_plural(len(graves), 'outro alerta grave', 'outros alertas graves')} em {nome}, o mais comum: {regras.most_common(1)[0][0]}.")
    else:
        partes.append(f"Nenhum outro alerta grave em {nome} nas 24 horas antes e depois.")
    if ativo:
        partes.append(f"Criticidade {CRITICIDADES.get(ativo['criticidade'], ativo['criticidade'])}" + (f", configuração segura com nota {ativo['sca_nota']}." if ativo["sca_nota"] is not None else "."))
    tom = "agrava" if graves and (critico or len(graves) >= 3) else "informa" if graves or critico else "atenua"
    return [_pergunta("ativo", "O que mais aconteceu nesse ativo?", " ".join(partes), tom,
                      f"Alertas de nível {NIVEL_GRAVE} ou mais no mesmo ativo, na mesma janela, e o cadastro dele.", _citar(graves))]


def do_armazem(armazem, banco, alerta):
    """Logs e fluxos de rede do endereço. O armazém fora do ar vira uma resposta, não um erro: o resto continua valendo."""
    ip = alerta["ip"]
    de, ate = alerta["ocorrido_em"] - JANELA, alerta["ocorrido_em"] + JANELA
    parametros = {"ip": ip, "de": de.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "ate": ate.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}
    janela = "ocorrido_em BETWEEN parseDateTime64BestEffort({de:String}, 3, 'UTC') AND parseDateTime64BestEffort({ate:String}, 3, 'UTC')"
    perguntas = []
    logs = armazem.linhas(f"""SELECT count() AS n, uniqExact(agente_id) AS ativos, groupArray(4)(decoder) AS leitores FROM (
                                  SELECT agente_id, decoder FROM {banco}.logs_leitura WHERE ip_origem = {{ip:String}} AND {janela})""", parametros)[0]
    n = int(logs["n"])
    como = f"Logs com origem {ip} no armazém, inclusive os que não viraram alerta, na mesma janela."
    if n:
        leitores = sorted({l for l in logs["leitores"] if l})
        perguntas.append(_pergunta("logs", "Quanto esse endereço aparece nos logs?",
                                   f"{_plural(n, 'log', 'logs')} com essa origem" + (f", lidos como {', '.join(leitores)}" if leitores else "") + ".", "informa", como))
    else:
        perguntas.append(_pergunta("logs", "Quanto esse endereço aparece nos logs?", "Nenhum log com essa origem além dos alertas.", "informa", como))

    if not int(armazem.linhas(f"SELECT count() AS n FROM {banco}.fluxos WHERE {janela}", parametros)[0]["n"]):
        return perguntas
    pares = armazem.linhas(
        f"""SELECT if(origem = {{ip:String}}, destino, origem) AS par, origem = {{ip:String}} AS dele, sum(bytes) AS bytes, count() AS fluxos,
                   topK(3)(porta_destino) AS portas
            FROM {banco}.fluxos WHERE (origem = {{ip:String}} OR destino = {{ip:String}}) AND {janela}
            GROUP BY par, dele ORDER BY bytes DESC LIMIT 200""", parametros)
    como = f"Fluxos de rede (NetFlow, IPFIX e sFlow) com {ip} de um lado, na mesma janela."
    if not pares:
        perguntas.append(_pergunta("fluxos", "Esse endereço trocou tráfego com a rede?", "Nenhum fluxo de rede com esse endereço.", "atenua", como))
        return perguntas
    def dele(p):
        return p["dele"] in (1, "1", True)

    internos = {p["par"] for p in pares if _interno(p["par"])}
    externos = {p["par"] for p in pares if not _interno(p["par"])}
    mandou = sum(int(p["bytes"]) for p in pares if dele(p))
    recebeu = sum(int(p["bytes"]) for p in pares if not dele(p))
    # As portas que o endereço procurou: nas respostas, a porta de destino é a dele, que não diz nada.
    portas = Counter()
    for p in pares:
        if dele(p):
            portas.update(int(x) for x in p["portas"])
    porta = f", mais na porta {portas.most_common(1)[0][0]}" if portas else ""
    fluxos = sum(int(p["fluxos"]) for p in pares)
    if _interno(ip):
        # Máquina da rede: o que pesa é quanto ela mandou para fora.
        para_fora = sum(int(p["bytes"]) for p in pares if dele(p) and not _interno(p["par"]))
        resposta = (f"Sim: {fluxos} fluxos, com {_plural(len(externos), 'endereço de fora', 'endereços de fora')} e "
                    f"{_plural(len(internos), 'máquina da rede', 'máquinas da rede')}. Mandou {_bytes(para_fora)} para fora{porta}.")
        tom = "agrava" if para_fora >= SAIDA_GRANDE else "informa"
    else:
        resposta = (f"Sim: {fluxos} fluxos com {_plural(len(internos), 'máquina da rede', 'máquinas da rede')}. "
                    f"Esse endereço mandou {_bytes(mandou)} e recebeu {_bytes(recebeu)}{porta}.")
        tom = "agrava" if recebeu >= SAIDA_GRANDE or len(internos) > 5 else "informa"
    perguntas.append(_pergunta("fluxos", "Esse endereço trocou tráfego com a rede?", resposta, tom, como))
    return perguntas


def investigar(con, identificador, armazem=None, banco=None):
    """O pacote de provas do alerta, ou None se ele não existe para esta organização."""
    alerta = con.execute(
        """SELECT id, ocorrido_em, nivel, regra_id, regra_descricao, regra_grupos, mitre, grupo_id, gerenciador_id, agente_id, agente_nome,
                  host(ip_origem) AS ip, usuario FROM eventos WHERE id = %s""", (identificador,)).fetchone()
    if not alerta:
        return None
    perguntas = do_alerta(con, alerta)
    if alerta["ip"]:
        perguntas += da_origem(con, alerta)
    if alerta["usuario"]:
        perguntas += da_conta(con, alerta)
    perguntas += do_ativo(con, alerta)
    armazem_respondeu = None
    if armazem is not None and alerta["ip"]:
        try:
            perguntas += do_armazem(armazem, banco, alerta)
            armazem_respondeu = True
        except Exception:
            armazem_respondeu = False
    ordem = {"agrava": 0, "atenua": 1, "informa": 2}
    return {
        "alerta": {"id": alerta["id"], "quando": alerta["ocorrido_em"].isoformat(), "descricao": alerta["regra_descricao"] or alerta["regra_id"],
                   "ip": alerta["ip"], "usuario": alerta["usuario"], "ativo": alerta["agente_nome"]},
        "janela": {"de": (alerta["ocorrido_em"] - JANELA).isoformat(), "ate": (alerta["ocorrido_em"] + JANELA).isoformat()},
        "perguntas": sorted(perguntas, key=lambda p: ordem[p["tom"]]),
        "armazem": armazem_respondeu,
    }
