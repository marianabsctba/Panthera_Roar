"""Relatório completo do período, em PDF. Tudo sai das mesmas tabelas da tela, sob o RLS do cliente da sessão.

O texto dos alertas pode ter sido escrito por um atacante: o modelo escapa tudo, e o gerador de PDF não
busca nenhum recurso. Conteúdo hostil vira texto no papel, nunca marcação nem acesso à rede.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader, select_autoescape

MODELOS = Path(__file__).parent / "modelos"
NIVEL_MINIMO = 5
FAIXAS = ("critica", "alta", "media", "baixa")
ROTULOS = {"critica": "Crítica", "alta": "Alta", "media": "Média", "baixa": "Baixa"}
CORES = {"critica": "#b3261e", "alta": "#d9730d", "media": "#b58900", "baixa": "#1a6fb5"}
NORMAS = {"pci_dss": "PCI DSS", "gdpr": "GDPR", "hipaa": "HIPAA", "nist_800_53": "NIST 800-53", "tsc": "TSC", "gpg13": "GPG13"}
MUDANCAS = {"added": "Criados", "modified": "Alterados", "deleted": "Apagados"}
ESTADOS_DE_EXECUCAO = {"nova": "Iniciando", "executando": "Executando", "aguardando_aprovacao": "Aguardando decisão", "concluida": "Concluída", "falhou": "Falhou", "recusada": "Recusada"}
TIPOS_DE_FONTE = {"syslog": "Syslog", "webhook": "Webhook", "api": "API", "github": "GitHub", "office365": "Microsoft 365", "msgraph": "Microsoft Graph", "aws": "AWS CloudTrail",
                  "azure": "Azure Log Analytics", "gcp": "Google Cloud Pub/Sub", "slack": "Aviso no Slack", "pagerduty": "Aviso no PagerDuty", "virustotal": "Consulta no VirusTotal", "maltiverse": "Consulta no Maltiverse"}
TITULOS_DE_SINAL = {"sucesso_apos_falhas": "Acesso depois de várias falhas", "viagem_impossivel": "Viagem impossível", "primeiro_privilegio": "Primeiro uso de privilégio", "pico_de_falhas": "Pico de falhas de acesso",
                    "primeiro_host": "Ativo nunca usado", "horario_incomum": "Horário fora do padrão", "primeiro_ip": "Endereço nunca usado", "host_raro_no_cliente": "Ativo incomum na organização",
                    "ioc_tocado": "Contato com indicador de ameaça", "grupo_administrativo": "Entrada em grupo administrativo",
                    "arquivo_sensivel": "Arquivo sensível alterado", "conta_criada": "Conta criada",
                    "pessoa_em_risco": "Pessoa em risco entrou", "ativo_em_risco": "Entrada em ativo em risco"}
LIMITE_DE_LINHAS = 25


def _linhas(con, sql, **parametros):
    return con.execute(sql, parametros).fetchall()


def _um(con, sql, **parametros):
    return con.execute(sql, parametros).fetchone()


def coletar(con, dias):
    """Só agregados e o que a tela já mostra: o conteúdo bruto dos logs fica de fora de propósito."""
    p = {"d": dias, "n": NIVEL_MINIMO, "l": LIMITE_DE_LINHAS}
    janela = "ocorrido_em >= now() - make_interval(days => %(d)s)"
    alertas = f"{janela} AND nivel >= %(n)s"
    d = {}

    atual = _um(con, f"""SELECT count(*) AS alertas, count(DISTINCT agente_id) AS ativos, count(DISTINCT ip_origem) AS origens, count(DISTINCT usuario) AS usuarios,
                                count(*) FILTER (WHERE severidade = 'critica') AS critica, count(*) FILTER (WHERE severidade = 'alta') AS alta,
                                count(*) FILTER (WHERE severidade = 'media') AS media, count(*) FILTER (WHERE severidade = 'baixa') AS baixa
                         FROM eventos WHERE {alertas}""", **p)
    anterior = _um(con, """SELECT count(*) AS alertas, count(*) FILTER (WHERE severidade IN ('critica', 'alta')) AS graves FROM eventos
                           WHERE nivel >= %(n)s AND ocorrido_em >= now() - make_interval(days => %(dobro)s) AND ocorrido_em < now() - make_interval(days => %(d)s)""", dobro=dias * 2, **p)
    d["resumo"] = {**atual, "anterior": anterior["alertas"], "graves": atual["critica"] + atual["alta"], "graves_anterior": anterior["graves"],
                   "eventos_total": _um(con, f"SELECT count(*) AS t FROM eventos WHERE {janela}", **p)["t"]}
    d["por_dia"] = _linhas(con, f"""SELECT ocorrido_em::date AS dia, count(*) FILTER (WHERE severidade = 'critica') AS critica, count(*) FILTER (WHERE severidade = 'alta') AS alta,
                                           count(*) FILTER (WHERE severidade = 'media') AS media, count(*) FILTER (WHERE severidade = 'baixa') AS baixa
                                    FROM eventos WHERE {alertas} GROUP BY 1 ORDER BY 1""", **p)
    d["regras"] = _linhas(con, f"""SELECT regra_id, max(regra_descricao) AS descricao, max(nivel) AS nivel, count(*) AS total, count(DISTINCT agente_id) AS ativos, max(ocorrido_em) AS ultimo
                                   FROM eventos WHERE {alertas} GROUP BY 1 ORDER BY total DESC, nivel DESC LIMIT %(l)s""", **p)
    d["ativos_com_alerta"] = _linhas(con, f"""SELECT coalesce(max(agente_nome), agente_id) AS ativo, count(*) AS total, count(*) FILTER (WHERE severidade IN ('critica', 'alta')) AS graves,
                                                     count(DISTINCT regra_id) AS regras, max(ocorrido_em) AS ultimo
                                              FROM eventos WHERE {alertas} GROUP BY agente_id ORDER BY graves DESC, total DESC LIMIT %(l)s""", **p)
    d["origens"] = _linhas(con, f"""SELECT host(ip_origem) AS origem, count(*) AS total, count(DISTINCT agente_id) AS ativos, max(bruto #>> '{{GeoLocation,country_name}}') AS pais, max(ocorrido_em) AS ultimo
                                    FROM eventos WHERE {alertas} AND ip_origem IS NOT NULL GROUP BY ip_origem ORDER BY total DESC LIMIT %(l)s""", **p)
    d["paises"] = _linhas(con, f"""SELECT bruto #>> '{{GeoLocation,country_name}}' AS pais, count(*) AS total, count(DISTINCT ip_origem) AS origens FROM eventos
                                   WHERE {alertas} AND bruto #>> '{{GeoLocation,country_name}}' IS NOT NULL GROUP BY 1 ORDER BY total DESC LIMIT %(l)s""", **p)
    d["usuarios"] = _linhas(con, f"""SELECT usuario, count(*) AS total, count(DISTINCT agente_id) AS ativos, max(ocorrido_em) AS ultimo FROM eventos
                                     WHERE {alertas} AND usuario IS NOT NULL GROUP BY 1 ORDER BY total DESC LIMIT %(l)s""", **p)

    d["riscos"] = _linhas(con, """SELECT a.severidade, a.estado, a.risco_maximo, a.aberto_em, a.encerrado_em, n.tipo, coalesce(n.nome, n.chave) AS entidade FROM alertas_risco a
                                  JOIN entidades n ON n.id = a.entidade_id WHERE a.aberto_em >= now() - make_interval(days => %(d)s) OR a.estado = 'aberto' ORDER BY a.risco_maximo DESC LIMIT %(l)s""", **p)
    d["sinais"] = _linhas(con, """SELECT tipo, count(*) AS total, count(DISTINCT entidade_id) AS entidades, sum(peso) AS peso FROM sinais WHERE ocorrido_em >= now() - make_interval(days => %(d)s)
                                  GROUP BY 1 ORDER BY peso DESC""", **p)

    d["tecnicas"] = _linhas(con, f"""SELECT m.tecnica, max(t.nome) AS nome, max(array_to_string(t.taticas, ', ')) AS taticas, count(*) AS total, count(DISTINCT e.agente_id) AS ativos
                                     FROM eventos e, unnest(e.mitre) AS m(tecnica) LEFT JOIN tecnicas_attack t ON t.tecnica = m.tecnica
                                     WHERE e.{janela} AND e.nivel >= %(n)s GROUP BY m.tecnica ORDER BY total DESC LIMIT %(l)s""", **p)
    d["taticas"] = _linhas(con, f"""SELECT ta.tatica, count(*) AS total, count(DISTINCT m.tecnica) AS tecnicas FROM eventos e, unnest(e.mitre) AS m(tecnica)
                                    JOIN tecnicas_attack t ON t.tecnica = m.tecnica, unnest(t.taticas) AS ta(tatica)
                                    WHERE e.{janela} AND e.nivel >= %(n)s GROUP BY 1 ORDER BY total DESC""", **p)
    tecnicas_vistas = [t["tecnica"] for t in d["tecnicas"]]
    d["defesas"] = _linhas(con, """SELECT defesa_nome, tatica_defesa, count(DISTINCT tecnica) AS tecnicas FROM tecnicas_defesa WHERE tecnica = ANY(%(t)s)
                                   GROUP BY 1, 2 ORDER BY tecnicas DESC, defesa_nome LIMIT %(l)s""", t=tecnicas_vistas, l=LIMITE_DE_LINHAS) if tecnicas_vistas else []

    fim = f"{janela} AND 'syscheck' = ANY(regra_grupos)"
    d["fim_mudancas"] = _linhas(con, f"SELECT bruto #>> '{{syscheck,event}}' AS mudanca, count(*) AS total FROM eventos WHERE {fim} GROUP BY 1 ORDER BY total DESC", **p)
    d["fim_arquivos"] = _linhas(con, f"""SELECT bruto #>> '{{syscheck,path}}' AS caminho, count(*) AS total, count(DISTINCT agente_id) AS ativos, max(ocorrido_em) AS ultimo FROM eventos
                                         WHERE {fim} GROUP BY 1 ORDER BY total DESC LIMIT %(l)s""", **p)
    d["fim_caminhos"] = _linhas(con, "SELECT caminho, sistema, modo, estado FROM fim_caminhos WHERE estado <> 'desativado' ORDER BY sistema, caminho")

    d["execucoes"] = _linhas(con, "SELECT estado, count(*) AS total FROM execucoes WHERE criada_em >= now() - make_interval(days => %(d)s) GROUP BY 1 ORDER BY total DESC", **p)
    d["playbooks"] = _linhas(con, """SELECT p.nome, p.ativo, (SELECT count(*) FROM execucoes x WHERE x.playbook_id = p.id AND x.criada_em >= now() - make_interval(days => %(d)s)) AS execucoes
                                     FROM playbooks p ORDER BY execucoes DESC, p.nome LIMIT %(l)s""", **p)
    d["execucoes_recentes"] = _linhas(con, """SELECT x.criada_em, p.nome AS playbook, x.alvo, x.estado FROM execucoes x JOIN playbooks p ON p.id = x.playbook_id
                                              WHERE x.criada_em >= now() - make_interval(days => %(d)s) ORDER BY x.id DESC LIMIT %(l)s""", **p)
    d["decisoes"] = _linhas(con, """SELECT coalesce(roar_nome_do_usuario(decidida_por), 'Sem decisão') AS pessoa, estado, count(*) AS total FROM aprovacoes
                                    WHERE criada_em >= now() - make_interval(days => %(d)s) GROUP BY 1, 2 ORDER BY total DESC""", **p)

    d["ativos"] = _linhas(con, """SELECT nome, agente_id, sistema, ip, estado, ultima_conexao, sca_politica, sca_nota, sca_aprovados, sca_reprovados, fim_fim FROM ativos
                                  WHERE agente_id <> '000' ORDER BY estado, nome""")
    d["fontes"] = _linhas(con, "SELECT nome, tipo, estado, ultimo_dado_em, mensagem FROM fontes WHERE estado <> 'desativada' ORDER BY tipo, nome")
    d["catalogo"] = _um(con, """SELECT (SELECT count(*) FROM regras) AS regras, (SELECT count(*) FROM regras_proprias WHERE estado = 'ativa' AND substitui IS NULL) AS proprias,
                                       (SELECT count(*) FROM regras_proprias WHERE estado = 'ativa' AND substitui IS NOT NULL AND desligada) AS desligadas,
                                       (SELECT count(*) FROM regras_proprias WHERE estado = 'ativa' AND substitui IS NOT NULL AND NOT desligada) AS editadas""")

    d["normas"] = []
    for chave, rotulo in NORMAS.items():
        controles = _linhas(con, f"""SELECT c.controle, count(*) AS total, count(DISTINCT e.agente_id) AS ativos, max(e.ocorrido_em) AS ultimo
                                     FROM eventos e, jsonb_array_elements_text(CASE WHEN jsonb_typeof(e.bruto -> 'rule' -> %(norma)s) = 'array' THEN e.bruto -> 'rule' -> %(norma)s ELSE '[]' END) AS c(controle)
                                     WHERE e.{janela} GROUP BY 1 ORDER BY total DESC LIMIT %(l)s""", norma=chave, **p)
        d["normas"].append({"rotulo": rotulo, "controles": controles})

    d["auditoria_acoes"] = _linhas(con, "SELECT acao, count(*) AS total, max(em) AS ultimo FROM auditoria WHERE em >= now() - make_interval(days => %(d)s) GROUP BY 1 ORDER BY total DESC", **p)
    d["auditoria_pessoas"] = _linhas(con, """SELECT coalesce(roar_nome_do_usuario(usuario_id), 'Removida') AS pessoa, count(*) AS total, max(em) AS ultimo FROM auditoria
                                             WHERE em >= now() - make_interval(days => %(d)s) GROUP BY usuario_id ORDER BY total DESC LIMIT %(l)s""", **p)
    d["usuarios_do_sistema"] = _linhas(con, "SELECT nome, perfil, ativo FROM roar_listar_usuarios()")
    d["cves"] = _um(con, "SELECT total, epss_data, carregada_em, falha FROM cves_carga")
    return d


def _variacao(atual, anterior):
    if not anterior:
        return "sem base de comparação" if not atual else "novo no período"
    delta = (atual - anterior) * 100 / anterior
    if abs(delta) < 0.5:
        return "estável"
    return f"{'+' if delta > 0 else ''}{delta:.0f}%".replace(".", ",")


def grafico_por_dia(por_dia):
    """Barras empilhadas em SVG, sem nada de fora. A tabela do apêndice traz os mesmos números."""
    largura, altura, margem_e, margem_b, topo = 720, 220, 44, 24, 8
    if not por_dia:
        return ""
    maximo = max(sum(int(d[f]) for f in FAIXAS) for d in por_dia) or 1
    teto = _teto_redondo(maximo)
    area = altura - margem_b - topo
    passo = (largura - margem_e) / len(por_dia)
    barra = max(2.0, min(passo - 2, 22))
    partes = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {largura} {altura}" class="grafico" role="img" aria-label="Alertas por dia">']
    # Degraus que dão número inteiro: arredondar 3,75 para 4 faria o eixo mentir.
    divisoes = next(d for d in (5, 4, 2, 1) if teto % d == 0)
    for i in range(divisoes + 1):
        y = topo + area * i / divisoes
        valor = teto * (divisoes - i) / divisoes
        partes.append(f'<line x1="{margem_e}" y1="{y:.1f}" x2="{largura}" y2="{y:.1f}" stroke="#e4e4e4" stroke-width="1"/>')
        partes.append(f'<text x="{margem_e - 6}" y="{y + 3:.1f}" text-anchor="end" font-size="9" fill="#666">{valor:,.0f}</text>'.replace(",", "."))
    salto = max(1, len(por_dia) // 8)
    for i, dia in enumerate(por_dia):
        x = margem_e + i * passo + (passo - barra) / 2
        y = topo + area
        for faixa in reversed(FAIXAS):
            valor = int(dia[faixa])
            if valor:
                h = area * valor / teto
                y -= h
                partes.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{barra:.1f}" height="{max(h - 1, 0.5):.1f}" fill="{CORES[faixa]}"/>')
        if i % salto == 0:
            partes.append(f'<text x="{x + barra / 2:.1f}" y="{altura - 8}" text-anchor="middle" font-size="9" fill="#666">{dia["dia"]:%d/%m}</text>')
    partes.append("</svg>")
    return "".join(partes)


def _teto_redondo(valor):
    base = 1
    while base * 10 < valor:
        base *= 10
    for m in (1, 2, 5, 10):
        if valor <= base * m:
            return base * m
    return base * 10


def barras_horizontais(linhas, rotulo, valor="total", cor="#c2185b"):
    """Barra por linha, em HTML simples. Os rótulos passam pelo escape do modelo."""
    maximo = max((int(l[valor]) for l in linhas), default=0) or 1
    return [{"rotulo": l[rotulo], "total": int(l[valor]), "largura": round(int(l[valor]) * 100 / maximo, 1), "cor": cor} for l in linhas]


def _nao_buscar_nada(url, *args, **kwargs):
    raise ValueError(f"recurso externo recusado: {str(url)[:80]}")


def _formatos(ambiente, fuso):
    def data(valor, com_hora=True):
        if not valor:
            return "-"
        if isinstance(valor, str):
            return valor
        if not isinstance(valor, datetime):
            return valor.strftime("%d/%m/%Y")
        return valor.astimezone(fuso).strftime("%d/%m/%Y %H:%M" if com_hora else "%d/%m/%Y")

    ambiente.filters["data"] = data
    ambiente.filters["n"] = lambda v: "-" if v is None else f"{int(v):,}".replace(",", ".")


def montar_html(dados, sessao, dias, tipo, agora=None):
    fuso = ZoneInfo(sessao["fuso"])
    agora = agora or datetime.now(timezone.utc)
    ambiente = Environment(loader=FileSystemLoader(MODELOS), autoescape=select_autoescape(["html"]))
    _formatos(ambiente, fuso)
    r = dados["resumo"]
    contexto = {
        **dados, "cliente": sessao["cliente_nome"], "autor": sessao["nome"], "agora": agora, "inicio": agora - timedelta(days=dias), "dias": dias, "tipo": tipo,
        "rotulos": ROTULOS, "cores": CORES, "faixas": FAIXAS, "mudancas": MUDANCAS, "estados_de_execucao": ESTADOS_DE_EXECUCAO, "tipos_de_fonte": TIPOS_DE_FONTE, "titulos_de_sinal": TITULOS_DE_SINAL,
        "variacao_alertas": _variacao(r["alertas"], r["anterior"]), "variacao_graves": _variacao(r["graves"], r["graves_anterior"]),
        "grafico": grafico_por_dia(dados["por_dia"]), "barras_taticas": barras_horizontais(dados["taticas"], "tatica"), "barras_paises": barras_horizontais(dados["paises"], "pais"),
        "barras_sinais": barras_horizontais([{**s, "titulo": TITULOS_DE_SINAL.get(s["tipo"], s["tipo"])} for s in dados["sinais"]], "titulo"),
        "desconectados": [a for a in dados["ativos"] if a["estado"] != "active"],
    }
    return ambiente.get_template("relatorio.html").render(contexto)


def gerar_pdf(html):
    from weasyprint import HTML

    return HTML(string=html, url_fetcher=_nao_buscar_nada, base_url="about:blank").write_pdf()


def resumo_do_arquivo(conteudo):
    return hashlib.sha256(conteudo).hexdigest()


def dados_em_json(dados):
    return json.dumps(dados, default=str, ensure_ascii=False, indent=2).encode()
