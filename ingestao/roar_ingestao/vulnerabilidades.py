"""Gestão contínua de vulnerabilidades, igual para qualquer ferramenta de varredura.

Cada ferramenta entrega uma lista de achados neste formato, e o resto é daqui: quem é novo, quem voltou,
quem foi corrigido. Corrigido só vale quando uma varredura pelo menos tão completa quanto a que achou
deixou de achar: varredura sem credencial não prova que sumiu o que só aparece com credencial.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

MAIOR_REDE = 65536
TAMANHO_DA_EVIDENCIA = 4000
NOME_DE_HOST = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*")
# Pontos da exposição: a conta é simples de propósito, para qualquer pessoa conseguir refazer.
PONTOS = {"critica": 10, "alta": 5, "media": 2, "baixa": 1, "informativa": 0}


class HostInvalido(Exception):
    """A mensagem aparece na tela."""


def validar_host(texto):
    """IP, rede ou nome. Devolve a forma normalizada, sem aceitar nada que vire opção de linha de comando."""
    texto = str(texto).strip()
    if not texto or texto.startswith("-"):
        raise HostInvalido("Informe um endereço, uma rede ou um nome.")
    try:
        if "/" in texto:
            rede = ipaddress.ip_network(texto, strict=False)
            if rede.num_addresses > MAIOR_REDE:
                raise HostInvalido(f"A rede {texto} é grande demais: divida em redes de até /16.")
            return str(rede)
        return str(ipaddress.ip_address(texto))
    except ValueError:
        pass
    if not NOME_DE_HOST.fullmatch(texto):
        raise HostInvalido(f"{texto[:80]} não é um endereço, uma rede nem um nome válido.")
    return texto.lower()


def severidade_do_cvss(cvss):
    """As quatro faixas da CVSS. Zero ou sem nota é informativo, e fica fora da contagem de risco."""
    if cvss is None or cvss <= 0:
        return "informativa"
    if cvss >= 9:
        return "critica"
    if cvss >= 7:
        return "alta"
    if cvss >= 4:
        return "media"
    return "baixa"


@dataclass
class Achado:
    host: str
    regra: str
    titulo: str
    cvss: float | None = None
    cves: list = field(default_factory=list)
    porta: str = ""
    evidencia: str = ""
    solucao: str = ""
    nome_do_host: str | None = None

    def chave(self, fonte):
        return f"{fonte}|{self.regra}|{self.porta}"


@dataclass
class Resultado:
    """O que uma varredura mediu. hosts_respondendo importa: host fora do ar não prova que nada foi corrigido."""
    fonte: str
    hosts_respondendo: list
    achados: list
    autenticada: bool = False
    intrusiva: bool = False
    todas_portas: bool = False


def _ativo(con, cliente, host, nome=None):
    linha = con.execute("""INSERT INTO vuln_ativos (cliente_id, host, nome, ultima_varredura) VALUES (%s, %s, %s, now())
                           ON CONFLICT (cliente_id, host) DO UPDATE SET nome = coalesce(EXCLUDED.nome, vuln_ativos.nome), ultima_varredura = now()
                           RETURNING id""", (cliente, host, nome)).fetchone()
    return linha[0]


def _historico(con, cliente, achado, de, para, varredura, motivo=None):
    con.execute("INSERT INTO vuln_historico (cliente_id, achado_id, de, para, varredura_id, motivo) VALUES (%s, %s, %s, %s, %s, %s)",
                (cliente, achado, de, para, varredura, motivo))


def gravar_resultado(con, cliente, varredura, resultado):
    """Precisa rodar em transação, com roar.cliente definido. Devolve (novos, reabertos, corrigidos)."""
    novos = reabertos = 0
    nomes = {a.host: a.nome_do_host for a in resultado.achados if a.nome_do_host}
    respondendo = {h: _ativo(con, cliente, h, nomes.get(h)) for h in resultado.hosts_respondendo}
    for a in resultado.achados:
        ativo = respondendo.get(a.host) or _ativo(con, cliente, a.host, a.nome_do_host)
        respondendo[a.host] = ativo
        chave = a.chave(resultado.fonte)
        existente = con.execute("SELECT id, estado FROM vuln_achados WHERE ativo_id = %s AND chave = %s", (ativo, chave)).fetchone()
        valores = (a.titulo[:500], sorted({c.upper() for c in a.cves}), a.cvss, severidade_do_cvss(a.cvss), a.porta or None, a.evidencia[:TAMANHO_DA_EVIDENCIA] or None, a.solucao[:TAMANHO_DA_EVIDENCIA] or None)
        if existente is None:
            achado = con.execute(
                """INSERT INTO vuln_achados (cliente_id, ativo_id, chave, fonte, titulo, cves, cvss, severidade, porta, evidencia, solucao, autenticada, intrusiva, todas_portas, ultima_varredura)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (cliente, ativo, chave, resultado.fonte, *valores, resultado.autenticada, resultado.intrusiva, resultado.todas_portas, varredura)).fetchone()[0]
            _historico(con, cliente, achado, None, "aberto", varredura)
            novos += 1
            continue
        achado, estado = existente
        # Aceito e falso positivo continuam como estão: a decisão foi de uma pessoa, e não cabe à varredura desfazer.
        voltou = estado == "corrigido"
        con.execute("""UPDATE vuln_achados SET titulo = %s, cves = %s, cvss = %s, severidade = %s, porta = %s, evidencia = %s, solucao = %s,
                         ultima_vez = now(), ultima_varredura = %s, estado = CASE WHEN %s THEN 'aberto' ELSE estado END, corrigido_em = CASE WHEN %s THEN NULL ELSE corrigido_em END,
                         autenticada = autenticada OR %s, intrusiva = intrusiva OR %s, todas_portas = todas_portas OR %s
                       WHERE id = %s""", (*valores, varredura, voltou, voltou, resultado.autenticada, resultado.intrusiva, resultado.todas_portas, achado))
        if voltou:
            _historico(con, cliente, achado, "corrigido", "aberto", varredura, "A varredura voltou a encontrar.")
            reabertos += 1
    corrigidos = con.execute(
        """UPDATE vuln_achados SET estado = 'corrigido', corrigido_em = now()
           WHERE cliente_id = %s AND fonte = %s AND estado = 'aberto' AND ativo_id = ANY(%s) AND ultima_varredura IS DISTINCT FROM %s
             AND (NOT autenticada OR %s) AND (NOT intrusiva OR %s) AND (NOT todas_portas OR %s)
           RETURNING id""",
        (cliente, resultado.fonte, [respondendo[h] for h in resultado.hosts_respondendo], varredura, resultado.autenticada, resultado.intrusiva, resultado.todas_portas)).fetchall()
    for (achado,) in corrigidos:
        _historico(con, cliente, achado, "aberto", "corrigido", varredura, "A varredura deixou de encontrar.")
    return novos, reabertos, len(corrigidos)


def concluir_varredura(banco, cliente, varredura, resultado):
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        novos, reabertos, corrigidos = gravar_resultado(banco.con, cliente, varredura, resultado)
        banco.con.execute("""UPDATE vuln_varreduras SET estado = 'concluida', terminada_em = now(), autenticada = %s, hosts_respondendo = %s, novos = %s, corrigidos = %s WHERE id = %s""",
                          (resultado.autenticada, len(resultado.hosts_respondendo), novos + reabertos, corrigidos, varredura))
    return novos, reabertos, corrigidos


def falhar_varredura(banco, cliente, varredura, mensagem):
    """Falha não fecha achado nenhum: não varrer não é o mesmo que estar limpo."""
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        banco.con.execute("UPDATE vuln_varreduras SET estado = 'falhou', terminada_em = now(), mensagem = %s WHERE id = %s", (str(mensagem)[:500], varredura))


def agendar_vencidas(banco, cliente, agora=None):
    """A agenda só enfileira. Alvo com varredura em curso espera a próxima volta, sem acumular pedidos."""
    agora = agora or datetime.now(timezone.utc)
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        vencidos = banco.con.execute(
            """SELECT a.id, a.modelo_id, a.a_cada_dias FROM vuln_alvos a
               WHERE a.ativo AND a.a_cada_dias > 0 AND a.proxima_em <= %s
                 AND NOT EXISTS (SELECT 1 FROM vuln_varreduras v WHERE v.alvo_id = a.id AND v.estado IN ('pendente', 'em_andamento'))""", (agora,)).fetchall()
        for alvo, modelo, dias in vencidos:
            banco.con.execute("INSERT INTO vuln_varreduras (cliente_id, alvo_id, modelo_id) VALUES (%s, %s, %s)", (cliente, alvo, modelo))
            banco.con.execute("UPDATE vuln_alvos SET proxima_em = %s WHERE id = %s", (agora + timedelta(days=dias), alvo))
    return len(vencidos)
