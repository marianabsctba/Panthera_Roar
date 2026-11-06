"""Avisos do sino por e-mail, pelo servidor de e-mail de cada organização.

    python -m roar_ingestao.avisos

Roda como root porque abre a senha do cofre. A conexão vai para o IP conferido (rede_externa): um nome que responde
um endereço público na conferência e um interno na conexão não leva o servidor para a rede interna. Junta os avisos
novos de cada volta num e-mail só, para um ataque com mil alertas não virar mil e-mails.
"""

import html
import logging
import os
import smtplib
import socket
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from . import cofre, rede_externa
from .ciclo import conexoes

log = logging.getLogger("roar.avisos")

SEGUNDOS_ENTRE_VOLTAS = 20
TEMPO_LIMITE = 20
SEGREDO = "email-senha"
AVISOS_POR_EMAIL = 50
ENDERECO = os.getenv("ROAR_ENDERECO_PUBLICO", "")
# Os mesmos nomes da tela (web/src/telas/Auditoria.tsx). Tipo sem nome aparece como veio.
NOMES = {
    "indicador_encontrado": "Evento bateu com um indicador de ameaça",
    "falha_explorada_no_ativo": "Falha já explorada por atacantes apareceu no ativo",
    "cve_passou_a_ser_explorada": "Falha aberta passou a ser explorada por atacantes",
    "busca_agendada": "Busca agendada encontrou o que procurava",
    "exposicao_externa": "Exposição grave encontrada na internet",
    "fonte_quieta": "Fonte de dados abaixo do normal",
    "logon_recusado": "Entrada recusada",
    "conta_bloqueada": "Conta bloqueada por tentativas",
    "mfa_falhou": "Código de verificação errado",
}


class EnvioFalhou(Exception):
    """A mensagem aparece na tela: diz o que corrigir, sem endereço interno."""


class _Preso(smtplib.SMTP):
    """Conecta no IP conferido e valida o certificado pelo nome que a organização informou."""

    def __init__(self, ip, **kwargs):
        self._ip = ip
        super().__init__(**kwargs)

    def _get_socket(self, host, port, timeout):
        return socket.create_connection((self._ip, port), timeout)


class _PresoSsl(smtplib.SMTP_SSL):
    def __init__(self, ip, **kwargs):
        self._ip = ip
        super().__init__(**kwargs)

    def _get_socket(self, host, port, timeout):
        bruto = socket.create_connection((self._ip, port), timeout)
        return self.context.wrap_socket(bruto, server_hostname=host)


def conectar(config, senha, contexto=None):
    """Devolve a conexão autenticada. Toda falha vira EnvioFalhou com um motivo que a pessoa entende."""
    try:
        _, ip = rede_externa.resolver(f"https://{config['servidor']}:{config['porta']}")
    except rede_externa.DestinoRecusado as erro:
        raise EnvioFalhou(str(erro).replace("O endereço", "O servidor de e-mail")) from None
    contexto = contexto or ssl.create_default_context()
    try:
        if config["seguranca"] == "ssl":
            smtp = _PresoSsl(ip, timeout=TEMPO_LIMITE, context=contexto)
        else:
            smtp = _Preso(ip, timeout=TEMPO_LIMITE)
        # O smtplib só guarda o nome quando recebe na criação, e o STARTTLS confere o certificado por ele.
        smtp._host = config["servidor"]
        smtp.connect(config["servidor"], config["porta"])
        if config["seguranca"] != "ssl":
            smtp.starttls(context=contexto)
        if config["usuario"]:
            smtp.login(config["usuario"], senha or "")
        return smtp
    except smtplib.SMTPAuthenticationError:
        raise EnvioFalhou("O servidor de e-mail recusou o usuário ou a senha.") from None
    except smtplib.SMTPNotSupportedError:
        raise EnvioFalhou("O servidor de e-mail não aceita conexão segura nesta porta. Tente a porta 465 com SSL.") from None
    except ssl.SSLCertVerificationError:
        raise EnvioFalhou("O certificado do servidor de e-mail não confere com o nome informado.") from None
    except (OSError, smtplib.SMTPException):
        raise EnvioFalhou("Não foi possível falar com o servidor de e-mail. Confira o endereço, a porta e a segurança.") from None


def mensagem(config, organizacao, assunto, linhas):
    """Texto simples e HTML com o mesmo conteúdo. linhas: [(título, detalhe, quando, contagem)]."""
    m = EmailMessage()
    m["Subject"] = assunto
    m["From"] = config["remetente"]
    m["To"] = ", ".join(config["destinatarios"])
    m["Date"] = formatdate(localtime=False)
    m["Message-ID"] = make_msgid(domain=config["remetente"].rsplit("@", 1)[-1] or None)
    rodape = f"Abra a console para ver os detalhes: {ENDERECO}" if ENDERECO else "Abra a console do Panthera Roar para ver os detalhes."
    texto = [f"Panthera Roar · {organizacao}", ""]
    for titulo, detalhe, quando, contagem in linhas:
        texto.append(f"- {titulo}{f' ({contagem} vezes)' if contagem > 1 else ''}: {detalhe} · {quando}")
    m.set_content("\n".join([*texto, "", rodape]))
    itens = "".join(f"<li><b>{html.escape(t)}</b>{f' ({c} vezes)' if c > 1 else ''}<br><span style=\"color:#555\">{html.escape(d)} · {html.escape(q)}</span></li>"
                    for t, d, q, c in linhas)
    m.add_alternative(f"""<div style="font-family:Arial,sans-serif;font-size:14px;color:#222">
<p style="margin:0 0 4px;color:#c2185b;font-weight:700;letter-spacing:2px">PANTHERA ROAR</p>
<p style="margin:0 0 12px;color:#555">{html.escape(organizacao)}</p><ul style="padding-left:18px">{itens}</ul>
<p style="color:#777;font-size:12px">{html.escape(rodape)}</p></div>""", subtype="html")
    return m


def _com_cliente(banco, cliente, sql, *args):
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        cursor = banco.con.execute(sql, args)
        return cursor.fetchall() if cursor.description else None


def _senha(banco, cliente):
    linha = _com_cliente(banco, cliente, "SELECT selado FROM segredos WHERE nome = %s", SEGREDO)
    return cofre.abrir(cofre.ler_privada(), cliente, SEGREDO, linha[0][0]) if linha else ""


def volta(banco, enviar=None):
    """Para cada organização com e-mail ligado: atende o teste pedido e manda os avisos novos. Devolve quantos e-mails saíram."""
    enviados = 0
    for (cliente,) in _clientes(banco):
        linhas = _com_cliente(banco, cliente, """SELECT e.servidor, e.porta, e.seguranca, e.usuario, e.remetente, e.destinatarios, e.tipos, e.ativo,
                                                        e.ultima_notificacao, e.teste_pedido_em, c.nome
                                                 FROM email_config e JOIN clientes c ON c.id = e.cliente_id""")
        if not linhas:
            continue
        servidor, porta, seguranca, usuario, remetente, destinatarios, tipos, ativo, ultima, teste, organizacao = linhas[0]
        config = {"servidor": servidor, "porta": porta, "seguranca": seguranca, "usuario": usuario, "remetente": remetente, "destinatarios": destinatarios}
        if teste:
            try:
                _mandar(config, _senha(banco, cliente), mensagem(config, organizacao, "Panthera Roar: e-mail de teste",
                                                               [("E-mail de teste", "Se você recebeu, os avisos do sino vão chegar aqui.", "agora", 1)]), enviar)
                resultado = "ok"
            except EnvioFalhou as erro:
                resultado = str(erro)
            _com_cliente(banco, cliente, "UPDATE email_config SET teste_pedido_em = NULL, teste_resultado = %s, teste_em = now()", resultado)
        if not ativo:
            continue
        novos = _com_cliente(banco, cliente, """SELECT id, tipo, alvo, contagem, atualizada_em FROM notificacoes
                                                WHERE id > %s AND (cardinality(%s::text[]) = 0 OR tipo = ANY(%s)) ORDER BY id LIMIT %s""",
                             ultima, tipos, tipos, AVISOS_POR_EMAIL)
        if not novos:
            continue
        assunto = f"Panthera Roar: {len(novos)} {'aviso novo' if len(novos) == 1 else 'avisos novos'} em {organizacao}"
        linhas_do_email = [(NOMES.get(tipo, tipo.replace("_", " ")), alvo or "", f"{em:%d/%m/%Y %H:%M} UTC", contagem) for _, tipo, alvo, contagem, em in novos]
        try:
            _mandar(config, _senha(banco, cliente), mensagem(config, organizacao, assunto, linhas_do_email), enviar)
            _com_cliente(banco, cliente, "UPDATE email_config SET ultima_notificacao = %s, ultimo_envio = now(), ultimo_erro = NULL", novos[-1][0])
            enviados += 1
        except EnvioFalhou as erro:
            # Fica para a próxima volta: o aviso não se perde enquanto o servidor de e-mail estiver fora.
            _com_cliente(banco, cliente, "UPDATE email_config SET ultimo_erro = %s", str(erro))
    return enviados


def _clientes(banco):
    with banco.con.transaction():
        return banco.con.execute("SELECT id FROM clientes").fetchall()


def _mandar(config, senha, msg, enviar=None):
    if enviar:
        return enviar(config, senha, msg)
    smtp = conectar(config, senha)
    try:
        smtp.send_message(msg)
    except smtplib.SMTPRecipientsRefused:
        raise EnvioFalhou("O servidor de e-mail recusou os destinatários.") from None
    except smtplib.SMTPException:
        raise EnvioFalhou("O servidor de e-mail recusou a mensagem.") from None
    finally:
        try:
            smtp.quit()
        except (OSError, smtplib.SMTPException):
            pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    _, banco, _ = conexoes()
    while True:
        try:
            if volta(banco):
                log.info("avisos mandados por e-mail")
        except Exception:
            log.exception("volta dos avisos por e-mail falhou")
        time.sleep(SEGUNDOS_ENTRE_VOLTAS)


if __name__ == "__main__":
    main()
