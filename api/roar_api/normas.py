"""O que cada controle de norma pede, em português, para "10.2.5" dizer alguma coisa a quem lê.

Os códigos são os que o Wazuh põe em cada regra. Os textos são resumos nossos, não a redação oficial das normas.
Quando um controle não está aqui, vale o nome do requisito ou da família acima dele.
"""

import re

NORMAS = {"lgpd": "LGPD", "pci_dss": "PCI DSS", "gdpr": "GDPR", "hipaa": "HIPAA", "nist_800_53": "NIST 800-53", "tsc": "TSC", "gpg13": "GPG13"}

# As regras do Wazuh seguem o PCI DSS 3.2.1.
PCI_DSS = {
    "1": "Firewall e segmentação da rede", "2": "Sem padrões do fabricante, com configuração segura", "3": "Proteger os dados de cartão guardados",
    "4": "Criptografar a transmissão em redes abertas", "5": "Proteger contra malware", "6": "Sistemas e aplicações seguros",
    "7": "Acesso só por necessidade de cada função", "8": "Identificar e autenticar o acesso", "9": "Restringir o acesso físico",
    "10": "Registrar e monitorar todo acesso", "11": "Testar a segurança com frequência", "12": "Política de segurança da informação",
    "1.1.1": "Aprovar e testar toda conexão de rede e mudança no firewall",
    "1.2.1": "Restringir o tráfego de entrada e saída ao necessário",
    "1.3.1": "Zona desmilitarizada para o que é público",
    "1.3.2": "Tráfego da internet só para endereços da zona desmilitarizada",
    "1.3.4": "Nada sai para a internet sem autorização",
    "1.3.6": "Dados de cartão numa zona interna, separada da pública",
    "1.4": "Firewall pessoal nos dispositivos que acessam a rede",
    "2.1": "Trocar senhas e contas padrão do fabricante",
    "2.2": "Padrão de configuração segura para todo componente",
    "2.2.3": "Só serviços e protocolos necessários, com proteção nos inseguros",
    "3.5.4": "Chaves de criptografia no menor número de lugares",
    "4.1": "Criptografia forte para dados de cartão em redes públicas",
    "5.1": "Antivírus nos sistemas sujeitos a malware",
    "5.2": "Antivírus atualizado, varrendo e registrando",
    "5.3": "Antivírus sempre ligado, sem o usuário desligar",
    "6.1": "Identificar vulnerabilidades e classificar o risco",
    "6.2": "Aplicar correções de segurança; as críticas em até um mês",
    "6.5": "Desenvolvimento seguro contra as falhas mais comuns",
    "6.5.1": "Falhas de injeção, como SQL injection",
    "6.5.2": "Estouro de buffer",
    "6.5.5": "Tratamento de erro inadequado",
    "6.5.7": "Cross-site scripting (XSS)",
    "6.5.8": "Controle de acesso inadequado",
    "6.5.10": "Autenticação e sessão quebradas",
    "6.6": "Proteger aplicações web públicas contra ataques conhecidos",
    "7.1": "Acesso aos dados limitado ao que cada função precisa",
    "7.2.1": "Controle de acesso cobrindo todos os componentes",
    "8.1": "Identificar cada usuário e administrador",
    "8.1.2": "Controlar a criação, a exclusão e a mudança de contas",
    "8.1.4": "Desativar contas sem uso há 90 dias",
    "8.1.5": "Controlar as contas de terceiros para acesso remoto",
    "8.1.6": "Bloquear a conta depois de no máximo 6 tentativas",
    "8.1.8": "Nova autenticação depois de 15 minutos parado",
    "8.2": "Autenticar todo usuário com senha, token ou biometria",
    "8.2.1": "Proteger as credenciais com criptografia forte",
    "8.2.4": "Trocar a senha pelo menos a cada 90 dias",
    "8.3": "Autenticação de múltiplos fatores",
    "8.3.1": "Múltiplos fatores para acesso administrativo",
    "8.6": "Token, cartão ou certificado de uma pessoa só",
    "8.7": "Acesso a bancos com dados de cartão só por meios restritos",
    "9.1.1": "Câmeras ou controle de acesso nas áreas sensíveis",
    "10.1": "Trilha de auditoria ligando cada acesso a uma pessoa",
    "10.2.1": "Registrar todo acesso de usuários a dados de cartão",
    "10.2.2": "Registrar toda ação com privilégio de administrador",
    "10.2.4": "Registrar as tentativas de acesso inválidas",
    "10.2.5": "Registrar o uso e a mudança de identificação e autenticação",
    "10.2.6": "Registrar quando os logs de auditoria param ou recomeçam",
    "10.2.7": "Registrar a criação e a exclusão de objetos do sistema",
    "10.4": "Relógios sincronizados nos sistemas críticos",
    "10.5.1": "Só quem precisa vê as trilhas de auditoria",
    "10.5.2": "Proteger as trilhas de auditoria contra alteração",
    "10.5.5": "Alertar quando um log for alterado",
    "10.6": "Revisar logs e eventos para achar anomalias",
    "10.6.1": "Revisar todo dia os eventos de segurança e os sistemas críticos",
    "10.6.2": "Revisar com frequência os logs dos demais componentes",
    "10.6.3": "Tratar as anomalias encontradas na revisão",
    "11.2.1": "Varredura de vulnerabilidades interna a cada trimestre",
    "11.2.3": "Varredura depois de toda mudança importante",
    "11.4": "Detecção ou prevenção de intrusão no tráfego",
    "11.5": "Monitorar a integridade de arquivos críticos",
}

GDPR = {
    "II_5.1.f": "Art. 5(1)(f): integridade e confidencialidade dos dados pessoais",
    "IV_30.1.g": "Art. 30(1)(g): descrever as medidas técnicas e organizacionais de segurança",
    "IV_32.2": "Art. 32(2): segurança proporcional aos riscos do tratamento",
    "IV_35.7.d": "Art. 35(7)(d): medidas para tratar os riscos, na avaliação de impacto",
    "II": "Cap. II: princípios do tratamento", "IV": "Cap. IV: controlador e operador",
}

# Lei 13.709/2018.
LGPD = {
    "Art. 6, VII": "Princípio da segurança: proteger os dados pessoais de acesso indevido e de incidentes",
    "Art. 37": "Registro das operações de tratamento",
    "Art. 38": "Relatório de impacto: medidas e mecanismos para reduzir os riscos",
    "Art. 46": "Medidas de segurança, técnicas e administrativas, contra acesso indevido e incidentes",
    "Art. 48": "Comunicar à ANPD e ao titular incidente que possa causar risco ou dano relevante",
    "Art. 49": "Sistemas que tratam dados pessoais seguindo requisitos de segurança",
    "Art. 50": "Boas práticas e programa de governança em privacidade",
}

# A LGPD não vem marcada nas regras do Wazuh. Os controles saem do GDPR, artigo por artigo, pelo mesmo fundamento.
DERIVADAS = {"lgpd": ("gdpr", {"II_5.1.f": "Art. 6, VII", "IV_30.1.g": "Art. 37", "IV_32.2": "Art. 46", "IV_35.7.d": "Art. 38"})}

HIPAA = {
    "164.308": "Salvaguardas administrativas", "164.310": "Salvaguardas físicas", "164.312": "Salvaguardas técnicas",
    "164.308.a.1": "Gestão da segurança: análise de risco e revisão de atividade",
    "164.312.a.1": "Controle de acesso: só pessoas e programas autorizados",
    "164.312.a.2.I": "Identificação única de cada usuário",
    "164.312.a.2.II": "Procedimento de acesso de emergência",
    "164.312.a.2.III": "Encerrar a sessão sozinho depois de inatividade",
    "164.312.a.2.IV": "Criptografia dos dados de saúde",
    "164.312.b": "Controles de auditoria: registrar e examinar atividade",
    "164.312.c.1": "Integridade: proteger contra alteração ou destruição indevida",
    "164.312.c.2": "Confirmar que os dados não foram alterados",
    "164.312.d": "Autenticar pessoa ou sistema antes do acesso",
    "164.312.e.1": "Segurança na transmissão",
    "164.312.e.2.I": "Integridade na transmissão",
    "164.312.e.2.II": "Criptografia na transmissão",
}

NIST_800_53 = {
    "AC": "Controle de acesso", "AT": "Conscientização e treinamento", "AU": "Auditoria e responsabilização", "CA": "Avaliação e monitoramento",
    "CM": "Gestão de configuração", "CP": "Plano de contingência", "IA": "Identificação e autenticação", "IR": "Resposta a incidentes",
    "MA": "Manutenção", "MP": "Proteção de mídia", "PE": "Proteção física e ambiental", "PL": "Planejamento", "PS": "Segurança de pessoal",
    "RA": "Avaliação de risco", "SA": "Aquisição de sistemas e serviços", "SC": "Proteção de sistemas e comunicações",
    "SI": "Integridade de sistemas e informação", "SR": "Cadeia de suprimentos",
    "AC.2": "Gestão de contas", "AC.3": "Aplicação do acesso", "AC.4": "Controle do fluxo de informação", "AC.6": "Menor privilégio",
    "AC.7": "Tentativas de logon malsucedidas", "AC.9": "Aviso do logon anterior", "AC.12": "Encerramento de sessão",
    "AC.21": "Compartilhamento de informação",
    "AU.5": "Reação a falha no registro de auditoria", "AU.6": "Revisão e análise dos registros de auditoria", "AU.8": "Carimbo de tempo",
    "AU.9": "Proteção dos registros de auditoria", "AU.12": "Geração de registros de auditoria", "AU.14": "Auditoria de sessão",
    "CA.3": "Troca de informação entre sistemas", "CA.9": "Conexões internas do sistema",
    "CM.1": "Política de gestão de configuração", "CM.2": "Configuração de referência", "CM.3": "Controle de mudanças de configuração",
    "CM.5": "Quem pode mudar a configuração", "CM.7": "Funcionalidade mínima",
    "IA.2": "Identificação e autenticação dos usuários", "IA.4": "Gestão de identificadores", "IA.5": "Gestão de autenticadores",
    "SA.3": "Ciclo de desenvolvimento seguro", "SA.11": "Testes de segurança pelo desenvolvedor",
    "SC.2": "Separar funções de usuário e de administração", "SC.5": "Proteção contra negação de serviço", "SC.7": "Proteção da fronteira da rede",
    "SC.8": "Confidencialidade e integridade na transmissão", "SC.12": "Gestão de chaves de criptografia",
    "SI.2": "Correção de falhas", "SI.3": "Proteção contra código malicioso", "SI.4": "Monitoramento do sistema",
    "SI.7": "Integridade de software, firmware e informação",
}

# Critérios de Serviços de Confiança (SOC 2), versão 2017.
TSC = {
    "CC6": "Acesso lógico e físico", "CC7": "Operação do sistema", "CC8": "Gestão de mudanças", "A1": "Disponibilidade", "PI1": "Integridade do processamento",
    "CC6.1": "Proteger o acesso lógico aos sistemas e dados", "CC6.2": "Cadastrar e autorizar usuários antes do acesso",
    "CC6.3": "Dar, mudar e tirar acesso pela função de cada um", "CC6.4": "Restringir o acesso físico",
    "CC6.6": "Proteger contra ameaças de fora do sistema", "CC6.7": "Restringir a transmissão e a movimentação de informação",
    "CC6.8": "Impedir ou detectar software não autorizado ou malicioso",
    "CC7.1": "Detectar mudanças de configuração e vulnerabilidades", "CC7.2": "Monitorar os componentes em busca de anomalias",
    "CC7.3": "Avaliar eventos de segurança para achar incidentes", "CC7.4": "Responder aos incidentes",
    "CC8.1": "Autorizar, testar e aprovar mudanças", "A1.2": "Proteção do ambiente, cópias de segurança e recuperação",
    "PI1.4": "Saídas do processamento completas e corretas", "PI1.5": "Guardar entradas e saídas completas e corretas",
}

# Controles de monitoramento protetivo (PMC) do guia GPG 13, do governo britânico.
GPG13 = {
    "1": "Horário correto nos registros", "2": "Tráfego de negócio que cruza a fronteira da rede", "3": "Atividade suspeita na fronteira da rede",
    "4": "Estado de estações, servidores e dispositivos", "5": "Atividade suspeita na rede interna", "6": "Conexões de rede",
    "7": "Sessões de cada usuário e estação", "8": "Situação das cópias de segurança", "9": "Alerta de eventos críticos",
    "10": "Situação da trilha de auditoria",
}

CATALOGO = {"lgpd": LGPD, "pci_dss": PCI_DSS, "gdpr": GDPR, "hipaa": HIPAA, "nist_800_53": NIST_800_53, "tsc": TSC, "gpg13": GPG13}


def _acima(controle):
    """Do mais específico ao mais geral: "164.312.a.2.I", "164.312.a.2", ..., "164"."""
    partes = re.split(r"([._])", controle)
    for fim in range(len(partes), 0, -2):
        yield "".join(partes[:fim])


def origem(norma):
    """A chave da norma no alerta e, para a norma derivada, a correspondência de cada controle."""
    return DERIVADAS.get(norma, (norma, None))


def traduzir(norma, controles):
    """Os controles do alerta nos da norma pedida. Na derivada, o que não tem correspondência fica de fora."""
    _, mapa = origem(norma)
    return [c for c in controles if c] if mapa is None else sorted({mapa[c] for c in controles if c in mapa})


def controles_com_alerta(con, norma, dias, limite=200):
    """Alertas por controle no período, com a maior severidade, os ativos e as principais regras."""
    chave, mapa = origem(norma)
    juncao, coluna, parametros = "", "c.controle", {"chave": chave, "d": dias, "l": limite}
    if mapa:
        juncao = "JOIN unnest(%(de)s::text[], %(para)s::text[]) AS m(origem, controle) ON m.origem = c.controle"
        coluna = "m.controle"
        parametros.update(de=list(mapa), para=list(mapa.values()))
    linhas = con.execute(f"""
        SELECT {coluna} AS controle, count(DISTINCT e.id) AS total, max(e.nivel) AS nivel, count(DISTINCT e.agente_id) AS ativos, max(e.ocorrido_em) AS ultimo,
               (array_agg(e.severidade ORDER BY array_position(ARRAY['baixa', 'media', 'alta', 'critica'], e.severidade) DESC))[1] AS severidade,
               (array_agg(DISTINCT e.regra_descricao))[1:3] AS regras, array_agg(DISTINCT c.controle) AS origens
        FROM eventos e
          CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(e.bruto -> 'rule' -> %(chave)s) = 'array'
                                                            THEN e.bruto -> 'rule' -> %(chave)s ELSE '[]' END) AS c(controle)
          {juncao}
        WHERE e.ocorrido_em >= now() - make_interval(days => %(d)s)
        GROUP BY 1 ORDER BY total DESC LIMIT %(l)s""", parametros).fetchall()
    for linha in linhas:
        linha["nome"] = nome_do_controle(norma, linha["controle"])
    return linhas


def controles_cobertos(con, norma):
    chave, _ = origem(norma)
    citados = [l["controle"] for l in con.execute(
        "SELECT DISTINCT jsonb_array_elements_text(normas -> %s) AS controle FROM regras WHERE normas ? %s", (chave, chave)).fetchall()]
    return traduzir(norma, citados)


def regras_da_norma(con, norma):
    chave, _ = origem(norma)
    return con.execute("SELECT count(*) AS total FROM regras WHERE normas ? %s", (chave,)).fetchone()["total"]


def nome_do_controle(norma, controle, so_o_requisito=False):
    """O nome do controle, ou do primeiro nível acima que tiver nome. None se a norma não diz nada sobre ele."""
    catalogo = CATALOGO.get(norma, {})
    codigo = str(controle).strip()
    if norma == "tsc":
        codigo = codigo.upper()
    if codigo in catalogo and not so_o_requisito:
        return catalogo[codigo]
    niveis = list(_acima(codigo))
    if so_o_requisito:
        niveis = niveis[-1:]
    for nivel in niveis:
        if nivel in catalogo:
            return catalogo[nivel]
    return None
