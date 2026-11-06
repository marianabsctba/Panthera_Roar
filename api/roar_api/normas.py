"""O que cada controle de norma pede, em português, para "10.2.5" dizer alguma coisa a quem lê.

Os códigos são os que o Wazuh põe em cada regra. Os textos são resumos nossos, não a redação oficial das normas.
Quando um controle não está aqui, vale o nome do requisito ou da família acima dele.
"""

import re

NORMAS = {"lgpd": "LGPD", "bacen": "Bacen (Res. CMN 4.893)", "iso_27001_2022": "ISO 27001:2022", "iso_27001": "ISO 27001:2013", "pci_dss": "PCI DSS", "gdpr": "GDPR", "hipaa": "HIPAA", "nist_800_53": "NIST 800-53", "tsc": "TSC", "gpg13": "GPG13"}

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

# Anexo A da versão 2013, a que as checagens de configuração marcam. A de 2022 renumerou tudo.
ISO_27001 = {
    "A.5": "Políticas de segurança da informação", "A.6": "Organização da segurança da informação", "A.7": "Segurança em recursos humanos",
    "A.8": "Gestão de ativos", "A.9": "Controle de acesso", "A.10": "Criptografia", "A.11": "Segurança física e do ambiente",
    "A.12": "Segurança nas operações", "A.13": "Segurança nas comunicações", "A.14": "Aquisição, desenvolvimento e manutenção de sistemas",
    "A.15": "Relação com fornecedores", "A.16": "Gestão de incidentes de segurança", "A.17": "Continuidade do negócio", "A.18": "Conformidade",
    "A.8.1.1": "Inventário dos ativos", "A.8.1.3": "Uso aceitável dos ativos", "A.8.3.1": "Gestão de mídias removíveis",
    "A.9.1.1": "Política de controle de acesso", "A.9.2.1": "Cadastro e descadastro de usuários", "A.9.2.3": "Gestão de acessos privilegiados",
    "A.9.2.5": "Revisão dos direitos de acesso", "A.9.2.6": "Retirada ou ajuste de direitos de acesso", "A.9.4.1": "Restrição de acesso à informação",
    "A.9.4.2": "Entrada segura nos sistemas", "A.9.4.3": "Gestão de senhas", "A.10.1.1": "Política de uso de criptografia",
    "A.12.1.2": "Gestão de mudanças", "A.12.2.1": "Controles contra malware", "A.12.3.1": "Cópias de segurança", "A.12.4.1": "Registro de eventos",
    "A.12.4.2": "Proteção dos registros", "A.12.4.3": "Registros de administradores e operadores", "A.12.4.4": "Relógios sincronizados",
    "A.12.5.1": "Instalação de software em sistemas em produção", "A.12.6.1": "Gestão de vulnerabilidades técnicas",
    "A.12.6.2": "Restrição à instalação de software", "A.13.1.1": "Controles de rede", "A.13.1.3": "Segregação de redes",
    "A.13.2.1": "Políticas de transferência de informação", "A.13.2.3": "Mensagens eletrônicas", "A.14.2.2": "Controle de mudanças em sistemas",
    "A.14.2.5": "Princípios de engenharia de sistemas seguros", "A.16.1.2": "Notificação de eventos de segurança", "A.16.1.7": "Coleta de evidências",
    "A.18.1.3": "Proteção de registros", "A.18.1.4": "Privacidade e proteção de dados pessoais",
}

# Anexo A da versão 2022: 93 controles em quatro temas, com outra numeração. Só os que a correspondência alcança.
ISO_27001_2022 = {
    "5": "Controles organizacionais", "6": "Controles de pessoas", "7": "Controles físicos", "8": "Controles tecnológicos",
    "5.1": "Políticas de segurança da informação", "5.9": "Inventário de informações e ativos", "5.10": "Uso aceitável de informações e ativos",
    "5.14": "Transferência de informações", "5.15": "Controle de acesso", "5.16": "Gestão de identidade", "5.17": "Informações de autenticação",
    "5.18": "Direitos de acesso", "5.28": "Coleta de evidências", "5.33": "Proteção de registros", "5.34": "Privacidade e proteção de dados pessoais",
    "6.8": "Relato de eventos de segurança da informação", "7.10": "Mídias de armazenamento", "8.2": "Direitos de acesso privilegiado",
    "8.3": "Restrição de acesso à informação", "8.5": "Autenticação segura", "8.7": "Proteção contra malware", "8.8": "Gestão de vulnerabilidades técnicas",
    "8.13": "Cópias de segurança", "8.15": "Registro de eventos", "8.17": "Sincronização de relógios", "8.19": "Instalação de software em sistemas em produção",
    "8.20": "Segurança de redes", "8.22": "Segregação de redes", "8.24": "Uso de criptografia", "8.27": "Arquitetura e engenharia de sistemas seguros",
    "8.32": "Gestão de mudanças",
}
# A correspondência oficial entre as versões (Anexo B da ISO 27002:2022), para os controles da 2013 que as checagens marcam.
DE_2013_PARA_2022 = {
    "A.5.1.1": "5.1", "A.5.1.2": "5.1", "A.8.1.1": "5.9", "A.8.1.3": "5.10", "A.8.3.1": "7.10", "A.9.1.1": "5.15", "A.9.2.1": "5.16", "A.9.2.3": "8.2",
    "A.9.2.5": "5.18", "A.9.2.6": "5.18", "A.9.4.1": "8.3", "A.9.4.2": "8.5", "A.9.4.3": "5.17", "A.10.1.1": "8.24", "A.12.1.2": "8.32", "A.12.2.1": "8.7",
    "A.12.3.1": "8.13", "A.12.4.1": "8.15", "A.12.4.2": "8.15", "A.12.4.3": "8.15", "A.12.4.4": "8.17", "A.12.5.1": "8.19", "A.12.6.1": "8.8",
    "A.12.6.2": "8.19", "A.13.1.1": "8.20", "A.13.1.3": "8.22", "A.13.2.1": "5.14", "A.13.2.3": "5.14", "A.14.2.2": "8.32", "A.14.2.5": "8.27",
    "A.16.1.2": "6.8", "A.16.1.7": "5.28", "A.18.1.3": "5.33", "A.18.1.4": "5.34",
}

# Resolução CMN 4.893/2021, a política de segurança cibernética das instituições financeiras. A Resolução BCB 85/2021,
# das instituições de pagamento, pede o mesmo no Art. 3º. O inciso II lista os controles, que aqui viram um item cada.
BACEN = {
    "Art. 3": "Política de segurança cibernética",
    "Art. 3, II (autenticação)": "Autenticação de quem acessa os sistemas",
    "Art. 3, II (criptografia)": "Criptografia",
    "Art. 3, II (intrusão)": "Prevenção e detecção de intrusão",
    "Art. 3, II (vazamento)": "Prevenção de vazamento de informações",
    "Art. 3, II (vulnerabilidades)": "Testes e varreduras periódicos para detectar vulnerabilidades",
    "Art. 3, II (malware)": "Proteção contra softwares maliciosos",
    "Art. 3, II (rastreabilidade)": "Mecanismos de rastreabilidade",
    "Art. 3, II (acesso e segmentação)": "Controles de acesso e segmentação da rede",
    "Art. 3, II (cópias de segurança)": "Cópias de segurança dos dados e das informações",
    "Art. 3, IV": "Registro, análise da causa e do impacto, e controle dos efeitos de incidentes relevantes",
}
# Cada controle do NIST 800-53 que as regras marcam, no item do Bacen que ele atende.
_NIST_PARA_BACEN = {
    "AC.7": "autenticação", "IA.2": "autenticação", "IA.4": "autenticação", "IA.5": "autenticação",
    "SC.8": "criptografia", "SC.12": "criptografia",
    "SI.4": "intrusão", "SI.7": "intrusão", "SC.5": "intrusão",
    "AC.4": "vazamento", "CA.3": "vazamento",
    "SI.2": "vulnerabilidades", "SA.11": "vulnerabilidades", "SA.3": "vulnerabilidades", "CM.1": "vulnerabilidades", "CM.2": "vulnerabilidades",
    "CM.3": "vulnerabilidades", "CM.5": "vulnerabilidades", "CM.7": "vulnerabilidades",
    "SI.3": "malware",
    "AU.5": "rastreabilidade", "AU.8": "rastreabilidade", "AU.9": "rastreabilidade", "AU.12": "rastreabilidade", "AU.14": "rastreabilidade",
    "AC.2": "acesso e segmentação", "AC.3": "acesso e segmentação", "AC.6": "acesso e segmentação", "AC.9": "acesso e segmentação",
    "AC.12": "acesso e segmentação", "AC.21": "acesso e segmentação", "SC.2": "acesso e segmentação", "SC.7": "acesso e segmentação",
    "CA.9": "acesso e segmentação",
}
# As regras escrevem AC.7; as checagens de configuração, AC-7. As duas grafias levam ao mesmo item.
NIST_PARA_BACEN = {**{k: f"Art. 3, II ({v})" for k, v in _NIST_PARA_BACEN.items()},
                   **{k.replace(".", "-"): f"Art. 3, II ({v})" for k, v in _NIST_PARA_BACEN.items()}, "AU.6": "Art. 3, IV", "AU-6": "Art. 3, IV"}

# Nome da norma no alerta, quando não é o mesmo daqui.
CHAVE_NO_ALERTA = {"iso_27001": "iso_27001-2013"}
# Normas que só as checagens de configuração marcam: as regras não citam, então não há regra que cubra.
SO_PELAS_CHECAGENS = {"iso_27001", "iso_27001_2022"}
# O nome, na tela, da norma de onde uma derivada sai.
NOMES_DA_ORIGEM = {"gdpr": "GDPR", "nist_800_53": "NIST 800-53", "iso_27001-2013": "ISO 27001:2013"}
# Como cada norma derivada sai da outra: a tela e o relatório mostram este texto.
EXPLICACOES = {
    "lgpd": "As regras não marcam a LGPD. Os controles saem do GDPR, artigo por artigo, pelo mesmo fundamento: Art. 5(1)(f) do GDPR no Art. 6, VII; "
            "Art. 30 no Art. 37; Art. 32 no Art. 46; Art. 35 no Art. 38. Artigos sem correspondência, como o Art. 48 (comunicação de incidente), não aparecem aqui.",
    "bacen": "As regras não marcam a Resolução CMN 4.893. Os controles saem do NIST 800-53, que as regras marcam: cada controle do NIST conta no item do "
             "Art. 3º, II que ele atende, como IA (identificação) em autenticação, AU (auditoria) em rastreabilidade e SI.3 em proteção contra softwares "
             "maliciosos. A Resolução BCB 85, das instituições de pagamento, pede os mesmos controles. Cópias de segurança e itens de governança, como a "
             "aprovação da política pelo conselho, não aparecem nos logs.",
    "iso_27001_2022": "As checagens de configuração marcam a ISO 27001 na versão 2013. Os controles saem dela pela correspondência oficial entre as "
                      "versões, como A.9.4.3 (gestão de senhas) em 5.17 e A.12.4.1 (registro de eventos) em 8.15. Controles novos da 2022, como o 8.16 "
                      "(monitoramento de atividades), não têm correspondência e não aparecem aqui.",
}

# A LGPD não vem marcada nas regras do Wazuh. Os controles saem do GDPR, artigo por artigo, pelo mesmo fundamento.
DERIVADAS = {"lgpd": ("gdpr", {"II_5.1.f": "Art. 6, VII", "IV_30.1.g": "Art. 37", "IV_32.2": "Art. 46", "IV_35.7.d": "Art. 38"}),
             "bacen": ("nist_800_53", NIST_PARA_BACEN), "iso_27001_2022": ("iso_27001-2013", DE_2013_PARA_2022)}

# Na grafia oficial da lei, "164.312(a)(2)(i)". As regras do Wazuh escrevem "164.312.a.2.I"; as checagens, a oficial.
HIPAA = {
    "164.308": "Salvaguardas administrativas", "164.310": "Salvaguardas físicas", "164.312": "Salvaguardas técnicas",
    "164.308(a)(1)": "Gestão da segurança: análise de risco e revisão de atividade",
    "164.308(a)(3)": "Segurança da força de trabalho",
    "164.308(a)(3)(i)": "Acesso aos dados de saúde só para quem precisa",
    "164.308(a)(3)(ii)(A)": "Autorizar e supervisionar quem trabalha com dados de saúde",
    "164.308(a)(3)(ii)(C)": "Tirar o acesso de quem sai ou muda de função",
    "164.308(a)(5)": "Conscientização e treinamento em segurança",
    "164.308(a)(5)(ii)(B)": "Proteção contra software malicioso",
    "164.308(a)(6)": "Incidentes de segurança",
    "164.308(a)(6)(ii)": "Identificar e responder a incidentes de segurança",
    "164.310(d)(1)": "Controle de dispositivos e mídias",
    "164.312(a)(1)": "Controle de acesso: só pessoas e programas autorizados",
    "164.312(a)(2)(i)": "Identificação única de cada usuário",
    "164.312(a)(2)(ii)": "Procedimento de acesso de emergência",
    "164.312(a)(2)(iii)": "Encerrar a sessão sozinho depois de inatividade",
    "164.312(a)(2)(iv)": "Criptografia dos dados de saúde",
    "164.312(b)": "Controles de auditoria: registrar e examinar atividade",
    "164.312(c)(1)": "Integridade: proteger contra alteração ou destruição indevida",
    "164.312(c)(2)": "Confirmar que os dados não foram alterados",
    "164.312(d)": "Autenticar pessoa ou sistema antes do acesso",
    "164.312(e)(1)": "Segurança na transmissão",
    "164.312(e)(2)(i)": "Integridade na transmissão",
    "164.312(e)(2)(ii)": "Criptografia na transmissão",
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

CATALOGO = {"lgpd": LGPD, "bacen": BACEN, "iso_27001_2022": ISO_27001_2022, "iso_27001": ISO_27001, "pci_dss": PCI_DSS, "gdpr": GDPR, "hipaa": HIPAA, "nist_800_53": NIST_800_53, "tsc": TSC, "gpg13": GPG13}


def canonico(norma, controle):
    """Uma grafia só para o mesmo controle. No HIPAA, a oficial: "164.312.a.2.I" vira "164.312(a)(2)(i)"."""
    codigo = str(controle).strip()
    if norma == "tsc":
        return codigo.upper()
    pontuado = re.fullmatch(r"(\d+\.\d+)\.(.+)", codigo) if norma == "hipaa" else None
    if pontuado:
        return pontuado.group(1) + "".join(f"({p.lower()})" for p in pontuado.group(2).split("."))
    return codigo


# A mesma conta do canonico(), no banco: o agrupamento junta as duas grafias numa linha só.
CANONICO_SQL = {
    "hipaa": r"""CASE WHEN {c} ~ '^\d+\.\d+\.' THEN substring({c} from '^\d+\.\d+')
                      || regexp_replace('.' || lower(substring({c} from '^\d+\.\d+\.(.*)$')), '\.([^.]+)', '(\1)', 'g') ELSE {c} END""",
    "tsc": "upper({c})",
}


def _acima(controle):
    """Do mais específico ao mais geral: "164.312(a)(2)(i)", "164.312(a)(2)", ..., "164.312", "164"."""
    while controle:
        yield controle
        if controle.endswith(")"):
            controle = controle[:controle.rindex("(")]
        elif re.search(r"[._]", controle):
            controle = re.split(r"[._](?=[^._]*$)", controle)[0]
        else:
            return


def origem(norma):
    """A chave da norma no alerta e, para a norma derivada, a correspondência de cada controle."""
    return DERIVADAS.get(norma, (CHAVE_NO_ALERTA.get(norma, norma), None))


def traduzir(norma, controles):
    """Os controles do alerta nos da norma pedida. Na derivada, o que não tem correspondência fica de fora."""
    _, mapa = origem(norma)
    if mapa is None:
        return list(dict.fromkeys(canonico(norma, c) for c in controles if c))
    return sorted({mapa[c] for c in controles if c in mapa})


def controles_com_alerta(con, norma, dias, limite=200):
    """Alertas por controle no período, com a maior severidade, os ativos e as principais regras."""
    chave, mapa = origem(norma)
    juncao, parametros = "", {"chave": chave, "d": dias, "l": limite}
    coluna = CANONICO_SQL.get(norma, "{c}").format(c="c.controle")
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
    codigo = canonico(norma, controle)
    if codigo in catalogo and not so_o_requisito:
        return catalogo[codigo]
    niveis = list(_acima(codigo))
    if so_o_requisito:
        niveis = niveis[-1:]
    for nivel in niveis:
        if nivel in catalogo:
            return catalogo[nivel]
    return None
