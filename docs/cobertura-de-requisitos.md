# Cobertura de requisitos

O que editais públicos brasileiros de SIEM pedem do produto, comparado com o que o Roar tem. Levantamento em novembro de 2026, sobre 5 documentos públicos de 2020 a 2025, lendo as seções técnicas e buscando por palavra-chave. "Docs" é em quantos dos 5 o requisito apareceu. Não é uma amostra estatística.

**Estados:** feito e testado · parcial · do Wazuh, sem tela · falta.

| Tema | Requisito | Docs | Estado no Roar |
|---|---|---|---|
| Coleta | Syslog e protocolos | 4 | Pronto na tela, por cliente. O syslog do Wazuh não tem TLS |
| | Fontes nativas por fabricante | 5 | Na tela: GitHub, Microsoft 365, Graph, AWS, Azure e Google Cloud, ainda sem conta real. Webhook e API genérica prontos |
| | Parser customizado | 4 | Do Wazuh, sem tela |
| | Cache no coletor | 4 | Do Wazuh, não medido |
| | Fluxo de rede | 4 | Falta |
| Normalização | Padrão único | 4 | Feito: todo evento sai em OCSF 1.3.0 (autenticação, arquivo, conta, grupo, sessão, conformidade e achado de detecção), um a um ou exportado com os filtros da tela |
| Correlação | Regras customizáveis | 4 | Feito: guiada, Sigma e XML, editar e desativar também as do catálogo |
| | Regras prontas | 4 | Feito: catálogo do Wazuh na tela, mais a base Sigma |
| | Listas de observação | 3 | Feito: tela para criar listas de IP, usuário, domínio e hash, que chegam ao servidor da organização e as regras em XML consultam |
| | MITRE ATT&CK | 2 | Feito: matriz completa com regras e D3FEND |
| Busca | Linguagem de consulta | 4 | Feito: em português e inglês |
| | Hunting | 2 | Feito: busca em eventos e logs brutos, e caça por lista de indicadores colada, com formato desarmado |
| UEBA | Análise de comportamento | 5 | Feito: login, privilégio, conta criada, grupo administrativo, arquivo sensível e indicador de ameaça, com pares e triagem pelo analista |
| | Score de risco | 3 | Feito |
| SOAR | Resposta automatizada | 5 | Feito: bloquear, desativar conta, avisar e registrar, com prova em agente real; catálogo de integrações por ligar |
| | Playbooks | 3 | Pronto: blocos, modelos, simulação e YAML |
| Inteligência | Feeds e IOC | 5 | Feito: MISP local já ligado, MISP e TAXII externos, conferência na chegada e nos últimos 90 dias quando chega indicador novo, e lista manual vinda da caça |
| | STIX | 3 | Feito: indicadores STIX 2.1 por TAXII 2.1 |
| Retenção | Período mínimo | 5 | Feito: prazo por organização para alertas e logs brutos, de 30 dias a 10 anos, cópia fria diária e recuperação de dias antigos |
| | Log bruto | 3 | Feito |
| Relatórios | Dashboards e exportação | 5 | Parcial: panorama, sem exportar |
| Compliance | Relatório por norma | 2 | Feito: PDF e JSON de LGPD (pela correspondência com o GDPR), ISO 27001:2013 (pelas checagens de configuração), PCI DSS, GDPR, HIPAA, NIST 800-53, TSC e GPG13, com o nome de cada controle em português, com alertas por controle, controles cobertos sem alerta, checagens de configuração reprovadas por controle e a guarda dos registros. Normas do Bacen e a ISO 27001:2022 faltam |
| | Ofuscar campos sensíveis | 2 | Feito: usuário vira apelido, IP, CPF, CNPJ, e-mail, cartão e telefone mascarados na saída para quem não é administrador nem N2, com liga e desliga por organização; o log guardado não muda. IPv6 só é mascarado em campo de IP, não no meio do texto |
| Acesso | Separação por unidade | 3 | Feito: isolamento por cliente |
| | Papéis (RBAC) | 5 | Feito: cinco perfis, checados em cada rota |
| | MFA | 2 | Feito: aplicativo autenticador, códigos de recuperação e exigência por organização; passkeys (WebAuthn) para entrar sem senha; login único por OpenID Connect por organização, com opção de exigir. SAML falta |
| Auditoria | Registro de ações | 4 | Feito: logon, logoff, recusas, acessos e ativos, com tela, exportação em CSV e aviso na tela; aviso por e-mail falta |
| | Integridade do log | 3 | Feito para volume pequeno: selos encadeados, assinados e ancorados, conferência por evento e pacote de evidência; armazenamento da prova não escala para terabytes por dia |
| Disponibilidade | Tolerância a falhas | 3 | Falta |
| Capacidade | Volume (EPS ou GB/dia) | 4 | Não medido de ponta a ponta |
| | Sem descarte em pico | 4 | Não testado |
| Integrações | API | 5 | Feito: chaves de API por organização, com perfil, validade, último uso e revogação; documentação OpenAPI das rotas que uma chave alcança, na tela API, com exemplo de cada uma. Webhook de entrada pronto |
| | Chamados | 3 | Parcial: caso próprio com itens, responsável, prazo pela severidade e histórico; integração com Jira, ServiceNow e GLPI falta |
| Idioma | Documentos ou suporte em português | 3 | Tela em português; documentação parcial |

## Volumes e prazos pedidos

- **Retenção:** de 90 dias a 1 ano, com até 5 anos em camada fria.
- **Volume:** de 200 GB/dia ou 5.000 EPS até 100.000 EPS.
- **Regras prontas:** de 150 a 2.000.
- **UEBA:** de 3.500 a 150.000 usuários.
