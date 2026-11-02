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
| Normalização | Padrão único | 4 | Parcial: evento próprio, sem OCSF |
| Correlação | Regras customizáveis | 4 | Parcial: conversão de Sigma em andamento, sem editor |
| | Regras prontas | 4 | Feito: catálogo do Wazuh na tela |
| | Listas de observação | 3 | Do Wazuh, sem tela |
| | MITRE ATT&CK | 2 | Parcial: técnica na regra, sem matriz |
| Busca | Linguagem de consulta | 4 | Parcial: busca simples |
| | Hunting | 2 | Parcial: busca em eventos e logs brutos |
| UEBA | Análise de comportamento | 5 | Feito, primeira versão |
| | Score de risco | 3 | Feito |
| SOAR | Resposta automatizada | 5 | Pronto: bloquear, avisar e registrar, com prova em agente real; faltam mais ações |
| | Playbooks | 3 | Pronto: blocos, modelos, simulação e YAML |
| Inteligência | Feeds e IOC | 5 | Falta |
| | STIX | 3 | Falta |
| Retenção | Período mínimo | 5 | Parcial: 90 dias configuráveis, sem camada fria para anos |
| | Log bruto | 3 | Feito |
| Relatórios | Dashboards e exportação | 5 | Parcial: panorama, sem exportar |
| Compliance | Relatório por norma | 2 | Falta: as regras do Wazuh já trazem a marcação |
| | Ofuscar campos sensíveis | 2 | Falta |
| Acesso | Separação por unidade | 3 | Feito: isolamento por cliente |
| | Papéis (RBAC) | 5 | Falta |
| | MFA | 2 | Falta |
| Auditoria | Registro de ações | 4 | Parcial: acesso a dado bruto |
| | Integridade do log | 3 | Falta |
| Disponibilidade | Tolerância a falhas | 3 | Falta |
| Capacidade | Volume (EPS ou GB/dia) | 4 | Não medido de ponta a ponta |
| | Sem descarte em pico | 4 | Não testado |
| Integrações | API | 5 | Parcial: só a interna da tela |
| | Chamados | 3 | Falta |
| Idioma | Documentos ou suporte em português | 3 | Tela em português; documentação parcial |

## Volumes e prazos pedidos

- **Retenção:** de 90 dias a 1 ano, com até 5 anos em camada fria.
- **Volume:** de 200 GB/dia ou 5.000 EPS até 100.000 EPS.
- **Regras prontas:** de 150 a 2.000.
- **UEBA:** de 3.500 a 150.000 usuários.
