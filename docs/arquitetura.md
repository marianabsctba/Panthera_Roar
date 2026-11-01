# Arquitetura do Panthera Roar

SIEM open source, sem nenhum componente pago, com análise de comportamento e resposta automatizada.

## Princípios

1. **Wazuh sem alteração no core.** Tudo o que é nosso fica em volta, para as atualizações continuarem simples.
2. **Uma tela só.** O analista não abre o Wazuh, e todo playbook nasce na nossa tela.
3. **IA local, que só sugere.** Toda ação passa por regra fixa ou aprovação humana, e todo veredito mostra as evidências.
4. **Conteúdo de log é dado não confiável.** Pode ter sido escrito pelo atacante, então vai delimitado como dado e nunca é seguido como instrução.
5. **Multi-tenant é a base, não um recurso.** Toda tabela e toda consulta carregam o cliente, o banco recusa acesso fora dele, e cada cliente tem fila de execução, credenciais e histórico de IA próprios.
6. **Trilha de auditoria só acrescenta.** Nada é editado nem apagado, e toda decisão fica com a identidade de quem decidiu.

## Componentes

```
agentes -> Wazuh -> indexer
                       |
                       v
                 ingestão (normaliza, deduplica, agrega)
                       |
                       v
                 fila de alertas <-> UEBA (score de risco por entidade)
                       |        <-> IA local (resumo e sugestão)
                       v
                 tela do Roar -> aprovação -> motor de SOAR -> integrações
                       |
                       v
                 trilha de auditoria
```

| Parte | Tecnologia | Papel |
|---|---|---|
| **Coleta e detecção** | Wazuh | Agentes, regras e decoders |
| **Ingestão** | Python | Lê o indexer e gera o evento normalizado |
| **UEBA** | Python | Baseline por entidade e por grupo de pares, score com decaimento |
| **IA** | Ollama, modelo aberto | Resumo, classificação e sugestão |
| **Motor de SOAR** | Temporal e workers nossos | Execução durável dos playbooks, com fila por cliente |
| **Integrações** | Apps MIT do Shuffle | Código das integrações, sem rodar o Shuffle |
| **API e dados** | FastAPI e PostgreSQL | Fila, playbooks, clientes e auditoria |
| **Tela** | Web, preto e rosa | Severidade em vermelho, âmbar e azul, sempre com ícone ou texto |

## Por que não rodar o Shuffle

O Shuffle 2.3.0 foi testado e funciona: fluxos são criados, executados e lidos só pela API. Mas a versão gratuita para em 3 sub-organizações, o que inviabiliza o multi-tenant, e o nosso modelo de cliente não caberia no dele.

| Parte | Licença | Decisão |
|---|---|---|
| Apps, definições OpenAPI e SDK | MIT | Usar como base das integrações |
| Backend | AGPL-3.0 | Não fazer fork; é um código grande, com um único arquivo de 1,25 MB |
| Marca "Shuffle" | | Não usar no produto |

O SDK aponta para os servidores da Shuffle quando a URL de retorno não é definida. O nosso executor não pode depender desse padrão, e nenhuma integração pode enviar dados para fora sem ser essa a sua função.

O motor fica atrás do nosso formato de playbook. Segundo a documentação do Temporal, o padrão indicado para SaaS é fila de tarefas por cliente, e o servidor próprio precisa de um autorizador configurado, porque o padrão libera tudo.

## Ordem de construção

### Fase 0: testes que podem mudar o desenho

Concluída. `infra/subir.sh` sobe tudo e `testes/fase0/` comprova:

- [x] Shuffle pela API e limite de sub-organizações (teste descartado junto com o Shuffle).
- [x] Integração MIT rodando em worker nosso, sem o Shuffle e sem falar com a Shuffle.
- [x] Playbook durável: com o worker morto no meio, o passo concluído não repete e o interrompido é refeito.
- [x] Fila por cliente: sem o worker de um cliente, nada dele roda.
- [x] Wazuh 4.14.9 com alertas chegando ao indexer, tudo em 127.0.0.1.

Limites do que foi testado:

- Só a integração HTTP foi exercitada. Cada integração nova precisa de revisão, porque roda dentro do worker do cliente.
- A auditoria de rede observa as conexões feitas pelo Python, não as do cliente nativo do Temporal.
- A recusa de passo de outro cliente no worker existe no código, mas nenhum teste chega a ela.

Pendências de segurança antes de qualquer dado real:

- Os resultados ficam abertos no histórico do Temporal: cifrar por cliente, com codec de payload.
- Configurar o autorizador do Temporal e TLS.
- Trocar as senhas padrão do Wazuh e gerar outras por instalação.
- A fila nunca pode vir da requisição: um fluxo posto na fila errada é processado pelo worker daquela fila, que vê o conteúdo mesmo sem executar a ação. A API deve derivar a fila do cliente autenticado.

### Fase 1: ingestão

Evento normalizado, deduplicação e agregação por ativo, origem e dia, com o cliente em cada registro.

### Fase 2: UEBA

1. Ligar cada evento a uma pessoa e a um host, usando AD ou IAM.
2. Regras simples: primeira vez neste host, viagem impossível, horário fora do padrão.
3. Baseline por entidade e por grupo de pares.
4. Score acumulado com decaimento, que só gera alerta acima de um limite.
5. Modelos de anomalia entram depois, como mais um sinal no score.

### Fase 3: IA local

Triagem separada do fluxo principal, com análise rápida e aprofundamento quando o caso parece grave. Usa decisões humanas anteriores do mesmo cliente como contexto, sem misturar clientes.

### Fase 4: tela e automação

Fila de alertas com aprovar e descartar, criação de playbooks em "quando, se, então", catálogo de ações em português e credenciais por cliente, cifradas.

### Fase 5: casos

Fica por último. Até aqui, a fila de alertas e a trilha de auditoria cobrem o fluxo de decisão. Requisitos previstos:

- linha do tempo com fuso horário;
- fato e hipótese em campos separados;
- ativos e indicadores com defang;
- andamento, responsável e passagem de plantão;
- evidências com hash e cadeia de custódia;
- indicação de dado pessoal envolvido.

## Decisões em aberto

- **Licença deste repositório.** Precisa estar definida antes de o código começar a crescer.
- **Nome.** Falta verificar uso anterior e registro de marca de "Roar" em segurança.
