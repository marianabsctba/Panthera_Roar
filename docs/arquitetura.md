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
agentes -> gerenciador do cliente -> indexer
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
| **Coleta e detecção** | Wazuh, um gerenciador por cliente | Agentes, regras e decoders |
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

Concluída. `infra/subir.sh` sobe tudo do zero com um comando, e `testes/fase0/` comprova o motor:

- [x] Shuffle pela API e limite de sub-organizações (teste descartado junto com o Shuffle).
- [x] Integração MIT rodando em worker nosso, sem o Shuffle e sem falar com a Shuffle.
- [x] Playbook durável: com o worker morto no meio, o passo concluído não repete e o interrompido é refeito.
- [x] Fila por cliente: sem o worker de um cliente, nada dele roda.
- [x] Wazuh 4.14.9 com alertas chegando ao indexer, tudo em 127.0.0.1 (coberto na Fase 1).

Limites do que foi testado:

- Só a integração HTTP foi exercitada. Cada integração nova precisa de revisão, porque roda dentro do worker do cliente.
- A auditoria de rede observa as conexões feitas pelo Python, não as do cliente nativo do Temporal.
- A recusa de passo de outro cliente no worker existe no código, mas nenhum teste chega a ela.

Pendências de segurança antes de qualquer dado real:

- Os resultados ficam abertos no histórico do Temporal: cifrar por cliente, com codec de payload.
- Configurar o autorizador do Temporal e TLS.
- Trocar a senha padrão de administrador do indexer e gerar outra por instalação.
- Definir retenção de eventos e da quarentena, que hoje crescem sem limite e guardam dado pessoal.
- A fila nunca pode vir da requisição: um fluxo posto na fila errada é processado pelo worker daquela fila, que vê o conteúdo mesmo sem executar a ação. A API deve derivar a fila do cliente autenticado.

### Fase 1: ingestão com um gerenciador por cliente

Concluída. `testes/fase1/testar_ingestao.py` comprova, com gerenciadores e agentes Wazuh reais:

- **Dono do alerta:** é o gerenciador em cujo índice o alerta está. Nome do agente, nome do gerenciador e conteúdo do log nunca decidem.
- **Detecção isolada:** o silêncio de 60 segundos das regras (`ignore`) vale para um gerenciador inteiro. Compartilhado, um ataque a um cliente calava a detecção de outro, o que foi provado com grupo de controle. Separados, os dois disparam.
- **Índice e credencial por cliente:** cada gerenciador só escreve no próprio prefixo. Não lê, não apaga, não altera pipeline, modelo de índice nem usuários. A ingestão lê com um usuário próprio, só de leitura.
- **Índice definido pela requisição:** o pipeline original escolhe o índice por um campo enviado pelo gerenciador. Testamos o desvio e o indexer recusa, porque confere a permissão também no destino. Mesmo assim removemos esse processador: cada gerenciador já grava direto no próprio índice, e um campo a menos decide para onde o dado vai.
- **Inscrição com senha:** cada gerenciador tem a sua, e agente com senha errada não entra.
- **Isolamento no banco:** RLS forçado em todas as tabelas de cliente. Sem cliente na transação, nada aparece. O papel da API só lê, e o da ingestão não muda o dono de um gerenciador nem grava em outro cliente.
- **Grupos:** um por ativo, origem e dia (sem origem, também por regra), com a maior severidade já vista. Ruído não esconde o evento grave.
- **Reprocessar não duplica:** cada ciclo relê 5 minutos para trás. Atraso maior que isso só entra com `--desde`.
- **Alerta hostil não trava a fila:** caractere nulo, UTF-8 inválido, estrutura profunda e alerta gigante foram testados.
- **Justiça entre clientes:** cada ciclo atende um volume limitado por gerenciador, e falha em um não para os outros.

Custo medido, em teste com um agente: cerca de 390 MiB por gerenciador, mais o indexer compartilhado (1,7 GiB). Vazão: de 430 a 580 alertas por segundo em um processo, gravando alerta por alerta. Serve para começar; lote em uma só instrução fica para quando o volume pedir.

Limites:

- **Indexer compartilhado:** permissões separam os dados, mas disco e memória são comuns, e o administrador do indexer vê tudo. Cliente que exija mais isolamento pode ter um indexer próprio.
- **Detecção de vulnerabilidades desligada:** ela usa um índice de estado compartilhado. Volta quando esse índice também for separado por cliente.
- **Certificado:** os gerenciadores usam o mesmo certificado de cliente para falar com o indexer. O que autoriza é o usuário de cada um, mas o certificado também deveria ser individual.
- **RLS:** protege contra consulta sem filtro, não contra SQL injection, porque quem executa SQL arbitrário pode definir outro cliente.
- **Dado em repouso:** ainda não está cifrado.
- **Descarte silencioso:** o pipeline do Wazuh apaga, sem registrar, o documento que falhar ao ser processado (`on_failure: drop`). Esse alerta nunca chega à ingestão nem à quarentena. Trocar o descarte por um índice de falhas é pendência antes de produção.

### Fase 2: UEBA

Primeira versão concluída, só com os logs do Wazuh. `testes/fase2/testar_ueba.py` comprova com cenários, uma simulação e um agente Wazuh real.

| Sinal | Peso | Quando |
|---|---|---|
| `sucesso_apos_falhas` | 50 | Login depois de 5 falhas ou mais do mesmo IP, no mesmo host, em 10 minutos |
| `viagem_impossivel` | 40 | Mais de 500 km a mais de 1000 km/h entre dois logins |
| `primeiro_privilegio` | 30 | Primeiro sudo daquela pessoa naquele host e como aquele usuário |
| `pico_de_falhas` | 20 | Falhas na hora muito acima do histórico, com mínimo de 20 |
| `primeiro_host` | 15 | Host nunca usado pela pessoa |
| `horario_incomum` | 15 | Hora local (no fuso do cliente) com menos de 2% do histórico |
| `primeiro_ip` | 10 | IP nunca usado pela pessoa |
| `host_raro_no_cliente` | 10 | Host usado por menos de 5% dos usuários do cliente |
| `ioc_tocado` | 50 | IP de origem ou destino do evento está na inteligência do cliente. Soma para o ativo e para a pessoa |
| `grupo_administrativo` | 40 | Entrada em grupo que manda na máquina ou no domínio (Windows 4728, 4732, 4756; usermod e gpasswd) |
| `arquivo_sensivel` | 25 | FIM viu mudança em arquivo de contas, privilégio ou inicialização. Com whodata, soma também para quem mexeu |
| `regra_disparada` | 5, 15 ou 30 | Regra de nível 7 ou mais no ativo e na pessoa do evento, pela severidade (média, alta, crítica), uma vez por dia por regra. Fora: SCA, FIM e login, que já têm sinal próprio |
| `taticas_em_sequencia` | 30 | Regras de 3 táticas diferentes do ATT&CK na mesma entidade em 24 horas |
| `pessoa_em_risco` | 20 | Pessoa com risco acima de 60 entrou no ativo. Soma para o ativo |
| `ativo_em_risco` | 15 | A pessoa entrou num ativo com risco acima de 60. Risco repassado não se repassa de novo |
| `conta_criada` | 20 | Conta criada (Windows 4720, useradd) por quem não costuma criar contas ali; sem autor, soma para o ativo |

O risco é a soma dos pesos, caindo pela metade a cada 24 horas. O alerta abre em 60, vira crítico em 100 e se encerra quando o risco cai abaixo de 30. Cada sinal conta uma vez por dia e aponta para o evento que o gerou, e assim todo alerta se explica.

Defesas contra envenenamento:

- **Falha não cria usuário:** nome inventado por atacante não vira entidade, e há limite de entidades por cliente.
- **Não se aprende com o ataque:** com risco alto ou depois de força bruta vencida, host, IP e horário não entram no baseline. A volta do atacante ainda é novidade.
- **Sinais de novidade esperam o aprendizado:** 14 dias e 20 logins. Viagem impossível e força bruta vencida valem desde o início.

O alerta de risco e o grupo de alertas do Wazuh ainda são filas separadas. A tela da Fase 4 as une.

Limites:

- **Simulação não é ambiente real:** em 60 usuários e 30 dias sintéticos, houve 0 alertas sem ataque e os 3 ataques foram detectados. Os pesos e limites foram escolhidos para esse cenário, e o limite de horário foi ajustado depois de ver os testes. Falta validar com dados reais ou públicos, como os conjuntos LANL e CERT, e os pesos precisarão de calibração.
- **Atacante presente desde o início:** o que ele fizer durante o aprendizado vira normal. Um ataque lento, abaixo do limite, também pode entrar no baseline.
- **Só autenticação e sudo:** o sinal depende dos grupos das regras do Wazuh. Testamos sshd e sudo reais; os eventos do Windows têm grupos parecidos, mas ainda não foram testados.
- **Identidade por nome:** sem AD ou IAM, `EMPRESA\maria` e `OUTRA\maria` viram a mesma pessoa, e não há grupo de pares por departamento. Os pares são todos os usuários do cliente.
- **Atraso de 30 segundos:** falhas que chegarem ao banco depois disso não contam para a força bruta vencida. Numa rodada real sem essa espera o sinal se perdeu; a causa provável é o indexer atualizar os shards em momentos diferentes, mas ela não foi confirmada.
- **Viagem impossível em eventos reais:** testada com localização simulada, porque o agente real usou IP de documentação, sem geolocalização.
- **Serviços:** ingestão e UEBA ainda são iniciados à mão (`python -m`), sem supervisão nem reinício automático.

### Fase 3: IA local

Triagem separada do fluxo principal, com análise rápida e aprofundamento quando o caso parece grave. Usa decisões humanas anteriores do mesmo cliente como contexto, sem misturar clientes.

### Fase 4: tela e automação

Primeira parte pronta, só de leitura: login, panorama com gráficos e fila de alertas com as evidências. `testes/fase4/testar_api.py` comprova o acesso e o isolamento, e `testes/fase4/semear_demonstracao.py` cria dados de exemplo para ver a tela.

- **Cliente vem da sessão:** nenhuma rota aceita cliente enviado pelo navegador. Id de outro cliente responde 404.
- **Sessão:** cookie `HttpOnly` e `SameSite=Strict`, com só o hash do token no banco. A API não lê usuários nem sessões, só usa funções específicas.
- **Dado de alerta é hostil:** a tela só monta elementos com `textContent`, e a política de conteúdo bloqueia script de fora. Conferido no navegador com um nome de usuário contendo HTML.
- **Fila sem ruído:** alertas abaixo do nível 5, como login normal, alimentam o UEBA mas não entram na fila nem nos gráficos.
- **Cores dos gráficos:** severidade passa nas checagens de daltonismo. Fica de fora só a faixa de brilho, porque amarelo é claro por natureza; legenda, rótulo e tabela de dados também identificam cada faixa.

Automação: playbooks em blocos empilhados (quando, se, então, senão, ao mesmo tempo, pedir aprovação), que também podem ser escritos em YAML, porque os dois são o mesmo formato (`motor/roar_motor/blocos.py`). `testes/fase4/testar_soar.py` comprova o fluxo com banco, Temporal e workers reais, e `testes/fase4/testar_bloqueio_real.py` vai de um ataque em log até a regra no firewall do agente.

- **Três entradas:** modelos prontos, "Automatizar isto" a partir de um alerta aberto e o editor do zero.
- **Simulação:** refaz os últimos 7 dias com as mesmas funções do disparo, sem executar nada, e mostra quantas vezes e em quais alvos teria disparado.
- **Aprovação no meio:** a execução espera no Temporal. A tela só grava a decisão, e `roar_motor.disparo` acorda a execução. Sem decisão em 72 horas, conta como recusa.
- **O alerta é hostil:** o alvo só vira comando se for um IP válido e público, fora da lista de protegidos do playbook. O endereço do webhook vem do playbook, nunca do alerta.
- **Limites de dano:** todo bloqueio vence sozinho (1 hora, 1 dia ou 7 dias), o mesmo alvo não repete dentro do intervalo, e acima de 20 execuções automáticas por hora o playbook volta a pedir aprovação.
- **Enviado não é feito:** a API da resposta ativa responde sucesso mesmo em ativo sem firewall. A tela só diz "confirmado" depois do alerta 651 do próprio ativo.
- **Papéis separados:** `roar_soar` não lê o bruto do alerta nem usuários e não decide por uma pessoa. A API decide, mas não altera execução.

Limites da automação:

- **Sem desbloqueio manual:** a API do Wazuh só envia o comando de adicionar. Para desfazer antes do prazo, é preciso remover a regra no próprio ativo.
- **Quem cria:** sem papéis, qualquer analista do cliente cria um playbook que bloqueia.
- **Rede interna:** webhook de saída e busca em API só conectam em endereço público, no IP já conferido, sem seguir redirecionamento (`ingestao/roar_ingestao/rede_externa.py`). `ROAR_DESTINO_INTERNO=1` libera a rede interna, para instalações cujo destino está nela de propósito.
- **Ações:** só bloquear, avisar e registrar. O catálogo das integrações e os scripts em contêiner isolado ainda não estão ligados à tela.
- **Serviço:** `roar_motor.disparo` ainda é iniciado à mão, e gerenciadores criados antes desta versão precisam ser recriados para ter os prazos de bloqueio.

Fontes de dados (`ingestao/roar_ingestao/fontes.py`, aplicadas por um serviço de ciclo curto): agente, syslog e módulos de nuvem são os do próprio Wazuh, e a tela só os configura. Webhook de entrada e busca em API são nossos, porque o Wazuh não tem, e entregam ao analisador do gerenciador do cliente, passando pelas mesmas regras. Uma configuração recusada volta à anterior sem parar a coleta. Limites: GitHub, Microsoft 365, Graph, AWS, Azure e Google Cloud foram testados com credencial falsa, então está provado que a configuração é aceita e o módulo roda, mas não que os dados chegam; PagerDuty, VirusTotal e Maltiverse só têm a configuração aceita, e o aviso de ponta a ponta foi provado só com o Slack apontando para um receptor local; a credencial da AWS fica em `/root/.aws`, fora dos volumes, e se perde ao recriar o contêiner; no agente, desativar conta e os bloqueios dependem do que o ativo tem instalado, e sem isso a API responde sucesso e nada muda; o `netsh` de Windows não foi testado; Docker fica para depois, porque exige biblioteca Python no agente; o syslog do Wazuh não tem TLS; o comando de instalação só foi provado em Debian e Ubuntu; gerenciadores antigos precisam ganhar a porta de syslog.

Guarda de credenciais (`ingestao/roar_ingestao/cofre.py`): a API só tem a chave pública, então grava e troca segredos, mas não os lê. Quem abre é o serviço que configura o gerenciador, com a chave privada, que fica em `/opt/panthera-roar/cofre` e nunca vai ao banco. O cliente e o nome da credencial entram na autenticação, então copiar um valor cifrado para outro cliente faz a abertura falhar. `testes/fase4/testar_cofre.py` comprova isso. Limites: quem tem root no servidor lê a chave privada, e os módulos de nuvem do Wazuh exigem a credencial aberta dentro do gerenciador daquele cliente.

Falta nesta fase: cadastro de usuários pela tela (hoje só direto no banco).

Limites da primeira parte:

- **Bloqueio de login:** fica na memória de um processo e é por e-mail, então quem souber o e-mail de alguém consegue bloquear essa pessoa por 15 minutos.
- **Sem MFA nem papéis:** todo usuário de um cliente vê tudo do cliente.
- **Regras em inglês:** as descrições vêm das regras do Wazuh.
- **Tela local:** roda sem proxy nem HTTPS. O cookie exige HTTPS por padrão, e só o teste local desliga isso (`ROAR_COOKIE_SEGURO=0`).
- **Consultas do panorama:** não foram medidas com volume real.

### Fase 5: casos

Fica por último. Até aqui, a fila de alertas e a trilha de auditoria cobrem o fluxo de decisão. Requisitos previstos:

- linha do tempo com fuso horário;
- fato e hipótese em campos separados;
- ativos e indicadores com defang;
- andamento, responsável e passagem de plantão;
- evidências com hash e cadeia de custódia;
- indicação de dado pessoal envolvido.

## Decisões em aberto

- **Nome.** Falta verificar uso anterior e registro de marca de "Roar" em segurança.
