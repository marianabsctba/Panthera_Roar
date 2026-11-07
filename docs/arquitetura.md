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
- Definir retenção da quarentena, que cresce sem limite e guarda dado pessoal. Os alertas no Postgres já têm prazo (`ROAR_DIAS_DE_ALERTAS`, `docs/clickhouse.md`).
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
- **Login único por SAML:** `api/roar_api/saml.py` monta o pedido (HTTP-Redirect) e confere a resposta (HTTP-POST). A assinatura é conferida pelo `signxml` com o certificado que a organização cadastrou, e tudo é lido só do elemento que ela cobre: uma asserção falsa embrulhando a verdadeira não é lida. A resposta tem de trazer uma só asserção, sem criptografia nem DOCTYPE, do emissor cadastrado, para o identificador do Roar, dentro do prazo e citando o pedido feito, guardado como uso único. A rota que recebe a resposta é a única liberada de POST vindo de outro site, porque vale pela assinatura e pelo pedido, não pela origem.
- **Avisos por e-mail:** o serviço `roar_ingestao.avisos` roda como root porque abre a senha do cofre. Conecta no IP conferido pelo `rede_externa` (servidor da rede interna é recusado), valida o certificado pelo nome informado e junta os avisos novos do sino de cada volta num e-mail só. Falha no envio fica na tela, e o aviso espera o envio seguinte.
- **Painéis e buscas agendadas:** os blocos dos painéis e as buscas agendadas passam pelo mesmo `api/roar_api/buscas.py`, que monta a consulta pela linguagem de consulta (o texto nunca chega cru ao índice) e lê o resultado. Os valores dos mais frequentes voltam na chave curta do campo, como `srcuser`, para a máscara de dado pessoal reconhecer. O serviço `roar_ingestao.buscas` roda como roar-svc, com a credencial de leitura do índice, e só olha os índices dos gerenciadores da própria organização. Ao valer a condição, grava pelo `roar_avisar`, que soma no mesmo aviso do sino.
- **Parsers próprios:** a console guarda o parser (`api/roar_api/parsers.py` gera o XML do guiado e confere o escrito à mão: só decodificadores com o nome do parser). Quem fala com o gerenciador é o serviço `roar_ingestao.parsers`: a console grava o pedido de teste em `parser_testes`, o serviço roda o log no teste do gerenciador, que lê os decodificadores do disco a cada sessão, e a console espera a resposta. O decodificador provisório fica no disco só durante o teste, com o gerenciador travado (`provisao.trava`), e a mesma trava cobre a validação e o reinício: um reinício nunca encontra o provisório. A instalação roda no ciclo das fontes, antes das regras próprias, em `etc/decoders/roar_parsers.xml`, validada e com volta à anterior. Prova com o gerenciador de verdade: o parser criado pela tela chegou ao servidor em 40 segundos, e um log enviado a ele saiu com os campos tirados.
- **Syslog no coletor:** quem recebe o syslog dos equipamentos é o coletor de cada gerenciador (`roar_ingestao.coletor_syslog`), não o Wazuh: a porta de syslog do gerenciador é publicada no contêiner do coletor. O coletor aceita só os endereços das fontes de syslog da organização e entrega cada linha ao analisador do gerenciador pelo socket da fila (`/var/ossec/queue/sockets/queue`, a mesma entrada que o leitor de arquivos do próprio Wazuh usa), com a mensagem `2:<endereço>:<linha>`: a origem é o endereço do equipamento, como quando o Wazuh recebia o syslog direto, e as regras e os decodificadores são os mesmos. Um primeiro desenho passava por arquivo (um por equipamento e por dia, lido pelo Wazuh com curinga) e perdia as primeiras linhas de cada arquivo novo: o Wazuh começa a ler do fim o arquivo que acha depois de ligado, mesmo com `only-future-events` desligado (provado com um arquivo escrito à mão). A parte que muda com as fontes (endereços aceitos, desvio, chave do repasse) fica em `coletor.d/syslog.yaml`, regravada pelo serviço de fontes, e o coletor a relê sozinho (`--watch-config`). **Desvio de volume** (por organização, tela Armazenamento, migração 076, começa desligado): o tráfego permitido de FortiGate, Sophos Firewall, pfSense, OPNsense, Palo Alto e Cisco ASA (Built/Teardown) não passa pelo gerenciador, que é o gargalo em volume alto: o coletor tira origem, destino, portas e ação e grava direto no armazém, pela mesma transformação dos logs do gerenciador (decodificador `roar-direto-<fabricante>`). Com ele ligado, regra própria sobre tráfego permitido deixa de disparar; a busca de indicadores de ameaça continua pegando, porque lê o armazém. Teste: `testes/fase4/testar_fontes.py` (gerenciadores de verdade) e, no servidor de teste, linhas dos seis fabricantes por UDP com o desvio desligado (todas pelo gerenciador, com a origem no endereço e os alertas) e ligado (o permitido direto no armazém, o resto pelo gerenciador). Limites: UDP não tem confirmação, então o que chega enquanto o gerenciador reinicia pode se perder (como antes, no Wazuh); o ganho de vazão do desvio só se mede no teste de carga.
- **Syslog cifrado (TLS):** o Wazuh não recebe syslog com TLS, e cada gerenciador já usa um bloco de quatro portas colado no do próximo. Então há um receptor só para a instalação (`recepcao` em `infra/docker-compose.yml`, um Vector), na porta 6514 (`SYSLOG_CIFRADO_PORTA`, escutando em `SYSLOG_CIFRADO_ENDERECO`, 127.0.0.1 até a pessoa abrir). A instalação tem uma autoridade própria (`roar_ingestao.syslog_cifrado`, chamado pelo `infra/servicos.sh` com o domínio); a chave dela fica fora do que o receptor monta, e a tela oferece o certificado para importar no equipamento (`GET /api/fontes/certificado-syslog`). A fonte de syslog com protocolo `tls` não abre porta: o serviço de fontes escreve as rotas (endereço para gerenciador) na configuração do receptor, que a relê sozinho, e o receptor repassa cada linha ao coletor do gerenciador dono, pela porta 5140 só na rede dos gerenciadores, como `ROAR <chave> <endereço> <linha>`; o coletor confere a chave (gerada na instalação, só o root lê) e segue como no syslog comum. Endereço já tomado por outra organização: a fonte mais nova é recusada, com o motivo. Teste: `testes/fase4/testar_syslog_cifrado.py`; de ponta a ponta no servidor de teste, 8 mensagens por TLS chegaram ao armazém com a origem no endereço e o país, dispararam o alerta de força bruta, e a fonte apareceu recebendo, com o equipamento. Limites: só TLS 1.2 (1.0 e 1.1 recusados de propósito; o 1.3 também não conectou no teste); o endereço que o receptor vê é o de quem conecta (equipamento atrás de NAT aparece pelo endereço público; conexão do próprio servidor chega pelo portão da rede do Docker); o receptor não pede certificado do equipamento: quem garante a origem é a lista de endereços.
- **Firewalls por fabricante:** o catálogo de Fontes de dados tem um cartão por fabricante (FortiGate, pfSense, OPNsense, Palo Alto, Sophos Firewall, Cisco ASA, MikroTik), com o passo a passo, a configuração pronta para copiar e um teste de linha (`POST /api/fontes/testar-linha`, a mesma fila do teste de parser, com a permissão de gerir fontes). A fonte cadastrada pelo cartão guarda o fabricante (`config.fabricante`) só para a tela. O que o Wazuh não lê vem do produto, igual para toda organização, em `ingestao/roar_ingestao/fabricantes/` (`roar_ingestao.fabricantes`, no ciclo das fontes, antes dos parsers da organização): hoje o MikroTik, com regras na faixa 100910 a 100929 (firewall, login recusado, login aceito e muitas recusas seguidas do mesmo endereço). Os decodificadores de firewall do Wazuh não usam o mesmo nome para o endereço (Sophos XG e Cisco gravam `src_ip`, Palo Alto `source_address`): a ingestão, o coletor, o histórico trazido do indexador e a inteligência leem nesta ordem (`normalizar.CAMPOS_DE_IP_DE_ORIGEM` e `CAMPOS_DE_IP_DE_DESTINO`; no coletor, a mesma lista em `vector.yaml`). Teste: `testes/fase4/testar_fabricantes.py` (19 checagens): cada exemplo do catálogo, lido da própria tela, passa pelo gerenciador de verdade. Limites: testado com linhas de exemplo, não com os equipamentos; o login recusado do Cisco ASA (113015) sai só com o número da mensagem, porque o decodificador genérico do Wazuh pega antes de qualquer filho acrescentado, e mudar isso exige trocar o arquivo dele inteiro.
- **Superfície externa:** `roar_ingestao.superficie` trabalha em fila e sem parar, em vez de varrer tudo de uma vez. Só uma volta roda por vez, presa por `pg_try_advisory_lock`, e cada volta faz no máximo uma descoberta de domínio (registro público de certificados e nomes comuns no DNS, com o curinga descontado) e confere 3 nomes, com 8 conexões ao mesmo tempo. Cada nome tem a hora da próxima conferência, espalhada em até 10% do intervalo, e ela é empurrada antes de conferir: o que cai no meio volta em 10 minutos, não a cada volta. A fila de todas as organizações sai por duas funções SECURITY DEFINER que só dizem de quem é o próximo, e o resto roda com o RLS da organização. Conferência sem resposta não fecha achado. Nome que aponta para a rede interna não é conferido, para o servidor não varrer a própria rede. A conferência é leve: porta aberta, certificado, HTTPS e o que o serviço anuncia ao conectar (uma conexão por porta, um HEAD no servidor web), sem nada intrusivo. A versão anunciada é comparada com as faixas de versão da NVD (`cves_versoes`), que a carga das CVEs guarda só para os produtos reconhecíveis. Quando o serviço anuncia o pacote da distribuição (OpenSSH_8.2p1 Ubuntu-4ubuntu0.5), `roar_ingestao.distribuicoes` descobre de qual versão do Ubuntu ou do Debian ele é (pela revisão, pelo Launchpad ou pelo índice de fontes do Debian) e pergunta ao OSV quais CVEs ainda pegam aquela versão exata; só essas valem. Sai só o nome e a versão do pacote, e a resposta fica um dia em `distro_consultas`. Sem o pacote, ou com a distribuição fora do ar, vira suspeita sem CVE ligada. Produtos web que não dizem a versão no cabeçalho são reconhecidos pela página (um GET da página inicial, seguindo um redirecionamento no mesmo nome): VPN e acesso remoto viram aviso de exposição com as falhas já exploradas do produto, e painel de administração vira achado. No nome do próprio domínio, `roar_ingestao.email_dominio` lê do DNS o SPF (contando as consultas dos includes, limite 10), o DMARC e o DKIM nos seletores mais usados, e mede a chave. DNS sem resposta não fecha os achados de e-mail. Cada endereço do nome é conferido, até 4, com o IPv4 primeiro. O CNAME é seguido a cada conferência (`roar_ingestao.tomada`): apelido para serviço de nuvem apagado (o destino some do DNS ou a página do provedor diz que o site não existe) vira achado; a descoberta também guarda o nome sem endereço que ainda é apelido. A partir da segunda conferência, o que mudou vai para `superficie_mudancas` (180 dias), e o sino avisa do que é grave e acabou de abrir ou reabrir. A nota de A a F (`api/roar_api/nota_externa.py`) é calculada na hora pelos achados externos, e a evolução é refeita pela história deles, sem tabela à parte. O cadastro do domínio exige a declaração de autorização, guardada com o nome de quem declarou.
- **Detecção de vulnerabilidades pelo agente:** cada gerenciador grava os achados e o inventário em índices de estado com o nome dele (`wazuh-states-*-gerenciador-<id>`), e só neles tem permissão. O conector do Wazuh tenta criar os modelos de índice toda vez que liga, e essa permissão vale para o cluster inteiro: o portão (`ingestao/roar_ingestao/portao.py`), no gateway da rede dos contêineres, responde esses pedidos sem repassar e encaminha o resto com a credencial do próprio gerenciador. Os modelos de verdade são criados por `provisao.preparar`, com a credencial de administração. O portão não guarda credencial nem acrescenta permissão. `roar_ingestao.vuln_agentes` leva os achados para Vulnerabilidades no ritmo da conferência das CVEs, e agente desconectado não fecha nada.
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
- **Serviços:** ingestão, UEBA e os demais rodam no systemd, com reinício automático (`infra/servicos.sh`).

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
- **Quem cria:** só os perfis Administração e Engenharia de detecção criam playbooks; N2 aprova.
- **Rede interna:** webhook de saída e busca em API só conectam em endereço público, no IP já conferido, sem seguir redirecionamento (`ingestao/roar_ingestao/rede_externa.py`). `ROAR_DESTINO_INTERNO=1` libera a rede interna, para instalações cujo destino está nela de propósito.
- **Ações:** só bloquear, avisar e registrar. O catálogo das integrações e os scripts em contêiner isolado ainda não estão ligados à tela.
- **Serviço:** `roar_motor.disparo` roda no systemd. Gerenciadores criados antes desta versão precisam ser recriados para ter os prazos de bloqueio.

Fontes de dados (`ingestao/roar_ingestao/fontes.py`, aplicadas por um serviço de ciclo curto): agente, syslog e módulos de nuvem são os do próprio Wazuh, e a tela só os configura. Webhook de entrada e busca em API são nossos, porque o Wazuh não tem, e entregam ao analisador do gerenciador do cliente, passando pelas mesmas regras. Uma configuração recusada volta à anterior sem parar a coleta. Limites: GitHub, Microsoft 365, Graph, AWS, Azure e Google Cloud foram testados com credencial falsa, então está provado que a configuração é aceita e o módulo roda, mas não que os dados chegam; PagerDuty, VirusTotal e Maltiverse só têm a configuração aceita, e o aviso de ponta a ponta foi provado só com o Slack apontando para um receptor local; a credencial da AWS fica em `/root/.aws`, fora dos volumes, e se perde ao recriar o contêiner; no agente, desativar conta e os bloqueios dependem do que o ativo tem instalado, e sem isso a API responde sucesso e nada muda; o `netsh` de Windows não foi testado; Docker fica para depois, porque exige biblioteca Python no agente; o syslog chega pelo coletor de cada gerenciador, e o cifrado por um receptor da instalação (acima); o comando de instalação só foi provado em Debian e Ubuntu; gerenciadores antigos precisam ganhar a porta de syslog.

Guarda de credenciais (`ingestao/roar_ingestao/cofre.py`): a API só tem a chave pública, então grava e troca segredos, mas não os lê. Quem abre é o serviço que configura o gerenciador, com a chave privada, que fica em `/opt/panthera-roar/cofre` e nunca vai ao banco. O cliente e o nome da credencial entram na autenticação, então copiar um valor cifrado para outro cliente faz a abertura falhar. `testes/fase4/testar_cofre.py` comprova isso. Limites: quem tem root no servidor lê a chave privada, e os módulos de nuvem do Wazuh exigem a credencial aberta dentro do gerenciador daquele cliente.

Limites da primeira parte:

- **Bloqueio de login:** fica na memória de um processo e é por e-mail, então quem souber o e-mail de alguém consegue bloquear essa pessoa por 15 minutos.
- **Acesso:** perfis por função conferidos em cada rota, autenticador, passkeys e login único por OpenID Connect (`api/roar_api/entrada.py`) e por SAML 2.0 (`api/roar_api/saml.py`).
- **Regras em inglês:** as descrições vêm das regras do Wazuh.
- **Tela local:** roda sem proxy nem HTTPS. O cookie exige HTTPS por padrão, e só o teste local desliga isso (`ROAR_COOKIE_SEGURO=0`).
- **Consultas do panorama:** não foram medidas com volume real.

### Fase 5: casos

Primeira parte pronta: o caso junta alertas, riscos e eventos de um incidente, com responsável, estado, prazo pela severidade, desfecho e um histórico que só cresce, em que toda mudança vira nota automática. `testes/fase4/testar_api.py` comprova o fluxo e o isolamento entre organizações.

Ainda previstos:

- fato e hipótese em campos separados;
- indicadores do caso com defang, ligados à caça de indicadores;
- passagem de plantão;
- evidências com hash ligadas ao caso, aproveitando os selos;
- indicação de dado pessoal envolvido;
- integração com Jira, ServiceNow e GLPI.

### Arquitetura: eventos no ClickHouse

Em andamento. Desenho, decisões e o que já está pronto em `docs/clickhouse.md`; por que o indexador não serve de armazém para 50 mil eventos por segundo em `docs/por-que-nao-o-indexador.md`.

## Decisões em aberto

- **Nome.** Falta verificar uso anterior e registro de marca de "Roar" em segurança.
