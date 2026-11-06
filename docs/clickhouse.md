# Desenho: eventos no ClickHouse

Fase de arquitetura. A etapa 1 da migração (os dois recebendo juntos) está pronta; o resto ainda é desenho. Meta: **50 mil eventos por segundo de um cliente só**, com a tela de logs respondendo em poucos segundos e sem perder evento em pico.

## Por que mudar

Hoje cada log faz este caminho:

```
agente -> gerenciador Wazuh -> Filebeat -> indexer (OpenSearch)
                                              |-- logs brutos (archives): lidos direto pela API, selos, buscas
                                              '-- alertas: ingestão Python -> Postgres (eventos, grupos_alerta)
```

O que não aguenta 50 mil por segundo:

| Ponto | Hoje | Em 50 mil eventos por segundo |
|---|---|---|
| Volume | ~1,7 KB por log no indexer | ~4,3 bilhões de logs por dia, ~7 TB por dia no indexer, mais réplica |
| Alertas no Postgres | um por um, 3 comandos cada, 430 a 580 por segundo medidos | mesmo com 10% dos logs virando alerta, são 5 mil por segundo: o Postgres vira o gargalo, e a tabela `eventos` não tem limpeza |
| Selos | carregam a janela de 15 minutos inteira na memória | 45 milhões de logs por janela |
| Consulta | OpenSearch com `track_total_hits` e agregações a cada página | caro em disco e memória, e o indexer é dividido entre os clientes |

O ClickHouse guarda log em colunas, comprimido. Em log de texto a compressão costuma ficar entre 8 e 15 vezes, o que leva os 7 TB por dia para algo entre 500 e 900 GB por dia. Agregação (contar por, linha do tempo, mais frequentes) é o forte dele. É Apache 2.0, sem parte paga.

## Como fica

```
agente -> gerenciador Wazuh -> archives.json / alerts.json (disco do gerenciador)
                                     |
                                  Vector (um por gerenciador, buffer em disco)
                                     |
                                  ClickHouse: banco do cliente (logs, alertas)
                                     |
          +--------------+-----------+------------+-------------+
          |              |           |            |             |
       API (logs,     agrupador   UEBA, SOAR,   selos       buscas
       painéis,       -> Postgres  inteligência (hash no     agendadas
       relatórios)    grupos_alerta (cursor)    ClickHouse)
```

O indexer continua, pequeno, só para o que o próprio Wazuh exige: os índices de estado (vulnerabilidades e inventário dos agentes). O Postgres continua com tudo que não é evento: fila (grupos), casos, regras, usuários, auditoria, configurações, sinais do UEBA.

### 1. Coleta: Vector em vez de Filebeat

- O gerenciador já grava `alerts.json` e, com `logall_json`, `archives.json`. Um Vector (Rust, licença MPL 2.0) lê esses arquivos com marcador de posição próprio, trata e grava no ClickHouse em lotes (10 mil linhas ou 1 segundo).
- **Sem perda em pico:** buffer em disco e confirmação de ponta a ponta. Se o ClickHouse parar, o Vector segura no disco e reenvia. O arquivo só é dado como lido depois da gravação.
- **Dono do evento:** o banco de destino é fixo na configuração do Vector daquele gerenciador, nunca vem do conteúdo do log. É a mesma regra de hoje, em que o dono é o índice do gerenciador.
- **Log hostil:** o Vector tira caractere nulo e UTF-8 inválido e corta o log gigante (os 256 KiB de hoje), guardando o hash do original. Faz o mesmo que o `normalizar.py`, só que em Rust e no caminho do dado.
- O Filebeat fica só para os índices de estado do Wazuh.

### 2. Um banco por cliente

Cada organização ganha um banco `roar_c_<id>` no ClickHouse:

- **Isolamento:** cada gerenciador grava com um usuário que só tem `INSERT` no banco do cliente dele. A API lê com um usuário de leitura, e o banco consultado sai sempre da sessão, nunca da requisição (como os nomes de índice hoje).
- **Cliente barulhento:** cada cliente tem cota própria (tempo máximo de consulta, memória, linhas lidas), e uma busca pesada de um não trava a tela do outro.
- **Retenção por cliente:** o TTL de cada tabela vem de `clientes.retencao_alertas_dias` e `retencao_logs_dias`, que já existem.
- **Remover uma organização:** `DROP DATABASE`, sem varrer tabela compartilhada.

### 3. As tabelas

`logs` (todos os logs) e `alertas` (os que bateram em regra), as duas com:

- **Ordem no disco:** `PARTITION BY toYYYYMMDD(ocorrido_em)` e `ORDER BY (toStartOfHour(ocorrido_em), agente_id, ocorrido_em)`. Busca por período e por ativo lê só o pedaço certo.
- **Campos fixos em colunas próprias:** os que a tela e a linguagem de consulta mais usam (agente, origem, usuário, regra, nível, tipo, país).
- **Resto do log:** `dados` (o JSON do Wazuh) e `full_log`, comprimidos com ZSTD.
- **Índices de salto:** bloom filter em `ip_origem` e `usuario`, e índice de texto (n-grama) em `full_log`. É o que faz o "contém" e a caça de indicadores não lerem tudo.
- **Para os leitores com cursor:** `id` (UUID gerado no Vector) e `recebido_em` (hora da gravação).

As colunas geradas de hoje (`pais`, `cidade`, `operadora`, `asn`) viram colunas preenchidas na entrada.

### 4. Quem lê, e como

| Hoje | Depois |
|---|---|
| `/api/logs`, painéis, buscas agendadas, caça nos logs, saúde das fontes, volume | A mesma linguagem de consulta, com um segundo tradutor: `consulta.py` passa a gerar SQL do ClickHouse com parâmetros, nunca texto colado. O tradutor do OpenSearch fica até o fim da migração. |
| `/api/fila`, panorama, relatórios, normas, risco de ativos | A fila continua no Postgres (`grupos_alerta`). Um **agrupador** novo lê os alertas do ClickHouse a cada poucos segundos, já somados por grupo no próprio ClickHouse, e atualiza só os grupos que mudaram: centenas de linhas por ciclo, não milhares por segundo. Panorama e relatórios contam no ClickHouse. |
| `/api/eventos`, detalhe do evento, OCSF, MITRE, FIM, YARA | Leem `alertas` no ClickHouse. O id do evento passa a ser o UUID. |
| UEBA, SOAR, inteligência | Mesmo modelo de cursor de hoje, trocando `id > cursor` por `(recebido_em, id) > cursor`, com os mesmos 30 segundos de atraso que o UEBA já usa. |
| Selos | O ClickHouse calcula o hash de cada log e o hash de cada minuto, em paralelo. O Python só monta a árvore com 15 folhas por janela, em vez de 45 milhões. A prova de um evento refaz o minuto dele. |
| Cópia fria | Vira armazenamento em camadas do ClickHouse: depois de N dias, o dado vai sozinho para o disco frio (disco barato ou S3/MinIO) e continua consultável, mais lento. Some o "pedir recuperação". |
| Pacote de evidência | Mesmos ids, lidos do ClickHouse. |

### 5. Postgres

- `eventos` deixa de receber alerta. Os casos e os sinais que apontam para `evento_id` passam a guardar o UUID do ClickHouse.
- `grupos_alerta` fica, alimentado pelo agrupador em lote.
- Fim do crescimento sem limite: nada de alto volume fica no Postgres.

## Migração sem parar nada

1. **Os dois ao mesmo tempo:** o Vector grava no ClickHouse enquanto o Filebeat continua no indexer. Um teste compara as contagens dos dois, janela a janela.
2. **Leitores um a um:** cada leitor ganha a opção por cliente (`armazem = opensearch | clickhouse`), na ordem: logs, painéis e buscas; depois relatórios e panorama; depois agrupador, UEBA, SOAR e inteligência; por último selos e cópia fria.
3. **Desliga o velho:** com todos os leitores no ClickHouse, o Filebeat para de mandar logs e alertas ao indexer, e a ingestão Python sai de cena.
4. **Dado antigo:** fica no indexer até vencer a retenção, ou é copiado para o ClickHouse com um script de uma vez só.

## Capacidade estimada (a confirmar no teste de carga)

| Item | Estimativa |
|---|---|
| Entrada | 50 mil logs por segundo, ~4,3 bilhões por dia |
| Disco quente | 500 a 900 GB por dia comprimido; 30 dias quentes = 15 a 27 TB |
| Gravação | Um servidor ClickHouse grava bem acima de 50 mil linhas por segundo em lote; o limite provável vem antes, no Wazuh |
| Wazuh | Um gerenciador só não deve dar conta de 50 mil por segundo. O cliente grande precisa de um cluster Wazuh (mestre e trabalhadores), cada nó com seu Vector |

## Teste de carga (fora da VPS)

- Gerador sintético de logs Wazuh em 10, 25 e 50 mil por segundo, por 1 hora.
- Medir o atraso entre o log e o ClickHouse, o tamanho no disco por dia, e o tempo da tela de logs (24 horas, filtro por ativo, "contém" no texto, "contar por").
- Derrubar o ClickHouse no meio e conferir que nada se perdeu.
- Selos de uma janela cheia.

## Decisões para você

1. **Dias quentes e cópia fria:** quantos dias ficam no disco rápido, e se o frio é disco local ou um S3/MinIO.
2. **Começar com um servidor ClickHouse ou já com três:** três, com réplica, já entram na alta disponibilidade. Um só é mais simples para começar, e a troca depois é planejada.
3. **Busca de texto:** o índice por n-grama atende "contém" e indicadores. Se precisar de busca de texto mais rica, pesar o índice de texto completo do ClickHouse, que ainda está amadurecendo.
4. **Ordem:** fazer o ClickHouse antes da alta disponibilidade (recomendado, porque a alta disponibilidade depende de onde os dados moram).

## Andamento

### Etapa 1: os dois recebendo juntos (pronta)

- **Servidor:** ClickHouse 26.8.36.3 (LTS) no `infra/docker-compose.yml` (`roar-armazem`), só em 127.0.0.1 e na rede dos gerenciadores, sem a porta nativa, com o usuário padrão removido. A porta é `ARMAZEM_PORTA` (8123 por padrão), porque a máquina pode já ter outro ClickHouse. Disco frio em `ARMAZEM_FRIO`, e as tabelas de registro do próprio ClickHouse vencem em 3 a 7 dias.
- **Banco por organização** (`ingestao/roar_ingestao/armazem.py`): `roar_c_<id>` com `logs` e `alertas`, retenção da organização e dias quentes de `ARMAZEM_DIAS_QUENTES`. O usuário de cada coletor só insere no banco da sua organização. O leitor (`roar_leitor`) só lê, com limite de tempo, memória e linhas. Senhas vão como hash, e nenhum valor de fora entra no SQL sem parâmetro.
- **Coletor** (`infra/wazuh/gerenciador/vector.yaml`): Vector 0.60.0 ao lado de cada gerenciador, com buffer de 1 GiB em disco e confirmação de ponta a ponta. O id é o hash do gerenciador com o log, então o reenvio do mesmo lote é descartado pelo ClickHouse. A provisão grava a configuração já com banco, usuário e senha, num arquivo só do root, porque o Vector não troca variáveis de ambiente dentro dela.
- **Provisão:** gerenciador novo já nasce com o coletor; `provisao preparar` liga os antigos; remover o gerenciador tira o usuário dele, e remover a organização apaga o banco. Mudar a retenção na tela muda a regra das tabelas.
- **Conferência:** `python -m roar_ingestao.conferir_armazem` compara, hora a hora, o indexador e o armazém de cada gerenciador.
- **Teste:** `testes/fase4/testar_armazem.py` (23 checagens): isolamento entre organizações, permissões de cada usuário, retenção, 50 eventos reais chegando igual nos dois lados, 80 eventos enviados com o ClickHouse parado entrando todos quando ele volta, sem repetir, e a conferência sem buraco.

Medido no servidor de teste: os índices do dia batem com o armazém (41 alertas e 42 logs), e a compressão já fica em 5,5 vezes numa amostra pequena.

Limites desta etapa:

- **Recusa do armazém (4xx) descarta o lote:** o Vector só repete 408, 429 e 5xx. Isso só acontece por erro de instalação (senha, permissão, tabela), e a conferência mostra o buraco; o arquivo diário compactado do Wazuh permite regravar. Falta rodar a conferência sozinha, com aviso no sino.
- **Cópia de segurança:** `infra/backup.sh` ainda não leva o armazém.
- **Arquivo do dia:** o coletor começa no arquivo atual do Wazuh. O que já tinha sido rodado para o arquivo compactado fica só no indexador, como combinado no passo 4 da migração.

### Etapa 2: leitores (pronta, menos a perícia)

- **Tradutor** (`api/roar_api/consulta_sql.py`): a mesma linguagem de consulta vira SQL, com todo valor como parâmetro. Os campos mais usados têm coluna própria; os outros saem do log original por caminho (`JSONExtractRaw`), também por parâmetro. Texto livre usa o índice de n-gramas, sem diferença de maiúscula.
- **Leitor** (`api/roar_api/leitor_armazem.py`): a tela de Logs brutos (lista, total, linha do tempo, campos mais frequentes, contar por, filtros clicados e paginação por cursor) e os blocos dos painéis respondem no mesmo formato do indexador. As buscas agendadas usam o mesmo caminho.
- **Opção por organização:** `clientes.ler_do_armazem`, na tela de Armazenamento, só para quem já tem o armazém. Fica na auditoria e volta quando quiser.
- **Localização:** o coletor localiza o endereço com as mesmas bases GeoLite2 do indexador (copiadas para `/opt/panthera-roar/geoip`), nos mesmos 10 campos e na mesma ordem do pipeline do Wazuh. Técnicas e táticas do MITRE ganharam colunas.
- **Teste:** `testes/fase4/testar_armazem.py` (54 checagens) roda as mesmas buscas nos dois lados sobre os mesmos eventos: 12 contagens com e, ou, não, curinga, faixa, campo existe e país; mais frequentes, barras, mapa, linha do tempo dividida, tabela, contar por, paginação sem repetir nem pular e filtros clicados. `testar_armazenamento.py` confere a opção pela API.

Achado: na contagem por valor com muitos empates, o indexador conta por aproximação (cada pedaço do índice manda só os primeiros colocados dele) e chegou a contar 3 ou 4 de 5 eventos de um mesmo IP. O armazém conta exato.

Segunda parte, com a mesma opção:

- **Caça de indicadores nos logs:** todos os indicadores numa leitura só. Conta o indicador inteiro, como o índice antigo: o LIKE usa o índice de n-gramas para achar os candidatos, e uma expressão regular confere a borda (203.0.113.1 não conta dentro de 203.0.113.15, nem evil.com dentro de sub.evil.com).
- **Saúde das fontes:** a última vez de cada origem, por gerenciador.
- **Volume:** eventos por segundo (médio, pico por minuto, agora), por hora, por dia, por ativo e por tipo, com a conta por minuto feita no armazém, e o disco ocupado por dia de `system.parts` (o leitor só lê as colunas de tamanho).
- **Teste:** `testar_armazem.py` (59 checagens) compara a caça e a saúde das fontes com o índice antigo e confere as somas do volume; `testar_armazenamento.py` chama as três rotas com a opção ligada.

Ainda lê do indexador: o pacote de perícia, que depende dos selos (etapa 4). Os relatórios leem do Postgres (etapa 3).

### Etapa 3: alertas no Postgres só os recentes, gravados em lote (pronta)

Decisão revista com os consumidores na mão: a tabela `eventos` não serve só à fila. UEBA, SOAR, inteligência, as telas de
Eventos, MITRE, FIM e YARA, os casos e os sinais dependem dela. Em vez de reescrever todos, o Postgres continua com os
alertas, mas só os recentes, e o histórico inteiro fica no armazém. Os logs, que são o grosso do volume, nunca passam
pelo Postgres.

- **Tabela dividida por dia** (`banco/migracoes/073_eventos_por_dia.sql`): mesmas colunas, índices, políticas e permissões, com os dados copiados. A chave de não repetir passa a levar `ocorrido_em`. `roar_manter_dias_de_eventos(dias)` cria os dias seguintes e descarta inteiro o dia vencido (`ROAR_DIAS_DE_ALERTAS`, 90 por padrão, mínimo 7); data fora dos dias criados cai numa partição à parte, apagada quando vence. A ingestão chama a manutenção de hora em hora. O sinal do UEBA deixou de ser chave estrangeira do evento: com o dia descartado, o sinal fica.
- **Gravação em lote** (`Armazenamento.gravar_em_lote`): três comandos por lote (eventos, grupos somados no lote, ligação evento e grupo) em vez de três por alerta. Lote com erro cai no caminho antigo, de um por um, que isola o alerta ruim na quarentena. Medido no servidor de teste: 6,3 mil alertas por segundo contra 480 um por um.
- **Ingestão lendo do armazém** (`ciclo.rodar_gerenciador_do_armazem`, ligada por `ROAR_ALERTAS_DO_ARMAZEM=1`): lê `alertas` na ordem de chegada (`recebido_em`, `id`), com 10 segundos de folga para não pular gravação em andamento, em lotes de 5 mil, e guarda a posição em `checkpoints.posicao`. Na troca, começa no que o indexer já entregou menos a janela de releitura, e não repete os alertas da janela (o id do próprio Wazuh é o mesmo dos dois lados). Gerenciador de organização sem armazém segue no indexer.
- **Teste:** `testes/fase4/testar_ingestao_em_lote.py` (15 checagens): o lote dá exatamente as mesmas contagens, grupos e quarentena do um por um, a vazão, o descarte do dia vencido, e a ingestão pelo armazém sem repetir na troca, sem reler e respeitando a folga.

Limites:

- **Alerta atrasado mais de 7 dias** em relação à chegada não entra no Postgres (continua no armazém).
- **Caso e sinal antigos:** passado o prazo, o item do caso que aponta para um alerta descartado perde o detalhe no Postgres; o alerta continua no armazém.

### Etapa 4: selos, perícia e cópia fria no armazém (pronta)

- **Selos sobre o armazém** (`roar_ingestao.selo`, ligada por `ROAR_SELOS_DO_ARMAZEM=1`): as leituras dos selos viraram uma fonte, com uma versão para o indexador e outra para o armazém. Mesma árvore de Merkle com sal por folha, mesma cadeia assinada e âncora pública. A folha é o log exatamente como o gerenciador gravou (`armazem.documento_original`), e o identificador é o id da linha. Cada selo guarda a origem (`selos.origem`, migração 074), e a conferência confere cada selo no lugar de onde ele veio: os antigos, no indexador; os novos, no armazém. A origem só entra no cabeçalho assinado quando é o armazém, então nenhum selo antigo mudou de hash, e o `verificar.py` dos pacotes calcula igual.
- **Perícia:** o pacote busca cada evento onde ele foi selado, pelo próprio id (id do armazém tem formato de UUID). Vale para o pacote de período (com a leitura do armazém ligada e selos feitos lá), para o pacote do caso (os alertas vindos do armazém na etapa 3 têm o id de lá) e para a tela Prova e evidência.
- **Cópia fria** (`roar_ingestao.copia_do_armazem`, no serviço de organizações): cada dia de cada organização vira uma cópia própria no disco de cópias (`ARMAZEM_COPIAS`), depois de fechar e passar dois dias de folga, e vence em `ROAR_ARQUIVO_DIAS`. Igual à do indexador, em que cada índice é um dia.
- **Teste:** `testes/fase4/testar_selos_do_armazem.py` (14 checagens): cabeçalho antigo intocado, selagem e conferência no armazém, conferência que não finge sem o armazém, pacote conferido pelo `verificar.py`, evento alterado, apagado e incluído depois apontados um por um, pacote que recusa evento alterado, e a cópia fria de um dia com o vencimento.

Limites:

- **Selo em volume muito alto:** a folha de cada evento ainda é calculada em Python, e as folhas de cada janela de 15 minutos ficam guardadas no Postgres. Em 50 mil eventos por segundo, são 45 milhões de folhas por janela. Antes da carga de verdade, o cálculo do resumo de cada evento precisa ir para o ClickHouse e as folhas para o próprio armazém, com o Postgres guardando só a raiz de cada minuto. Medir no teste de carga.
- **Trazer de volta da cópia fria do armazém:** a cópia é feita e vence; a recuperação pela tela ainda é a do indexador.

### Etapa 5: armazém ligado, caminho antigo desligado (pronta)

- **Ligado por padrão** (`infra/.env.exemplo`): `ROAR_ALERTAS_DO_ARMAZEM=1`, `ROAR_SELOS_DO_ARMAZEM=1` e `ROAR_SO_ARMAZEM=1`. A migração `075_armazem_ligado.sql` deixa a leitura do armazém ligada para todas as organizações, e para as novas já nasce ligada. A chave na tela Armazenamento continua, para voltar uma organização ao indexador se for preciso.
- **Filebeat parado** (`infra/wazuh/gerenciador/1-roar-filebeat`): com `ROAR_SO_ARMAZEM=1`, o script de partida do Filebeat dentro do gerenciador vira uma espera sem fim, e o original fica guardado em `run.original` para voltar com `ROAR_SO_ARMAZEM=0`. Logs e alertas vão só pelo coletor. O indexador continua com o estado (vulnerabilidades e inventário dos agentes), que não passa pelo Filebeat.
- **Histórico trazido** (`python -m roar_ingestao.trazer_do_indexador [--gerenciador <id>]`): copia para o armazém o que o indexador tem de antes do primeiro evento do coletor, com o mesmo formato de linha e o país e a operadora que o indexador já tinha achado. Rodar de novo não repete. Os índices antigos ficam no indexador até vencerem pela retenção.
- **Trava do envio do Vector, e a troca do buffer:** no servidor de teste, um evento que chegava depois de um tempo parado às vezes ficava preso no buffer em disco do Vector até chegar o próximo, sem registro de erro. É um defeito conhecido do buffer em disco (vectordotdev/vector#10806; a correção, vectordotdev/vector#26946, ainda não saiu numa versão). O coletor passou a usar buffer em memória com a confirmação de ponta a ponta: a posição no arquivo do Wazuh só avança depois que o armazém confirma a gravação, então o próprio arquivo guarda o que falta enviar, com o armazém fora do ar ou com o coletor reiniciado. O buffer em disco quase não protegia: 1 GB cobre segundos em 50 mil eventos por segundo. Testado: 7 minutos parado e o evento seguinte chega em segundos; armazém desligado, evento escrito, coletor reiniciado com o armazém fora, e o evento chega quando o armazém volta.
- **Vigia dos coletores** (`roar_ingestao.vigia_do_coletor`, no serviço de organizações, a cada minuto): rede de segurança para qualquer outra trava. Se o gerenciador escreveu no arquivo de logs há mais de 5 minutos e nada dele chegou ao armazém depois disso, reinicia o coletor. No máximo um reinício a cada 15 minutos por gerenciador. Teste: `testes/fase4/testar_vigia_do_coletor.py` (8 checagens); no servidor, destravou o coletor parado e o evento preso chegou.
- **Resumo por hora de cada origem** (`origens_por_hora`, com a visão `origens_por_hora_visao`, criados em `armazem.criar_organizacao`): eventos, entendidos pelo gerenciador e o último evento, por hora e por origem (o endereço do equipamento no syslog, o módulo na nuvem, o arquivo no agente), por 35 dias. A saúde das fontes lê daqui, sem varrer os logs (`api/roar_api/saude_das_fontes.py`). A visão roda com a permissão de quem a criou (`SQL SECURITY DEFINER`): com a permissão do coletor, que só insere, o armazém gravava os logs mas devolvia erro ao coletor, que descartava o lote achando que falhou. Teste: `testes/fase4/testar_saude_das_fontes.py` (20 checagens).
- **Feito no servidor de teste:** histórico trazido dos três gerenciadores, gerenciadores refeitos com o coletor e o Filebeat parado, ingestão lendo do armazém sem repetir os alertas da troca, selos novos feitos no armazém (`selos.origem = 'armazem'` desde 19:17 UTC de 6/11).

Para voltar ao caminho antigo: `ROAR_SO_ARMAZEM=0` e `ROAR_ALERTAS_DO_ARMAZEM=0` no `.env`, refazer os gerenciadores (`provisao preparar`) e reiniciar a ingestão. Os selos já feitos no armazém continuam sendo conferidos lá.

### Próximas etapas

6. Selo em volume alto (acima) e recuperação da cópia fria do armazém.
   Medir no teste de carga o buffer em memória (50 mil eventos por envio) e a confirmação de ponta a ponta.
7. Teste de carga fora da VPS.
