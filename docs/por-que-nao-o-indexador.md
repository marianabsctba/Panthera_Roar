# Por que não guardar os logs no indexer do Wazuh

Este documento explica por que o indexer do Wazuh (baseado no OpenSearch) não é um bom lugar para guardar ~7 TB de logs por dia, e por que o Panthera Roar vai guardar os eventos no ClickHouse. O desenho técnico está em `docs/clickhouse.md`.

## 1. De onde vêm os 7 TB por dia

- **Medido:** no nosso ambiente de teste, cada log bruto ocupa cerca de 1,7 KB no indexer (índices `archives`, já com a compressão `best_compression`).
- **Conta:** 50 mil eventos por segundo dão cerca de 4,3 bilhões de eventos por dia. Vezes 1,7 KB, são ~7 TB por dia, sem réplica.
- **Conferência:** a tabela de disco da própria Wazuh (servidor com 0,25 alerta por segundo usa 3,7 GB em 90 dias) dá, pela nossa conta, perto de 1,9 KB por documento. Está na mesma faixa do que medimos.
- **Falta confirmar:** é uma estimativa a partir de uma medição pequena. O número real sai do teste de carga.

## 2. O que 7 TB por dia vira no disco

Três coisas multiplicam esse número:

- **Retenção:** o disco guarda todos os dias da retenção, não só o de hoje.
- **Réplica:** cada réplica é uma cópia inteira. Com uma réplica (o mínimo para não perder dado quando um nó cai), o volume dobra.
- **Folga:** o OpenSearch para de colocar dados novos num nó quando o disco passa de 85% (limite baixo), começa a tirar dados do nó em 90% (limite alto) e trava a gravação em 95%. Na prática, o disco não pode passar de 85%.

Conta aproximada, feita por nós com esses números. É uma estimativa, não uma medição:

| Retenção quente | Dados (sem réplica) | Com 1 réplica | Disco com folga de 85% | Nós de dados (10 TB úteis cada) | Shards (50 GB, com réplica) |
|---|---|---|---|---|---|
| 30 dias | 210 TB | 420 TB | ~494 TB | ~50 | ~8.400 |
| 90 dias | 630 TB | 1.260 TB | ~1.480 TB | ~150 | ~25.200 |
| 180 dias | 1.260 TB | 2.520 TB | ~2.960 TB | ~300 | ~50.400 |

Os "10 TB úteis por nó" são uma hipótese nossa para um servidor grande. Não há número oficial para isso. A AWS sugere, para carga pesada, 2 vCPU e 8 GB de memória para cada 100 GB de disco. Por essa regra, 30 dias pediriam centenas de nós. A conta da tabela já é a versão otimista.

## 3. O que dizem os guias oficiais

- **Wazuh:** recomenda 16 GB de memória e 8 núcleos por nó do indexer. A tabela de disco dela é para alertas, em escala de centenas de GB, não para logs brutos em escala de centenas de TB.
- **Tamanho de shard:** a AWS recomenda de 10 a 30 GB por shard quando a busca precisa ser rápida, e de 30 a 50 GB em log. 7 TB por dia dão ~140 shards primários por dia, ou ~280 com réplica.
- **Memória:** a heap da JVM deve ficar em até metade da memória e abaixo de ~32 GB, para manter os ponteiros comprimidos. Então um nó não ganha mais "cérebro" só por ter mais memória.
- **Shards por nó:** no máximo 25 shards por GB de heap (guia da AWS), e o OpenSearch limita, por padrão, 1.000 shards por nó. Com 31 GB de heap, são ~775 shards por nó. Em 30 dias quem manda é o disco, não esse limite.

## 4. Por que cada byte custa caro no OpenSearch

Cada documento é guardado em várias estruturas ao mesmo tempo:

- **Índice invertido:** para a busca de texto, cada palavra aponta para os documentos onde aparece.
- **Doc values:** uma cópia por coluna dos campos, usada para contar, ordenar e agregar.
- **`_source`:** o JSON original inteiro, guardado para devolver o documento.

É ótimo para busca de texto livre, mas o mesmo dado aparece duas ou três vezes. Um banco em colunas, como o ClickHouse, guarda cada campo separado e comprime cada coluna sozinha. Como valores parecidos ficam juntos (o mesmo agente, a mesma regra, o mesmo IP), a compressão é bem maior. Em log de texto, costuma ficar entre 8 e 15 vezes. Esse número é uma referência geral. No nosso servidor de teste, os primeiros 85 eventos que chegaram ao ClickHouse já ficaram 5,5 vezes menores; amostra pequena comprime pior, e o número de verdade sai do teste de carga.

## 5. O custo de operar nessa escala

- **Muitos shards:** milhares de shards e um índice por dia por cliente deixam o estado do cluster grande. O nó mestre fica mais lento a cada mudança.
- **Merges:** o OpenSearch junta pedaços de índice o tempo todo. Em 7 TB por dia, isso gasta disco e CPU sem parar.
- **Nó que cai:** o cluster copia de novo todos os shards daquele nó (até ~10 TB) pela rede. Enquanto isso, fica sem réplica de parte dos dados.
- **Consultas:** contar e agrupar sobre bilhões de documentos usa muita memória. Uma tela de "mais frequentes" em 24 horas lê dezenas de shards.
- **Vários clientes:** o indexer é um só para todos. Uma busca pesada de um cliente deixa a tela dos outros lenta.
- **Segundo gargalo:** a nossa ingestão grava alertas um a um no PostgreSQL, a 430 a 580 por segundo (medido). Isso também sai do caminho na mudança.

## 6. O que este documento não diz

O Wazuh e o OpenSearch são bons e continuam no projeto. Agentes, regras, detecção e os índices de estado (vulnerabilidades e inventário) seguem no Wazuh. Empresas grandes rodam clusters OpenSearch de centenas de nós, e a AWS documenta clusters de petabytes. Então dá para fazer. O ponto é o custo: muitos nós, muito disco e uma equipe cuidando do cluster. É isso que queremos evitar. O problema é só usar o indexer como depósito de longo prazo de 50 mil logs brutos por segundo.

## 7. O que fazemos no lugar

O indexer fica pequeno, só com os índices de estado do Wazuh. Logs e alertas passam a ir para o ClickHouse, um banco por cliente, alimentado por um Vector em cada gerenciador, com buffer em disco para não perder evento em pico. A estimativa é de 500 a 900 GB por dia para o mesmo volume, ou 15 a 27 TB em 30 dias, sem réplica. Todos esses números serão confirmados no teste de carga fora da VPS, com 10, 25 e 50 mil eventos por segundo.

## Fontes

- Wazuh, requisitos do indexer: https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html
- OpenSearch, configurações do cluster (limites de disco e `cluster.max_shards_per_node`): https://docs.opensearch.org/latest/install-and-configure/configuring-opensearch/cluster-settings/
- OpenSearch, instalação (heap em metade da memória): https://docs.opensearch.org/latest/install-and-configure/install-opensearch/index/
- OpenSearch, parâmetro `doc_values`: https://docs.opensearch.org/docs/field-types/mapping-parameters/doc-values
- Elasticsearch 7.10, base do OpenSearch (heap até 50% e perto de 32 GB): https://www.elastic.co/guide/en/elasticsearch/reference/7.10/important-settings.html
- AWS, cálculo de disco: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/bp-storage.html
- AWS, número de shards: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/bp-sharding.html
- AWS, escolha de máquinas: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/bp-instances.html
- AWS, escala de petabytes: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/petabyte-scale.html
