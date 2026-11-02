# Padrão da console

A console é React com Mantine. O visual é preto com rosa metálico. Estas regras valem para toda tela.

## Texto

- Pouco texto na tela. Nada de parágrafo explicando o que a tela faz: isso vai no `ajuda` do `Cabecalho`, em uma ou duas frases.
- Português do Brasil, com acentos. Sem travessão.
- A tela não cita nome de ferramenta por baixo (Wazuh, OpenSearch, Temporal, Greenbone, Shuffle) nem conta bastidor. Formatos que a pessoa escreve, como YARA, Sigma e MITRE ATT&CK, podem aparecer.

## Controles

- Três estilos de botão: `variant="filled"` para a ação principal, o padrão para as secundárias, `variant="subtle" color="gray"` para Cancelar.
- No máximo uma ação principal por área da tela.
- Ações de uma linha ficam em `AcoesDaLinha` (o menu "⋯"), nunca como vários botões na tabela.
- Busca é `Busca`: compacta, largura fixa, aplica sozinha. Sem botão Buscar.
- Filtros ficam em `Select` ou `SegmentedControl` pequenos, na mesma linha da busca.
- Formulários abrem em `Modal`. Detalhes abrem em `Drawer`. Página longa vira `Tabs`.
- Erro da API aparece no próprio campo ou num `Alert` curto.

## Tudo leva a algum lugar

Isto é uma ferramenta de investigação, não um relatório.

- Todo número, barra, ponto e linha que represente registros abre o que está por trás dele.
- `Numero` com `aoClicar`, `Ranking` com `aoClicar`, `Tabela` com `aoClicarLinha`, gráfico com `barChartProps.onClick`.
- O que abre precisa ser exatamente o que o número conta.
- Clicar em eventos usa `GavetaDeEventos`, com os filtros de `/api/eventos`.

## Gráficos

- Finos e metálicos: use `BarrasMetalicas` e `Ranking`.
- Marca é rosa metálico. Severidade nunca é rosa: cada uma é um metal da própria cor, e sempre leva ícone e texto (`Severidade`).
- Uma cor por significado, um eixo só, legenda na ordem da gravidade.
- Toda barra tem dica ao passar o mouse.

## Datas e números

- Data é `Data`, que respeita o fuso da pessoa e não quebra linha.
- Número usa `numero()`, e coluna numérica é `alinhar: "right"`.
- Taxa pequena não pode virar zero por arredondamento.

## Permissões e módulos

- Esconda o que a pessoa não pode fazer com `usePode()`, mas quem decide é a API.
- Nunca confie só na tela.

## Construção

Na pasta `web`, `npm run construir` confere os tipos e gera os arquivos em `api/roar_api/estatico/console`.
