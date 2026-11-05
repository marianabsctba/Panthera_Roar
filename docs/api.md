# API do Panthera Roar

Outros sistemas usam o Roar pela mesma API que a console usa: abrir casos, ler a fila, exportar eventos, caçar indicadores, gerar relatórios. Este guia mostra como começar. A lista completa de rotas, com parâmetros e exemplos, fica na tela **API** da console, e o arquivo OpenAPI sai pelo botão **OpenAPI** dela ou em `GET /api/openapi.json`.

## Criar uma chave

Quem tem o perfil Administração cria as chaves da organização.

1. No menu da console, abra **API** e clique em **Nova chave**.
2. Dê um nome que diga quem vai usar, como "SOAR externo" ou "Data lake".
3. Escolha o perfil e a validade (30 dias, 90 dias, 1 ano ou sem prazo).
4. Clique em **Criar** e copie a chave na hora. Ela começa com `roar_` e não aparece de novo: o Roar guarda só o resumo dela.

| Perfil da chave | O que pode |
|---|---|
| Analista N1 | ler, abrir casos e triar riscos; vê dado pessoal mascarado |
| Analista N2 | o mesmo, vendo dado pessoal, e aprovar automações |
| Engenharia de detecção | regras, fontes, automações e vulnerabilidades |
| Auditoria | só ler, inclusive a trilha de auditoria |

Não existe chave com perfil de Administração: uma chave vazada não consegue criar pessoas nem outras chaves.

## Usar a chave

Mande a chave no cabeçalho `Authorization`, depois da palavra `Bearer`:

```bash
export ROAR=https://siem.exemplo.test
export ROAR_CHAVE=roar_...

curl -H "Authorization: Bearer $ROAR_CHAVE" "$ROAR/api/fila"
```

Abrir um caso:

```bash
curl -X POST -H "Authorization: Bearer $ROAR_CHAVE" -H "Content-Type: application/json" \
  -d '{"titulo": "Phishing reportado pelo e-mail", "severidade": "alta"}' \
  "$ROAR/api/casos"
```

Caçar indicadores nos últimos 30 dias:

```bash
curl -X POST -H "Authorization: Bearer $ROAR_CHAVE" -H "Content-Type: application/json" \
  -d '{"texto": "185.220.101.4 mal-exemplo[.]com", "dias": 30}' \
  "$ROAR/api/inteligencia/cacar"
```

Exportar os alertas dos últimos 7 dias no padrão OCSF, um evento por linha:

```bash
curl -H "Authorization: Bearer $ROAR_CHAVE" "$ROAR/api/eventos/ocsf?dias=7&alertas=true" -o eventos.ndjson
```

## Regras que valem sempre

- A chave só enxerga a organização em que foi criada.
- O que ela faz aparece em nome de quem a criou, como "Ana (chave SOAR externo)", nos casos e na auditoria.
- O mascaramento de dado pessoal vale como na tela.
- Trocar senha, autenticador, passkey e sair não aceitam chave: só pela tela.
- Chave revogada, vencida, ou de quem foi desativado, para de valer na hora.

## Respostas de erro

| Código | Quer dizer |
|---|---|
| 401 | chave ausente, errada, vencida ou revogada |
| 403 | o perfil da chave não permite esta ação |
| 404 | não existe, ou é de outra organização |
| 409 | conflito com o estado atual, como encerrar o que já foi encerrado |
| 422 | dado inválido; a mensagem diz o que corrigir |
| 429 | muitas tentativas; espere alguns minutos |

## Formatos

- **JSON** em quase tudo.
- **NDJSON** (um JSON por linha) na exportação OCSF: [schema.ocsf.io](https://schema.ocsf.io/1.3.0).
- **PDF** nos relatórios.
- **CSV** e **XML** na exportação de vulnerabilidades e da auditoria.
