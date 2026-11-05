# Segurança

## Relatar uma falha

Não abra uma issue pública. Use **Report a vulnerability**, na aba **Security** deste repositório, que manda o relato direto e em sigilo.

Conte o que encontrou, como reproduzir e qual versão ou commit usou. A correção sai antes de qualquer divulgação.

## Versões cobertas

O projeto ainda está em construção: só a versão mais recente da branch `main` recebe correção.

## Como o Roar se protege

- Cada organização fica isolada no próprio banco, por política de linha, e não só no código.
- Senhas com Argon2, passkeys, autenticador e login único com o token conferido por inteiro.
- Segredos de integrações cifrados; nenhum volta para a tela depois de salvo.
- Conteúdo de log é tratado como dado não confiável: nunca vira instrução, nem na tela, nem nos relatórios, nem para a IA.
- Trilha de auditoria que só acrescenta, e selos encadeados e assinados sobre os eventos.
- Dependências Python travadas e conferidas com `pip-audit` antes de cada troca.

Os detalhes e as pendências conhecidas estão em [docs/arquitetura.md](docs/arquitetura.md).
