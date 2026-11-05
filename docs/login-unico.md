# Login único e passkeys

Dois jeitos de entrar no Roar sem depender só da senha. Os dois podem conviver com a senha e o autenticador.

## Passkey

A passkey fica no celular, no computador ou numa chave de segurança, e entra sem senha nem código. Ela é presa ao endereço do Roar: um site falso não consegue usar, mesmo que a pessoa caia no golpe.

Cada pessoa cadastra a sua:

1. Clique no seu nome, no alto da console, e escolha **Passkeys**.
2. Dê um nome, como "Celular", e digite a senha atual.
3. Clique em **Adicionar passkey** e confirme no aparelho, com a digital, o rosto ou o PIN.
4. Na próxima vez, clique em **Entrar com passkey** na tela de entrada.

Cadastre mais de uma, em aparelhos diferentes. A passkey só funciona em HTTPS, ou em `localhost` para quem desenvolve.

Se um aparelho devolver um contador de uso menor que o último visto, sinal de credencial copiada, a entrada é recusada.

## Login único (SSO)

A organização entra com a conta da empresa, pelo padrão OpenID Connect. Cada organização configura o seu provedor, em **Usuários → Login único (SSO)**, com o perfil Administração.

Antes de começar, copie o **endereço de retorno** que a tela mostra. Ele é sempre o endereço da console seguido de `/api/sso/retorno`.

### Google Workspace

1. No [Google Cloud Console](https://console.cloud.google.com/), abra **APIs e serviços → Credenciais**.
2. Clique em **Criar credenciais → ID do cliente OAuth**, tipo **Aplicativo da Web**.
3. Em **URIs de redirecionamento autorizados**, cole o endereço de retorno.
4. No Roar, escolha **Google**, cole o **ID do cliente** e a **chave secreta do cliente**.
5. Em **Domínios de e-mail aceitos**, informe o domínio da empresa, como `empresa.com.br`.
6. Clique em **Salvar**.

### Microsoft Entra ID

1. No [Microsoft Entra](https://entra.microsoft.com/), abra **Registros de aplicativo → Novo registro**.
2. Em **URI de redirecionamento**, escolha **Web** e cole o endereço de retorno.
3. Em **Certificados e segredos**, crie um **segredo do cliente** e copie o **valor**.
4. No Roar, escolha **Microsoft** e informe o **ID do diretório (locatário)**, o **ID do aplicativo (cliente)** e o valor do segredo.
5. Informe os domínios de e-mail aceitos e clique em **Salvar**.

Use o ID do locatário, no formato `00000000-0000-0000-0000-000000000000`. Com o nome do domínio ou com `common`, a Microsoft não declara um emissor fixo, e o Roar recusa porque não consegue conferir o token.

### Outro provedor OpenID Connect

Escolha **Outro** e informe o **emissor**: o endereço que aparece como `issuer` em `/.well-known/openid-configuration` do provedor. Depois, o ID e a chave secreta do cliente. Sem chave secreta, o Roar usa só PKCE, para aplicativos públicos.

### Como a pessoa entra

Ela digita o e-mail na tela de entrada e clica em **Entrar com Google**, **Entrar com Microsoft** ou **Outro login único**. O Roar acha a organização pelo e-mail e leva ao provedor dela. Se ela clicar no botão errado, a tela diz qual usar.

### O que o Roar confere

- O token é validado por inteiro: assinatura pelas chaves do provedor, emissor, audiência, validade e o nonce do pedido.
- O pedido usa PKCE e serve uma vez só.
- O e-mail tem de estar confirmado no provedor e ser de um domínio aceito.
- Só entra quem já é usuário ativo da mesma organização. O login único não cria pessoas nem muda ninguém de organização.
- A chave secreta fica cifrada e não volta para a tela.
- O Roar só conversa com o provedor em endereço público, em HTTPS.

### Exigir o login único

Com **Exigir o login único** ligado, a senha e a passkey deixam de valer para quem não tem o perfil Administração. Quem administra continua entrando com a senha, para não ficar trancado fora se o provedor cair.

Antes de exigir, teste com uma pessoa. Quem sai da empresa e é desativado no provedor deixa de entrar no Roar, mas desative também em **Usuários**, para encerrar as sessões abertas na hora.

### Quando não entra

| Mensagem | O que fazer |
|---|---|
| Este e-mail não entra por login único | a organização não configurou, ou está desligado |
| Sua organização entra pelo... | use o botão do provedor indicado |
| Não há usuário ativo com este e-mail nesta organização | crie a pessoa em Usuários, com o mesmo e-mail do provedor |
| Este e-mail não é de um domínio aceito | confira os domínios na configuração |
| O pedido de login único venceu | o pedido vale 10 minutos; tente de novo |
| O emissor informado não é o que o provedor declara | confira o endereço; na Microsoft, use o ID do locatário |
