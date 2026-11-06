# Demonstração estática da console

A demonstração é a própria console (`web/`), construída em modo demonstração: as telas são as mesmas, e as respostas da
API vêm gravadas da organização Demonstração. Nada sai do navegador; o que mudaria algo responde como se tivesse dado
certo, sem gravar nada. Um aviso no canto diz que os dados são fictícios.

## Gerar de novo

No servidor de teste, com um usuário administrador da organização Demonstração (a senha num arquivo só do root):

```bash
sudo /opt/panthera-roar/venv/bin/python infra/demo/semear_vitrine.py --email <usuário> --senha-em <arquivo>
sudo /opt/panthera-roar/venv/bin/python infra/demo/gravar_respostas.py --email <usuário> --senha-em <arquivo> --saida web/demo/dados-demo.json
```

Depois, na máquina de desenvolvimento:

```bash
npm --prefix web run demo
```

O resultado vai para `demo/`, pronto para qualquer servidor de arquivos, inclusive numa subpasta.

- `semear_vitrine.py` cria dois casos e um playbook pela própria API, para essas telas não aparecerem vazias. Rodar de novo não duplica.
- `gravar_respostas.py` percorre as rotas que a console usa, acha os ids nas listas para gravar os detalhes e roda os blocos dos painéis. No fim troca o que for real, pela lista em `infra/demo/trocas.json` (fora do Git: ela mesma tem dado real), e para se algo da lista `nunca` sobrar.
- Ao abrir a demonstração, o console do navegador avisa cada rota sem resposta gravada (`demonstração sem resposta gravada`).

## Publicar no GitHub Pages

```bash
bash infra/demo/publicar.sh "docs(demo): o que mudou"
```

O script põe a pasta `demo/` no ramo `gh-pages`, numa cópia de trabalho à parte, sem mexer na `main`. O Pages do
repositório serve esse ramo: https://marianabsctba.github.io/Panthera_Roar/

Para testar antes, sirva a pasta do projeto e abra `/demo/`, como fica no Pages:

```bash
python -m http.server 8710
```
