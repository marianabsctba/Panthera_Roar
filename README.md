# Panthera Roar

SIEM open source com análise de comportamento, resposta automatizada e IA local, sem nenhum componente pago.

**Powered by Mariana BS**

O Roar recebe os logs dos seus servidores, estações e serviços de nuvem, transforma o que importa em alertas, soma o risco de cada pessoa e de cada ativo, e pode responder sozinho ou pedir a sua decisão antes. Tudo numa tela só, em português, com várias organizações isoladas na mesma instalação.

**Estado:** em construção, com as fases 0 a 4 prontas e testadas. O que já cobre dos editais públicos de SIEM está em [docs/cobertura-de-requisitos.md](docs/cobertura-de-requisitos.md).

## O que faz

**Coletar**
- Agente nos servidores e estações (testado em Linux e Windows; macOS ainda sem teste), syslog para equipamentos, conectores de nuvem e SaaS (Microsoft 365, AWS, Azure, Google Cloud, GitHub), webhook e API genérica.
- Integridade de arquivos com quem alterou, e busca de malware por regras YARA da comunidade.
- Retenção configurável por organização, cópia fria diária e recuperação de dias antigos.

**Detectar**
- Catálogo de regras pronto, regras próprias em formato guiado, Sigma ou XML, e matriz MITRE ATT&CK com as defesas do D3FEND.
- Inteligência de ameaças: MISP local já incluído, MISP e TAXII externos, conferência dos eventos antigos quando chega indicador novo, e caça de uma lista colada.
- Busca nos logs brutos com uma linguagem simples, em português.

**Comportamento (UEBA)**
- Risco por pessoa e por ativo, que soma sinais e cai pela metade a cada 24 horas: acesso depois de várias falhas, viagem impossível, primeiro uso de privilégio, conta criada, entrada em grupo administrativo, arquivo sensível alterado, contato com indicador de ameaça, regras disparadas e sequência de táticas do ATT&CK, entre outros.
- Aprende o normal de cada pessoa, compara com os pares que usam os mesmos ativos e pesa mais nos ativos críticos.
- O analista encerra o risco como falso positivo, esperado ou resolvido, e o Roar aprende com a decisão.

**Investigar e responder**
- Fila de trabalho, casos com responsável, prazo e histórico, e linha do tempo de cada risco.
- Playbooks em blocos, sem programar: bloquear endereço, desativar conta, avisar por webhook, sempre com aprovação quando o risco de errar é alto.
- Vulnerabilidades: varredura de rede, web e contêiner, priorizada pela exploração real (EPSS e catálogo KEV).

**Provar e cumprir**
- Selos encadeados e assinados a cada 15 minutos, âncora pública diária e pacote de evidência que se confere fora do Roar.
- Relatórios em PDF e JSON, com histórico, e relatório por norma: LGPD, PCI DSS, GDPR, HIPAA, NIST 800-53, TSC e GPG13.
- Eventos exportados no padrão aberto OCSF.

**Acesso**
- Perfis por função, conferidos em cada rota, e isolamento de cada organização no próprio banco.
- Passkeys, autenticador com códigos de recuperação, e login único com Google, Microsoft ou outro provedor OpenID Connect.
- Dado pessoal mascarado para quem não precisa ver (CPF, CNPJ, e-mail, cartão, telefone, usuário e IP).
- API pública com chaves por organização e documentação OpenAPI.

## Como funciona

```
agentes, syslog, nuvem -> gerenciador de cada organização -> indexador
                                       |
                                       v
                       ingestão (normaliza, deduplica, agrega)
                                       |
                                       v
                fila de alertas <-> UEBA (risco por pessoa e por ativo)
                                       |
                                       v
         tela e API do Roar -> aprovação -> motor de automação -> integrações
                                       |
                                       v
                      trilha de auditoria e selos de integridade
```

O Wazuh faz a coleta e as regras de base, sem alteração no código dele. Tudo o que é do Roar fica em volta: banco PostgreSQL com isolamento por organização, API em Python, console em React e motor de automação. Os princípios, os componentes e as decisões estão em [docs/arquitetura.md](docs/arquitetura.md).

## Instalar

Requer Linux com Docker, systemd, Git e Python 3.12, rodando como root ou com `sudo`.

```bash
sudo bash infra/subir.sh --email pessoa@exemplo.test --dominio siem.exemplo.test
```

- `--perfil`: `completo` (padrão), `siem` ou `vulnerabilidades`, que não precisa de Wazuh, indexador nem Temporal.
- `--dominio`: o endereço da console. Sem ele, usa `https://localhost` com certificado próprio.
- `--com-greenbone`: liga o scanner de rede, que é opcional e pesado.

Rodar o mesmo comando de novo atualiza.

### Primeiro acesso

1. Abra `/opt/panthera-roar/primeiro-acesso.txt`: tem o e-mail e uma senha temporária.
2. Entre na console e troque a senha.
3. Clique no seu nome, no alto da tela, e cadastre uma passkey ou o autenticador.
4. Siga o artigo **Primeiros passos**, em Ajuda, no menu da console.

### Backup

Backup diário e cifrado em `/opt/panthera-roar/backups`. Guarde `/opt/panthera-roar/backup.chave` fora do servidor, e confira de tempos em tempos:

```bash
sudo bash /opt/panthera-roar/app/infra/restaurar.sh --verificar /opt/panthera-roar/backups/ARQUIVO
```

Os eventos no indexador não entram nesse backup. Eles vão numa cópia fria diária do próprio indexador, em `/opt/panthera-roar/arquivo`, guardada pelo prazo de `ROAR_ARQUIVO_DIAS` (365 por padrão). Para essa cópia sobreviver à perda do servidor, monte um NAS nessa pasta antes de instalar, ou copie a pasta para fora.

Para conferir uma instalação em produção sem parar nada:

```bash
sudo bash /opt/panthera-roar/app/infra/conferir.sh
```

## Documentação

| Para | Onde |
|---|---|
| Usar cada tela | **Ajuda**, no menu da console, com busca |
| Integrar outro sistema | [docs/api.md](docs/api.md) e a tela **API** da console |
| Configurar login único e passkeys | [docs/login-unico.md](docs/login-unico.md) |
| Entender o desenho e as decisões | [docs/arquitetura.md](docs/arquitetura.md) |
| Ver o que cobre dos editais | [docs/cobertura-de-requisitos.md](docs/cobertura-de-requisitos.md) |
| Relatar uma falha de segurança | [SECURITY.md](SECURITY.md) |

## Desenvolver e testar

Requer o mesmo ambiente da instalação. Os testes rodam contra os serviços instalados, com eles pausados:

```bash
sudo bash infra/subir.sh
sudo bash testes/rodar.sh testes/fase4/testar_api.py testes/fase4/testar_perfis.py
```

| Pasta | O que cobre |
|---|---|
| `testes/fase0` | o motor de automação |
| `testes/fase1` | a ingestão, com agente Wazuh real |
| `testes/fase2` | o UEBA, com cenários, simulação de 30 dias e ataque real |
| `testes/fase4` | API, perfis, relatórios, fontes, inteligência, vulnerabilidades e o resto da tela |

Cada organização tem o seu gerenciador do Wazuh:

```bash
sudo PYTHONPATH=ingestao /opt/panthera-roar/venv/bin/python -m roar_ingestao.provisao criar --nome acme
```

Para ver a console com dados de exemplo (o acesso fica em `/opt/panthera-roar/demonstracao.txt`):

```bash
sudo /opt/panthera-roar/venv/bin/python testes/fase4/semear_demonstracao.py
```

A console fica em `web/`. Para mexer nela com recarga automática:

```bash
npm --prefix web install
npm --prefix web run dev
```

Para gerar a versão que a API serve, use `npm --prefix web run construir`. As dependências Python ficam travadas em `infra/travas/`: atualize, rode o `pip-audit` e só então troque.

## Licença

[AGPL-3.0](LICENSE). A fonte da assinatura, Mr De Haviland, é distribuída sob a [SIL Open Font License](api/roar_api/estatico/fontes/OFL-MrDeHaviland.txt).

---

<p align="center">
  <strong>Panthera Roar</strong><br>
  SIEM open source com análise de comportamento.<br><br>
  <strong>Powered by Mariana BS</strong>
</p>
