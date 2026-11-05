# Panthera Roar

SIEM open source com análise de comportamento, resposta automatizada e IA local, sem nenhum componente pago.

**Powered by Mariana BS**

**Estado:** em construção. A arquitetura, a ordem de construção e as pendências de segurança estão em [docs/arquitetura.md](docs/arquitetura.md).

## Instalar

Requer Linux com Docker, systemd, Git e Python 3.12, rodando como root ou com `sudo`.

```bash
sudo bash infra/subir.sh --email pessoa@exemplo.test --dominio siem.exemplo.test
```

Escolha o que instalar com `--perfil`: `completo` (padrão), `siem` ou `vulnerabilidades`, que não precisa de Wazuh, indexador nem Temporal. Sem `--dominio`, usa `https://localhost` com certificado próprio. O acesso inicial fica em `/opt/panthera-roar/primeiro-acesso.txt`, com uma senha temporária. Rodar o mesmo comando de novo atualiza. `--com-greenbone` liga o scanner de rede, que é opcional e pesado.

Backup diário e cifrado em `/opt/panthera-roar/backups`. Guarde `/opt/panthera-roar/backup.chave` fora do servidor, e confira de tempos em tempos:

```bash
sudo bash /opt/panthera-roar/app/infra/restaurar.sh --verificar /opt/panthera-roar/backups/ARQUIVO
```

Os eventos no indexador não entram nesse backup. Eles vão numa cópia fria diária do próprio indexador, em `/opt/panthera-roar/arquivo`, guardada pelo prazo de `ROAR_ARQUIVO_DIAS` (365 por padrão). Para essa cópia sobreviver à perda do servidor, monte um NAS nessa pasta antes de instalar, ou copie a pasta para fora.

## Ambiente de teste

Requer Linux com Docker, Git e Python 3.12, rodando como root ou com `sudo`.

```bash
sudo bash infra/subir.sh
sudo /opt/panthera-roar/venv-motor/bin/python testes/fase0/testar_motor.py
sudo /opt/panthera-roar/venv/bin/python testes/fase1/testar_ingestao.py
sudo /opt/panthera-roar/venv/bin/python testes/fase2/testar_ueba.py
sudo /opt/panthera-roar/venv/bin/python testes/fase4/testar_api.py
```

Cada cliente tem o seu gerenciador do Wazuh:

```bash
sudo PYTHONPATH=ingestao /opt/panthera-roar/venv/bin/python -m roar_ingestao.provisao criar --nome acme
```

Para ver a tela com dados de exemplo (o acesso fica em `/opt/panthera-roar/demonstracao.txt`):

```bash
sudo /opt/panthera-roar/venv/bin/python testes/fase4/semear_demonstracao.py
cd api && sudo ROAR_COOKIE_SEGURO=0 /opt/panthera-roar/venv/bin/python -m uvicorn roar_api.app:app --port 8600
```

## Licença

[AGPL-3.0](LICENSE). A fonte da assinatura, Mr De Haviland, é distribuída sob a [SIL Open Font License](api/roar_api/estatico/fontes/OFL-MrDeHaviland.txt).

---

<p align="center">
  <strong>Panthera Roar</strong><br>
  SIEM open source com análise de comportamento.<br><br>
  <strong>Powered by Mariana BS</strong>
</p>
