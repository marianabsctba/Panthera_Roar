# Panthera Roar

SIEM open source com análise de comportamento, resposta automatizada e IA local, sem nenhum componente pago.

**Estado:** em construção, ainda não usar com dados reais. A arquitetura, a ordem de construção e as pendências de segurança estão em [docs/arquitetura.md](docs/arquitetura.md).

## Ambiente de teste

Requer Linux com Docker, Git e Python 3.12, rodando como root ou com `sudo`.

```bash
sudo bash infra/subir.sh
sudo /opt/panthera-roar/venv/bin/python testes/fase0/testar_motor.py
sudo bash testes/fase0/testar_wazuh.sh
sudo /opt/panthera-roar/venv/bin/python testes/fase1/testar_ingestao.py
```
