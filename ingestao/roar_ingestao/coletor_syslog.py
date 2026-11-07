"""Syslog recebido pelo coletor do gerenciador, em vez do próprio Wazuh (docs/arquitetura.md, "Syslog no coletor").

O coletor (Vector) escuta a porta de syslog do gerenciador e a porta de repasse do receptor cifrado, aceita só os
endereços das fontes de syslog daquela organização e entrega cada linha ao analisador do gerenciador pelo socket que o
próprio leitor de arquivos do Wazuh usa, com o endereço do equipamento como origem. Nada passa por arquivo: o Wazuh lê
arquivo novo a partir do fim, e as primeiras linhas de cada um se perderiam. Com o desvio de volume ligado na organização,
o tráfego permitido dos firewalls conhecidos vai direto ao armazém, sem passar pelo gerenciador, que é o gargalo em volume
alto. A parte que muda com as fontes fica em coletor.d/syslog.yaml, que o coletor relê sozinho.
"""

import json
from pathlib import Path

MODELO = Path(__file__).resolve().parent / "coletor_syslog.yaml"
# A porta em que o coletor recebe o syslog cifrado repassado pelo receptor da instalação (só na rede dos gerenciadores).
PORTA_DO_REPASSE = 5140


def configuracao(redes, desvio, chave):
    """A parte do coletor que muda com as fontes. Sem rede nenhuma, ele recebe e descarta."""
    return (MODELO.read_text(encoding="utf-8")
            .replace("__REDES__", json.dumps(sorted(set(redes))))
            .replace("__DESVIO__", "true" if desvio else "false")
            .replace("__CHAVE__", chave))


def gravar(pasta_do_gerenciador, texto):
    """Troca o arquivo de uma vez só, numa pasta montada inteira (troca de arquivo montado sozinho não chega ao contêiner).
    Só o root lê: tem a chave do repasse. Devolve True se mudou."""
    pasta = Path(pasta_do_gerenciador) / "coletor.d"
    pasta.mkdir(mode=0o700, exist_ok=True)
    pasta.chmod(0o700)
    destino = pasta / "syslog.yaml"
    if destino.exists() and destino.read_text(encoding="utf-8") == texto:
        return False
    provisorio = pasta / "syslog.yaml.novo"
    provisorio.touch(mode=0o600)
    provisorio.chmod(0o600)
    provisorio.write_text(texto, encoding="utf-8")
    provisorio.replace(destino)
    return True
