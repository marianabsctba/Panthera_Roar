#!/usr/bin/env python3
"""Saúde por fonte (api/roar_api/saude_das_fontes.py): eventos, vazão, quanto foi entendido e a queda em relação ao normal
da mesma hora; o resumo por hora do armazém; e o aviso de fonte quieta. As contas usam dados de mentira; o resumo usa o
armazém real, com uma organização temporária e o usuário de coletor, que só insere.

    sudo bash testes/rodar.sh testes/fase4/testar_saude_das_fontes.py
"""

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao"), str(RAIZ / "api")]

from roar_api import saude_das_fontes as saude  # noqa: E402
from roar_ingestao import armazem, fontes_quietas, provisao  # noqa: E402

RESULTADOS = []
AGORA = datetime(2026, 11, 6, 15, 20, tzinfo=timezone.utc)


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def origem(por_hora, dias=8, ultima=None, entendidos=1.0):
    """Uma origem com `por_hora` eventos em cada hora dos últimos dias; `ultima` troca a última hora fechada."""
    atual = int(AGORA.replace(minute=0, second=0, microsecond=0).timestamp())
    horas = {}
    for i in range(1, dias * 24 + 1):
        h = atual - 3600 * i
        e = por_hora(h)
        if i == 1 and ultima is not None:
            e = ultima
        if e:
            horas[h] = (e, int(e * entendidos))
    return {"ultimo": float(max(horas) * 1000 + 1000) if horas else 0.0, "horas": horas, "primeira": min(horas) if horas else atual}


def contas():
    print("== Contas", flush=True)
    constante = origem(lambda h: 3600)
    c = saude.somar([constante], AGORA)
    registrar("24 horas, vazão e entendidos", c["eventos_24h"] == 23 * 3600 and c["eps"] == round(23 * 3600 / 86400, 3) and c["entendidos"] == 100.0, str(c)[:200])
    registrar("o gráfico tem as 24 horas, a atual por último", len(c["horas"]) == 24 and c["horas"][-1] == 0 and c["horas"][0] == 3600)
    registrar("em dia: não está abaixo do normal", c["normal_da_hora"] == 3600 and not c["abaixo_do_normal"])
    caiu = saude.somar([origem(lambda h: 3600, ultima=100)], AGORA)
    registrar("a última hora com menos de um quinto do normal é queda", caiu["abaixo_do_normal"] and caiu["ultima_hora"] == 100)
    # Escritório: muito de dia, quase nada de madrugada. A madrugada se compara com as madrugadas.
    escritorio = lambda h: 5000 if 11 <= datetime.fromtimestamp(h, timezone.utc).hour <= 21 else 200  # noqa: E731
    madrugada = AGORA.replace(hour=4)
    registrar("madrugada quieta de escritório não é queda", not saude.somar([origem(escritorio)], madrugada)["abaixo_do_normal"])
    registrar("o mesmo escritório quieto à tarde é queda", saude.somar([origem(escritorio, ultima=50)], AGORA)["abaixo_do_normal"])
    pequena = saude.somar([origem(lambda h: 20, ultima=0)], AGORA)
    registrar("fonte pequena demais não vira alarme", not pequena["abaixo_do_normal"] and pequena["normal_da_hora"] == 20)
    nova = saude.somar([origem(lambda h: 3600, dias=2, ultima=100)], AGORA)
    registrar("fonte de dois dias usa a média dos dias que tem", nova["normal_da_hora"] == 3600 and nova["abaixo_do_normal"], str(nova["normal_da_hora"]))
    registrar("fonte de menos de um dia não tem normal ainda", saude.somar([origem(lambda h: 3600, dias=1)], AGORA)["normal_da_hora"] is None)
    meio = saude.somar([origem(lambda h: 1000, entendidos=0.5)], AGORA)
    registrar("metade entendida aparece como 50%", meio["entendidos"] == 50.0)

    print("\n== Fontes", flush=True)
    origens = {"10.0.0.1": origem(lambda h: 3600), "10.0.0.2": origem(lambda h: 3600, ultima=0), "192.168.9.9": origem(lambda h: 500),
               "/var/log/auth.log": origem(lambda h: 50), "Wazuh-AWS": origem(lambda h: 900)}
    syslog = {"tipo": "syslog", "nome": "Firewalls", "config": {"origens": ["10.0.0.0/24"]}}
    conta = saude.da_fonte(syslog, origens, AGORA)
    enderecos = [q["endereco"] for q in conta["equipamentos"]]
    registrar("syslog conta só os endereços da lista, e o quieto vem primeiro", enderecos == ["10.0.0.2", "10.0.0.1"], str(enderecos))
    registrar("a fonte inteira não esconde o equipamento que parou", conta["equipamentos"][0]["abaixo_do_normal"] and not conta["abaixo_do_normal"])
    aws = saude.da_fonte({"tipo": "aws", "nome": "Conta AWS", "config": {}}, origens, AGORA)
    registrar("nuvem conta pelo nome do módulo", aws["eventos_24h"] == 23 * 900 and "equipamentos" not in aws)
    vazia = saude.da_fonte({"tipo": "gcp", "nome": "GCP", "config": {}}, origens, AGORA)
    registrar("fonte sem nada: zero, sem normal e sem queda", vazia["eventos_24h"] == 0 and vazia["normal_da_hora"] is None and not vazia["abaixo_do_normal"])
    avisos = fontes_quietas.quietas(syslog, conta)
    registrar("o aviso cita a fonte, o equipamento e os números", len(avisos) == 1 and avisos[0][0] == "10.0.0.2"
              and "Firewalls (10.0.0.2): 0 eventos na última hora; o normal nesse horário é 3.600" == avisos[0][1], str(avisos))


def resumo_no_armazem():
    print("\n== Resumo por hora no armazém", flush=True)
    env = provisao.ler_env(provisao.DESTINO / ".env")
    adm, leitor = armazem.admin(env), armazem.leitor(env)
    cliente, gerenciador = str(uuid.uuid4()), f"saude{uuid.uuid4().hex[:8]}"
    banco = armazem.banco_do(cliente)
    agora = datetime.now(timezone.utc)
    hora = agora.replace(minute=0, second=0, microsecond=0)

    def linha(local, quando, decoder="sshd"):
        return {"id": str(uuid.uuid4()), "ocorrido_em": quando.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "gerenciador": gerenciador,
                "agente_id": "000", "local": local, "decoder": decoder, "full_log": "x"}

    try:
        armazem.criar_organizacao(adm, cliente, 30, 30)
        # Já gravado antes do resumo existir: entra de uma vez quando ele é criado.
        adm.executar(f"DROP TABLE {banco}.origens_por_hora_visao")
        adm.executar(f"DROP TABLE {banco}.origens_por_hora")
        antigos = [linha("10.0.0.1", hora - timedelta(days=d, minutes=30)) for d in range(1, 4) for _ in range(5)]
        adm.executar(f"INSERT INTO {banco}.logs FORMAT JSONEachRow " + "\n".join(json.dumps(l) for l in antigos))
        armazem.criar_resumo_das_origens(adm, banco)
        total = int(adm.linhas(f"SELECT sum(eventos) AS n FROM {banco}.origens_por_hora")[0]["n"])
        registrar("o que já estava gravado entra no resumo ao criar", total == 15, str(total))

        # O coletor só insere: a visão roda com a permissão de quem a criou.
        senha = uuid.uuid4().hex
        usuario = armazem.criar_gravador(adm, gerenciador, cliente, senha)
        novos = [linha("10.0.0.1", hora - timedelta(minutes=30)), linha("10.0.0.1", hora - timedelta(minutes=29), decoder=""),
                 linha("10.0.0.2", hora - timedelta(minutes=10))]
        r = requests.post(f"{armazem.url(env)}/", params={"query": f"INSERT INTO {banco}.logs FORMAT JSONEachRow"},
                          data="\n".join(json.dumps(l) for l in novos), auth=(usuario, senha), timeout=30)
        registrar("o coletor grava sem erro com a visão ligada", r.status_code == 200, f"{r.status_code} {r.text[:200]}")
        origens = saude.ler(leitor, banco, gerenciador)
        um = origens.get("10.0.0.1", {"horas": {}})
        ultima = int((hora - timedelta(hours=1)).timestamp())
        registrar("a gravação do coletor cai no resumo, com o não entendido separado", um["horas"].get(ultima) == (2, 1) and "10.0.0.2" in origens, str(um.get("horas")))
        conta = saude.da_fonte({"tipo": "syslog", "nome": "t", "config": {"origens": ["10.0.0.0/24"]}}, origens)
        registrar("a fonte soma os dois equipamentos", conta["eventos_24h"] == 3 and len(conta["equipamentos"]) == 2, str(conta)[:200])
        registrar("outro gerenciador não aparece no resumo deste", not saude.ler(leitor, banco, "outro"))
    finally:
        armazem.remover_gravador(adm, gerenciador)
        armazem.remover_organizacao(adm, cliente)


def main():
    contas()
    resumo_no_armazem()
    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
