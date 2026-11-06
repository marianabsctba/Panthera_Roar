#!/usr/bin/env python3
"""Casos e um playbook de vitrine na organização Demonstração, para a demonstração estática não mostrar telas vazias.

    sudo /opt/panthera-roar/venv/bin/python infra/demo/semear_vitrine.py --email <usuário da Demonstração> --senha-em <arquivo>

Usa a própria API, com o usuário dado: nada entra por fora das regras. Rodar de novo não duplica (procura pelo título).
"""

import argparse
import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "api"), str(RAIZ / "ingestao")]

from fastapi.testclient import TestClient  # noqa: E402

CASOS = [
    {"titulo": "Força bruta no SSH de srv-web-01 vinda de fora", "severidade": "alta", "alertas": ("brute force", "authentication failures"),
     "nota": "Alerta de força bruta aberto pela fila. Começando a investigar a origem e se houve login com sucesso depois.",
     "fatos": ["Mais de 300 tentativas de senha em 20 minutos, de três endereços da mesma operadora.",
               "Nenhum login com sucesso dessas origens até agora."],
     "hipoteses": ["É varredura automática, sem alvo específico na organização."],
     "passagem": {"para": "Plantão da noite", "feito": "Origens bloqueadas por 24 horas pelo playbook, com aprovação.",
                  "pendente": "Confirmar com a equipe de infraestrutura se o SSH precisa ficar aberto para a internet."}},
    {"titulo": "Possível ransomware em srv-dominio", "severidade": "critica", "alertas": ("ransomware", "yara"),
     "nota": "Alerta de possível ransomware e um arquivo que bateu numa regra YARA, no mesmo ativo e no mesmo dia.",
     "fatos": ["O arquivo suspeito foi gravado às 03:12, fora da janela de manutenção.", "O ativo foi isolado da rede às 03:40."],
     "hipoteses": ["Teste de segurança da própria equipe, não comunicado.", "Execução real, a partir de um e-mail aberto no dia anterior."]},
]
PLAYBOOK = {"nome": "Bloquear força bruta vinda de fora, com aprovação", "intervalo_minutos": 60, "definicao": {
    "quando": {"tipo": "evento", "regra_id": "5712"}, "se": [{"campo": "alvo_externo", "op": "igual", "valor": True}],
    "blocos": [{"tipo": "aprovacao"}, {"tipo": "acao", "acao": "bloquear_ip", "parametros": {"duracao_minutos": 1440}}]}}


def principal():
    args = argparse.ArgumentParser()
    args.add_argument("--email", required=True)
    args.add_argument("--senha-em", required=True)
    a = args.parse_args()
    os.environ.setdefault("ROAR_COOKIE_SEGURO", "1")
    from roar_api.app import app

    with TestClient(app, base_url="https://testserver") as http:
        r = http.post("/api/entrar", json={"email": a.email, "senha": Path(a.senha_em).read_text().strip()})
        if r.status_code not in (200, 204):
            raise SystemExit(f"não entrou: {r.status_code}")
        fila = http.get("/api/fila").json()
        grupos = [g for g in fila.get("grupos", []) if isinstance(g, dict) and "id" in g]
        existentes = {c["titulo"] for c in http.get("/api/casos").json().get("casos", [])}
        for caso in CASOS:
            if caso["titulo"] in existentes:
                continue
            # Os alertas da fila que combinam com o assunto do caso, até três.
            itens = [{"tipo": "grupo", "id": g["id"]} for g in grupos if any(p in (g.get("descricao") or "").lower() for p in caso["alertas"])][:3]
            criado = http.post("/api/casos", json={"titulo": caso["titulo"], "severidade": caso["severidade"], "itens": itens, "nota": caso["nota"]})
            caso_id = criado.json()["id"]
            for texto in caso["fatos"]:
                http.post(f"/api/casos/{caso_id}/notas", json={"texto": texto, "tipo": "fato"})
            for texto in caso["hipoteses"]:
                http.post(f"/api/casos/{caso_id}/notas", json={"texto": texto, "tipo": "hipotese"})
            if caso.get("passagem"):
                http.post(f"/api/casos/{caso_id}/passagem", json=caso["passagem"])
            http.patch(f"/api/casos/{caso_id}", json={"estado": "investigando"})
            print("caso criado:", caso["titulo"])
        playbooks = http.get("/api/automacao").json().get("playbooks", [])
        if not any(p.get("nome") == PLAYBOOK["nome"] for p in playbooks):
            r = http.post("/api/automacao/playbooks", json=PLAYBOOK)
            print("playbook:", r.status_code, r.text[:120])


if __name__ == "__main__":
    principal()
