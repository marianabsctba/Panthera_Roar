#!/usr/bin/env bash
# Fase 0: o Wazuh subiu e os alertas chegam ao indexer? Requer infra/subir.sh já executado.
set -uo pipefail

COMPOSE=/opt/panthera-roar/wazuh/single-node/docker-compose.yml
SENHA_INDEXER="$(grep -m1 'INDEXER_PASSWORD=' "$COMPOSE" | cut -d= -f2)"
SENHA_API="$(grep -m1 'API_PASSWORD=' "$COMPOSE" | cut -d= -f2)"
FALHAS=0

verificar() {
  if [ "$2" = "0" ]; then echo "[PASSOU] $1${3:+: $3}"; else echo "[FALHOU] $1${3:+: $3}"; FALHAS=$((FALHAS + 1)); fi
}

esperar() {
  for _ in $(seq 1 60); do eval "$1" >/dev/null 2>&1 && return 0; sleep 5; done
  return 1
}

esperar "curl -kfsS -m 5 -u admin:$SENHA_INDEXER https://127.0.0.1:9200/_cluster/health"
verificar "indexer responde" $?

TOKEN=""
for _ in $(seq 1 60); do
  TOKEN="$(curl -kfsS -m 10 -u "wazuh-wui:$SENHA_API" -X POST 'https://127.0.0.1:55000/security/user/authenticate?raw=true' 2>/dev/null)" && break
  sleep 5
done
[ -n "$TOKEN" ]; verificar "API do gerenciador autentica" $?

VERSAO="$(curl -kfsS -m 10 -H "Authorization: Bearer $TOKEN" https://127.0.0.1:55000/ | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["api_version"])')"
[ -n "$VERSAO" ]; verificar "API informa a versão" $? "$VERSAO"

TOTAL=0
for _ in $(seq 1 48); do
  TOTAL="$(curl -kfsS -m 10 -u "admin:$SENHA_INDEXER" 'https://127.0.0.1:9200/wazuh-alerts-*/_count' 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)["count"])' 2>/dev/null || echo 0)"
  [ "$TOTAL" -gt 0 ] && break
  sleep 5
done
[ "$TOTAL" -gt 0 ]; verificar "alertas chegam ao indexer" $? "$TOTAL alertas"

PORTAS="$(ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515|9200|55000)$' | grep -v '^127\.0\.0\.1:' || true)"
[ -z "$PORTAS" ]; verificar "portas só em 127.0.0.1" $? "$PORTAS"

exit "$FALHAS"
