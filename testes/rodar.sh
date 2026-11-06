#!/usr/bin/env bash
# Roda testes com os serviços pausados: eles percorrem todos os clientes e disputariam os dados de teste.
#
#   sudo bash testes/rodar.sh testes/fase4/testar_selos.py [outros testes]
#
# Só para máquina de teste. Em produção, use infra/conferir.sh.
set -uo pipefail

PY="${ROAR_PYTHON:-/opt/panthera-roar/venv/bin/python}"
SERVICOS="roar-ingestao roar-fontes roar-selo roar-ueba roar-disparo roar-varredura roar-inteligencia roar-biblioteca roar-organizacoes roar-superficie"
retomar() { systemctl start $SERVICOS 2>/dev/null || true; }
trap retomar EXIT
systemctl stop $SERVICOS 2>/dev/null || true

falhas=0
for teste in "$@"; do
  echo "== $teste"
  "$PY" -u "$teste" || falhas=$((falhas + 1))
done
exit "$falhas"
