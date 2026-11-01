#!/bin/sh
# Cria o namespace do Roar quando o servidor estiver pronto.
set -eu

for _ in $(seq 1 30); do
  if temporal operator namespace describe -n roar >/dev/null 2>&1 \
    || temporal operator namespace create -n roar >/dev/null 2>&1; then
    exit 0
  fi
  sleep 5
done
echo "Não foi possível criar o namespace roar" >&2
exit 1
