#!/usr/bin/env bash
# Módulo opcional: scanner de rede. Ocupa dezenas de GB e pede 8 GB de memória livres.
set -euo pipefail

DESTINO="${ROAR_DESTINO:-/opt/panthera-roar}"
PASTA="$DESTINO/greenbone"
C="docker compose --project-name roar-greenbone --project-directory $PASTA -f $PASTA/compose.yaml -f $PASTA/compose.override.yaml"

mkdir -p "$PASTA"
[ -f "$PASTA/compose.yaml" ] || curl -fsSL -o "$PASTA/compose.yaml" https://greenbone.github.io/docs/latest/_static/compose.yaml
# Quem fala com ele é o Roar, pelo socket: a tela própria dele não fica exposta nem na máquina.
cat >"$PASTA/compose.override.yaml" <<'SOBRE'
services:
  nginx:
    ports: !reset []
SOBRE
$C up -d

if ! grep -q '^GREENBONE_SENHA=' "$DESTINO/.env"; then
  SENHA="$(openssl rand -hex 24)"
  until $C exec -T -u gvmd gvmd true 2>/dev/null; do sleep 5; done
  $C exec -T -u gvmd -e NOVA="$SENHA" gvmd sh -c 'gvmd --user=admin --new-password="$NOVA"'
  echo "GREENBONE_SENHA=$SENHA" >>"$DESTINO/.env"
fi
echo "Scanner de rede ligado. A primeira carga da base leva bastante tempo."
