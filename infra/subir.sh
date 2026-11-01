#!/usr/bin/env bash
# Sobe o ambiente. Roda em Linux com Docker. Na primeira vez gera os segredos em .env.
set -euo pipefail

BASE="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(dirname "$BASE")"
DESTINO="/opt/panthera-roar"

# Versão fixa das integrações MIT (github.com/Shuffle/python-apps).
APPS_REPO="https://github.com/Shuffle/python-apps"
APPS_COMMIT="4a3d72091be4eb4f0c1e01fbbf62e4183d6dcc6d"

WAZUH_VERSAO="v4.14.9"

gerar() { head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-"$1"; }

mkdir -p "$DESTINO"
cp -r "$BASE/docker-compose.yml" "$BASE/temporal" "$DESTINO/"

if [ ! -f "$DESTINO/.env" ]; then
  sed -e "s|^POSTGRES_SENHA=.*|POSTGRES_SENHA=$(gerar 32)|" "$BASE/.env.exemplo" >"$DESTINO/.env"
  chmod 600 "$DESTINO/.env"
fi

docker compose --project-directory "$DESTINO" --project-name panthera-roar up -d --wait temporal
docker compose --project-directory "$DESTINO" --project-name panthera-roar up temporal-namespace --no-log-prefix

sysctl -qw vm.max_map_count=262144 2>/dev/null || sudo sysctl -qw vm.max_map_count=262144

if [ ! -d "$DESTINO/wazuh/.git" ]; then
  git clone -q --depth 1 --branch "$WAZUH_VERSAO" https://github.com/wazuh/wazuh-docker "$DESTINO/wazuh"
fi
WAZUH="$DESTINO/wazuh/single-node"
cp "$BASE/wazuh/docker-compose.override.yml" "$WAZUH/docker-compose.override.yml"
if [ ! -f "$WAZUH/config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
  docker compose --project-directory "$WAZUH" -f "$WAZUH/generate-indexer-certs.yml" run --rm generator
fi
docker compose --project-directory "$WAZUH" --project-name panthera-roar-wazuh up -d wazuh.indexer wazuh.manager

if [ ! -d "$DESTINO/apps/.git" ]; then
  rm -rf "$DESTINO/apps"
  git init -q "$DESTINO/apps"
  git -C "$DESTINO/apps" remote add origin "$APPS_REPO"
  git -C "$DESTINO/apps" sparse-checkout set http
fi
git -C "$DESTINO/apps" fetch -q --depth 1 origin "$APPS_COMMIT"
git -C "$DESTINO/apps" checkout -q FETCH_HEAD

if [ ! -x "$DESTINO/venv/bin/python" ]; then
  python3 -m venv "$DESTINO/venv"
fi
"$DESTINO/venv/bin/pip" install -q -r "$RAIZ/motor/requirements.txt"

echo "Ambiente no ar."
