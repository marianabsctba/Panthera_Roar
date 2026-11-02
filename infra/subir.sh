#!/usr/bin/env bash
# Instala ou atualiza. Roda em Linux com Docker e systemd. Na primeira vez gera os segredos em .env.
#
#   sudo bash infra/subir.sh --email pessoa@exemplo.test [--dominio siem.exemplo.test] [--organizacao "Minha empresa"] [--com-greenbone]
#
# Sem domínio, usa localhost com certificado próprio.
set -euo pipefail

DOMINIO=localhost; EMAIL=""; ORGANIZACAO="Minha organização"; COM_GREENBONE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dominio) DOMINIO="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --organizacao) ORGANIZACAO="$2"; shift 2 ;;
    --com-greenbone) COM_GREENBONE=1; shift ;;
    *) echo "Opção desconhecida: $1" >&2; exit 2 ;;
  esac
done
case "$DOMINIO" in *[!A-Za-z0-9.:-]*) echo "Domínio inválido." >&2; exit 2 ;; esac

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
# Domínio de verdade tira certificado público; endereço local usa a autoridade própria da borda.
case "$DOMINIO" in
  localhost|*.local|*.test|*.internal|[0-9]*.[0-9]*.[0-9]*.[0-9]*) TLS="tls internal" ;;
  *) TLS="" ;;
esac
cat >"$DESTINO/Caddyfile" <<CADDY
$DOMINIO {
  $TLS
  header {
    Strict-Transport-Security "max-age=31536000"
    -Server
  }
  reverse_proxy 127.0.0.1:8600
}
CADDY

# Acrescenta só as chaves que faltam, para instalações existentes manterem as senhas.
touch "$DESTINO/.env"
chmod 600 "$DESTINO/.env"
while IFS='=' read -r chave valor; do
  case "$chave" in ''|\#*) continue ;; esac
  grep -q "^$chave=" "$DESTINO/.env" && continue
  [ "$valor" = "TROCAR" ] && valor="$(gerar 32)"
  echo "$chave=$valor" >>"$DESTINO/.env"
done <"$BASE/.env.exemplo"

docker compose --project-directory "$DESTINO" --project-name panthera-roar up -d --wait temporal banco
docker compose --project-directory "$DESTINO" --project-name panthera-roar up temporal-namespace --no-log-prefix
bash "$BASE/migrar.sh" "$DESTINO/.env"

sysctl -qw vm.max_map_count=262144 2>/dev/null || sudo sysctl -qw vm.max_map_count=262144

if [ ! -d "$DESTINO/wazuh/.git" ]; then
  git clone -q --depth 1 --branch "$WAZUH_VERSAO" https://github.com/wazuh/wazuh-docker "$DESTINO/wazuh"
fi
WAZUH="$DESTINO/wazuh/single-node"
cp "$BASE/wazuh/docker-compose.override.yml" "$WAZUH/docker-compose.override.yml"
if [ ! -f "$WAZUH/config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
  docker compose --project-directory "$WAZUH" -f "$WAZUH/generate-indexer-certs.yml" run --rm generator
fi
docker compose --project-directory "$WAZUH" --project-name panthera-roar-wazuh up -d wazuh.indexer
for chave in INDEXER_USERNAME INDEXER_PASSWORD; do
  grep -q "^WAZUH_$chave=" "$DESTINO/.env" \
    || echo "WAZUH_$chave=$(grep -m1 "$chave=" "$WAZUH/docker-compose.yml" | cut -d= -f2-)" >>"$DESTINO/.env"
done

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
"$DESTINO/venv/bin/pip" install -q -r "$RAIZ/motor/requirements.txt" -r "$RAIZ/ingestao/requirements.txt" -r "$RAIZ/ueba/requirements.txt" -r "$RAIZ/api/requirements.txt"
# As integrações de terceiros fixam versões próprias, e rodam isoladas do resto.
if [ ! -x "$DESTINO/venv-motor/bin/python" ]; then
  python3 -m venv "$DESTINO/venv-motor"
fi
"$DESTINO/venv-motor/bin/pip" install -q -r "$RAIZ/motor/requirements.txt" -r "$RAIZ/motor/requirements-integracoes.txt"

PYTHONPATH="$RAIZ/ingestao" "$DESTINO/venv/bin/python" -m roar_ingestao.provisao preparar

bash "$BASE/servicos.sh" "$DOMINIO"
docker compose --project-directory "$DESTINO" --project-name panthera-roar up -d borda

if [ -n "$EMAIL" ]; then
  PYTHONPATH="$RAIZ/ingestao" "$DESTINO/venv/bin/python" -m roar_ingestao.provisao primeiro-acesso --organizacao "$ORGANIZACAO" --email "$EMAIL"
fi

if [ "$COM_GREENBONE" = 1 ]; then
  bash "$BASE/greenbone.sh"
fi

echo "Pronto: https://$DOMINIO"
echo "Faça o primeiro backup e guarde a chave fora deste servidor: bash $DESTINO/app/infra/backup.sh"
