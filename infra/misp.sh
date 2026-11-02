#!/usr/bin/env bash
# Plataforma de inteligência da instalação: uns 2,3 GB de memória e 5 GB de disco.
# Vem ligada no perfil completo e no de SIEM. Quem usa outra plataforma instala com --sem-misp.
set -euo pipefail

DESTINO="${ROAR_DESTINO:-/opt/panthera-roar}"
PASTA="$DESTINO/misp"
COMMIT=fbfe1e1ecafddf8bbd98420022e693c39fcc66e3
BASE="https://raw.githubusercontent.com/MISP/misp-docker/$COMMIT"
PORTA=18643
ENDERECO="http://127.0.0.1:$PORTA"
# Só os feeds públicos gerais. Cada outro feed tem termos próprios: quem administra liga depois de ler.
FEEDS_PADRAO='CIRCL OSINT Feed|The Botvrij.eu Data'
C="docker compose --project-name roar-misp --project-directory $PASTA -f $PASTA/docker-compose.yml -f $PASTA/compose.override.yaml"

valor() { grep -m1 "^$1=" "$DESTINO/.env" | cut -d= -f2-; }
garantir() { grep -q "^$1=" "$DESTINO/.env" || echo "$1=$(openssl rand -hex "$2")" >>"$DESTINO/.env"; }

mkdir -p "$PASTA"/{configs,logs,files,gnupg,ssl,custom}
[ -f "$PASTA/docker-compose.yml" ] || curl -fsSL -o "$PASTA/docker-compose.yml" "$BASE/docker-compose.yml"
[ -f "$PASTA/template.env" ] || curl -fsSL -o "$PASTA/template.env" "$BASE/template.env"

garantir MISP_SENHA 24
garantir MISP_CHAVE 20
garantir MISP_BANCO_SENHA 24
garantir MISP_BANCO_RAIZ 24
garantir MISP_CIFRA 16
grep -q '^ROAR_MISP_ENDERECO=' "$DESTINO/.env" || echo "ROAR_MISP_ENDERECO=$ENDERECO" >>"$DESTINO/.env"

(
  umask 077
  {
    cat "$PASTA/template.env"
    cat <<AMBIENTE

ADMIN_EMAIL=admin@misp.local
ADMIN_ORG=Panthera Roar
ADMIN_KEY=$(valor MISP_CHAVE)
ADMIN_PASSWORD=$(valor MISP_SENHA)
DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true
ENCRYPTION_KEY=$(valor MISP_CIFRA)
BASE_URL=$ENDERECO
MYSQL_PASSWORD=$(valor MISP_BANCO_SENHA)
MYSQL_ROOT_PASSWORD=$(valor MISP_BANCO_RAIZ)
INNODB_BUFFER_POOL_SIZE=512M
INNODB_LOG_FILE_SIZE=128M
NGINX_HTTP_PORT=127.0.0.1:$PORTA
NGINX_HTTPS_PORT=127.0.0.1:18644
AMBIENTE
  } >"$PASTA/.env"
)

# Programas em versão fixa. A porta só existe na própria máquina: quem fala com ele é o Roar.
cat >"$PASTA/compose.override.yaml" <<SOBRE
services:
  redis:
    image: valkey/valkey@sha256:828b1cbb1c258e02b9cd9588063fa997e097444e610d3f3c00d43e21400e2b8d
  db:
    image: mariadb@sha256:d769e37960821dfdcf096954f6e7ac89f747e116c1bba98e48edd265dfc7deae
  misp-modules:
    image: ghcr.io/misp/misp-docker/misp-modules@sha256:2324771fcc271748a61be4bc14a83e8df9ade1d6e314ccbc7bfa0d9cd6fbdbe5
    # O padrão do projeto dá 5 segundos para carregar, e numa máquina ocupada leva minutos.
    healthcheck:
      start_period: 300s
  misp-core:
    image: ghcr.io/misp/misp-docker/misp-core@sha256:4f97118678df217bf8ff62a22dbd6d0512f919fb2217f5fb620cba767e6e18ce
    healthcheck:
      start_period: 600s
  misp-nginx:
    image: ghcr.io/misp/misp-docker/misp-nginx@sha256:88ffa2971d58feb63e1bfe63580c232e2c20f0920bbf60bd3202cb863d3caf65
SOBRE
$C up -d --no-build db redis misp-modules misp-core misp-nginx

CHAVE="$(valor MISP_CHAVE)"
pedir() { curl -fsS --max-time 120 -H "Authorization: $CHAVE" -H 'Accept: application/json' -H 'Content-Type: application/json' "$@"; }
echo "Esperando a plataforma de inteligência. Na primeira vez leva alguns minutos."
for _ in $(seq 1 180); do
  pedir "$ENDERECO/servers/getVersion" >/dev/null 2>&1 && break
  sleep 10
done
pedir "$ENDERECO/servers/getVersion" >/dev/null

pedir -X POST "$ENDERECO/feeds/loadDefaultFeeds" >/dev/null || true
pedir "$ENDERECO/feeds" | "$DESTINO/venv/bin/python" -c "
import json, re, sys
for item in json.load(sys.stdin):
    f = item['Feed']
    if re.fullmatch(r'''$FEEDS_PADRAO''', f['name']):
        print(f['id'])
" | while read -r feed; do
  pedir -X POST "$ENDERECO/feeds/enable/$feed" >/dev/null
  pedir -X POST "$ENDERECO/feeds/fetchFromFeed/$feed" >/dev/null || true
done
echo "Plataforma de inteligência ligada."
