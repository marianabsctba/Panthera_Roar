#!/usr/bin/env bash
# Módulo opcional: scanner de rede. Ocupa dezenas de GB e pede 8 GB de memória livres.
set -euo pipefail

DESTINO="${ROAR_DESTINO:-/opt/panthera-roar}"
PASTA="$DESTINO/greenbone"
COMPOSE_TESTADO=5b5117a7c200491de13bc7b79c97dc858c016c51017982d8f1de7ca077c1a868
C="docker compose --project-name roar-greenbone --project-directory $PASTA -f $PASTA/compose.yaml -f $PASTA/compose.override.yaml"

mkdir -p "$PASTA"
[ -f "$PASTA/compose.yaml" ] || curl -fsSL -o "$PASTA/compose.yaml" https://greenbone.github.io/docs/latest/_static/compose.yaml
# Se o arquivo oficial mudar, alguém precisa ler antes: este é o que foi testado.
if [ "$(sha256sum "$PASTA/compose.yaml" | cut -d' ' -f1)" != "$COMPOSE_TESTADO" ]; then
  echo "O arquivo de instalação do scanner mudou desde o último teste. Confira $PASTA/compose.yaml e atualize COMPOSE_TESTADO." >&2
  exit 1
fi
# Quem fala com ele é o Roar, pelo socket: a tela própria dele não fica exposta nem na máquina.
# Programas em versão fixa. As bases de vulnerabilidades continuam na última, porque é para isso que elas existem.
cat >"$PASTA/compose.override.yaml" <<SOBRE
services:
  nginx:
    image: registry.community.greenbone.net/community/nginx@sha256:57e6a98d192f48e03acecdd193e8cf0a5b7fcf8c8be3cd7611f9725179ed8c19
    ports: !reset []
  redis-server:
    image: registry.community.greenbone.net/community/redis-server@sha256:6da6a7c7221aa3ab231961fd6ca001d552b6a2c7727ac6201c6d8a360baa963a
  pg-gvm:
    image: registry.community.greenbone.net/community/pg-gvm@sha256:a18d9e2f0cbba7839e65547a2331ce8f984500e8c4fbe91d08f9a48036d03fa2
  pg-gvm-migrator:
    image: registry.community.greenbone.net/community/pg-gvm-migrator@sha256:8fc1cc11cac0481674527e01ec7610a8195110cf117d700bd47fe3af7012b34d
  gvmd:
    image: registry.community.greenbone.net/community/gvmd@sha256:e59a6a684b112ea77fe4ddd7e5ca35e6a07d36bf854f1b411d11d12f9b0c608a
  gsa:
    image: registry.community.greenbone.net/community/gsa@sha256:2868c871c719e3d5079117f9ad31a4c1356d4aecd455962b90509d5de9c45a16
  gsad:
    image: registry.community.greenbone.net/community/gsad@sha256:8b2d983d934981c5f1c5cf95e3165489595e36679ff899d60ba4a4fe565d3aec
  openvas:
    image: registry.community.greenbone.net/community/openvas-scanner@sha256:7a7c440cf675a83ca1b6d8284eb28450893a8b05f5fed1f98e997df605792632
  configure-openvas:
    image: registry.community.greenbone.net/community/openvas-scanner@sha256:7a7c440cf675a83ca1b6d8284eb28450893a8b05f5fed1f98e997df605792632
  openvasd:
    image: registry.community.greenbone.net/community/openvas-scanner@sha256:7a7c440cf675a83ca1b6d8284eb28450893a8b05f5fed1f98e997df605792632
  ospd-openvas:
    image: registry.community.greenbone.net/community/ospd-openvas@sha256:31a85272abc77521c98451ce6834ed7d2f887e98ff1b26ff3fd94f00d000b169
SOBRE
$C up -d

if ! grep -q '^GREENBONE_SENHA=' "$DESTINO/.env"; then
  SENHA="$(openssl rand -hex 24)"
  until $C exec -T -u gvmd gvmd true 2>/dev/null; do sleep 5; done
  $C exec -T -u gvmd -e NOVA="$SENHA" gvmd sh -c 'gvmd --user=admin --new-password="$NOVA"'
  echo "GREENBONE_SENHA=$SENHA" >>"$DESTINO/.env"
fi
echo "Scanner de rede ligado. A primeira carga da base leva bastante tempo."
