#!/usr/bin/env bash
# Backup cifrado: bancos, chaves, configuração e gerenciadores. Sem a chave, não abre.
#
#   infra/backup.sh [pasta de destino]
#
# Os eventos no indexador ficam fora: são muitos terabytes em produção e pedem snapshot em disco próprio.
set -euo pipefail

DESTINO="${ROAR_DESTINO:-/opt/panthera-roar}"
PASTA="${1:-$DESTINO/backups}"
MANTER_DIAS="${ROAR_BACKUP_DIAS:-14}"
CHAVE="$DESTINO/backup.chave"

mkdir -p "$PASTA"; chmod 700 "$PASTA"
if [ ! -f "$CHAVE" ]; then
  (umask 077; head -c 48 /dev/urandom | base64 -w0 >"$CHAVE")
  echo "Chave de backup criada em $CHAVE. Guarde uma cópia FORA deste servidor: sem ela, o backup não abre." >&2
fi

TRABALHO="$(mktemp -d)"
trap 'rm -rf "$TRABALHO"' EXIT
docker exec roar-banco pg_dump -U roar_admin -Fc roar >"$TRABALHO/roar.dump"
# O perfil só de vulnerabilidades não tem automação.
if docker ps --format '{{.Names}}' | grep -qx roar-postgresql; then
  docker exec roar-postgresql pg_dump -U temporal -Fc temporal >"$TRABALHO/temporal.dump"
fi

# Inscrição dos agentes e configuração de cada gerenciador: sem isso, todo agente precisaria ser reinscrito.
mkdir -p "$TRABALHO/volumes"
for volume in $(docker volume ls -q --filter name=roar-ger- | grep -E '_(etc|api_configuration|sslcerts|rules|decoders)$|_ossec_etc$|_wazuh_etc$' || true); do
  docker run --rm -v "$volume:/dados:ro" -v "$TRABALHO/volumes:/saida" --network none alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc tar czf "/saida/$volume.tar.gz" -C /dados . 2>/dev/null \
    || echo "Volume $volume não entrou no backup." >&2
done

ITENS=()
for item in .env api.env servicos.env Caddyfile cofre selo gerenciadores; do
  [ -e "$DESTINO/$item" ] && ITENS+=("$item")
done
tar czf "$TRABALHO/arquivos.tar.gz" -C "$DESTINO" "${ITENS[@]}"

( cd "$TRABALHO"; find . -type f ! -name RESUMOS -exec sha256sum {} + >RESUMOS )

ARQUIVO="$PASTA/roar-$(date -u +%Y%m%dT%H%M%SZ).tar.enc"
tar cf - -C "$TRABALHO" . | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "file:$CHAVE" -out "$ARQUIVO.tmp"
mv "$ARQUIVO.tmp" "$ARQUIVO"
chmod 600 "$ARQUIVO"
find "$PASTA" -name 'roar-*.tar.enc' -mtime +"$MANTER_DIAS" -delete
echo "$ARQUIVO"
