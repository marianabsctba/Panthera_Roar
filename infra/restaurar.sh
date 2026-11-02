#!/usr/bin/env bash
# Backup que nunca foi restaurado não é backup.
#
#   infra/restaurar.sh --verificar arquivo.tar.enc    abre em bancos descartáveis e confere, sem tocar em nada
#   infra/restaurar.sh --aplicar   arquivo.tar.enc    substitui os bancos e os arquivos atuais
set -euo pipefail

MODO="${1:-}"; ARQUIVO="${2:-}"
DESTINO="${ROAR_DESTINO:-/opt/panthera-roar}"
CHAVE="${ROAR_BACKUP_CHAVE:-$DESTINO/backup.chave}"
case "$MODO" in --verificar|--aplicar) ;; *) echo "Use --verificar ou --aplicar, e o arquivo." >&2; exit 2 ;; esac
[ -f "$ARQUIVO" ] || { echo "Arquivo não encontrado: $ARQUIVO" >&2; exit 2; }

TRABALHO="$(mktemp -d)"
TESTE="roar-restauracao-$$"
limpar() { rm -rf "$TRABALHO"; docker rm -f "$TESTE" >/dev/null 2>&1 || true; }
trap limpar EXIT

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:$CHAVE" -in "$ARQUIVO" | tar xf - -C "$TRABALHO"
( cd "$TRABALHO"; sha256sum --quiet -c RESUMOS ) || { echo "O backup está corrompido." >&2; exit 1; }
echo "Abriu, e os resumos conferem."

if [ "$MODO" = "--verificar" ]; then
  docker run -d --name "$TESTE" --network none -e POSTGRES_PASSWORD=descartavel -e POSTGRES_USER=roar_admin -e POSTGRES_DB=roar postgres:16 >/dev/null
  until docker exec "$TESTE" pg_isready -q -U roar_admin -d roar 2>/dev/null; do sleep 1; done
  sleep 2
  for papel in roar_ingestao roar_api roar_ueba roar_soar; do
    docker exec "$TESTE" psql -q -U roar_admin -d roar -c "CREATE ROLE $papel" >/dev/null
  done
  docker exec -i "$TESTE" pg_restore --no-owner --exit-on-error -U roar_admin -d roar <"$TRABALHO/roar.dump" >/dev/null
  for tabela in clientes usuarios eventos selos vuln_achados auditoria; do
    echo "$tabela: $(docker exec "$TESTE" psql -At -U roar_admin -d roar -c "SELECT count(*) FROM $tabela")"
  done
  tar tzf "$TRABALHO/arquivos.tar.gz" | grep -qE '^(\./)?cofre/privada$' || { echo "A chave do cofre não está no backup." >&2; exit 1; }
  tar tzf "$TRABALHO/arquivos.tar.gz" | grep -qE '^(\./)?selo/privada$' || { echo "A chave dos selos não está no backup." >&2; exit 1; }
  echo "Volumes de gerenciador: $(ls "$TRABALHO/volumes" 2>/dev/null | wc -l)"
  echo "Restauração verificada, sem tocar no ambiente."
  exit 0
fi

SERVICOS="api ingestao fontes varredura cves selo ueba disparo"
for nome in $SERVICOS; do systemctl stop "roar-$nome" 2>/dev/null || true; done
systemctl stop 'roar-worker@*' 2>/dev/null || true
tar xzf "$TRABALHO/arquivos.tar.gz" -C "$DESTINO"
docker exec roar-banco psql -q -U roar_admin -d postgres -c "DROP DATABASE IF EXISTS roar WITH (FORCE)" -c "CREATE DATABASE roar"
docker exec -i roar-banco pg_restore -U roar_admin -d roar <"$TRABALHO/roar.dump"
docker exec roar-postgresql psql -q -U temporal -d postgres -c "DROP DATABASE IF EXISTS temporal WITH (FORCE)" -c "CREATE DATABASE temporal"
docker exec -i roar-postgresql pg_restore -U temporal -d temporal <"$TRABALHO/temporal.dump"
for arquivo in "$TRABALHO"/volumes/*.tar.gz; do
  [ -e "$arquivo" ] || continue
  volume="$(basename "$arquivo" .tar.gz)"
  docker run --rm -v "$volume:/dados" -v "$TRABALHO/volumes:/entrada:ro" --network none alpine:3.20 sh -c "tar xzf '/entrada/$volume.tar.gz' -C /dados"
done
for nome in $SERVICOS; do systemctl start "roar-$nome" 2>/dev/null || true; done
for cliente in $(docker exec roar-banco psql -At -U roar_admin -d roar -c "SELECT DISTINCT cliente_id FROM gerenciadores"); do
  systemctl start "roar-worker@$cliente" 2>/dev/null || true
done
echo "Restaurado. Os eventos do indexador não fazem parte deste backup."
