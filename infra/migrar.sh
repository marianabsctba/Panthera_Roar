#!/usr/bin/env bash
# Aplica as migrações pendentes e define as senhas dos papéis da aplicação.
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
ENV="${1:-/opt/panthera-roar/.env}"

valor() { grep -m1 "^$1=" "$ENV" | cut -d= -f2-; }
psql_roar() { docker exec -i roar-banco psql -q -U roar_admin -d roar -v ON_ERROR_STOP=1 "$@"; }

psql_roar <<'SQL'
CREATE TABLE IF NOT EXISTS migracoes (
  nome text PRIMARY KEY,
  aplicada_em timestamptz NOT NULL DEFAULT now()
);
SQL

for arquivo in "$RAIZ"/banco/migracoes/*.sql; do
  nome="$(basename "$arquivo")"
  if [ -z "$(psql_roar -Atc "SELECT 1 FROM migracoes WHERE nome = '$nome'")" ]; then
    {
      cat "$arquivo"
      echo "INSERT INTO migracoes (nome) VALUES ('$nome');"
    } | psql_roar --single-transaction
    echo "Migração aplicada: $nome"
  fi
done

# Pela entrada padrão, para a senha não aparecer na lista de processos.
psql_roar <<SQL
ALTER ROLE roar_ingestao PASSWORD '$(valor ROAR_INGESTAO_SENHA)';
ALTER ROLE roar_api PASSWORD '$(valor ROAR_API_SENHA)';
ALTER ROLE roar_ueba PASSWORD '$(valor ROAR_UEBA_SENHA)';
SQL
