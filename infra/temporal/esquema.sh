#!/bin/sh
# Cria os bancos e aplica o esquema do Temporal. Pode rodar de novo sem efeito.
set -eu

ferramenta() {
  temporal-sql-tool --plugin postgres12 --ep "$POSTGRES_SEEDS" -u "$POSTGRES_USER" -p 5432 --db "$@"
}

for banco in temporal temporal_visibility; do
  pasta=temporal
  [ "$banco" = temporal_visibility ] && pasta=visibility
  ferramenta "$banco" create || true
  ferramenta "$banco" setup-schema -v 0.0 || true
  ferramenta "$banco" update-schema -d "/etc/temporal/schema/postgresql/v12/$pasta/versioned"
done
