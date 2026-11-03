#!/bin/sh
# Cria o namespace do Roar quando o servidor estiver pronto.
set -eu

# O servidor exige certificado de cliente: este contêiner usa o do próprio servidor, que serve aos dois lados.
TLS="--tls-cert-path /etc/temporal/tls/servidor.pem --tls-key-path /etc/temporal/tls/servidor.key --tls-ca-path /etc/temporal/tls/ca.pem --tls-server-name temporal"

for _ in $(seq 1 30); do
  # shellcheck disable=SC2086
  if temporal operator namespace describe $TLS -n roar >/dev/null 2>&1 \
    || temporal operator namespace create $TLS -n roar >/dev/null 2>&1; then
    exit 0
  fi
  sleep 5
done
echo "Não foi possível criar o namespace roar" >&2
exit 1
