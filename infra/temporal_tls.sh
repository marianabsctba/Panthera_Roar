#!/usr/bin/env bash
# Certificados do Temporal: só entra quem apresenta o de cliente. Pode rodar de novo: não troca o que já existe.
#
#   sudo bash infra/temporal_tls.sh
#
# Sem isso, qualquer processo da máquina lia o histórico das automações de todas as organizações e podia pôr
# trabalho na fila de qualquer uma. A chave de cliente fica com o root, que roda os workers, e com o grupo roar-svc,
# que roda o disparo. A API roda com outro usuário e não a lê.
set -euo pipefail

DESTINO="${ROAR_DESTINO:-/opt/panthera-roar}"
PASTA="$DESTINO/temporal-tls"
SERVIDOR="$PASTA/servidor"
CLIENTE="$PASTA/cliente"
DIAS=3650
# O contêiner do Temporal roda com este usuário e precisa ler a chave dele.
USUARIO_DO_TEMPORAL=1000

if [ -f "$CLIENTE/cliente.pem" ] && [ -f "$SERVIDOR/servidor.pem" ]; then
  echo "Certificados do Temporal já existem."
  exit 0
fi

# O grupo dos serviços nasce aqui, igual a infra/servicos.sh, porque a chave precisa dele antes dos serviços existirem.
id roar-svc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin roar-svc
mkdir -p "$SERVIDOR" "$CLIENTE"
TRABALHO="$(mktemp -d)"
trap 'rm -rf "$TRABALHO"' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days "$DIAS" -subj "/CN=Panthera Roar Temporal" \
  -keyout "$TRABALHO/ca.key" -out "$TRABALHO/ca.pem" 2>/dev/null

emitir() {
  local nome="$1" assunto="$2" extensoes="$3" destino="$4"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$assunto" \
    -keyout "$destino/$nome.key" -out "$TRABALHO/$nome.csr" 2>/dev/null
  printf '%s\n' "$extensoes" >"$TRABALHO/$nome.ext"
  openssl x509 -req -in "$TRABALHO/$nome.csr" -CA "$TRABALHO/ca.pem" -CAkey "$TRABALHO/ca.key" -CAcreateserial \
    -days "$DIAS" -extfile "$TRABALHO/$nome.ext" -out "$destino/$nome.pem" 2>/dev/null
}
# O servidor também apresenta o próprio certificado ao falar consigo mesmo, por isso serve aos dois lados.
emitir servidor temporal "subjectAltName=DNS:temporal,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth,clientAuth" "$SERVIDOR"
emitir cliente roar-motor "extendedKeyUsage=clientAuth" "$CLIENTE"
cp "$TRABALHO/ca.pem" "$SERVIDOR/ca.pem"
cp "$TRABALHO/ca.pem" "$CLIENTE/ca.pem"
# A chave da autoridade não fica: certificado novo sai de uma autoridade nova, rodando este script de novo.

chown -R "$USUARIO_DO_TEMPORAL:$USUARIO_DO_TEMPORAL" "$SERVIDOR"
chmod 700 "$SERVIDOR"; chmod 600 "$SERVIDOR"/*.key; chmod 644 "$SERVIDOR"/*.pem
chown -R root:roar-svc "$CLIENTE"
chmod 750 "$CLIENTE"; chmod 640 "$CLIENTE"/*.key; chmod 644 "$CLIENTE"/*.pem
chmod 755 "$PASTA"
echo "Certificados do Temporal criados."
