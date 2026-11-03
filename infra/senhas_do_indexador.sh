#!/usr/bin/env bash
# Troca as senhas padrão que o Wazuh traz no indexador. Pode rodar de novo: só age enquanto a senha for a de fábrica.
#
#   sudo bash infra/senhas_do_indexador.sh
#
# Usa o certificado de super-administrador pela API, e não o arquivo de usuários: regravar o arquivo apagaria os
# usuários que o Roar cria pela API, um por gerenciador.
set -euo pipefail

DESTINO="${ROAR_DESTINO:-/opt/panthera-roar}"
WAZUH="$DESTINO/wazuh/single-node"
CERTS="$WAZUH/config/wazuh_indexer_ssl_certs"
USUARIOS="$WAZUH/config/wazuh_indexer/internal_users.yml"
ENV="$DESTINO/.env"
FABRICA="SecretPassword"

atual="$(grep -m1 '^WAZUH_INDEXER_PASSWORD=' "$ENV" | cut -d= -f2-)"
if [ "$atual" != "$FABRICA" ]; then
  echo "Senha do indexador já foi trocada."
  exit 0
fi

gerar() { head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-"$1"; }
# O certificado do indexador é emitido para o nome do serviço, não para o endereço local.
api() { curl -sS --fail-with-body --resolve wazuh.indexer:9200:127.0.0.1 --cacert "$CERTS/root-ca.pem" --cert "$CERTS/admin.pem" --key "$CERTS/admin-key.pem" \
  -H 'Content-Type: application/json' "$@"; }
URL="https://wazuh.indexer:9200/_plugins/_security/api/internalusers"

for n in $(seq 1 60); do
  api -o /dev/null "$URL/admin" 2>/dev/null && break
  [ "$n" = 60 ] && { echo "O indexador não respondeu com o certificado de administrador." >&2; exit 1; }
  sleep 5
done

admin="$(gerar 32)"
painel="$(gerar 32)"
# O painel do Wazuh não é usado, mas o usuário dele existe e tinha senha conhecida.
api -X PATCH "$URL/admin" -d "[{\"op\":\"add\",\"path\":\"/password\",\"value\":\"$admin\"}]" >/dev/null
api -X PATCH "$URL/kibanaserver" -d "[{\"op\":\"add\",\"path\":\"/password\",\"value\":\"$painel\"}]" >/dev/null
# Usuários de exemplo, com senha igual ao nome. Nada do Roar usa.
for usuario in kibanaro logstash readall snapshotrestore; do
  api -X DELETE "$URL/$usuario" >/dev/null 2>&1 || true
done

# Mantém o arquivo de acordo: se o índice de segurança for recriado a partir dele, não volta a senha de fábrica.
hash() { docker exec -e JAVA_HOME=/usr/share/wazuh-indexer/jdk panthera-roar-wazuh-wazuh.indexer-1 \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$1" | tail -1; }
python3 - "$USUARIOS" "$(hash "$admin")" "$(hash "$painel")" <<'PY'
import re
import sys

caminho, admin, painel = sys.argv[1:]
texto = open(caminho, encoding="utf-8").read()
for usuario, novo in (("admin", admin), ("kibanaserver", painel)):
    texto = re.sub(rf'(^{usuario}:\n\s+hash: )"[^"]*"', lambda m: f'{m[1]}"{novo}"', texto, count=1, flags=re.M)
# Tira os usuários de exemplo, cada um até o próximo bloco.
texto = re.sub(r"^(kibanaro|logstash|readall|snapshotrestore):\n(?:[ \t].*\n|\n)*", "", texto, flags=re.M)
open(caminho, "w", encoding="utf-8").write(texto)
PY

sed -i "s/^WAZUH_INDEXER_PASSWORD=.*/WAZUH_INDEXER_PASSWORD=$admin/" "$ENV"
for conta in "admin:$FABRICA" kibanaserver:kibanaserver kibanaro:kibanaro readall:readall; do
  # 401 é recusado; qualquer outra resposta quer dizer que a senha entrou.
  if [ "$(curl -sk -o /dev/null -w '%{http_code}' -u "$conta" https://127.0.0.1:9200)" != 401 ]; then
    echo "Uma senha de fábrica ainda entra: ${conta%%:*}." >&2
    exit 1
  fi
done
echo "Senhas do indexador trocadas."
