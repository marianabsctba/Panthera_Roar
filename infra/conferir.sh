#!/usr/bin/env bash
# Confere uma instalação em produção. Só lê, a não ser com --queda e --backup.
#
#   sudo bash infra/conferir.sh [--queda] [--backup]
#
# --queda derruba a API de propósito, para provar que ela volta. --backup gera um backup e o restaura em banco descartável.
set -uo pipefail

DESTINO="${ROAR_DESTINO:-/opt/panthera-roar}"
FALHAS=0; TOTAL=0
QUEDA=0; BACKUP=0
for arg in "$@"; do
  case "$arg" in --queda) QUEDA=1 ;; --backup) BACKUP=1 ;; esac
done

prova() {
  local nome="$1"; shift
  TOTAL=$((TOTAL + 1))
  if "$@" >/dev/null 2>&1; then echo "[PASSOU] $nome"; else echo "[FALHOU] $nome"; FALHAS=$((FALHAS + 1)); fi
}
nao() { ! "$@"; }

DOMINIO="$(sed -n 's/^\([^ ]*\) {$/\1/p' "$DESTINO/Caddyfile" | head -1)"
URL="https://$DOMINIO"
curl_borda() { curl -sk --resolve "$DOMINIO:443:127.0.0.1" "$@"; }

echo "== Serviços"
PERFIL="$(cat "$DESTINO/perfil" 2>/dev/null || echo completo)"
case "$PERFIL" in
  vulnerabilidades) SERVICOS="api varredura cves" ;;
  siem) SERVICOS="api ingestao fontes cves selo ueba disparo inteligencia biblioteca" ;;
  *) SERVICOS="api ingestao fontes varredura cves selo ueba disparo inteligencia biblioteca" ;;
esac
echo "Perfil: $PERFIL"
for nome in $SERVICOS; do
  prova "roar-$nome no ar" systemctl is-active --quiet "roar-$nome"
  prova "roar-$nome volta sozinho depois de reiniciar a máquina" systemctl is-enabled --quiet "roar-$nome"
done
for cliente in $(docker exec roar-banco psql -At -U roar_admin -d roar -c "SELECT DISTINCT cliente_id FROM gerenciadores"); do
  prova "automação da organização $cliente no ar" systemctl is-active --quiet "roar-worker@$cliente"
done
prova "backup diário agendado" systemctl is-active --quiet roar-backup.timer

echo "== Rede"
prova "a console responde por HTTPS" bash -c "curl -sk --resolve '$DOMINIO:443:127.0.0.1' '$URL/api/saude' | grep -q '\"ok\"'"
prova "HTTP redireciona para HTTPS" bash -c "curl -s -o /dev/null -w '%{http_code}' --resolve '$DOMINIO:80:127.0.0.1' 'http://$DOMINIO/' | grep -qE '30[18]'"
prova "HSTS ligado" bash -c "curl -skI --resolve '$DOMINIO:443:127.0.0.1' '$URL/' | grep -qi strict-transport-security"
prova "sem revelar o servidor" bash -c "! curl -skI --resolve '$DOMINIO:443:127.0.0.1' '$URL/' | grep -qi '^server:'"
prova "API presa à máquina" bash -c "ss -ltn | grep -q '127.0.0.1:8600' && ! ss -ltn | grep -qE '(0\.0\.0\.0|\*|\[::\]):8600'"
for porta in 5433 7233 9200; do
  prova "porta $porta não está aberta para fora" bash -c "! ss -ltn | grep -qE '(0\.0\.0\.0|\*|\[::\]):$porta '"
done
prova "cookie de sessão exige HTTPS" bash -c "! grep -q 'ROAR_COOKIE_SEGURO=0' /etc/systemd/system/roar-api.service"

echo "== Segredos"
prova "a API não roda como root" bash -c "[ \"\$(systemctl show -p User --value roar-api)\" = roar-api ]"
como_api() { runuser -u roar-api -- "$@"; }
prova "a API não lê o .env completo" nao como_api cat "$DESTINO/.env"
prova "a API não lê a chave do cofre" nao como_api cat "$DESTINO/cofre/privada"
prova "a API não lê a chave dos selos" nao como_api cat "$DESTINO/selo/privada"
prova "a API não fala com o Docker" nao como_api docker ps
prova "a API lê os próprios segredos" como_api cat "$DESTINO/api.env"
prova "a API lê a chave pública do cofre" como_api cat "$DESTINO/cofre/publica"
prova "os segredos da API não têm a senha de administrador" bash -c "! grep -q BANCO_SENHA '$DESTINO/api.env'"
prova ".env só do root" bash -c "[ \"\$(stat -c '%a %U' '$DESTINO/.env')\" = '600 root' ]"
prova "nenhuma senha TROCAR sobrou" bash -c "! grep -q '=TROCAR$' '$DESTINO/.env'"
if docker ps --format '{{.Names}}' | grep -q '^roar-greenbone-gvmd'; then
  prova "tela própria do scanner não está exposta" bash -c "! ss -ltn | grep -qE ':(9392) '"
fi

echo "== Origem real"
EMAIL_FALSO="conferencia-$RANDOM@exemplo.test"
curl_borda -o /dev/null -X POST -H 'Content-Type: application/json' -H 'X-Forwarded-For: 203.0.113.99' -d "{\"email\":\"$EMAIL_FALSO\",\"senha\":\"x\"}" "$URL/api/entrar"
sleep 1
prova "cabeçalho forjado não engana o registro de origem" bash -c "! journalctl -u roar-api --since '-30 sec' | grep -F '$EMAIL_FALSO' | grep -q 203.0.113.99"
prova "a tentativa ficou no log" bash -c "journalctl -u roar-api --since '-30 sec' | grep -qF '$EMAIL_FALSO'"
prova "as ações recentes da trilha têm origem" bash -c "[ \"\$(docker exec roar-banco psql -At -U roar_admin -d roar -c \"SELECT count(*) FROM auditoria WHERE usuario_id IS NOT NULL AND origem IS NULL AND em > (SELECT coalesce(max(aplicada_em), now()) FROM migracoes WHERE nome = '032_origem_na_trilha.sql')\")\" = 0 ]"

if [ "$QUEDA" = 1 ]; then
  echo "== Queda"
  ANTES="$(systemctl show -p MainPID --value roar-api)"
  kill -9 "$ANTES" 2>/dev/null
  sleep 12
  DEPOIS="$(systemctl show -p MainPID --value roar-api)"
  prova "a API volta depois de morta" bash -c "[ '$DEPOIS' != '$ANTES' ] && [ '$DEPOIS' != 0 ]"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl_borda "$URL/api/saude" | grep -q '"ok"' && break
    sleep 3
  done
  prova "e volta a responder" bash -c "curl -sk --resolve '$DOMINIO:443:127.0.0.1' '$URL/api/saude' | grep -q '\"ok\"'"
fi

if [ "$BACKUP" = 1 ]; then
  echo "== Backup"
  ARQUIVO="$(bash "$DESTINO/app/infra/backup.sh" 2>/dev/null | tail -1)"
  prova "gera o backup" test -s "$ARQUIVO"
  prova "só o root lê" bash -c "[ \"\$(stat -c '%a' '$ARQUIVO')\" = 600 ]"
  prova "o arquivo está cifrado" bash -c "! head -c 4096 '$ARQUIVO' | grep -qa PGDMP"
  bash "$DESTINO/app/infra/restaurar.sh" --verificar "$ARQUIVO" 2>&1 | sed 's/^/   /'
  prova "restaura em banco descartável" bash "$DESTINO/app/infra/restaurar.sh" --verificar "$ARQUIVO"
  prova "chave errada não abre" bash -c "ROAR_BACKUP_CHAVE=/etc/hostname bash '$DESTINO/app/infra/restaurar.sh' --verificar '$ARQUIVO'; [ \$? -ne 0 ]"
fi

echo
echo "$((TOTAL - FALHAS)) de $TOTAL passaram."
[ "$FALHAS" = 0 ]
