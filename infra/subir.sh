#!/usr/bin/env bash
# Instala ou atualiza. Roda em Linux com Docker e systemd. Na primeira vez gera os segredos em .env.
#
#   sudo bash infra/subir.sh --email pessoa@exemplo.test [--dominio siem.exemplo.test] [--organizacao "Minha empresa"] [--perfil completo|siem|vulnerabilidades] [--com-greenbone]
#
# Sem domínio, usa localhost com certificado próprio.
set -euo pipefail

DOMINIO=localhost; EMAIL=""; ORGANIZACAO="Minha organização"; COM_GREENBONE=0; PERFIL=completo; SEM_MISP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dominio) DOMINIO="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --organizacao) ORGANIZACAO="$2"; shift 2 ;;
    --perfil) PERFIL="$2"; shift 2 ;;
    --com-greenbone) COM_GREENBONE=1; shift ;;
    --sem-misp) SEM_MISP=1; shift ;;
    *) echo "Opção desconhecida: $1" >&2; exit 2 ;;
  esac
done
case "$DOMINIO" in *[!A-Za-z0-9.:-]*) echo "Domínio inválido." >&2; exit 2 ;; esac
case "$PERFIL" in completo|siem|vulnerabilidades) ;; *) echo "Perfil desconhecido: use completo, siem ou vulnerabilidades." >&2; exit 2 ;; esac

BASE="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(dirname "$BASE")"
DESTINO="/opt/panthera-roar"

# Versão fixa das integrações MIT (github.com/Shuffle/python-apps).
APPS_REPO="https://github.com/Shuffle/python-apps"
APPS_COMMIT="4a3d72091be4eb4f0c1e01fbbf62e4183d6dcc6d"

WAZUH_VERSAO="v4.14.9"

gerar() { head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-"$1"; }

mkdir -p "$DESTINO"
cp -r "$BASE/docker-compose.yml" "$BASE/temporal" "$DESTINO/"
# Domínio de verdade tira certificado público; endereço local usa a autoridade própria da borda.
case "$DOMINIO" in
  localhost|*.local|*.test|*.internal|[0-9]*.[0-9]*.[0-9]*.[0-9]*) TLS="tls internal" ;;
  *) TLS="" ;;
esac
cat >"$DESTINO/Caddyfile" <<CADDY
$DOMINIO {
  $TLS
  header {
    Strict-Transport-Security "max-age=31536000"
    -Server
  }
  reverse_proxy 127.0.0.1:8600
}
CADDY

# Acrescenta só as chaves que faltam, para instalações existentes manterem as senhas.
touch "$DESTINO/.env"
chmod 600 "$DESTINO/.env"
while IFS='=' read -r chave valor; do
  case "$chave" in ''|\#*) continue ;; esac
  grep -q "^$chave=" "$DESTINO/.env" && continue
  [ "$valor" = "TROCAR" ] && valor="$(gerar 32)"
  echo "$chave=$valor" >>"$DESTINO/.env"
done <"$BASE/.env.exemplo"

echo "$PERFIL" >"$DESTINO/perfil"
if [ "$PERFIL" != vulnerabilidades ]; then
  bash "$BASE/temporal_tls.sh"
fi
if [ "$PERFIL" = vulnerabilidades ]; then
  docker compose --project-directory "$DESTINO" --project-name panthera-roar up -d --wait banco
else
  docker compose --project-directory "$DESTINO" --project-name panthera-roar up -d --wait temporal banco
  docker compose --project-directory "$DESTINO" --project-name panthera-roar up temporal-namespace --no-log-prefix
fi
bash "$BASE/migrar.sh" "$DESTINO/.env"

if [ "$PERFIL" != vulnerabilidades ]; then
  sysctl -qw vm.max_map_count=262144 2>/dev/null || sudo sysctl -qw vm.max_map_count=262144

  if [ ! -d "$DESTINO/wazuh/.git" ]; then
    git clone -q --depth 1 --branch "$WAZUH_VERSAO" https://github.com/wazuh/wazuh-docker "$DESTINO/wazuh"
  fi
  WAZUH="$DESTINO/wazuh/single-node"
  cp "$BASE/wazuh/docker-compose.override.yml" "$WAZUH/docker-compose.override.yml"
  if [ ! -f "$WAZUH/config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
    docker compose --project-directory "$WAZUH" -f "$WAZUH/generate-indexer-certs.yml" run --rm generator
  fi
  # O indexador só grava cópia em pasta declarada na configuração dele.
  mkdir -p "$DESTINO/arquivo"
  chown 1000:1000 "$DESTINO/arquivo"
  chmod 700 "$DESTINO/arquivo"
  # O arquivo do Wazuh termina sem quebra de linha: sem a primeira, a linha nova grudaria na anterior e o indexador não subiria.
  grep -q '^path.repo:' "$WAZUH/config/wazuh_indexer/wazuh.indexer.yml" \
    || printf '\npath.repo: ["/mnt/roar-arquivo"]\n' >>"$WAZUH/config/wazuh_indexer/wazuh.indexer.yml"
  docker compose --project-directory "$WAZUH" --project-name panthera-roar-wazuh up -d wazuh.indexer
  for chave in INDEXER_USERNAME INDEXER_PASSWORD; do
    grep -q "^WAZUH_$chave=" "$DESTINO/.env" \
      || echo "WAZUH_$chave=$(grep -m1 "$chave=" "$WAZUH/docker-compose.yml" | cut -d= -f2-)" >>"$DESTINO/.env"
  done
  # A senha de fábrica é pública: troca antes de qualquer outra coisa usar o indexador.
  bash "$BASE/senhas_do_indexador.sh"

  if [ ! -d "$DESTINO/apps/.git" ]; then
    rm -rf "$DESTINO/apps"
    git init -q "$DESTINO/apps"
    git -C "$DESTINO/apps" remote add origin "$APPS_REPO"
    git -C "$DESTINO/apps" sparse-checkout set http
  fi
  git -C "$DESTINO/apps" fetch -q --depth 1 origin "$APPS_COMMIT"
  git -C "$DESTINO/apps" checkout -q FETCH_HEAD
fi

if [ ! -x "$DESTINO/venv/bin/python" ]; then
  python3 -m venv "$DESTINO/venv"
fi
# Versões travadas: instalar hoje ou daqui a um ano dá o mesmo conjunto, já conferido contra falhas conhecidas.
"$DESTINO/venv/bin/pip" install -q -r "$BASE/travas/principal.txt"
if [ "$PERFIL" != vulnerabilidades ]; then
  # As integrações de terceiros fixam versões próprias, e rodam isoladas do resto.
  if [ ! -x "$DESTINO/venv-motor/bin/python" ]; then
    python3 -m venv "$DESTINO/venv-motor"
  fi
  # O SDK fixa bibliotecas antigas e com falhas: entra sem dependências, e o que ele usa vem da trava.
  "$DESTINO/venv-motor/bin/pip" install -q --no-deps -r "$BASE/travas/motor.txt"
fi

if [ "$PERFIL" != vulnerabilidades ]; then
  PYTHONPATH="$RAIZ/ingestao" "$DESTINO/venv/bin/python" -m roar_ingestao.provisao preparar
fi

bash "$BASE/servicos.sh" "$DOMINIO" "$PERFIL"
docker compose --project-directory "$DESTINO" --project-name panthera-roar up -d borda

if [ -n "$EMAIL" ]; then
  PYTHONPATH="$RAIZ/ingestao" "$DESTINO/venv/bin/python" -m roar_ingestao.provisao primeiro-acesso --organizacao "$ORGANIZACAO" --email "$EMAIL"
fi

if [ "$SEM_MISP" = 0 ] && [ "$PERFIL" != vulnerabilidades ]; then
  bash "$BASE/misp.sh"
fi

if [ "$COM_GREENBONE" = 1 ]; then
  bash "$BASE/greenbone.sh"
fi

echo "Pronto: https://$DOMINIO"
echo "Faça o primeiro backup e guarde a chave fora deste servidor: bash $DESTINO/app/infra/backup.sh"
