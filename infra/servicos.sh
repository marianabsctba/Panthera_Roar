#!/usr/bin/env bash
# Instala o código em /opt/panthera-roar/app, separa os segredos por serviço e liga tudo no systemd.
# Pode rodar de novo: é assim que uma atualização acontece.
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
DESTINO="${ROAR_DESTINO:-/opt/panthera-roar}"
DOMINIO="${1:-localhost}"
PERFIL="${2:-$(cat "$DESTINO/perfil" 2>/dev/null || echo completo)}"
APP="$DESTINO/app"
PY="$DESTINO/venv/bin/python"

valor() { grep -m1 "^$1=" "$DESTINO/.env" | cut -d= -f2-; }

# Um usuário sem nada para quem atende a rede, outro para os serviços que só falam com o banco.
for usuario in roar-api roar-svc; do
  id "$usuario" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$usuario"
done

mkdir -p "$APP"
for pasta in api ingestao motor ueba banco; do
  rm -rf "${APP:?}/$pasta.novo"
  cp -a "$RAIZ/$pasta" "$APP/$pasta.novo"
  find "$APP/$pasta.novo" -name __pycache__ -type d -prune -exec rm -rf {} +
  rm -rf "${APP:?}/$pasta"
  mv "$APP/$pasta.novo" "$APP/$pasta"
done
chown -R root:root "$APP"
chmod -R go-w "$APP"
chmod 755 "$DESTINO" "$APP"

# Cada serviço lê só o que usa. Quem invade a API não leva a senha de administrador do banco.
escrever_env() {
  local arquivo="$DESTINO/$1" grupo="$2"; shift 2
  local temporario; temporario="$(mktemp)"
  for chave in "$@"; do echo "$chave=$(valor "$chave")" >>"$temporario"; done
  install -m 640 -o root -g "$grupo" "$temporario" "$arquivo"
  rm -f "$temporario"
}
escrever_env api.env roar-api ROAR_API_SENHA ROAR_LEITOR_SENHA ROAR_MFA_CHAVE RETENCAO_DIAS ROAR_ARQUIVO_DIAS ARMAZEM_LEITOR_SENHA ARMAZEM_PORTA SYSLOG_CIFRADO_PORTA NETFLOW_PORTA SFLOW_PORTA
escrever_env servicos.env roar-svc ROAR_INGESTAO_SENHA ROAR_LEITOR_SENHA ROAR_UEBA_SENHA ROAR_SOAR_SENHA RETENCAO_DIAS ROAR_SELO_ANCORA ARMAZEM_LEITOR_SENHA ARMAZEM_PORTA ROAR_SELOS_DO_ARMAZEM

# Só as chaves públicas e o certificado da autoridade ficam legíveis fora do root.
[ -f "$DESTINO/cofre/privada" ] || PYTHONPATH="$APP/ingestao" "$PY" -m roar_ingestao.cofre gerar

# Syslog cifrado: a autoridade e o certificado do receptor saem do domínio. O receptor relê as rotas sozinho; o serviço de
# fontes as escreve. Sobe depois dos certificados, que ele monta.
PYTHONPATH="$APP/ingestao" "$PY" -m roar_ingestao.syslog_cifrado --dominio "$DOMINIO"
# Fluxos de rede: a pasta em que o goflow2 escreve é do usuário dele. O receptor lê a pasta e o serviço de fontes gira o
# arquivo.
PYTHONPATH="$APP/ingestao" "$PY" -c "from roar_ingestao import fluxos; fluxos.preparar()"
docker compose --project-directory "$DESTINO" --project-name panthera-roar up -d recepcao fluxos >/dev/null
chmod 755 "$DESTINO/cofre"; chmod 600 "$DESTINO/cofre/privada"; chmod 644 "$DESTINO/cofre/publica"
if [ "$PERFIL" != vulnerabilidades ]; then
  install -m 644 "$DESTINO/wazuh/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem" "$DESTINO/ca-indexer.pem"
fi
if [ ! -f "$DESTINO/selo/privada" ]; then
  ROAR_SELO_PASTA="$DESTINO/selo" PYTHONPATH="$APP/ingestao" "$PY" -c "from roar_ingestao.selo import carregar_chave; carregar_chave()"
fi
chown -R roar-svc:roar-svc "$DESTINO/selo"
chmod 755 "$DESTINO/selo"; chmod 600 "$DESTINO/selo/privada"; chmod 644 "$DESTINO/selo/publica"

unidade() {
  # nome, usuário, arquivo de segredos, pasta de trabalho, comando, extras
  local nome="$1" usuario="$2" env="$3" pasta="$4" comando="$5" extras="${6:-}"
  local protecao="ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes"
  # Quem usa o Docker já equivale a root: restringir o sistema de arquivos só daria falsa segurança.
  [ "$usuario" = root ] && protecao="PrivateTmp=yes"
  cat >"/etc/systemd/system/roar-$nome.service" <<UNIDADE
[Unit]
Description=Panthera Roar: $nome
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service
StartLimitIntervalSec=0

[Service]
User=$usuario
WorkingDirectory=$APP/$pasta
Environment=ROAR_ENV=$DESTINO/$env
Environment=ROAR_INDEXER_CA=$DESTINO/ca-indexer.pem
Environment=PYTHONPATH=$APP/ingestao:$APP/motor:$APP/api
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=ROAR_ENDERECO_PUBLICO=$DOMINIO
Environment=ROAR_PERFIL=$PERFIL
$extras
ExecStart=$comando
Restart=always
RestartSec=5
NoNewPrivileges=yes
$protecao

[Install]
WantedBy=multi-user.target
UNIDADE
}

unidade api roar-api api.env api "$PY -m uvicorn roar_api.app:app --host 127.0.0.1 --port 8600 --no-access-log --proxy-headers --forwarded-allow-ips 127.0.0.1"
unidade ingestao root .env ingestao "$PY -u -m roar_ingestao.ciclo"
unidade fontes root .env ingestao "$PY -u -m roar_ingestao.fontes"
unidade parsers root .env ingestao "$PY -u -m roar_ingestao.parsers"
unidade avisos root .env ingestao "$PY -u -m roar_ingestao.avisos"
unidade varredura root .env ingestao "$PY -u -m roar_ingestao.varredura"
unidade inteligencia root .env ingestao "$PY -u -m roar_ingestao.inteligencia"
# Quem cria gerenciador precisa do Docker, e a API não tem: ela só registra o pedido.
unidade organizacoes root .env ingestao "$PY -u -m roar_ingestao.organizacoes"
# Um por organização: a fila e as ações de um cliente não passam pelo processo de outro.
unidade "worker@" root .env motor "$DESTINO/venv-motor/bin/python -u -m roar_motor.worker --cliente %i"
unidade cves roar-svc servicos.env ingestao "$PY -u -m roar_ingestao.cves"
unidade buscas roar-svc servicos.env ingestao "$PY -u -m roar_ingestao.buscas"
unidade superficie roar-svc servicos.env ingestao "$PY -u -m roar_ingestao.superficie"
# Só os contêineres alcançam o gateway da rede deles. O certificado vem de provisao.preparar.
unidade portao roar-svc servicos.env ingestao "$PY -u -m roar_ingestao.portao" "Environment=ROAR_PORTAO_ENDERECO=$(docker network inspect panthera-roar-wazuh_default --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)"
unidade biblioteca roar-svc servicos.env ingestao "$PY -u -m roar_ingestao.biblioteca" "MemoryHigh=2G"
unidade selo roar-svc servicos.env ingestao "$PY -u -m roar_ingestao.selo" "ReadWritePaths=$DESTINO/selo"
unidade ueba roar-svc servicos.env ueba "$PY -u -m roar_ueba.motor" "Environment=PYTHONPATH=$APP/ueba:$APP/ingestao"
unidade disparo roar-svc servicos.env motor "$PY -u -m roar_motor.disparo"

cat >/etc/systemd/system/roar-backup.service <<UNIDADE
[Unit]
Description=Panthera Roar: backup
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/bin/bash $APP/infra/backup.sh
UNIDADE
cat >/etc/systemd/system/roar-backup.timer <<UNIDADE
[Unit]
Description=Panthera Roar: backup diário

[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true
RandomizedDelaySec=900

[Install]
WantedBy=timers.target
UNIDADE
mkdir -p "$APP/infra/wazuh"
# O modelo de que cada organização nova nasce: sem ele, só dá para criar organização de dentro do repositório.
rm -rf "$APP/infra/wazuh/gerenciador"
cp -a "$RAIZ/infra/wazuh/gerenciador" "$APP/infra/wazuh/gerenciador"
cp "$RAIZ/infra/backup.sh" "$RAIZ/infra/restaurar.sh" "$RAIZ/infra/conferir.sh" "$APP/infra/"

case "$PERFIL" in
  vulnerabilidades) SERVICOS="api varredura cves organizacoes avisos superficie"; DESLIGAR="ingestao fontes parsers buscas selo ueba disparo inteligencia biblioteca portao" ;;
  siem) SERVICOS="api ingestao fontes parsers buscas avisos cves selo ueba disparo inteligencia biblioteca organizacoes portao"; DESLIGAR="varredura superficie" ;;
  *) SERVICOS="api ingestao fontes parsers buscas avisos varredura superficie cves selo ueba disparo inteligencia biblioteca organizacoes portao"; DESLIGAR="" ;;
esac
systemctl daemon-reload
for nome in $DESLIGAR; do systemctl disable --now --quiet "roar-$nome" 2>/dev/null || true; done
for nome in $SERVICOS; do
  systemctl enable --quiet "roar-$nome"
  systemctl restart "roar-$nome"
done
if [ "$PERFIL" != vulnerabilidades ]; then
  for cliente in $(docker exec roar-banco psql -At -U roar_admin -d roar -c "SELECT DISTINCT cliente_id FROM gerenciadores"); do
    systemctl enable --quiet "roar-worker@$cliente"
    systemctl restart "roar-worker@$cliente"
  done
fi
systemctl enable --quiet --now roar-backup.timer
echo "Serviços ligados: $SERVICOS"
