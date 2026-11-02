"""Busca de malware com YARA. Quem varre é o agente, sobre o arquivo que a integridade acabou de ver mudar.

As regras e o script chegam pela pasta compartilhada do gerenciador. Essa pasta não dá permissão de execução,
e o agente não aceita programa vindo do gerenciador: por isso alguém instala o script uma vez em cada servidor.
"""

import hashlib
import logging
from pathlib import Path

import yara

from . import provisao

log = logging.getLogger("roar.yara")
PASTA_GERENCIADORES = Path("/opt/panthera-roar/gerenciadores")
TAMANHO_MAXIMO = 256 * 1024
ARQUIVO_DE_REGRAS = "roar_yara.yar"
ARQUIVO_DO_SCRIPT = "roar_yara.sh"
ARQUIVO_DAS_DETECCOES = "roar_yara.xml"

REGRA_ACHADO, REGRA_PRONTO, REGRA_ERRO = "100900", "100901", "100902"

COMANDO_DE_INSTALACAO = (
    "sudo apt-get install -y yara jq && "
    f"sudo install -o root -g wazuh -m 750 /var/ossec/etc/shared/{ARQUIVO_DO_SCRIPT} /var/ossec/active-response/bin/{ARQUIVO_DO_SCRIPT} && "
    f"sudo /var/ossec/active-response/bin/{ARQUIVO_DO_SCRIPT} --conferir"
)

SCRIPT = r"""#!/bin/sh
# Resposta ativa do Panthera Roar: varre com YARA o arquivo que a integridade acabou de ver mudar.
REGRAS=/var/ossec/etc/shared/roar_yara.yar
LOG=/var/ossec/logs/active-responses.log
LIMITE=268435456
SEGUNDOS=120

avisar() { printf '%s\n' "$1" >> "$LOG"; }
sem_controle() { printf '%s' "$1" | tr -d '\000-\037'; }

if ! command -v yara >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  avisar 'roar-yara-erro: motivo=faltam yara ou jq neste servidor'
  exit 0
fi

if [ "$1" = "--conferir" ]; then
  PRONTO="roar-yara-pronto: versao=$(yara --version | tr -d '[:space:]')"
  if [ -f "$LOG" ]; then
    avisar "$PRONTO"
  else
    # Em servidor novo o log ainda não existe, e o agente só lê o que chega depois de abri-lo: sem esperar, o aviso se perderia.
    : > "$LOG"
    chown root:wazuh "$LOG"
    chmod 660 "$LOG"
    ( sleep 90; avisar "$PRONTO" ) </dev/null >/dev/null 2>&1 &
  fi
  echo "Pronto. A confirmação aparece na tela em alguns minutos."
  exit 0
fi

read -r ENTRADA
CAMINHO=$(printf '%s' "$ENTRADA" | jq -r '.parameters.alert.syscheck.path // empty')
[ -n "$CAMINHO" ] && [ -f "$CAMINHO" ] && [ -f "$REGRAS" ] || exit 0
LIMPO=$(sem_controle "$CAMINHO")

if [ "$(wc -c < "$CAMINHO")" -gt "$LIMITE" ]; then
  avisar "roar-yara-erro: motivo=arquivo grande demais para varrer: $LIMPO"
  exit 0
fi

# Lê pela entrada padrão: o nome do arquivo pode ser de um atacante e assim nunca entra na saída do programa.
if ! SAIDA=$(timeout "$SEGUNDOS" yara -w -N "$REGRAS" /dev/stdin < "$CAMINHO" 2>/dev/null); then
  avisar "roar-yara-erro: motivo=a varredura falhou ou demorou demais: $LIMPO"
  exit 0
fi

printf '%s\n' "$SAIDA" | while read -r REGRA _; do
  [ -n "$REGRA" ] && avisar "roar-yara: regra=$REGRA arquivo=$LIMPO"
done
exit 0
"""

DECODIFICADORES = r"""<decoder name="roar-yara">
  <prematch>^roar-yara: </prematch>
</decoder>
<decoder name="roar-yara-campos">
  <parent>roar-yara</parent>
  <regex>regra=(\S+) arquivo=(\.+)</regex>
  <order>yara_regra, yara_arquivo</order>
</decoder>
<decoder name="roar-yara-pronto">
  <prematch>^roar-yara-pronto: </prematch>
</decoder>
<decoder name="roar-yara-pronto-campos">
  <parent>roar-yara-pronto</parent>
  <regex>versao=(\S+)</regex>
  <order>yara_versao</order>
</decoder>
<decoder name="roar-yara-erro">
  <prematch>^roar-yara-erro: </prematch>
</decoder>
<decoder name="roar-yara-erro-campos">
  <parent>roar-yara-erro</parent>
  <regex>motivo=(\.+)</regex>
  <order>yara_motivo</order>
</decoder>
"""

DETECCOES = f"""<group name="roar_yara,malware,">
  <rule id="{REGRA_ACHADO}" level="12">
    <decoded_as>roar-yara</decoded_as>
    <description>YARA: arquivo bateu com a regra $(yara_regra): $(yara_arquivo)</description>
    <mitre><id>T1204</id></mitre>
  </rule>
</group>
<group name="roar_yara,">
  <rule id="{REGRA_PRONTO}" level="3">
    <decoded_as>roar-yara-pronto</decoded_as>
    <description>YARA pronto neste servidor, versão $(yara_versao)</description>
  </rule>
  <rule id="{REGRA_ERRO}" level="9">
    <decoded_as>roar-yara-erro</decoded_as>
    <description>YARA não conseguiu varrer: $(yara_motivo)</description>
  </rule>
</group>
"""

# Só entra na configuração quando a organização tem regra: sem isso, todo servidor sem o script reclamaria a cada mudança de arquivo.
FRAGMENTO = f"""
<ossec_config>
  <command>
    <name>roar_yara</name>
    <executable>{ARQUIVO_DO_SCRIPT}</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <active-response>
    <disabled>no</disabled>
    <command>roar_yara</command>
    <location>local</location>
    <rules_id>550,554</rules_id>
  </active-response>
</ossec_config>
"""


class RegraInvalida(Exception):
    """A mensagem aparece na tela, então precisa explicar o que corrigir."""


def validar(fonte, outras=()):
    """Compila aqui para o erro aparecer na tela, e não só depois, em cada servidor. Devolve os nomes das regras."""
    if not str(fonte).strip():
        raise RegraInvalida("Cole o texto da regra.")
    if len(fonte.encode()) > TAMANHO_MAXIMO or "\x00" in fonte:
        raise RegraInvalida("A regra passa do tamanho aceito, 256 KB.")
    try:
        # Com include, uma regra leria arquivos do servidor onde o agente roda.
        compiladas = yara.compile(source=fonte, includes=False)
    except yara.Error as erro:
        raise RegraInvalida(f"A regra não compila: {erro}") from None
    regras = list(compiladas)
    if not regras:
        raise RegraInvalida("O texto não tem nenhuma regra.")
    if any(r.is_global for r in regras):
        raise RegraInvalida("Regra global não é aceita: ela silenciaria as outras regras da organização.")
    if compiladas.match(data=b""):
        raise RegraInvalida("Esta regra bate até com um arquivo vazio e geraria um alerta a cada mudança. Exija algum conteúdo.")
    try:
        yara.compile(source="\n".join((*outras, fonte)), includes=False)
    except yara.Error as erro:
        raise RegraInvalida(f"Esta regra conflita com outra da organização: {erro}") from None
    return [r.identifier for r in regras]


def _com_cliente(banco, cliente, sql, *args):
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        cursor = banco.con.execute(sql, args)
        return cursor.fetchall() if cursor.description else None


def fragmento_de_configuracao(banco, gerenciador_id, cliente):
    tem = _com_cliente(banco, cliente, "SELECT count(*) FROM yara_regras WHERE gerenciador_id = %s AND estado IN ('pendente', 'ativa')", gerenciador_id)
    return FRAGMENTO if tem[0][0] else ""


def aplicar_regras(banco, gerenciador_id, cliente):
    linhas = _com_cliente(banco, cliente, "SELECT id, fonte, estado FROM yara_regras WHERE gerenciador_id = %s AND estado IN ('pendente', 'ativa', 'desativada') ORDER BY id", gerenciador_id)
    em_uso = [l[1] for l in linhas if l[2] != "desativada"]
    pendentes = [l[0] for l in linhas if l[2] == "pendente"]
    conteudo = "\n".join(em_uso)
    resumo = hashlib.sha256((conteudo + SCRIPT + DECODIFICADORES + DETECCOES).encode()).hexdigest() if em_uso else ""
    marca = PASTA_GERENCIADORES / gerenciador_id / "yara.aplicado"
    anterior = marca.read_text() if marca.exists() else ""
    if resumo == anterior and not pendentes:
        return 0
    ok = True
    if resumo != anterior:
        ok, detalhe = provisao.aplicar_yara(gerenciador_id, conteudo, SCRIPT, DECODIFICADORES, DETECCOES, ARQUIVO_DAS_DETECCOES)
        if ok:
            marca.write_text(resumo)
        else:
            log.error("gerenciador %s recusou o YARA: %s", gerenciador_id, str(detalhe)[:300])
    for pendente in pendentes:
        _com_cliente(banco, cliente, "UPDATE yara_regras SET estado = %s, mensagem = %s WHERE id = %s",
                     "ativa" if ok else "recusada", None if ok else "O gerenciador recusou esta configuração. Nada mudou.", pendente)
    return len(pendentes)
