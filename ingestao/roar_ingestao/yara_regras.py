"""Busca de malware com YARA. Quem varre é o agente, sobre o arquivo que a integridade acabou de ver mudar.

As regras e o script chegam pela pasta compartilhada do gerenciador. Essa pasta não dá permissão de execução,
e o agente não aceita programa vindo do gerenciador: por isso alguém instala o script uma vez em cada servidor.
"""

import bisect
import hashlib
import logging
import os
import re
from pathlib import Path

import yara

from . import provisao

log = logging.getLogger("roar.yara")
PASTA_GERENCIADORES = Path("/opt/panthera-roar/gerenciadores")
TAMANHO_MAXIMO = 256 * 1024
ARQUIVO_DE_REGRAS = "roar_yara.yar"
ARQUIVO_DO_SCRIPT = "roar_yara.sh"
ARQUIVO_DO_SCRIPT_WINDOWS = "roar_yara.ps1"
ARQUIVO_DE_PARTIDA_WINDOWS = "roar_yara.cmd"
ARQUIVO_DAS_DETECCOES = "roar_yara.xml"

REGRA_ACHADO, REGRA_PRONTO, REGRA_ERRO, REGRA_NAO_VARRIDO = "100900", "100901", "100902", "100903"

COMANDO_DE_INSTALACAO = (
    "sudo apt-get install -y yara jq && "
    f"sudo install -o root -g wazuh -m 750 /var/ossec/etc/shared/{ARQUIVO_DO_SCRIPT} /var/ossec/active-response/bin/{ARQUIVO_DO_SCRIPT} && "
    f"sudo /var/ossec/active-response/bin/{ARQUIVO_DO_SCRIPT} --conferir"
)

# Versão oficial do YARA para Windows, conferida pelo hash publicado pelo projeto.
YARA_WINDOWS = "https://github.com/VirusTotal/yara/releases/download/v4.6.0/yara-4.6.0-2443-win64.zip"
YARA_WINDOWS_SHA256 = "5E7124F173ED442458429AC0F79A4DB2C024CC183C595737D477A7575D81E6DC"
# O YARA precisa do runtime do Visual C++, que um Windows Server limpo não traz. O endereço não tem versão fixa: quem garante é a assinatura da Microsoft.
RUNTIME_WINDOWS = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
COMANDO_DE_INSTALACAO_WINDOWS = (
    "$a = \"${env:ProgramFiles(x86)}\\ossec-agent\"; $z = \"$env:TEMP\\roar-yara.zip\"; $p = \"$env:TEMP\\roar-yara\"; $v = \"$env:TEMP\\roar-vc.exe\"; "
    "if (-not (Test-Path \"$env:windir\\System32\\vcruntime140.dll\")) { "
    f"Invoke-WebRequest -UseBasicParsing -Uri {RUNTIME_WINDOWS} -OutFile $v; "
    "$s = Get-AuthenticodeSignature $v; "
    "if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'O instalador do runtime não confere.' }; "
    "Start-Process -Wait $v '/install /quiet /norestart'; Remove-Item -Force $v }; "
    f"Invoke-WebRequest -UseBasicParsing -Uri {YARA_WINDOWS} -OutFile $z; "
    f"if ((Get-FileHash $z -Algorithm SHA256).Hash -ne '{YARA_WINDOWS_SHA256}') {{ throw 'O arquivo baixado não confere.' }}; "
    "Expand-Archive -Force $z $p; "
    "Copy-Item -Force \"$p\\yara64.exe\", \"$p\\yarac64.exe\" \"$a\\active-response\\bin\\\"; "
    f"Copy-Item -Force \"$a\\shared\\{ARQUIVO_DO_SCRIPT_WINDOWS}\", \"$a\\shared\\{ARQUIVO_DE_PARTIDA_WINDOWS}\" \"$a\\active-response\\bin\\\"; "
    "Remove-Item -Recurse -Force $z, $p; "
    f"& \"$a\\active-response\\bin\\{ARQUIVO_DE_PARTIDA_WINDOWS}\" --conferir"
)

SCRIPT = r"""#!/bin/sh
# Resposta ativa do Panthera Roar: varre com YARA o arquivo que a integridade acabou de ver mudar.
REGRAS=/var/ossec/etc/shared/roar_yara.yar
COMPILADO=/var/ossec/var/roar_yara.yarc
LOG=/var/ossec/logs/active-responses.log
LIMITE=268435456
SEGUNDOS=120

avisar() { printf '%s\n' "$1" >> "$LOG"; }
sem_controle() { printf '%s' "$1" | tr -d '\000-\037'; }

if ! command -v yara >/dev/null 2>&1 || ! command -v yarac >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
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
  avisar "roar-yara-aviso: motivo=arquivo grande demais para varrer: $LIMPO"
  exit 0
fi

# Compila só quando as regras mudam: com o pacote da biblioteca, cada varredura cai de mais de 1 s para 50 ms.
if [ ! -f "$COMPILADO" ] || [ "$REGRAS" -nt "$COMPILADO" ]; then
  if ! yarac -w "$REGRAS" "$COMPILADO.$$" 2>/dev/null; then
    rm -f "$COMPILADO.$$"
    avisar 'roar-yara-erro: motivo=as regras não compilam neste servidor; confira a versão do yara'
    exit 0
  fi
  mv -f "$COMPILADO.$$" "$COMPILADO"
fi

# Lê pela entrada padrão: o nome do arquivo pode ser de um atacante e assim nunca entra na saída do programa.
if ! SAIDA=$(timeout "$SEGUNDOS" yara -w -N -C "$COMPILADO" /dev/stdin < "$CAMINHO" 2>/dev/null); then
  avisar "roar-yara-aviso: motivo=a varredura falhou ou demorou demais: $LIMPO"
  exit 0
fi

printf '%s\n' "$SAIDA" | while read -r REGRA _; do
  [ -n "$REGRA" ] && avisar "roar-yara: regra=$REGRA arquivo=$LIMPO"
done
exit 0
"""

# O Windows não aceita quebra de linha em nome de arquivo, mas o caminho ainda passa pela limpeza antes de ir ao log.
# A marca de início é o que faz o PowerShell 5 ler o arquivo como UTF-8: sem ela, os acentos dos avisos saem trocados.
SCRIPT_WINDOWS = "\ufeff" + r"""# Resposta ativa do Panthera Roar: varre com YARA o arquivo que a integridade acabou de ver mudar.
# Lê o argumento à mão: declarado, o PowerShell tentaria ler --conferir como nome de parâmetro, e o script ficaria esperando a entrada para sempre.
$Modo = "$($args[0])"
$Bin = $PSScriptRoot
$Base = Split-Path (Split-Path $Bin)
$Regras = Join-Path $Base "shared\roar_yara.yar"
$Compilado = Join-Path $Base "roar_yara.yarc"
$Log = Join-Path $Base "active-response\active-responses.log"
$Limite = 268435456
$Milissegundos = 120000
$Yara = Join-Path $Bin "yara64.exe"
$Yarac = Join-Path $Bin "yarac64.exe"
$Utf8 = New-Object System.Text.UTF8Encoding($false)

function Avisar([string]$Texto) { [IO.File]::AppendAllText($Log, "$Texto`n", $Utf8) }
function Rodar([string]$Programa, [string]$Argumentos, [int]$Prazo) {
  $i = New-Object Diagnostics.ProcessStartInfo
  $i.FileName = $Programa; $i.Arguments = $Argumentos; $i.UseShellExecute = $false; $i.CreateNoWindow = $true
  $i.RedirectStandardOutput = $true; $i.RedirectStandardError = $true; $i.StandardOutputEncoding = $Utf8
  $p = [Diagnostics.Process]::Start($i)
  $saida = $p.StandardOutput.ReadToEndAsync(); $erro = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($Prazo)) { $p.Kill(); return $null }
  $p.WaitForExit()
  return [pscustomobject]@{ Codigo = $p.ExitCode; Saida = $saida.Result }
}

if (-not (Test-Path -LiteralPath $Yara) -or -not (Test-Path -LiteralPath $Yarac)) {
  Avisar "roar-yara-erro: motivo=falta o yara neste servidor"
  exit 0
}

if ($Modo -eq "--conferir") {
  $Versao = "$((Rodar $Yara "--version" 30000).Saida)".Trim()
  if (-not $Versao) {
    Avisar "roar-yara-erro: motivo=o yara não abre neste servidor; falta o runtime do Visual C++"
    Write-Output "O yara não abre neste servidor: falta o runtime do Visual C++."
    exit 0
  }
  # Em servidor novo o log ainda não existe, e o agente só lê o que chega depois de abri-lo: sem esperar, o aviso se perderia.
  if (-not (Test-Path -LiteralPath $Log)) {
    [IO.File]::WriteAllText($Log, "", $Utf8)
    Write-Output "Aguarde 90 segundos..."
    Start-Sleep -Seconds 90
  }
  Avisar "roar-yara-pronto: versao=$Versao"
  Write-Output "Pronto. A confirmação aparece na tela em alguns minutos."
  exit 0
}

[Console]::InputEncoding = $Utf8
try { $Caminho = ([Console]::In.ReadLine() | ConvertFrom-Json).parameters.alert.syscheck.path } catch { exit 0 }
if (-not $Caminho -or -not (Test-Path -LiteralPath $Caminho -PathType Leaf) -or -not (Test-Path -LiteralPath $Regras)) { exit 0 }
$Limpo = $Caminho -replace '[\x00-\x1f]', ''

if ((Get-Item -LiteralPath $Caminho).Length -gt $Limite) {
  Avisar "roar-yara-aviso: motivo=arquivo grande demais para varrer: $Limpo"
  exit 0
}

# Compila só quando as regras mudam: com o pacote da biblioteca, a varredura fica dezenas de vezes mais rápida.
if (-not (Test-Path -LiteralPath $Compilado) -or (Get-Item -LiteralPath $Regras).LastWriteTimeUtc -gt (Get-Item -LiteralPath $Compilado).LastWriteTimeUtc) {
  $Temporario = "$Compilado.$PID"
  $r = Rodar $Yarac "-w `"$Regras`" `"$Temporario`"" $Milissegundos
  if (-not $r -or $r.Codigo -ne 0) {
    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $Temporario
    Avisar "roar-yara-erro: motivo=as regras não compilam neste servidor; confira a versão do yara"
    exit 0
  }
  Move-Item -Force -LiteralPath $Temporario -Destination $Compilado
}

$r = Rodar $Yara "-w -N -C `"$Compilado`" `"$Caminho`"" $Milissegundos
if (-not $r -or $r.Codigo -ne 0) {
  Avisar "roar-yara-aviso: motivo=a varredura falhou ou demorou demais: $Limpo"
  exit 0
}
foreach ($Linha in ($r.Saida -split "`r?`n")) {
  $Regra = ($Linha -split ' ', 2)[0]
  if ($Regra) { Avisar "roar-yara: regra=$Regra arquivo=$Limpo" }
}
exit 0
"""

PARTIDA_WINDOWS = """@echo off\r
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0roar_yara.ps1" %*\r
exit /b 0\r
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
<decoder name="roar-yara-aviso">
  <prematch>^roar-yara-aviso: </prematch>
</decoder>
<decoder name="roar-yara-aviso-campos">
  <parent>roar-yara-aviso</parent>
  <regex>motivo=(\.+)</regex>
  <order>yara_motivo</order>
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
    <description>YARA com problema neste servidor: $(yara_motivo)</description>
  </rule>
  <rule id="{REGRA_NAO_VARRIDO}" level="7">
    <decoded_as>roar-yara-aviso</decoded_as>
    <description>YARA não varreu um arquivo: $(yara_motivo)</description>
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
  <command>
    <name>roar_yara_windows</name>
    <executable>{ARQUIVO_DE_PARTIDA_WINDOWS}</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <active-response>
    <disabled>no</disabled>
    <command>roar_yara</command>
    <location>local</location>
    <rules_id>550,554</rules_id>
  </active-response>
  <active-response>
    <disabled>no</disabled>
    <command>roar_yara_windows</command>
    <location>local</location>
    <rules_id>550,554</rules_id>
  </active-response>
</ossec_config>
"""


class RegraInvalida(Exception):
    """A mensagem aparece na tela, então precisa explicar o que corrigir."""


# Pacote da biblioteca: formato do YARA Forge, com uma regra por bloco e o fechamento na primeira coluna.
_REGRA = re.compile(r"^((?:(?:private|global)\s+)*)rule\s+(\w+)[^\n{]*\n?\s*\{", re.M)
_SECAO = re.compile(r"Repository Name:\s*([^\n]+)")
_META = re.compile(r'^\s+(description|author|source_url|license|license_url|score)\s*=\s*(?:"(.*)"|(\d+))\s*$', re.M)
MINIMO_DE_REGRAS = 1000
# Uma versão que encolhe de repente provavelmente veio cortada.
FRACAO_MINIMA = 0.7
MAXIMO_DO_PACOTE = 40 * 1024 * 1024
PASTAS_DE_PROGRAMAS = ("/usr/bin", "/usr/sbin")
ARQUIVOS_NA_CONFERENCIA = 300
FRACAO_MAXIMA_DE_BATIDAS = 0.01


def regras_do_pacote(texto):
    """Lê sem interpretar a regra: quem decide se ela vale é o compilador."""
    secoes = [(m.start(), m[1].strip()) for m in _SECAO.finditer(texto)]
    inicios = [s[0] for s in secoes]
    saida = []
    for m in _REGRA.finditer(texto):
        fim = texto.find("\n}", m.end())
        fim = len(texto) if fim < 0 else fim + 2
        meta = {}
        for chave, aspas, numero in _META.findall(texto[m.start():fim]):
            meta.setdefault(chave, aspas or numero)
        indice = bisect.bisect(inicios, m.start()) - 1
        saida.append({
            "nome": m[2], "privada": "private" in m[1], "inicio": m.start(), "fim": fim,
            "repositorio": secoes[indice][1] if indice >= 0 else None,
            "descricao": (meta.get("description") or "")[:2000] or None, "autor": (meta.get("author") or "")[:300] or None,
            "licenca": ((meta.get("license") if meta.get("license") != "N/A" else None) or meta.get("license_url") or "")[:300] or None, "endereco": (meta.get("source_url") or "")[:600] or None,
            "pontuacao": int(meta["score"]) if meta.get("score", "").isdigit() else None,
        })
    return saida


def sem_regras(texto, nomes):
    if not nomes:
        return texto
    fora = set(nomes)
    partes, posicao = [], 0
    for regra in regras_do_pacote(texto):
        if regra["nome"] in fora:
            partes.append(texto[posicao:regra["inicio"]])
            posicao = regra["fim"]
    partes.append(texto[posicao:])
    return "".join(partes)


def _programas_do_sistema():
    achados = []
    for pasta in PASTAS_DE_PROGRAMAS:
        try:
            with os.scandir(pasta) as itens:
                achados += sorted(i.path for i in itens if i.is_file(follow_symlinks=False))
        except OSError:
            continue
    passo = max(1, len(achados) // ARQUIVOS_NA_CONFERENCIA)
    return achados[::passo][:ARQUIVOS_NA_CONFERENCIA]


def conferir_pacote(texto, regras_antes=None):
    """O portão de uma versão nova: as regras vão rodar como root em todos os servidores de quem usa."""
    if len(texto.encode()) > MAXIMO_DO_PACOTE or "\x00" in texto:
        raise RegraInvalida("A versão nova da biblioteca YARA passa do tamanho esperado. A atual continua valendo.")
    try:
        compiladas = yara.compile(source=texto, includes=False)
    except yara.Error:
        raise RegraInvalida("A versão nova da biblioteca YARA não compila. A atual continua valendo.") from None
    regras = list(compiladas)
    total = len(regras)
    if total < MINIMO_DE_REGRAS or (regras_antes and total < regras_antes * FRACAO_MINIMA):
        raise RegraInvalida(f"A versão nova da biblioteca YARA veio com {total} regras, bem menos que o esperado. A atual continua valendo.")
    if any(r.is_global for r in regras):
        raise RegraInvalida("A versão nova da biblioteca YARA traz regra global, que calaria as outras. A atual continua valendo.")
    if compiladas.match(data=b"") or compiladas.match(data=os.urandom(1024 * 1024)):
        raise RegraInvalida("A versão nova da biblioteca YARA bate com qualquer arquivo. A atual continua valendo.")
    arquivos = _programas_do_sistema()
    batidas = 0
    for caminho in arquivos:
        try:
            batidas += 1 if compiladas.match(caminho, timeout=20) else 0
        except yara.Error:
            continue
    if arquivos and batidas / len(arquivos) > FRACAO_MAXIMA_DE_BATIDAS:
        raise RegraInvalida(f"A versão nova da biblioteca YARA acusou {batidas} de {len(arquivos)} programas comuns do sistema. A atual continua valendo.")
    return total


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
    tem = _com_cliente(banco, cliente, """SELECT (SELECT count(*) FROM yara_regras WHERE gerenciador_id = %s AND estado IN ('pendente', 'ativa'))
                                                 + (SELECT count(*) FROM yara_assinatura WHERE gerenciador_id = %s AND ativa)""", gerenciador_id, gerenciador_id)
    return FRAGMENTO if tem[0][0] else ""


def _pacote_a_usar(banco, gerenciador_id, cliente):
    """Devolve a assinatura, a versão que ela deve usar e o resumo dessa versão, sem trazer os megabytes do pacote."""
    linha = _com_cliente(banco, cliente, "SELECT ativa, automatica, versao, excluidas, estado FROM yara_assinatura WHERE gerenciador_id = %s", gerenciador_id)
    if not linha or not linha[0][0]:
        return (linha[0] if linha else None), None, None
    ativa, automatica, versao, excluidas, estado = linha[0]
    atual = _com_cliente(banco, cliente, "SELECT versao FROM bibliotecas_estado WHERE nome = 'yara'")
    alvo = atual[0][0] if atual and (automatica or not versao) else versao
    resumo = _com_cliente(banco, cliente, "SELECT sha256 FROM yara_pacotes WHERE versao = %s", alvo) if alvo else None
    return linha[0], alvo, (resumo[0][0] if resumo else None)


def aplicar_regras(banco, gerenciador_id, cliente):
    linhas = _com_cliente(banco, cliente, "SELECT id, fonte, estado FROM yara_regras WHERE gerenciador_id = %s AND estado IN ('pendente', 'ativa', 'desativada') ORDER BY id", gerenciador_id)
    proprias = [l[1] for l in linhas if l[2] != "desativada"]
    pendentes = [l[0] for l in linhas if l[2] == "pendente"]
    assinatura, alvo, resumo_do_pacote = _pacote_a_usar(banco, gerenciador_id, cliente)
    excluidas = sorted(assinatura[3]) if assinatura else []
    # Pacote apagado ou ainda não baixado: fica o que está lá, sem esvaziar nada por engano.
    if assinatura and assinatura[0] and not resumo_do_pacote:
        return 0
    conteudo_previsto = "\n".join(proprias) + (resumo_do_pacote or "") + ",".join(excluidas)
    resumo = hashlib.sha256((conteudo_previsto + SCRIPT + SCRIPT_WINDOWS + PARTIDA_WINDOWS + DECODIFICADORES + DETECCOES).encode()).hexdigest() if (proprias or resumo_do_pacote) else ""
    marca = PASTA_GERENCIADORES / gerenciador_id / "yara.aplicado"
    anterior = marca.read_text() if marca.exists() else ""
    assinatura_pendente = assinatura and assinatura[4] == "pendente"
    if resumo == anterior and not pendentes and not assinatura_pendente:
        return 0
    ok, motivo = True, None
    if resumo != anterior:
        partes = []
        if resumo_do_pacote:
            pacote = _com_cliente(banco, cliente, "SELECT conteudo FROM yara_pacotes WHERE versao = %s", alvo)[0][0]
            partes.append(sem_regras(pacote, excluidas))
        partes += proprias
        conteudo = "\n".join(partes)
        try:
            if conteudo:
                yara.compile(source=conteudo, includes=False)
        except yara.Error as erro:
            ok, motivo = False, "Esta combinação de regras não compila. Se você tirou uma regra da biblioteca, outra pode depender dela. Nada mudou."
            log.error("gerenciador %s: as regras não compilam: %s", gerenciador_id, str(erro)[:300])
        if ok:
            scripts = {ARQUIVO_DO_SCRIPT: SCRIPT, ARQUIVO_DO_SCRIPT_WINDOWS: SCRIPT_WINDOWS, ARQUIVO_DE_PARTIDA_WINDOWS: PARTIDA_WINDOWS}
            ok, detalhe = provisao.aplicar_yara(gerenciador_id, conteudo, scripts, DECODIFICADORES, DETECCOES, ARQUIVO_DAS_DETECCOES)
            if ok:
                marca.write_text(resumo)
            else:
                motivo = "O gerenciador recusou esta configuração. Nada mudou."
                log.error("gerenciador %s recusou o YARA: %s", gerenciador_id, str(detalhe)[:300])
    for pendente in pendentes:
        _com_cliente(banco, cliente, "UPDATE yara_regras SET estado = %s, mensagem = %s WHERE id = %s", "ativa" if ok else "recusada", motivo, pendente)
    if assinatura:
        _com_cliente(banco, cliente, "UPDATE yara_assinatura SET estado = %s, mensagem = %s, versao = %s WHERE gerenciador_id = %s",
                     "aplicada" if ok else "recusada", motivo, alvo if ok and alvo else assinatura[2], gerenciador_id)
    return len(pendentes)
