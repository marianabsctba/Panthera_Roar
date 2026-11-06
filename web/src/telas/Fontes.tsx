import { Sparkline } from "@mantine/charts";
import { Alert, Badge, Box, Button, Card, Drawer, Group, Modal, NumberInput, PasswordInput, SegmentedControl, Select, SimpleGrid, Stack, Switch, Tabs, Text, Textarea, TextInput, Title, Tooltip } from "@mantine/core";
import { IconAlertTriangle, IconLock, IconPlugConnected, IconServer2 } from "@tabler/icons-react";
import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";

import { detalhe, enviar, useDados, usePode } from "../api";
import { AcoesDaLinha, BlocoDeComando, Busca, Cabecalho, Carregando, Data, Estado, Numero, Painel, Tabela, Vazio } from "../componentes";
import { numero } from "../formato";
import { ComoLe, Parsers, type Leitura } from "./FontesParsers";
import { ir } from "../rota";

// ------------------------------------------------------------------ catálogo

interface Conector {
  id: string;
  rotulo: string;
  logo?: string;
  sigla?: string;
  resumo: string;
  prova: string;
  passos: string[];
  cuidado?: string;
  /** Tipo da fonte para os conectores de nuvem, que usam o mesmo formulário. */
  tipo?: string;
  tipos?: string[];
  permissao?: string;
  /** Equipamentos de rede: protocolo que já vem no formulário, uma linha de exemplo e a configuração para copiar. */
  protocolo?: "tcp" | "udp";
  amostra?: string;
  comando?: (endereco: string, porta: number) => string;
}

const SEM_CONTA_REAL = "Ainda não testado com uma conta real";
const PROVAS_BOAS = new Set(["agente", "syslog", "webhook", "api"]);
const PROVA_DO_EQUIPAMENTO = "Testado com linhas de exemplo, ainda não com o equipamento";
const CADASTRE = "Em Conectar, cadastre o endereço de onde o equipamento manda os logs. O que vier de outro endereço é ignorado.";
const TESTE = "Antes de apontar o envio, cole abaixo uma linha do seu equipamento e clique em Testar: aparecem os campos que o Roar tira.";

const CATALOGO: { grupo: string; itens: Conector[] }[] = [
  { grupo: "Ativos e rede", itens: [
    { id: "agente", rotulo: "Agente", logo: "linux", resumo: "Linux, Windows e macOS: logs, integridade de arquivos, inventário e resposta a incidentes.", prova: "Testado em Linux e Windows Server. macOS ainda não",
      passos: ["Abra o comando do sistema do ativo, logo abaixo.", "Rode o comando no ativo como administrador.", "Em alguns minutos o ativo aparece conectado em Ativos."],
      cuidado: "O comando traz a senha de inscrição da sua organização: não o publique. Para bloquear endereços, o ativo precisa ter firewall.", permissao: "instalar_agente" },
    { id: "syslog", rotulo: "Syslog", sigla: "SYS", resumo: "Firewall, switch e outros equipamentos que não aceitam agente.", prova: "Testado com envio real",
      passos: ["Em Conectar, cadastre os endereços dos equipamentos: o que estiver fora da lista é ignorado.", "Espere a fonte ficar ativa.", "No equipamento, aponte o envio de syslog para o endereço e a porta mostrados aqui."],
      cuidado: "O syslog não é cifrado: use apenas em rede de confiança.", tipos: ["syslog"] },
  ] },
  { grupo: "Firewalls e rede", itens: [
    { id: "fortigate", rotulo: "FortiGate", logo: "fortinet", resumo: "Tráfego, bloqueios, VPN e acessos de administrador dos firewalls Fortinet.", prova: PROVA_DO_EQUIPAMENTO, tipos: ["syslog"], protocolo: "udp",
      passos: [CADASTRE, "No FortiGate, abra a linha de comando (CLI Console) e cole a configuração abaixo.", "Nas políticas que quer acompanhar, ligue Log Allowed Traffic com All Sessions: sem isso, só os bloqueios chegam.", TESTE],
      comando: (e, p) => `config log syslogd setting\n    set status enable\n    set server "${e}"\n    set port ${p}\n    set mode udp\nend`,
      amostra: 'date=2026-11-06 time=10:16:40 devname="FGT60F-MATRIZ" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="admin" ui="https(198.51.100.7)" method="https" srcip=198.51.100.7 dstip=10.0.10.1 action="login" status="failed" reason="passwd_invalid"' },
    { id: "pfsense", rotulo: "pfSense", logo: "pfsense", resumo: "Bloqueios e liberações das regras de firewall do pfSense.", prova: PROVA_DO_EQUIPAMENTO, tipos: ["syslog"], protocolo: "udp",
      passos: [CADASTRE, "No pfSense, abra Status > System Logs > Settings.", "Marque Enable Remote Logging, informe o endereço e a porta abaixo em Remote log servers e marque Firewall Events. Salve.", "Nas regras que quer acompanhar, marque Log packets that are handled by this rule.", TESTE],
      comando: (e, p) => `${e}:${p}`,
      amostra: "Nov  6 10:15:02 pfSense filterlog[48520]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,24811,0,DF,6,tcp,60,198.51.100.7,10.0.10.5,51544,22,0,S,1508344447,,64240,,mss;sackOK;TS;nop;wscale" },
    { id: "opnsense", rotulo: "OPNsense", logo: "opnsense", resumo: "Bloqueios e liberações das regras de firewall do OPNsense.", prova: PROVA_DO_EQUIPAMENTO, tipos: ["syslog"], protocolo: "udp",
      passos: [CADASTRE, "No OPNsense, abra System > Settings > Logging, aba Remote, e adicione um destino.", "Escolha o transporte UDP(4), a aplicação filter (firewall), o endereço e a porta abaixo. Deixe desmarcado o RFC5424. Salve e aplique.", "Nas regras que quer acompanhar, marque Log packets that are handled by this rule.", TESTE],
      comando: (e, p) => `${e}:${p}`,
      amostra: "Nov  6 10:15:02 OPNsense.localdomain filterlog[48520]: 81,,,fae559338f65e11c53669fc3642c93c2,igb0,match,block,in,4,0x0,,64,24811,0,DF,6,tcp,60,198.51.100.7,10.0.10.5,51544,22,0,S,1508344447,,64240,,mss;sackOK;TS;nop;wscale" },
    { id: "paloalto", rotulo: "Palo Alto", logo: "paloaltonetworks", resumo: "Tráfego, ameaças e eventos de sistema dos firewalls Palo Alto Networks.", prova: PROVA_DO_EQUIPAMENTO, tipos: ["syslog"], protocolo: "udp",
      passos: [CADASTRE, "Em Device > Server Profiles > Syslog, crie um perfil com o endereço e a porta abaixo, transporte UDP e formato BSD.", "Em Objects > Log Forwarding, crie um perfil que mande Traffic e Threat para esse servidor, e aplique o perfil nas regras de segurança.", "Em Device > Log Settings, mande também System e Configuration para o mesmo servidor. Faça o commit.", TESTE],
      comando: (e, p) => `${e}:${p}`,
      amostra: "Nov  6 10:15:02 PA-MATRIZ 1,2026/11/06 10:15:02,012801000000,TRAFFIC,deny,2560,2026/11/06 10:15:02,198.51.100.7,10.0.10.5,0.0.0.0,0.0.0.0,bloqueio-entrada,,,not-applicable,vsys1,untrust,trust,ethernet1/1,,encaminhar-siem,2026/11/06 10:15:02,0,1,51544,22,0,0,0x0,tcp,deny,74,74,0,1,2026/11/06 10:15:01,0,any,0,7123456789,0x0,BR,10.0.0.0-10.255.255.255,0,1,0,policy-deny,0,0,0,0,,PA-MATRIZ,from-policy,,,0,,0,,N/A,0,0,0,0" },
    { id: "sophos", rotulo: "Sophos Firewall", logo: "sophos", resumo: "Regras de firewall, IPS e autenticação do Sophos Firewall (antigo XG).", prova: PROVA_DO_EQUIPAMENTO, tipos: ["syslog"], protocolo: "udp",
      passos: [CADASTRE, "Em System services > Log settings, adicione um servidor syslog com o endereço e a porta abaixo, severidade Information e formato Device standard.", "Na mesma tela, marque as categorias que vão para esse servidor: Firewall, IPS, Authentication e as outras que quiser. Salve.", TESTE],
      comando: (e, p) => `${e}:${p}`,
      amostra: 'device="SFW" date=2026-11-06 time=10:15:02 timezone="-03" device_name="XG135" device_id=C01001ABCDEF12 log_id=010101600001 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny" priority=Information fw_rule_id=5 in_interface="Port2" out_interface="Port1" src_ip=198.51.100.7 dst_ip=10.0.10.5 protocol="TCP" src_port=51544 dst_port=22' },
    { id: "ciscoasa", rotulo: "Cisco ASA", logo: "cisco", resumo: "Conexões negadas e permitidas, VPN e comandos de administrador do Cisco ASA.", prova: PROVA_DO_EQUIPAMENTO, tipos: ["syslog"], protocolo: "udp",
      passos: [CADASTRE, "No ASA, entre no modo de configuração (configure terminal) e cole a configuração abaixo, trocando inside pelo nome da interface que chega ao Roar.", "Grave com write memory.", TESTE],
      comando: (e, p) => `logging enable\nlogging timestamp\nlogging trap informational\nlogging host inside ${e} udp/${p}`,
      cuidado: "O login recusado no ASA chega, mas sem o usuário e o endereço separados: o servidor ainda não lê essa mensagem por inteiro.",
      amostra: 'Nov  6 2026 10:15:02 ASA-MATRIZ : %ASA-4-106023: Deny tcp src outside:198.51.100.7/51544 dst inside:10.0.10.5/22 by access-group "outside_access_in" [0x0, 0x0]' },
    { id: "mikrotik", rotulo: "MikroTik", logo: "mikrotik", resumo: "Firewall e logins do RouterOS, lidos por um parser do Roar.", prova: PROVA_DO_EQUIPAMENTO, tipos: ["syslog"], protocolo: "udp",
      passos: [CADASTRE, "No terminal do RouterOS, cole a configuração abaixo: ela manda os logs de firewall e de sistema, que trazem os logins.", "Nas regras de firewall que quer acompanhar, ligue log. Um log-prefix, se houver, aparece no Roar como prefixo.", TESTE],
      comando: (e, p) => `/system logging action add name=roar target=remote remote=${e} remote-port=${p}\n/system logging add topics=firewall action=roar\n/system logging add topics=system action=roar`,
      amostra: "Nov  6 10:16:40 MikroTik system,error,critical login failure for user admin from 198.51.100.7 via winbox" },
  ] },
  { grupo: "Nuvem e SaaS", itens: [
    { id: "aws", rotulo: "AWS CloudTrail", logo: "amazonwebservices", resumo: "Quem fez o quê na conta da AWS.", prova: SEM_CONTA_REAL,
      passos: ["No CloudTrail, crie uma trilha que grave em um bucket do S3.", "No IAM, crie um usuário só com s3:GetObject e s3:ListBucket nesse bucket.", "Gere uma chave de acesso para esse usuário.", "Em Conectar, preencha o bucket, a chave de acesso e a chave secreta."], tipo: "aws" },
    { id: "azure", rotulo: "Azure Log Analytics", sigla: "AZ", resumo: "Atividade da assinatura do Azure, lida de um workspace.", prova: SEM_CONTA_REAL,
      passos: ["No Entra ID, registre um aplicativo e crie um segredo para ele.", "Dê ao aplicativo permissão de leitura no workspace do Log Analytics.", "Em Conectar, preencha o domínio, o aplicativo, o workspace e o segredo."], tipo: "azure" },
    { id: "gcp", rotulo: "Google Cloud Pub/Sub", logo: "googlecloud", resumo: "Registros do Google Cloud, entregues por uma assinatura do Pub/Sub.", prova: SEM_CONTA_REAL,
      passos: ["Encaminhe os registros para um tópico do Pub/Sub e crie uma assinatura.", "Em IAM e administrador, crie uma conta de serviço com os papéis Pub/Sub Publisher e Pub/Sub Subscriber.", "Gere uma chave em JSON para essa conta.", "Em Conectar, preencha o projeto, a assinatura e cole o JSON."],
      cuidado: "Cada cliente pode ter uma assinatura do Google Cloud: é um limite do coletor.", tipo: "gcp" },
    { id: "office365", rotulo: "Microsoft 365", sigla: "365", resumo: "Atividade de Exchange, SharePoint, OneDrive e Teams, e administração.", prova: SEM_CONTA_REAL,
      passos: ["No Entra ID, registre um aplicativo e crie um segredo para ele.", "Dê ao aplicativo a permissão de leitura do feed de atividades da API de gerenciamento do Office 365.", "Em Conectar, preencha o locatário, o aplicativo e o segredo."], tipo: "office365" },
    { id: "msgraph", rotulo: "Microsoft Graph", sigla: "GR", resumo: "Alertas e incidentes de segurança, entradas e auditoria do diretório.", prova: SEM_CONTA_REAL,
      passos: ["No Entra ID, registre um aplicativo e crie um segredo para ele.", "Dê ao aplicativo permissão de leitura de alertas e incidentes de segurança e dos logs de auditoria.", "Em Conectar, preencha o locatário, o aplicativo e o segredo."], tipo: "msgraph" },
    { id: "github", rotulo: "GitHub", logo: "github", resumo: "Log de auditoria da organização: permissões, membros e atividade.", prova: SEM_CONTA_REAL,
      passos: ["Entre com a conta dona da organização e crie um token de acesso pessoal.", "Marque o escopo read:audit_log e gere o token.", "Em Conectar, preencha a organização e o token."],
      cuidado: "Só funciona com o plano GitHub Enterprise Cloud: nos outros, a API de auditoria não existe.", tipo: "github" },
  ] },
  { grupo: "Seus sistemas", itens: [
    { id: "webhook", rotulo: "Webhook", sigla: "API", resumo: "Qualquer sistema que saiba enviar JSON por HTTP.", prova: "Testado com envio real",
      passos: ["Em Conectar, crie o endereço e guarde o token: ele aparece uma única vez.", "No sistema de origem, envie um POST em JSON com o token no cabeçalho Authorization.", "Os eventos passam pelas mesmas regras de qualquer outro log."], tipos: ["webhook"] },
    { id: "api", rotulo: "Buscar em uma API", sigla: "GET", resumo: "Sistemas sem módulo pronto: buscamos de tempos em tempos e entregamos só o novo.", prova: "Testado com um sistema de exemplo",
      passos: ["Informe o endereço, sempre em https.", "Se a lista não for a raiz da resposta, diga onde ela está, como data.itens.", "Se precisar de credencial, informe o cabeçalho e o valor."],
      cuidado: "Endereços da rede interna são recusados.", tipos: ["api"] },
  ] },
  { grupo: "Avisos e consultas", itens: [
    { id: "slack", rotulo: "Slack", logo: "slack", resumo: "Avisa um canal a partir de um nível de alerta.", prova: "Testado com um receptor local, ainda não no Slack",
      passos: ["No Slack, crie um Incoming Webhook para o canal.", "Em Conectar, preencha o nível e o endereço do webhook."], cuidado: "Os alertas saem do ambiente com os dados que trazem.", tipo: "slack" },
    { id: "pagerduty", rotulo: "PagerDuty", logo: "pagerduty", resumo: "Abre um incidente a partir de um nível de alerta.", prova: SEM_CONTA_REAL,
      passos: ["No serviço do PagerDuty, adicione uma integração e copie a chave.", "Em Conectar, preencha o nível e a chave."], cuidado: "Os alertas saem do ambiente com os dados que trazem.", tipo: "pagerduty" },
    { id: "virustotal", rotulo: "VirusTotal", logo: "virustotal", resumo: "Consulta o hash de cada arquivo alterado.", prova: SEM_CONTA_REAL,
      passos: ["Copie a chave da API na sua conta do VirusTotal.", "Preencha em Conectar."], cuidado: "O hash sai para um serviço externo, nunca o arquivo. Na chave gratuita valem os termos e o limite deles.", tipo: "virustotal" },
    { id: "maltiverse", rotulo: "Maltiverse", sigla: "MV", resumo: "Consulta endereços e hashes dos alertas.", prova: SEM_CONTA_REAL,
      passos: ["Copie a chave da API na sua conta do Maltiverse.", "Em Conectar, preencha o nível e a chave."], cuidado: "Endereços e hashes saem para um serviço externo.", tipo: "maltiverse" },
  ] },
];

interface CampoDeConector { id: string; rotulo: string; valor?: string }
const CAMPOS_MICROSOFT: CampoDeConector[] = [{ id: "locatario", rotulo: "Locatário (tenant ID)" }, { id: "aplicativo", rotulo: "Aplicativo (client ID)" }];
const CAMPO_NIVEL: CampoDeConector = { id: "nivel", rotulo: "Avisar a partir do nível", valor: "10" };
const CONECTORES: Record<string, { segredo: string; longo?: boolean; campos: CampoDeConector[]; nota?: string }> = {
  github: { segredo: "Token de acesso", campos: [{ id: "organizacao", rotulo: "Organização" }] },
  office365: { segredo: "Segredo do aplicativo", campos: CAMPOS_MICROSOFT },
  msgraph: { segredo: "Segredo do aplicativo", campos: CAMPOS_MICROSOFT },
  aws: { segredo: "Chave secreta", campos: [{ id: "bucket", rotulo: "Bucket dos registros" }, { id: "chave_de_acesso", rotulo: "Chave de acesso" }] },
  azure: { segredo: "Segredo do aplicativo", campos: [{ id: "dominio", rotulo: "Domínio do locatário" }, { id: "aplicativo", rotulo: "Aplicativo (client ID)" }, { id: "workspace", rotulo: "Workspace" }] },
  gcp: { segredo: "Arquivo JSON da conta de serviço", longo: true, campos: [{ id: "projeto", rotulo: "Projeto" }, { id: "assinatura", rotulo: "Assinatura" }] },
  slack: { segredo: "Endereço do webhook do Slack", campos: [CAMPO_NIVEL], nota: "Os alertas a partir deste nível saem do ambiente para o Slack, com os dados que trazem." },
  pagerduty: { segredo: "Chave da integração", campos: [CAMPO_NIVEL], nota: "Os alertas a partir deste nível saem do ambiente para o PagerDuty, com os dados que trazem." },
  maltiverse: { segredo: "Chave da API", campos: [CAMPO_NIVEL], nota: "Endereços e hashes dos alertas são enviados para consulta em um serviço externo." },
  virustotal: { segredo: "Chave da API", campos: [], nota: "O hash de cada arquivo alterado é enviado ao VirusTotal, nunca o arquivo. Na chave gratuita valem os termos e o limite deles." },
};

// ------------------------------------------------------------------ fontes

interface Fonte {
  id: number;
  tipo: string;
  nome: string;
  config: Record<string, unknown>;
  estado: string;
  mensagem: string | null;
  criada_em: string | null;
  aplicada_em: string | null;
  saude: string | null;
  ultimo_dado: string | null;
  /** Só com o armazém de eventos: a conta das últimas horas (api/roar_api/saude_das_fontes.py). */
  volume?: Volume;
}
interface ContaDeVolume {
  eventos_24h: number;
  entendidos: number | null;
  ultima_hora: number;
  normal_da_hora: number | null;
  abaixo_do_normal: boolean;
  ultimo: string | null;
}
interface Volume extends ContaDeVolume {
  eps: number;
  horas: number[];
  equipamentos?: (ContaDeVolume & { endereco: string })[];
}
interface VisaoDeFontes {
  fontes: Fonte[];
  agentes: { total: number; conectados: number };
  endereco: string | null;
  porta_syslog: number | null;
}

const SAUDE_DA_FONTE: Record<string, string> = { recebendo: "● Recebendo", parada: "▲ Parada", nunca_recebeu: "○ Nada recebido ainda", desconhecida: "? Não foi possível conferir" };
const ESTADOS_DE_FONTE: Record<string, string> = { pendente: "Aplicando", recusada: "Recusada", ativa: "Ativa" };
const TIPOS_DE_FONTE: Record<string, string> = {
  syslog: "Syslog", webhook: "Webhook", api: "API", github: "GitHub", office365: "Microsoft 365", msgraph: "Microsoft Graph", aws: "AWS CloudTrail",
  azure: "Azure Log Analytics", gcp: "Google Cloud Pub/Sub", slack: "Aviso no Slack", pagerduty: "Aviso no PagerDuty", maltiverse: "Consulta no Maltiverse", virustotal: "Consulta no VirusTotal",
};
const CAMPOS_DA_CONFIG: Record<string, string> = {
  protocolo: "Protocolo", origens: "Endereços", organizacao: "Organização", locatario: "Locatário", aplicativo: "Aplicativo", bucket: "Bucket", dominio: "Domínio", workspace: "Workspace",
  projeto: "Projeto", assinatura: "Assinatura", nivel: "A partir do nível", endereco: "Endereço", caminho: "Onde está a lista", cabecalho: "Cabeçalho", intervalo_minutos: "Buscar a cada (minutos)",
};

const abaixoDoNormal = (f: Fonte) => Boolean(f.volume?.abaixo_do_normal || f.volume?.equipamentos?.some((q) => q.abaixo_do_normal));
const comProblema = (f: Fonte) => f.estado === "recusada" || Boolean(f.mensagem) || f.saude === "parada" || abaixoDoNormal(f);
// O webhook guarda só o resumo do token, e a busca em API pode não ter credencial nenhuma.
const temCredencial = (f: Fonte) => Boolean(f.config.segredo) || f.tipo === "webhook";

function detalheDaFonte(f: Fonte) {
  const c = f.config;
  if (f.tipo === "syslog") return `${String(c.protocolo ?? "").toUpperCase()}: ${((c.origens as string[] | undefined) ?? []).join(", ")}`;
  const direto = c.organizacao ?? c.locatario ?? c.endereco ?? c.bucket ?? c.dominio ?? c.projeto;
  if (direto !== undefined && direto !== null) return String(direto);
  if (c.nivel !== undefined) return `A partir do nível ${String(c.nivel)}`;
  return f.tipo === "webhook" ? "Token guardado" : "-";
}

/** As fontes de um cartão. O cartão de um fabricante mostra só as cadastradas por ele; o de Syslog, todas as de syslog. */
function fontesDoConector(item: Conector, fontes: Fonte[]) {
  const tipos: string[] = item.tipos ?? [item.tipo ?? ""];
  return fontes.filter((f) => tipos.includes(f.tipo) && (!item.amostra || f.config.fabricante === item.id));
}

function situacaoDoConector(item: Conector, visao: VisaoDeFontes | null): { texto: string; marca: "ok" | "alerta" | "neutro" } {
  if (item.id === "agente") {
    const { total = 0, conectados = 0 } = visao?.agentes ?? {};
    return total ? { texto: `${conectados} de ${total} conectados`, marca: conectados ? "ok" : "alerta" } : { texto: "Não conectado", marca: "neutro" };
  }
  const fontes = fontesDoConector(item, visao?.fontes ?? []);
  if (!fontes.length) return { texto: "Não conectado", marca: "neutro" };
  if (fontes.some((f) => f.estado === "recusada")) return { texto: "Recusado", marca: "alerta" };
  if (fontes.some((f) => f.estado === "pendente")) return { texto: "Aplicando", marca: "neutro" };
  if (fontes.some((f) => f.mensagem || f.saude === "parada")) return { texto: "Com problema", marca: "alerta" };
  if (fontes.some((f) => f.saude === "recebendo")) return { texto: "Recebendo", marca: "ok" };
  return { texto: fontes[0].saude === null ? "Conectado" : "Conectado, sem dados ainda", marca: "neutro" };
}

const semAcento = (t: string) => t.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase();

function irParaAtivos() {
  // A aplicação acompanha a rota pelo popstate.
  ir("/ativos");
  window.dispatchEvent(new PopStateEvent("popstate"));
}

// ------------------------------------------------------------------ peças

function Logo({ item, tamanho = 36 }: { item: Conector; tamanho?: number }) {
  return (
    <Box style={{ display: "flex", flex: "none", alignItems: "center", justifyContent: "center", width: tamanho, height: tamanho, borderRadius: 8, border: "1px solid var(--roar-borda)", background: "var(--mantine-color-dark-5)" }}>
      {item.logo
        // Os logotipos são de uma cor só, em preto: invertidos, ficam iguais no fundo escuro.
        ? <img src={`/estatico/logos/${item.logo}.svg`} alt="" width={tamanho * 0.55} height={tamanho * 0.55} style={{ filter: "invert(1)" }} />
        : <Text span fz={11} fw={700} style={{ color: "var(--mantine-color-rosa-1)", letterSpacing: "-.02em" }}>{item.sigla}</Text>}
    </Box>
  );
}

const CORES_DA_MARCA = { ok: "var(--mantine-color-green-5)", alerta: "var(--mantine-color-red-5)", neutro: "var(--mantine-color-dark-2)" };
const SINAL_DA_MARCA = { ok: "●", alerta: "▲", neutro: "○" };

function SituacaoDoConector({ situacao }: { situacao: ReturnType<typeof situacaoDoConector> }) {
  return <Text span size="xs" fw={500} style={{ color: CORES_DA_MARCA[situacao.marca], whiteSpace: "nowrap" }}>{SINAL_DA_MARCA[situacao.marca]} {situacao.texto}</Text>;
}

function CartaoDeConector({ item, visao, aoAbrir }: { item: Conector; visao: VisaoDeFontes; aoAbrir: () => void }) {
  return (
    <Card component="button" type="button" className="clicavel" onClick={aoAbrir} p="md" h="100%" style={{ gap: 10 }}>
      <Group gap="sm" wrap="nowrap">
        <Logo item={item} />
        <Text size="sm" fw={600} truncate>{item.rotulo}</Text>
      </Group>
      <Text size="xs" c="dimmed" lineClamp={2} style={{ flex: 1 }}>{item.resumo}</Text>
      <SituacaoDoConector situacao={situacaoDoConector(item, visao)} />
    </Card>
  );
}

function SituacaoDaFonte({ fonte }: { fonte: Fonte }) {
  const problema = fonte.mensagem && fonte.estado !== "recusada";
  const selo = <Estado tipo={problema ? "problema" : fonte.estado}>{problema ? "Com problema" : ESTADOS_DE_FONTE[fonte.estado] ?? fonte.estado}</Estado>;
  return fonte.mensagem ? <Tooltip label={fonte.mensagem} maw={320} multiline><span>{selo}</span></Tooltip> : selo;
}

function Fato({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return (
    <Group justify="space-between" gap="lg" wrap="nowrap" align="flex-start">
      <Text size="sm" c="dimmed" style={{ whiteSpace: "nowrap" }}>{rotulo}</Text>
      <Text span size="sm" ta="right" style={{ overflowWrap: "anywhere" }}>{children}</Text>
    </Group>
  );
}

function Entendidos({ valor }: { valor: number | null }) {
  if (valor === null) return <>-</>;
  return <Text span size="sm" c={valor < 80 ? "orange" : undefined}>{numero(valor)}%</Text>;
}

function UltimaHora({ conta }: { conta: ContaDeVolume }) {
  return (
    <Group gap={6} wrap="nowrap" justify="flex-end">
      <Text span size="sm">{numero(conta.ultima_hora)}</Text>
      {conta.normal_da_hora !== null && <Text span size="xs" c="dimmed">normal {numero(conta.normal_da_hora)}</Text>}
      {conta.abaixo_do_normal && <Badge size="xs" color="orange" variant="light">Abaixo do normal</Badge>}
    </Group>
  );
}

function VolumeDaFonte({ volume }: { volume: Volume }) {
  return (
    <Stack gap="sm">
      <Title order={3}>Últimas 24 horas</Title>
      <Sparkline h={56} data={volume.horas} curveType="linear" fillOpacity={0.25} aria-label="Eventos por hora nas últimas 24 horas" />
      <Stack gap={8}>
        <Fato rotulo="Eventos">{numero(volume.eventos_24h)}</Fato>
        <Fato rotulo="Por segundo, em média">{numero(volume.eps)}</Fato>
        <Fato rotulo="Entendidos pelo gerenciador"><Entendidos valor={volume.entendidos} /></Fato>
        <Fato rotulo="Na última hora"><UltimaHora conta={volume} /></Fato>
      </Stack>
      {volume.entendidos !== null && volume.entendidos < 80 && (
        <Text size="xs" c="dimmed">O que o gerenciador não entende chega como texto, sem campos para buscar e para as regras. Um parser próprio, na aba Parsers, resolve.</Text>
      )}
      {volume.equipamentos && (
        <Tabela
          linhas={volume.equipamentos}
          chave={(q) => q.endereco}
          vazio="Nenhum equipamento da lista mandou nada nos últimos 7 dias."
          colunas={[
            { titulo: "Equipamento", celula: (q) => <span className="mono">{q.endereco}</span> },
            { titulo: "Último dado", celula: (q) => <Data valor={q.ultimo} /> },
            { titulo: "24 h", celula: (q) => numero(q.eventos_24h) },
            { titulo: "Entendidos", celula: (q) => <Entendidos valor={q.entendidos} /> },
            { titulo: "Última hora", celula: (q) => <UltimaHora conta={q} /> },
          ]}
        />
      )}
    </Stack>
  );
}

// ------------------------------------------------------------------ formulários

function Rodape({ aoFechar, rotulo, ocupado }: { aoFechar: () => void; rotulo: string; ocupado: boolean }) {
  return (
    <Group justify="flex-end" mt="xs">
      <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
      <Button variant="filled" type="submit" loading={ocupado}>{rotulo}</Button>
    </Group>
  );
}

function Erro({ texto }: { texto: string | null }) {
  return texto ? <Alert color="red" variant="light" p="xs" fz="sm">{texto}</Alert> : null;
}

interface PropsDoFormulario { item: Conector; aoFechar: () => void; aoCriar: () => void }

function FormularioDeSyslog({ item, aoFechar, aoCriar }: PropsDoFormulario) {
  const [nome, setNome] = useState(item.id === "syslog" ? "" : item.rotulo);
  const [protocolo, setProtocolo] = useState<string>(item.protocolo ?? "tcp");
  const [origens, setOrigens] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const [ocupado, setOcupado] = useState(false);
  const salvar = async (e: FormEvent) => {
    e.preventDefault();
    setErro(null);
    if (!nome.trim()) return setErro("Dê um nome ao equipamento.");
    setOcupado(true);
    const r = await enviar("/api/fontes", { nome: nome.trim(), protocolo, origens: origens.split("\n").map((l) => l.trim()).filter(Boolean), fabricante: item.amostra ? item.id : null });
    setOcupado(false);
    if (!r.ok) return setErro(await detalhe(r, "Confira os endereços."));
    aoCriar();
    aoFechar();
  };
  return (
    <form onSubmit={salvar} noValidate>
      <Stack gap="sm">
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
          <TextInput label="Nome" placeholder="Firewall da matriz" maxLength={120} value={nome} onChange={(e) => setNome(e.currentTarget.value)} data-autofocus />
          <Select label="Protocolo" allowDeselect={false} value={protocolo} onChange={(v) => setProtocolo(v ?? "tcp")} data={item.protocolo === "udp" ? [{ value: "udp", label: "UDP (o que o equipamento usa)" }, { value: "tcp", label: "TCP" }] : [{ value: "tcp", label: "TCP (recomendado)" }, { value: "udp", label: "UDP" }]} />
        </SimpleGrid>
        <Textarea label="Endereços que podem enviar, um por linha" placeholder={"192.168.10.1\n10.20.0.0/24"} rows={3} spellCheck={false} value={origens} onChange={(e) => setOrigens(e.currentTarget.value)} />
        <Erro texto={erro} />
        <Rodape aoFechar={aoFechar} rotulo="Salvar" ocupado={ocupado} />
      </Stack>
    </form>
  );
}

function FormularioDeNuvem({ item, aoFechar, aoCriar }: PropsDoFormulario) {
  const conector = CONECTORES[item.tipo ?? ""];
  const [nome, setNome] = useState(item.rotulo);
  const [campos, setCampos] = useState<Record<string, string>>(() => Object.fromEntries(conector.campos.map((c) => [c.id, c.valor ?? ""])));
  // A credencial mora só neste formulário, que some inteiro ao fechar a janela.
  const [segredo, setSegredo] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const [ocupado, setOcupado] = useState(false);
  const salvar = async (e: FormEvent) => {
    e.preventDefault();
    setErro(null);
    const credencial = conector.longo ? segredo.trim() : segredo;
    if (!nome.trim() || !credencial) return setErro("Preencha o nome e a credencial.");
    setOcupado(true);
    const r = await enviar("/api/fontes/nuvem", { nome: nome.trim(), tipo: item.tipo, campos, segredo: credencial });
    setOcupado(false);
    if (!r.ok) return setErro(await detalhe(r, "Confira os campos."));
    aoCriar();
    aoFechar();
  };
  return (
    <form onSubmit={salvar} noValidate autoComplete="off">
      <Stack gap="sm">
        {conector.nota && <Text size="xs" c="dimmed">{conector.nota}</Text>}
        <TextInput label="Nome" maxLength={120} value={nome} onChange={(e) => setNome(e.currentTarget.value)} />
        {conector.campos.length > 0 && (
          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
            {conector.campos.map((c, i) => (
              <TextInput key={c.id} label={c.rotulo} spellCheck={false} data-autofocus={i === 0 || undefined} value={campos[c.id] ?? ""} onChange={(e) => { const v = e.currentTarget.value; setCampos((a) => ({ ...a, [c.id]: v })); }} />
            ))}
          </SimpleGrid>
        )}
        {conector.longo
          ? <Textarea label={conector.segredo} rows={5} spellCheck={false} value={segredo} onChange={(e) => setSegredo(e.currentTarget.value)} styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 12 } }} />
          : <PasswordInput label={conector.segredo} maxLength={4096} autoComplete="new-password" value={segredo} onChange={(e) => setSegredo(e.currentTarget.value)} />}
        <Group gap={6} wrap="nowrap"><IconLock size={14} color="var(--mantine-color-dark-2)" /><Text size="xs" c="dimmed">Fica cifrada no cofre e não volta para a tela.</Text></Group>
        <Erro texto={erro} />
        <Rodape aoFechar={aoFechar} rotulo="Conectar" ocupado={ocupado} />
      </Stack>
    </form>
  );
}

function FormularioDeWebhook({ aoFechar, aoCriar }: PropsDoFormulario) {
  const [nome, setNome] = useState("");
  const [exemplo, setExemplo] = useState<string | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [ocupado, setOcupado] = useState(false);
  const salvar = async (e: FormEvent) => {
    e.preventDefault();
    setErro(null);
    if (!nome.trim()) return setErro("Dê um nome ao endereço.");
    setOcupado(true);
    const r = await enviar("/api/fontes/webhook", { nome: nome.trim() });
    setOcupado(false);
    if (!r.ok) return setErro(await detalhe(r, "Não foi possível criar."));
    const { token, caminho } = await r.json() as { token: string; caminho: string };
    setExemplo(`curl -X POST ${window.location.origin}${caminho} -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" -d '{"mensagem": "teste"}'`);
    aoCriar();
  };
  if (exemplo) {
    return (
      <Stack gap="sm">
        <Alert color="yellow" variant="light" p="xs" fz="sm">Guarde agora: este token não aparece de novo.</Alert>
        <BlocoDeComando texto={exemplo} />
        <Group justify="flex-end"><Button onClick={aoFechar}>Fechar</Button></Group>
      </Stack>
    );
  }
  return (
    <form onSubmit={salvar} noValidate>
      <Stack gap="sm">
        <TextInput label="Nome" placeholder="Sistema de RH" maxLength={120} value={nome} onChange={(e) => setNome(e.currentTarget.value)} data-autofocus />
        <Erro texto={erro} />
        <Rodape aoFechar={aoFechar} rotulo="Criar" ocupado={ocupado} />
      </Stack>
    </form>
  );
}

function FormularioDeApi({ aoFechar, aoCriar }: PropsDoFormulario) {
  const [nome, setNome] = useState("");
  const [intervalo, setIntervalo] = useState<number | string>(15);
  const [endereco, setEndereco] = useState("");
  const [caminho, setCaminho] = useState("");
  const [cabecalho, setCabecalho] = useState("");
  const [segredo, setSegredo] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const [ocupado, setOcupado] = useState(false);
  const salvar = async (e: FormEvent) => {
    e.preventDefault();
    setErro(null);
    if (!nome.trim()) return setErro("Dê um nome ao sistema.");
    setOcupado(true);
    const r = await enviar("/api/fontes/api", { nome: nome.trim(), endereco: endereco.trim(), caminho: caminho.trim(), intervalo_minutos: Number(intervalo || 15), cabecalho: cabecalho.trim(), segredo });
    setOcupado(false);
    if (!r.ok) return setErro(await detalhe(r, "Confira os campos."));
    aoCriar();
    aoFechar();
  };
  return (
    <form onSubmit={salvar} noValidate autoComplete="off">
      <Stack gap="sm">
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
          <TextInput label="Nome" maxLength={120} value={nome} onChange={(e) => setNome(e.currentTarget.value)} data-autofocus />
          <NumberInput label="Buscar a cada (minutos)" min={5} max={1440} value={intervalo} onChange={setIntervalo} />
        </SimpleGrid>
        <TextInput label="Endereço completo, começando por https" maxLength={2000} spellCheck={false} value={endereco} onChange={(e) => setEndereco(e.currentTarget.value)} />
        <TextInput label="Onde está a lista na resposta (opcional)" placeholder="data.itens" maxLength={200} spellCheck={false} value={caminho} onChange={(e) => setCaminho(e.currentTarget.value)} />
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
          <TextInput label="Cabeçalho da credencial (opcional)" placeholder="Authorization" maxLength={64} spellCheck={false} value={cabecalho} onChange={(e) => setCabecalho(e.currentTarget.value)} />
          <PasswordInput label="Credencial (opcional)" maxLength={4096} autoComplete="new-password" value={segredo} onChange={(e) => setSegredo(e.currentTarget.value)} />
        </SimpleGrid>
        <Erro texto={erro} />
        <Rodape aoFechar={aoFechar} rotulo="Conectar" ocupado={ocupado} />
      </Stack>
    </form>
  );
}

function InstalacaoDoAgente() {
  // Cada leitura fica na auditoria e traz a senha de inscrição: só pede com a gaveta do agente aberta.
  const { dados, erro } = useDados<{ sistemas: { nome: string; provado: boolean; comando: string }[] }>("/api/fontes/instalacao");
  if (erro) return <Erro texto={erro} />;
  if (!dados) return <Carregando />;
  return (
    <Tabs defaultValue={dados.sistemas[0]?.nome}>
      <Tabs.List mb="sm">
        {dados.sistemas.map((s) => <Tabs.Tab key={s.nome} value={s.nome}>{s.nome.replace(/\s*\(.*$/, "")}</Tabs.Tab>)}
      </Tabs.List>
      {dados.sistemas.map((s) => {
        const observacao = /\((.*)\)/.exec(s.nome)?.[1];
        return (
          <Tabs.Panel key={s.nome} value={s.nome}>
            <Stack gap="xs">
              <Group gap="xs">
                <Estado tipo={s.provado ? "pronto" : "pendente"}>{s.provado ? "Testado" : "Comando ainda não testado aqui"}</Estado>
                {observacao && <Text size="xs" c="dimmed">{observacao[0].toUpperCase() + observacao.slice(1)}.</Text>}
              </Group>
              <BlocoDeComando texto={s.comando} />
            </Stack>
          </Tabs.Panel>
        );
      })}
    </Tabs>
  );
}

// O que o Roar tira de cada campo, nos mesmos nomes e na mesma ordem da ingestão (ingestao/roar_ingestao/normalizar.py).
const ORIGEM = ["srcip", "src_ip", "source_address"];
const DESTINO = ["dstip", "dst_ip", "destination_address"];
const USUARIO = ["srcuser", "dstuser", "user_name", "source_user", "username", "user"];
const ACAO = ["action", "status", "content_type"];
const primeiro = (campos: Record<string, unknown>, nomes: string[]) => nomes.map((n) => campos[n]).find((v) => typeof v === "string" && v.trim()) as string | undefined;

function TesteDeLinha({ amostra }: { amostra: string }) {
  const [linha, setLinha] = useState(amostra);
  const [leitura, setLeitura] = useState<Leitura | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [testando, setTestando] = useState(false);
  const testar = async () => {
    setTestando(true); setErro(null); setLeitura(null);
    const r = await enviar("/api/fontes/testar-linha", { log: linha });
    setTestando(false);
    if (!r.ok) return setErro(await detalhe(r, "O servidor não respondeu ao teste. Tente de novo em instantes."));
    setLeitura((await r.json()).hoje);
  };
  const aproveitado: [string, string | undefined][] = leitura ? [
    ["Origem", primeiro(leitura.campos, ORIGEM)], ["Destino", primeiro(leitura.campos, DESTINO)],
    ["Usuário", primeiro(leitura.campos, USUARIO)], ["Ação", primeiro(leitura.campos, ACAO)],
  ] : [];
  return (
    <Stack gap="xs">
      <Title order={2}>Testar com uma linha do equipamento</Title>
      <Text size="sm" c="dimmed">Já vem uma linha de exemplo. Troque por uma do seu equipamento, se tiver: o teste não grava nada.</Text>
      <Textarea aria-label="Linha de log do equipamento" rows={3} spellCheck={false} className="mono" value={linha} onChange={(e) => setLinha(e.currentTarget.value)} />
      <Group><Button onClick={testar} loading={testando} disabled={!linha.trim()}>Testar</Button></Group>
      <Erro texto={erro} />
      {leitura && (
        <Stack gap="xs">
          {!leitura.decodificador ? (
            <Alert color="yellow" variant="light" p="xs" fz="sm" icon={<IconAlertTriangle size={16} />}>O servidor não reconheceu esta linha: ela chegaria como texto, sem campos. Na aba Parsers dá para ensinar o formato.</Alert>
          ) : (
            <Stack gap={8}>
              {aproveitado.map(([rotulo, valor]) => <Fato key={rotulo} rotulo={rotulo}>{valor ? <span className="mono">{valor}</span> : <Text span size="sm" c="dimmed">não veio</Text>}</Fato>)}
            </Stack>
          )}
          <ComoLe titulo="Tudo o que o servidor leu" leitura={leitura} />
        </Stack>
      )}
    </Stack>
  );
}

// ------------------------------------------------------------------ gavetas

function GavetaDoConector({ item, visao, aoFechar, aoMudar, aoAbrirFonte }: { item: Conector | null; visao: VisaoDeFontes; aoFechar: () => void; aoMudar: () => void; aoAbrirFonte: (f: Fonte) => void }) {
  const pode = usePode();
  const [conectando, setConectando] = useState(false);
  const fechar = () => { setConectando(false); aoFechar(); };
  const podeConectar = item ? pode(item.permissao ?? "gerir_fontes") : false;
  const tipos = item ? item.tipos ?? [item.tipo ?? ""] : [];
  const fontes = item ? fontesDoConector(item, visao.fontes) : [];
  const Formulario = tipos.includes("syslog") ? FormularioDeSyslog : item?.id === "webhook" ? FormularioDeWebhook : item?.id === "api" ? FormularioDeApi : FormularioDeNuvem;
  const prova = item && PROVAS_BOAS.has(item.id) ? "pronto" : "outro";

  return (
    // Esc na janela de conectar não pode fechar também a gaveta que está por trás.
    <Drawer opened={item !== null} onClose={fechar} size="lg" closeOnEscape={!conectando} title={item && <Group gap="sm" wrap="nowrap"><Logo item={item} tamanho={28} /><Text span fw={600}>{item.rotulo}</Text></Group>}>
      {item && (
        <Stack gap="md">
          <Text size="sm">{item.resumo}</Text>
          <Group gap="xs">
            <Estado tipo={prova}>{item.prova}</Estado>
            <SituacaoDoConector situacao={situacaoDoConector(item, visao)} />
          </Group>

          <Stack gap="xs">
            <Title order={2}>Como implantar</Title>
            {item.passos.map((p, i) => (
              <Group key={p} gap="sm" wrap="nowrap" align="flex-start">
                <Badge variant="outline" circle size="md" color="rosa" className="numero" style={{ flex: "none" }}>{i + 1}</Badge>
                <Text size="sm">{p}</Text>
              </Group>
            ))}
          </Stack>

          {item.cuidado && <Alert color="yellow" variant="light" p="xs" fz="sm" icon={<IconAlertTriangle size={16} />}>{item.cuidado}</Alert>}
          {tipos.includes("syslog") && visao.porta_syslog && (
            <Text size="sm">Aponte {item.id === "syslog" ? "os equipamentos" : "o equipamento"} para <span className="mono">{visao.endereco}</span>, porta <span className="mono">{visao.porta_syslog}</span>{item.protocolo === "udp" ? ", em UDP" : ""}.</Text>
          )}
          {item.comando && visao.porta_syslog && visao.endereco && <BlocoDeComando texto={item.comando(visao.endereco, visao.porta_syslog)} />}
          {item.amostra && pode("gerir_fontes") && <TesteDeLinha key={item.id} amostra={item.amostra} />}

          {!podeConectar && <Text size="sm" c="dimmed">Seu perfil não permite conectar. Peça a quem administra.</Text>}
          {podeConectar && item.id === "agente" && <InstalacaoDoAgente />}
          {podeConectar && item.id !== "agente" && <Group><Button variant="filled" leftSection={<IconPlugConnected size={14} />} onClick={() => setConectando(true)}>Conectar</Button></Group>}
          {item.id === "agente" && <Group><Button leftSection={<IconServer2 size={14} />} onClick={irParaAtivos}>Ver ativos</Button></Group>}

          {fontes.length > 0 && (
            <Stack gap="xs">
              <Title order={2}>Já conectados</Title>
              <Tabela
                linhas={fontes}
                chave={(f) => f.id}
                vazio=""
                aoClicarLinha={aoAbrirFonte}
                colunas={[
                  { titulo: "Nome", celula: (f) => f.nome },
                  { titulo: "Estado", largura: 110, celula: (f) => <SituacaoDaFonte fonte={f} /> },
                  { titulo: "Dados", celula: (f) => SAUDE_DA_FONTE[f.saude ?? ""] ?? "-" },
                ]}
              />
            </Stack>
          )}

          {podeConectar && item.id !== "agente" && (
            // Fechar a janela desmonta o formulário, e a credencial digitada vai junto.
            <Modal opened={conectando} onClose={() => setConectando(false)} title={`Conectar ${item.rotulo}`} size="lg" closeOnClickOutside={false}>
              <Formulario key={item.id} item={item} aoFechar={() => setConectando(false)} aoCriar={aoMudar} />
            </Modal>
          )}
        </Stack>
      )}
    </Drawer>
  );
}

function GavetaDaFonte({ fonte, aoFechar, aoDesativar }: { fonte: Fonte | null; aoFechar: () => void; aoDesativar: (f: Fonte) => void }) {
  const pode = usePode();
  const valor = (v: unknown) => (Array.isArray(v) ? v.join(", ") : String(v));
  return (
    <Drawer opened={fonte !== null} onClose={aoFechar} title={fonte?.nome ?? ""} size="md">
      {fonte && (
        <Stack gap="md">
          <Group gap="xs">
            <SituacaoDaFonte fonte={fonte} />
            {fonte.saude && <Text size="xs" c="dimmed">{SAUDE_DA_FONTE[fonte.saude] ?? fonte.saude}</Text>}
          </Group>
          {fonte.mensagem && <Alert color="red" variant="light" p="xs" fz="sm">{fonte.mensagem}</Alert>}
          <Stack gap={8}>
            <Fato rotulo="Tipo">{TIPOS_DE_FONTE[fonte.tipo] ?? fonte.tipo}</Fato>
            {Object.entries(CAMPOS_DA_CONFIG).map(([campo, rotulo]) => {
              const v = fonte.config[campo];
              if (v === undefined || v === null || v === "") return null;
              return <Fato key={campo} rotulo={rotulo}><span className="mono">{campo === "protocolo" ? valor(v).toUpperCase() : valor(v)}</span></Fato>;
            })}
            <Fato rotulo="Último dado"><Data valor={fonte.ultimo_dado} /></Fato>
            <Fato rotulo="Criada em"><Data valor={fonte.criada_em} /></Fato>
            <Fato rotulo="Aplicada em"><Data valor={fonte.aplicada_em} /></Fato>
            {temCredencial(fonte) && <Fato rotulo="Credencial">{fonte.tipo === "webhook" ? "Só o resumo do token" : "Cifrada no cofre"}</Fato>}
          </Stack>
          {fonte.volume && <VolumeDaFonte volume={fonte.volume} />}
          {pode("gerir_fontes") && <Group><Button onClick={() => aoDesativar(fonte)}>Desativar</Button></Group>}
        </Stack>
      )}
    </Drawer>
  );
}

// ------------------------------------------------------------------ abas

function Catalogo({ visao, aoAbrir }: { visao: VisaoDeFontes; aoAbrir: (item: Conector) => void }) {
  const [busca, setBusca] = useState("");
  const [grupo, setGrupo] = useState("todos");
  const grupos = useMemo(() => {
    const termo = semAcento(busca.trim());
    return CATALOGO
      .filter((g) => grupo === "todos" || g.grupo === grupo)
      .map((g) => ({ ...g, itens: g.itens.filter((i) => semAcento(`${i.rotulo} ${i.resumo}`).includes(termo)) }))
      .filter((g) => g.itens.length);
  }, [busca, grupo]);
  return (
    <Stack gap="md">
      <Group gap="sm" wrap="wrap">
        <Busca valor={busca} aoMudar={setBusca} dica="Buscar conector" />
        <SegmentedControl size="xs" value={grupo} onChange={setGrupo} aria-label="Categoria" data={[{ label: "Todos", value: "todos" }, ...CATALOGO.map((g) => ({ label: g.grupo, value: g.grupo }))]} />
      </Group>
      {!grupos.length && <Vazio>Nenhum conector encontrado.</Vazio>}
      {grupos.map((g) => (
        <Stack key={g.grupo} gap="xs">
          {grupo === "todos" && <Title order={2}>{g.grupo}</Title>}
          <SimpleGrid cols={{ base: 1, xs: 2, md: 3, xl: 4 }} spacing="md">
            {g.itens.map((i) => <CartaoDeConector key={i.id} item={i} visao={visao} aoAbrir={() => aoAbrir(i)} />)}
          </SimpleGrid>
        </Stack>
      ))}
      <Text size="xs" c="dimmed">Os logotipos pertencem às suas respectivas marcas e só identificam com quem cada conector fala.</Text>
    </Stack>
  );
}

function Configuradas({ fontes, soProblema, aoMudarFiltro, aoAbrir, aoDesativar }: { fontes: Fonte[]; soProblema: boolean; aoMudarFiltro: (v: boolean) => void; aoAbrir: (f: Fonte) => void; aoDesativar: (f: Fonte) => void }) {
  const pode = usePode();
  const linhas = soProblema ? fontes.filter(comProblema) : fontes;
  return (
    <Painel titulo="Fontes configuradas" acao={<Switch size="xs" label="Só com problema" checked={soProblema} onChange={(e) => aoMudarFiltro(e.currentTarget.checked)} />}>
      <Tabela
        linhas={linhas}
        chave={(f) => f.id}
        vazio={fontes.length ? "Nenhuma fonte com problema." : "Nenhum equipamento configurado."}
        aoClicarLinha={aoAbrir}
        colunas={[
          { titulo: "Nome", celula: (f) => <Text size="sm" fw={500}>{f.nome}</Text> },
          { titulo: "Tipo", celula: (f) => TIPOS_DE_FONTE[f.tipo] ?? f.tipo },
          { titulo: "Detalhe", celula: (f) => <span className="mono">{detalheDaFonte(f)}</span> },
          { titulo: "Estado", largura: 110, celula: (f) => <SituacaoDaFonte fonte={f} /> },
          { titulo: "Dados", celula: (f) => (
            <Group gap={6} wrap="nowrap">
              <Text span size="sm" style={{ whiteSpace: "nowrap" }}>{SAUDE_DA_FONTE[f.saude ?? ""] ?? "-"}</Text>
              {abaixoDoNormal(f) && <Badge size="xs" color="orange" variant="light">Abaixo do normal</Badge>}
            </Group>
          ) },
          { titulo: "Últimas 24 h", largura: 170, celula: (f) => f.volume ? (
            <Group gap={8} wrap="nowrap">
              <Sparkline w={80} h={24} data={f.volume.horas} curveType="linear" fillOpacity={0.25} aria-hidden />
              <Text span size="sm">{numero(f.volume.eventos_24h)}</Text>
            </Group>
          ) : "-" },
          { titulo: "Último dado", largura: 150, celula: (f) => <Data valor={f.ultimo_dado} /> },
          { titulo: "", largura: 40, celula: (f) => (
            <AcoesDaLinha rotulo={`Ações de ${f.nome}`} itens={[
              { texto: "Ver detalhes", aoClicar: () => aoAbrir(f) },
              ...(pode("gerir_fontes") ? [{ texto: "Desativar", perigo: true, aoClicar: () => aoDesativar(f) }] : []),
            ]} />
          ) },
        ]}
      />
    </Painel>
  );
}

function Cofre({ fontes, aoAbrir, aoDesativar }: { fontes: Fonte[]; aoAbrir: (f: Fonte) => void; aoDesativar: (f: Fonte) => void }) {
  const pode = usePode();
  return (
    <Painel titulo="Cofre de credenciais">
      <Tabela
        linhas={fontes}
        chave={(f) => f.id}
        vazio="Nenhuma credencial guardada."
        aoClicarLinha={aoAbrir}
        colunas={[
          { titulo: "Fonte", celula: (f) => <Text size="sm" fw={500}>{f.nome}</Text> },
          { titulo: "Tipo", celula: (f) => TIPOS_DE_FONTE[f.tipo] ?? f.tipo },
          { titulo: "Como fica guardada", celula: (f) => <Group gap={6} wrap="nowrap"><IconLock size={14} color="var(--mantine-color-dark-2)" /><Text span size="sm">{f.tipo === "webhook" ? "Só o resumo do token" : "Cifrada, não volta para a tela"}</Text></Group> },
          { titulo: "Desde", largura: 150, celula: (f) => <Data valor={f.criada_em} /> },
          { titulo: "", largura: 40, celula: (f) => (
            <AcoesDaLinha rotulo={`Ações de ${f.nome}`} itens={pode("gerir_fontes") ? [{ texto: "Desativar e apagar", perigo: true, aoClicar: () => aoDesativar(f) }] : []} />
          ) },
        ]}
      />
    </Painel>
  );
}

// ------------------------------------------------------------------ tela

export function Fontes() {
  const { dados, erro, recarregar } = useDados<VisaoDeFontes>("/api/fontes");
  const [aba, setAba] = useState<string | null>("catalogo");
  const [soProblema, setSoProblema] = useState(false);
  const [conector, setConector] = useState<Conector | null>(null);
  const [idDaFonte, setIdDaFonte] = useState<number | null>(null);
  const [desativar, setDesativar] = useState<Fonte | null>(null);
  const [erroAoDesativar, setErroAoDesativar] = useState<string | null>(null);

  // Quem está aplicando muda de estado sozinho, e esta tela não tem outro jeito de mostrar isso.
  const aplicando = dados?.fontes.some((f) => f.estado === "pendente") ?? false;
  useEffect(() => {
    if (!aplicando) return;
    const t = setInterval(recarregar, 15000);
    return () => clearInterval(t);
  }, [aplicando, recarregar]);

  const confirmarDesativar = async () => {
    if (!desativar) return;
    const r = await enviar(`/api/fontes/${desativar.id}/desativar`);
    if (!r.ok) {
      setErroAoDesativar(await detalhe(r, "Não foi possível desativar."));
      return;
    }
    setDesativar(null);
    setIdDaFonte(null);
    recarregar();
  };
  const pedirDesativar = (f: Fonte) => { setErroAoDesativar(null); setDesativar(f); };
  const abrirFonte = (f: Fonte) => setIdDaFonte(f.id);

  const cabecalho = <Cabecalho titulo="Fontes de dados" ajuda="De onde vêm os logs e para onde vão os avisos. Escolha um conector para ver o passo a passo e conectar. Credenciais ficam cifradas e não voltam para a tela." />;
  if (!dados) return <>{cabecalho}<Carregando erro={erro} /></>;

  const problemas = dados.fontes.filter(comProblema).length;
  const noCofre = dados.fontes.filter(temCredencial);

  return (
    <>
      {cabecalho}
      <Stack gap="md">
        <SimpleGrid cols={{ base: 2, md: 4 }} spacing="md">
          <Numero rotulo="Ativos conectados" valor={numero(dados.agentes.conectados)} detalhe={`de ${numero(dados.agentes.total)} inscritos`} aoClicar={irParaAtivos} />
          <Numero rotulo="Fontes configuradas" valor={numero(dados.fontes.length)} aoClicar={() => { setSoProblema(false); setAba("configuradas"); }} />
          <Numero rotulo="Com problema" valor={numero(problemas)} destaque={problemas ? "var(--mantine-color-red-5)" : undefined} aoClicar={() => { setSoProblema(true); setAba("configuradas"); }} />
          <Numero rotulo="Credenciais no cofre" valor={numero(noCofre.length)} aoClicar={() => setAba("cofre")} />
        </SimpleGrid>

        <Tabs value={aba} onChange={setAba}>
          <Tabs.List mb="md">
            <Tabs.Tab value="catalogo">Conectores</Tabs.Tab>
            <Tabs.Tab value="configuradas">Configuradas</Tabs.Tab>
            <Tabs.Tab value="cofre">Cofre de credenciais</Tabs.Tab>
            <Tabs.Tab value="parsers">Parsers</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="catalogo"><Catalogo visao={dados} aoAbrir={setConector} /></Tabs.Panel>
          <Tabs.Panel value="configuradas"><Configuradas fontes={dados.fontes} soProblema={soProblema} aoMudarFiltro={setSoProblema} aoAbrir={abrirFonte} aoDesativar={pedirDesativar} /></Tabs.Panel>
          <Tabs.Panel value="cofre"><Cofre fontes={noCofre} aoAbrir={abrirFonte} aoDesativar={pedirDesativar} /></Tabs.Panel>
          <Tabs.Panel value="parsers"><Parsers /></Tabs.Panel>
        </Tabs>
      </Stack>

      <GavetaDoConector item={conector} visao={dados} aoFechar={() => setConector(null)} aoMudar={recarregar} aoAbrirFonte={abrirFonte} />
      <GavetaDaFonte fonte={dados.fontes.find((f) => f.id === idDaFonte) ?? null} aoFechar={() => setIdDaFonte(null)} aoDesativar={pedirDesativar} />
      <Modal opened={desativar !== null} onClose={() => setDesativar(null)} title={`Desativar ${desativar?.nome ?? ""}?`}>
        <Stack gap="sm">
          <Text size="sm">{desativar && temCredencial(desativar) ? "A fonte para de receber dados e a credencial guardada é apagada. Para voltar, será preciso conectar de novo." : "A fonte para de receber dados. Para voltar, será preciso conectar de novo."}</Text>
          <Erro texto={erroAoDesativar} />
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={() => setDesativar(null)}>Cancelar</Button>
            <Button variant="filled" onClick={confirmarDesativar}>Desativar</Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
