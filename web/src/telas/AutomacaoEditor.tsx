import { ActionIcon, Alert, Box, Button, Card, Group, Menu, Modal, NumberInput, SegmentedControl, Select, SimpleGrid, Stack, Text, Textarea, TextInput, Title, Tooltip } from "@mantine/core";
import { IconArrowsSplit, IconArrowDown, IconArrowUp, IconBan, IconCheck, IconGitBranch, IconHandStop, IconNote, IconPlus, IconTrash, IconUserOff, IconWebhook, IconX } from "@tabler/icons-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";

import { detalhe, enviar, ler } from "../api";
import { Data, Tabela } from "../componentes";
import { nomeDoPais, numero } from "../formato";
import { SEVERIDADES } from "../tema";

// ------------------------------------------------------------------ formato do playbook

export interface Condicao { campo: string; op: string; valor: unknown }
export interface Parametros { duracao_minutos?: number; metodo?: string; protegidos?: string[]; protegidas?: string[]; url?: string; texto?: string }
export type Bloco =
  | { tipo: "aprovacao" }
  | { tipo: "acao"; acao: string; parametros: Parametros }
  | { tipo: "se"; condicao: Condicao; entao: Bloco[]; senao?: Bloco[] }
  | { tipo: "paralelo"; ramos: Bloco[][] };
export type Quando = { tipo: "evento"; regra_id: string } | { tipo: "risco"; severidade: string } | { tipo: "indicador" };
export interface Definicao { quando: Quando; se?: Condicao[]; blocos: Bloco[] }
export interface AberturaDoPlaybook { id?: number; nome?: string; definicao?: Definicao; intervalo_minutos?: number; rascunho?: boolean }

export const NOMES_DE_ACAO: Record<string, string> = { bloquear_ip: "Bloquear o endereço", desativar_conta: "Desativar a conta", webhook: "Avisar um endereço web", registrar: "Registrar uma nota" };

const CONDICOES: { id: string; rotulo: string; campo: string; op: string; fixo?: boolean; tipo?: "numero" | "severidade" | "texto" | "pais"; padrao?: unknown }[] = [
  { id: "externo", rotulo: "O endereço é externo", campo: "alvo_externo", op: "igual", fixo: true },
  { id: "interno", rotulo: "O endereço não é externo", campo: "alvo_externo", op: "igual", fixo: false },
  { id: "nivel_minimo", rotulo: "Nível a partir de", campo: "nivel", op: "minimo", tipo: "numero", padrao: 10 },
  { id: "nivel_maximo", rotulo: "Nível até", campo: "nivel", op: "maximo", tipo: "numero", padrao: 10 },
  { id: "severidade", rotulo: "Severidade a partir de", campo: "severidade", op: "minimo", tipo: "severidade", padrao: "alta" },
  { id: "na_rede", rotulo: "Endereço dentro da rede", campo: "alvo", op: "na_rede", tipo: "texto", padrao: "" },
  { id: "fora_da_rede", rotulo: "Endereço fora da rede", campo: "alvo", op: "fora_da_rede", tipo: "texto", padrao: "" },
  { id: "pais_e", rotulo: "País de origem é", campo: "pais", op: "e", tipo: "pais", padrao: "Brazil" },
  { id: "pais_nao_e", rotulo: "País de origem não é", campo: "pais", op: "nao_e", tipo: "pais", padrao: "Brazil" },
];
const SE_EXTERNO: Condicao = { campo: "alvo_externo", op: "igual", valor: true };

const NOVOS_BLOCOS: Record<string, () => Bloco> = {
  bloquear_ip: () => ({ tipo: "acao", acao: "bloquear_ip", parametros: { duracao_minutos: 60, protegidos: [] } }),
  desativar_conta: () => ({ tipo: "acao", acao: "desativar_conta", parametros: { duracao_minutos: 60, protegidas: [] } }),
  webhook: () => ({ tipo: "acao", acao: "webhook", parametros: { url: "" } }),
  registrar: () => ({ tipo: "acao", acao: "registrar", parametros: { texto: "" } }),
  aprovacao: () => ({ tipo: "aprovacao" }),
  se: () => ({ tipo: "se", condicao: { ...SE_EXTERNO }, entao: [], senao: [] }),
  paralelo: () => ({ tipo: "paralelo", ramos: [[], []] }),
};
const ROTULOS_DE_BLOCO: Record<string, string> = {
  bloquear_ip: "Bloquear o endereço no ativo", desativar_conta: "Desativar a conta no ativo", webhook: "Avisar um endereço web", registrar: "Registrar uma nota",
  aprovacao: "Pedir aprovação", se: "Se... senão", paralelo: "Fazer ao mesmo tempo",
};
const ICONES_DE_BLOCO: Record<string, ReactNode> = {
  bloquear_ip: <IconBan size={16} />, desativar_conta: <IconUserOff size={16} />, webhook: <IconWebhook size={16} />, registrar: <IconNote size={16} />,
  aprovacao: <IconHandStop size={16} />, se: <IconGitBranch size={16} />, paralelo: <IconArrowsSplit size={16} />,
};

const MODELOS: { titulo: string; texto: string; nome: string; definicao: Definicao }[] = [
  {
    titulo: "Força bruta em SSH", texto: "Pede aprovação e bloqueia o endereço de quem está tentando.", nome: "Força bruta em SSH: bloquear",
    definicao: { quando: { tipo: "evento", regra_id: "5712" }, se: [SE_EXTERNO], blocos: [NOVOS_BLOCOS.aprovacao(), NOVOS_BLOCOS.bloquear_ip()] },
  },
  {
    titulo: "Conta em risco", texto: "Avisa a equipe quando o risco de uma pessoa ou ativo fica crítico.", nome: "Conta em risco: avisar a equipe",
    definicao: { quando: { tipo: "risco", severidade: "critica" }, se: [], blocos: [NOVOS_BLOCOS.webhook()] },
  },
  {
    titulo: "Risco com origem externa", texto: "Se a origem for externa, bloqueia com aprovação. Se for interna, só avisa.", nome: "Risco alto: bloquear se externo, avisar se interno",
    definicao: { quando: { tipo: "risco", severidade: "alta" }, se: [], blocos: [{ tipo: "se", condicao: SE_EXTERNO, entao: [NOVOS_BLOCOS.aprovacao(), NOVOS_BLOCOS.bloquear_ip()], senao: [NOVOS_BLOCOS.webhook()] }] },
  },
  { titulo: "Em branco", texto: "Comece do zero.", nome: "", definicao: { quando: { tipo: "evento", regra_id: "" }, se: [], blocos: [] } },
];

function condicaoConhecida(c: Condicao) {
  return CONDICOES.find((m) => m.campo === c.campo && m.op === c.op && (m.fixo === undefined || m.fixo === c.valor)) ?? CONDICOES[0];
}

export function descreverCondicao(c: Condicao) {
  const m = condicaoConhecida(c);
  if (m.fixo !== undefined) return m.rotulo;
  if (m.tipo === "pais") return `${m.rotulo} ${nomeDoPais(String(c.valor))}`;
  if (m.tipo === "severidade") return `${m.rotulo} ${(SEVERIDADES[c.valor as keyof typeof SEVERIDADES]?.texto ?? String(c.valor)).toLowerCase()}`;
  return `${m.rotulo} ${String(c.valor)}`;
}

export function descreverGatilho(definicao: Definicao) {
  const q = definicao.quando;
  const base = q.tipo === "indicador" ? "Evento bateu com indicador de ameaça"
    : q.tipo === "risco" ? `Risco a partir de ${(SEVERIDADES[q.severidade as keyof typeof SEVERIDADES]?.texto ?? q.severidade).toLowerCase()}`
      : `Alerta da regra ${q.regra_id}`;
  const partes = (definicao.se ?? []).map(descreverCondicao);
  return partes.length ? `${base}, se ${partes.join(" e ").toLowerCase()}` : base;
}

export function contarAcoes(lista: Bloco[]): string[] {
  const nomes: string[] = [];
  for (const b of lista) {
    if (b.tipo === "acao") nomes.push(NOMES_DE_ACAO[b.acao] ?? b.acao);
    if (b.tipo === "se") nomes.push(...contarAcoes(b.entao), ...contarAcoes(b.senao ?? []));
    if (b.tipo === "paralelo") b.ramos.forEach((r) => nomes.push(...contarAcoes(r)));
  }
  return [...new Set(nomes)];
}

/** "Automatizar isto" na fila: parte do alerta que a pessoa já está vendo, ela não precisa saber número de regra. */
export function rascunhoDeGrupo(grupo: { ip_origem?: string | null; regras?: string[] }, eventos: { regra_id: string; regra_descricao?: string | null }[]): AberturaDoPlaybook {
  const regra = eventos[0]?.regra_id ?? grupo.regras?.[0] ?? "";
  const nome = `Responder a: ${eventos[0]?.regra_descricao ?? `regra ${regra}`}`.slice(0, 120);
  const definicao: Definicao = grupo.ip_origem
    ? { quando: { tipo: "evento", regra_id: regra }, se: [SE_EXTERNO], blocos: [NOVOS_BLOCOS.aprovacao(), NOVOS_BLOCOS.bloquear_ip()] }
    : { quando: { tipo: "evento", regra_id: regra }, se: [], blocos: [NOVOS_BLOCOS.webhook()] };
  return { nome, definicao, rascunho: true };
}

export function rascunhoDeRisco(alerta: { severidade: string }): AberturaDoPlaybook {
  return {
    nome: `Responder a risco ${SEVERIDADES[alerta.severidade as keyof typeof SEVERIDADES]?.texto.toLowerCase() ?? ""}`.trim(),
    definicao: { quando: { tipo: "risco", severidade: alerta.severidade }, se: [], blocos: [{ tipo: "se", condicao: SE_EXTERNO, entao: [NOVOS_BLOCOS.aprovacao(), NOVOS_BLOCOS.bloquear_ip()], senao: [NOVOS_BLOCOS.webhook()] }] },
    rascunho: true,
  };
}

// ------------------------------------------------------------------ peças do editor

const SEVERIDADES_DO_GATILHO = [{ value: "alta", label: "Alta" }, { value: "critica", label: "Crítica" }];
const NIVEIS = Array.from({ length: 17 }, (_, i) => ({ value: String(i), label: String(i) }));
const DURACOES = [{ value: "60", label: "1 hora" }, { value: "1440", label: "1 dia" }, { value: "10080", label: "7 dias" }];

let promessaDosPaises: Promise<{ value: string; label: string }[]> | null = null;

// O motor compara com o nome em inglês, que é como o indexador escreve o país; a tela mostra em português.
function carregarPaises() {
  promessaDosPaises ??= ler<{ paises: { c: string }[]; pontos: { c: string }[] }>("/estatico/mapa-paises.json").then((d) => {
    const ingles = new Intl.DisplayNames(["en"], { type: "region" });
    const portugues = new Intl.DisplayNames(["pt-BR"], { type: "region" });
    const codigos = [...new Set([...d.paises, ...d.pontos].map((p) => p.c))];
    return codigos.map((c) => ({ value: ingles.of(c) ?? c, label: portugues.of(c) ?? c })).sort((a, b) => a.label.localeCompare(b.label, "pt-BR"));
  });
  return promessaDosPaises;
}

function CampoDePais({ valor, aoMudar }: { valor: string; aoMudar: (v: string) => void }) {
  const [paises, setPaises] = useState<{ value: string; label: string }[]>([]);
  useEffect(() => {
    let valendo = true;
    carregarPaises().then((p) => { if (valendo) setPaises(p); }).catch(() => {});
    return () => { valendo = false; };
  }, []);
  const opcoes = useMemo(() => {
    const unicas = new Map(paises.map((p) => [p.value, p]));
    if (!unicas.has(valor)) unicas.set(valor, { value: valor, label: valor });
    return [...unicas.values()];
  }, [paises, valor]);
  return <Select w={200} aria-label="País" searchable allowDeselect={false} value={valor} data={opcoes} onChange={(v) => { if (v) aoMudar(v); }} />;
}

function EditorDeCondicao({ condicao, aoMudar, aoRemover }: { condicao: Condicao; aoMudar: (c: Condicao) => void; aoRemover?: () => void }) {
  const m = condicaoConhecida(condicao);
  return (
    <Group gap="xs" wrap="wrap">
      <Select
        w={230}
        aria-label="Condição"
        allowDeselect={false}
        value={m.id}
        data={CONDICOES.map((o) => ({ value: o.id, label: o.rotulo }))}
        onChange={(id) => {
          const nova = CONDICOES.find((o) => o.id === id);
          if (nova) aoMudar({ campo: nova.campo, op: nova.op, valor: nova.fixo ?? nova.padrao });
        }}
      />
      {m.tipo === "numero" && <Select w={80} aria-label="Nível" allowDeselect={false} value={String(condicao.valor)} data={NIVEIS} onChange={(v) => aoMudar({ ...condicao, valor: Number(v) })} />}
      {m.tipo === "pais" && <CampoDePais valor={String(condicao.valor)} aoMudar={(v) => aoMudar({ ...condicao, valor: v })} />}
      {m.tipo === "texto" && <TextInput w={180} aria-label="Rede" placeholder="10.0.0.0/8" spellCheck={false} value={String(condicao.valor ?? "")} onChange={(e) => aoMudar({ ...condicao, valor: e.currentTarget.value.trim() })} />}
      {m.tipo === "severidade" && <Select w={110} aria-label="Severidade" allowDeselect={false} value={String(condicao.valor)} data={SEVERIDADES_DO_GATILHO} onChange={(v) => aoMudar({ ...condicao, valor: v })} />}
      {aoRemover && <Tooltip label="Remover condição"><ActionIcon variant="subtle" color="gray" aria-label="Remover condição" onClick={aoRemover}><IconX size={16} /></ActionIcon></Tooltip>}
    </Group>
  );
}

const paraLista = (texto: string) => texto.split("\n").map((l) => l.trim()).filter(Boolean);

/** O texto fica aqui, senão a lista engoliria a linha em branco no meio da digitação. */
function CampoDeLista({ rotulo, placeholder, valor, aoMudar }: { rotulo: string; placeholder?: string; valor: string[]; aoMudar: (v: string[]) => void }) {
  const [texto, setTexto] = useState(valor.join("\n"));
  useEffect(() => {
    if (paraLista(texto).join("\n") !== valor.join("\n")) setTexto(valor.join("\n"));
    // Só o valor de fora importa: subir e descer um bloco troca o que este campo mostra.
  }, [valor]);
  return (
    <Textarea
      label={rotulo}
      placeholder={placeholder}
      spellCheck={false}
      autosize
      minRows={2}
      maxRows={6}
      value={texto}
      onChange={(e) => {
        setTexto(e.currentTarget.value);
        aoMudar(paraLista(e.currentTarget.value));
      }}
    />
  );
}

function Ramo({ titulo, acao, children }: { titulo: string; acao?: ReactNode; children: ReactNode }) {
  return (
    <Box pl="sm" style={{ borderLeft: "2px solid var(--roar-borda)" }}>
      <Group justify="space-between" mb={6} gap="xs">
        <Text size="xs" fw={600} c="dimmed">{titulo}</Text>
        {acao}
      </Group>
      {children}
    </Box>
  );
}

function CorpoDoBloco({ bloco, aoMudar }: { bloco: Bloco; aoMudar: (b: Bloco) => void }) {
  if (bloco.tipo === "aprovacao") return <Text size="xs" c="dimmed">A execução espera aqui até alguém decidir. Sem decisão em 72 horas, conta como recusa.</Text>;
  if (bloco.tipo === "se") {
    return (
      <Stack gap="sm">
        <EditorDeCondicao condicao={bloco.condicao} aoMudar={(condicao) => aoMudar({ ...bloco, condicao })} />
        <Ramo titulo="Então"><PilhaDeBlocos blocos={bloco.entao} aoMudar={(entao) => aoMudar({ ...bloco, entao })} /></Ramo>
        <Ramo titulo="Senão"><PilhaDeBlocos blocos={bloco.senao ?? []} aoMudar={(senao) => aoMudar({ ...bloco, senao })} /></Ramo>
      </Stack>
    );
  }
  if (bloco.tipo === "paralelo") {
    return (
      <Stack gap="sm">
        {bloco.ramos.map((ramo, i) => (
          <Ramo
            key={i}
            titulo={`Ramo ${i + 1}`}
            acao={bloco.ramos.length > 2 && <Tooltip label="Remover ramo"><ActionIcon variant="subtle" color="gray" size="sm" aria-label={`Remover o ramo ${i + 1}`} onClick={() => aoMudar({ ...bloco, ramos: bloco.ramos.filter((_, j) => j !== i) })}><IconX size={14} /></ActionIcon></Tooltip>}
          >
            <PilhaDeBlocos blocos={ramo} aoMudar={(novo) => aoMudar({ ...bloco, ramos: bloco.ramos.map((r, j) => (j === i ? novo : r)) })} />
          </Ramo>
        ))}
        {bloco.ramos.length < 5 && <Group><Button onClick={() => aoMudar({ ...bloco, ramos: [...bloco.ramos, []] })}>Adicionar ramo</Button></Group>}
      </Stack>
    );
  }
  const p = bloco.parametros ?? {};
  const mudar = (parte: Parametros) => aoMudar({ ...bloco, parametros: { ...p, ...parte } });
  if (bloco.acao === "bloquear_ip") {
    return (
      <Stack gap="xs">
        <Group grow align="flex-start">
          <Select label="Desbloquear sozinho depois de" allowDeselect={false} value={String(p.duracao_minutos ?? 60)} data={DURACOES} onChange={(v) => mudar({ duracao_minutos: Number(v) })} />
          <Select label="Como bloquear" allowDeselect={false} value={p.metodo ?? "firewall"} data={[{ value: "firewall", label: "No firewall do ativo" }, { value: "rota", label: "Com uma rota nula" }, { value: "hosts", label: "No arquivo de hosts (só Linux)" }]} onChange={(v) => mudar({ metodo: v ?? "firewall" })} />
        </Group>
        <CampoDeLista rotulo="Nunca bloquear, um por linha" placeholder={"8.8.8.8\n200.200.0.0/16"} valor={p.protegidos ?? []} aoMudar={(protegidos) => mudar({ protegidos })} />
      </Stack>
    );
  }
  if (bloco.acao === "desativar_conta") {
    return (
      <Stack gap="xs">
        <Text size="xs" c="dimmed">Precisa de um bloco de aprovação antes. Por enquanto só em ativos Linux, e nunca em contas como root.</Text>
        <Select label="Reativar sozinha depois de" w={240} allowDeselect={false} value={String(p.duracao_minutos ?? 60)} data={DURACOES} onChange={(v) => mudar({ duracao_minutos: Number(v) })} />
        <CampoDeLista rotulo="Nunca desativar, uma conta por linha" valor={p.protegidas ?? []} aoMudar={(protegidas) => mudar({ protegidas })} />
      </Stack>
    );
  }
  if (bloco.acao === "webhook") return <TextInput label="Endereço web completo, começando por https" type="url" spellCheck={false} value={p.url ?? ""} onChange={(e) => mudar({ url: e.currentTarget.value.trim() })} />;
  if (bloco.acao === "registrar") return <TextInput label="Nota" maxLength={1000} value={p.texto ?? ""} onChange={(e) => mudar({ texto: e.currentTarget.value })} />;
  return null;
}

const corDoBloco = (b: Bloco) => (b.tipo === "aprovacao" ? "var(--mantine-color-yellow-6)" : b.tipo === "acao" ? "var(--mantine-color-rosa-4)" : "var(--mantine-color-dark-2)");

function PilhaDeBlocos({ blocos, aoMudar }: { blocos: Bloco[]; aoMudar: (b: Bloco[]) => void }) {
  const mover = (de: number, para: number) => {
    const nova = [...blocos];
    nova.splice(para, 0, nova.splice(de, 1)[0]);
    aoMudar(nova);
  };
  const itemDoMenu = (tipo: string) => <Menu.Item key={tipo} fz="sm" leftSection={ICONES_DE_BLOCO[tipo]} onClick={() => aoMudar([...blocos, NOVOS_BLOCOS[tipo]()])}>{ROTULOS_DE_BLOCO[tipo]}</Menu.Item>;
  return (
    <Stack gap={6}>
      {blocos.map((bloco, i) => {
        const chave = bloco.tipo === "acao" ? bloco.acao : bloco.tipo;
        return (
          <Box key={i} p="xs" style={{ border: "1px solid var(--roar-borda)", borderLeft: `3px solid ${corDoBloco(bloco)}`, borderRadius: 6, background: "var(--mantine-color-dark-7)" }}>
            <Group justify="space-between" mb={6} wrap="nowrap">
              <Group gap={6} wrap="nowrap">{ICONES_DE_BLOCO[chave]}<Text size="sm" fw={600}>{ROTULOS_DE_BLOCO[chave] ?? chave}</Text></Group>
              <Group gap={2} wrap="nowrap">
                <Tooltip label="Subir"><ActionIcon variant="subtle" color="gray" size="sm" disabled={i === 0} aria-label="Subir o bloco" onClick={() => mover(i, i - 1)}><IconArrowUp size={14} /></ActionIcon></Tooltip>
                <Tooltip label="Descer"><ActionIcon variant="subtle" color="gray" size="sm" disabled={i === blocos.length - 1} aria-label="Descer o bloco" onClick={() => mover(i, i + 1)}><IconArrowDown size={14} /></ActionIcon></Tooltip>
                <Tooltip label="Remover"><ActionIcon variant="subtle" color="gray" size="sm" aria-label="Remover o bloco" onClick={() => aoMudar(blocos.filter((_, j) => j !== i))}><IconTrash size={14} /></ActionIcon></Tooltip>
              </Group>
            </Group>
            <CorpoDoBloco bloco={bloco} aoMudar={(novo) => aoMudar(blocos.map((b, j) => (j === i ? novo : b)))} />
          </Box>
        );
      })}
      <Group>
        <Menu position="bottom-start" shadow="md" withinPortal>
          <Menu.Target><Button leftSection={<IconPlus size={14} />}>Adicionar bloco</Button></Menu.Target>
          <Menu.Dropdown>
            <Menu.Label>Ações</Menu.Label>
            {["bloquear_ip", "desativar_conta", "webhook", "registrar"].map(itemDoMenu)}
            <Menu.Label>Fluxo</Menu.Label>
            {["aprovacao", "se", "paralelo"].map(itemDoMenu)}
          </Menu.Dropdown>
        </Menu>
      </Group>
    </Stack>
  );
}

function Etapa({ titulo, children }: { titulo: string; children: ReactNode }) {
  return (
    <Card p="sm">
      <Text size="xs" fw={700} c="rosa.2" mb="xs">{titulo}</Text>
      {children}
    </Card>
  );
}

const Ligacao = () => <Box w={2} h={10} ml={24} style={{ background: "var(--roar-borda)" }} />;

// ------------------------------------------------------------------ simulação

interface Simulacao {
  dias: number; analisados: number; limitado: boolean; disparos: number; recusas: number; alvos: { alvo: string; total: number }[];
  exemplos: { quando: string; titulo: string | null; alvo: string | null; passos: { tipo: string; acao: string | null; recusa: string | null }[] }[];
}

function ResultadoDaSimulacao({ s }: { s: Simulacao }) {
  const vezes = s.disparos === 1 ? "1 vez" : `${numero(s.disparos)} vezes`;
  return (
    <Card p="sm">
      <Stack gap="xs">
        <Title order={3}>{s.disparos ? `Nos últimos ${s.dias} dias, isto teria disparado ${vezes}.` : `Nos últimos ${s.dias} dias, isto não teria disparado nenhuma vez.`}</Title>
        {s.limitado && <Text size="xs" c="dimmed">{`Olhei só os primeiros ${numero(s.analisados)} acontecimentos: o número real pode ser maior.`}</Text>}
        {s.recusas > 0 && <Text size="xs" c="dimmed">{`${numero(s.recusas)} bloqueios seriam recusados, por alvo protegido ou sem endereço público.`}</Text>}
        {s.alvos.length > 0 && (
          <Tabela linhas={s.alvos} chave={(a) => a.alvo} vazio="" colunas={[{ titulo: "Alvo", celula: (a) => <span className="mono">{a.alvo}</span> }, { titulo: "Vezes", alinhar: "right", largura: 70, celula: (a) => numero(a.total) }]} />
        )}
        {s.exemplos.length > 0 && (
          <Tabela
            linhas={s.exemplos}
            chave={(e) => `${e.quando}-${e.alvo}`}
            vazio=""
            colunas={[
              { titulo: "Quando", largura: 150, celula: (e) => <Data valor={e.quando} /> },
              { titulo: "O que aconteceu", celula: (e) => e.titulo ?? "-" },
              { titulo: "Alvo", celula: (e) => <span className="mono">{e.alvo ?? "-"}</span> },
              { titulo: "Faria", celula: (e) => e.passos.map((p) => (p.tipo === "aprovacao" ? "Pedir aprovação" : `${NOMES_DE_ACAO[p.acao ?? ""] ?? p.acao}${p.recusa ? ` (recusado: ${p.recusa})` : ""}`)).join(", ") || "-" },
            ]}
          />
        )}
      </Stack>
    </Card>
  );
}

// ------------------------------------------------------------------ editor

function Formulario({ abertura, aoFechar, aoSalvar }: { abertura: AberturaDoPlaybook; aoFechar: () => void; aoSalvar: () => void }) {
  const [nome, setNome] = useState(abertura.nome ?? "");
  const [intervalo, setIntervalo] = useState<number | string>(abertura.intervalo_minutos ?? 60);
  const [definicao, setDefinicao] = useState<Definicao>(abertura.definicao ?? MODELOS[0].definicao);
  const [modelo, setModelo] = useState<number | null>(abertura.definicao ? null : 0);
  const [modo, setModo] = useState<"blocos" | "codigo">("blocos");
  const [codigo, setCodigo] = useState("");
  const [validacao, setValidacao] = useState<{ ok: boolean; texto?: string } | null>(null);
  const [simulacao, setSimulacao] = useState<Simulacao | null>(null);
  const [ocupado, setOcupado] = useState(false);
  const minutos = Number(intervalo || 0);
  const se = definicao.se ?? [];
  const q = definicao.quando;

  // A regra do que pode ou não pode mora só na API: a tela pergunta enquanto a pessoa monta.
  useEffect(() => {
    let valendo = true;
    const espera = setTimeout(async () => {
      try {
        const r = modo === "codigo"
          ? await enviar("/api/automacao/de-codigo", { texto: codigo })
          : await enviar("/api/automacao/para-codigo", { nome: nome.trim() || "Sem nome", intervalo_minutos: minutos, definicao });
        const texto = r.ok ? undefined : await detalhe(r, "Confira os blocos do playbook.");
        if (valendo) setValidacao({ ok: r.ok, texto });
      } catch { /* sem conexão: quem responde é o salvar */ }
    }, 400);
    return () => { valendo = false; clearTimeout(espera); };
  }, [modo, codigo, nome, minutos, definicao]);

  const mudarDefinicao = (d: Definicao) => {
    setDefinicao(d);
    setSimulacao(null);
  };
  const mudarQuando = (quando: Quando) => mudarDefinicao({ ...definicao, quando });
  const usarModelo = (i: number) => {
    setModelo(i);
    setNome(MODELOS[i].nome);
    mudarDefinicao(MODELOS[i].definicao);
  };

  // No modo código o texto é a fonte: precisa virar blocos antes de simular ou salvar.
  const atual = async () => {
    if (modo === "blocos") return { nome: nome.trim(), intervalo_minutos: minutos, definicao };
    const r = await enviar("/api/automacao/de-codigo", { texto: codigo });
    if (!r.ok) {
      setValidacao({ ok: false, texto: await detalhe(r, "Confira o texto do playbook.") });
      return null;
    }
    const d: { nome: string; intervalo_minutos: number; definicao: Definicao } = await r.json();
    setDefinicao(d.definicao);
    setNome(d.nome);
    setIntervalo(d.intervalo_minutos);
    return d;
  };

  const trocarModo = async (novo: string) => {
    if (novo === modo) return;
    if (novo === "codigo") {
      const r = await enviar("/api/automacao/para-codigo", { nome: nome.trim() || "Sem nome", intervalo_minutos: minutos, definicao });
      if (!r.ok) {
        setValidacao({ ok: false, texto: await detalhe(r, "Complete os blocos antes de ver o código.") });
        return;
      }
      setCodigo((await r.json()).texto);
      setModo("codigo");
      return;
    }
    if (await atual()) setModo("blocos");
  };

  const simular = async () => {
    setOcupado(true);
    try {
      const a = await atual();
      if (!a) return;
      const r = await enviar("/api/automacao/simular", { definicao: a.definicao, intervalo_minutos: a.intervalo_minutos });
      if (!r.ok) {
        setSimulacao(null);
        setValidacao({ ok: false, texto: await detalhe(r, "Complete o playbook antes de simular.") });
        return;
      }
      setSimulacao(await r.json());
    } finally {
      setOcupado(false);
    }
  };

  const salvar = async () => {
    setOcupado(true);
    try {
      const a = await atual();
      if (!a) return;
      if (!a.nome) {
        setValidacao({ ok: false, texto: "Dê um nome ao playbook." });
        return;
      }
      const r = abertura.id
        ? await fetch(`/api/automacao/playbooks/${abertura.id}`, { method: "PUT", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(a) })
        : await enviar("/api/automacao/playbooks", a);
      if (r.status === 401) {
        window.location.assign("/");
        return;
      }
      if (!r.ok) {
        setValidacao({ ok: false, texto: await detalhe(r, "Confira os blocos do playbook.") });
        return;
      }
      aoSalvar();
      aoFechar();
    } finally {
      setOcupado(false);
    }
  };

  const aviso = validacao && !validacao.ok ? validacao.texto : modo === "blocos" && !nome.trim() ? "Dê um nome ao playbook." : null;

  return (
    <Stack gap="sm">
      <Group align="flex-start" grow>
        <TextInput label="Nome" maxLength={120} value={nome} disabled={modo === "codigo"} onChange={(e) => setNome(e.currentTarget.value)} data-autofocus />
        <NumberInput label="Não repetir para o mesmo alvo por (minutos)" min={0} max={10080} value={intervalo} disabled={modo === "codigo"} onChange={setIntervalo} />
      </Group>

      {!abertura.id && !abertura.rascunho && (
        <SimpleGrid cols={{ base: 2, md: 4 }} spacing="xs">
          {MODELOS.map((m, i) => (
            <Card key={m.titulo} p="xs" component="button" type="button" className="clicavel" data-selecionado={modelo === i || undefined} aria-pressed={modelo === i} onClick={() => usarModelo(i)}>
              <Text size="sm" fw={600}>{m.titulo}</Text>
              <Text size="xs" c="dimmed">{m.texto}</Text>
            </Card>
          ))}
        </SimpleGrid>
      )}

      <Group><SegmentedControl size="xs" aria-label="Como editar" value={modo} onChange={trocarModo} data={[{ value: "blocos", label: "Blocos" }, { value: "codigo", label: "Código" }]} /></Group>

      {modo === "codigo" ? (
        <Textarea label="Playbook em YAML" value={codigo} onChange={(e) => { setCodigo(e.currentTarget.value); setSimulacao(null); }} autosize minRows={16} maxRows={28} spellCheck={false} styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 12 } }} />
      ) : (
        <Stack gap={0}>
          <Etapa titulo="QUANDO">
            <Group gap="xs" align="flex-end" wrap="wrap">
              <Select
                w={290}
                label="Acontecer"
                allowDeselect={false}
                value={q.tipo}
                data={[{ value: "evento", label: "Alerta de uma regra" }, { value: "risco", label: "Risco de uma pessoa ou ativo" }, { value: "indicador", label: "Evento bateu com indicador de ameaça" }]}
                onChange={(tipo) => mudarQuando(tipo === "risco" ? { tipo, severidade: "alta" } : tipo === "indicador" ? { tipo } : { tipo: "evento", regra_id: "" })}
              />
              {q.tipo === "risco" && <Select w={170} label="Severidade a partir de" allowDeselect={false} value={q.severidade} data={SEVERIDADES_DO_GATILHO} onChange={(v) => mudarQuando({ tipo: "risco", severidade: v ?? "alta" })} />}
              {q.tipo === "evento" && <TextInput w={170} label="Número da regra" inputMode="numeric" maxLength={8} placeholder="5712" value={q.regra_id} onChange={(e) => mudarQuando({ tipo: "evento", regra_id: e.currentTarget.value.trim() })} />}
            </Group>
          </Etapa>
          <Ligacao />
          <Etapa titulo="SE">
            <Stack gap="xs">
              {se.map((c, i) => (
                <EditorDeCondicao
                  key={i}
                  condicao={c}
                  aoMudar={(nova) => mudarDefinicao({ ...definicao, se: se.map((x, j) => (j === i ? nova : x)) })}
                  aoRemover={() => mudarDefinicao({ ...definicao, se: se.filter((_, j) => j !== i) })}
                />
              ))}
              <Group><Button leftSection={<IconPlus size={14} />} disabled={se.length >= 10} onClick={() => mudarDefinicao({ ...definicao, se: [...se, SE_EXTERNO] })}>Adicionar condição</Button></Group>
            </Stack>
          </Etapa>
          <Ligacao />
          <Etapa titulo="ENTÃO">
            <PilhaDeBlocos blocos={definicao.blocos} aoMudar={(blocos) => mudarDefinicao({ ...definicao, blocos })} />
          </Etapa>
        </Stack>
      )}

      {simulacao && <ResultadoDaSimulacao s={simulacao} />}

      <Stack gap="xs" pos="sticky" bottom={0} pt="xs" style={{ background: "var(--mantine-color-body)", zIndex: 1 }}>
        {aviso
          ? <Alert color="yellow" variant="light" p="xs">{aviso}</Alert>
          : validacao?.ok && <Group gap={6} c="green.4"><IconCheck size={14} /><Text size="xs">Pronto para salvar.</Text></Group>}
        <Group justify="flex-end">
          <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
          <Button disabled={ocupado} onClick={simular}>Simular nos últimos 7 dias</Button>
          <Button variant="filled" disabled={ocupado} onClick={salvar}>Salvar playbook</Button>
        </Group>
      </Stack>
    </Stack>
  );
}

export function EditorDePlaybook({ abertura, aoFechar, aoSalvar }: { abertura: AberturaDoPlaybook | null; aoFechar: () => void; aoSalvar: () => void }) {
  return (
    // Um clique fora não pode jogar fora um playbook montado bloco a bloco.
    <Modal opened={abertura !== null} onClose={aoFechar} closeOnClickOutside={false} title={abertura?.id ? "Editar playbook" : "Novo playbook"} size={920}>
      {abertura && <Formulario abertura={abertura} aoFechar={aoFechar} aoSalvar={aoSalvar} />}
    </Modal>
  );
}
