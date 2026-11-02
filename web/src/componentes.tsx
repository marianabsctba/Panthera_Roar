import { BarChart } from "@mantine/charts";
import { ActionIcon, Badge, Box, Card, Center, CopyButton, Drawer, Group, Loader, Menu, Popover, ScrollArea, Stack, Table, Text, TextInput, Title, Tooltip } from "@mantine/core";
import { IconCheck, IconCopy, IconDots, IconHelp, IconSearch } from "@tabler/icons-react";
import { useEffect, useId, useState, type KeyboardEvent, type ReactNode } from "react";

import { useDados, useEu, usePode } from "./api";
import { BotaoDaCesta } from "./cesta";
import { nomeDaCidade, nomeDoPais, numero, quando } from "./formato";
import { SEVERIDADES } from "./tema";

/** Título, ajuda sob demanda e, à direita, no máximo uma ação principal. */
export function Cabecalho({ titulo, ajuda, children }: { titulo: string; ajuda: string; children?: ReactNode }) {
  return (
    <Group justify="space-between" mb="md" wrap="wrap" gap="sm">
      <Group gap={6}>
        <Title order={1}>{titulo}</Title>
        <Popover width={320} position="bottom-start" withArrow shadow="md">
          <Popover.Target>
            <ActionIcon variant="subtle" color="gray" size="sm" aria-label={`O que é ${titulo}`}><IconHelp size={16} /></ActionIcon>
          </Popover.Target>
          <Popover.Dropdown><Text size="sm">{ajuda}</Text></Popover.Dropdown>
        </Popover>
      </Group>
      <Group gap="xs">{children}</Group>
    </Group>
  );
}

export function Painel({ titulo, acao, children, p }: { titulo?: string; acao?: ReactNode; children: ReactNode; p?: string | number }) {
  return (
    <Card p={p ?? "md"}>
      {(titulo || acao) && (
        <Group justify="space-between" mb="sm" wrap="nowrap">
          {titulo && <Title order={2}>{titulo}</Title>}
          {acao}
        </Group>
      )}
      {children}
    </Card>
  );
}

export function Numero({ rotulo, valor, detalhe, destaque, aoClicar, selecionado }: { rotulo: string; valor: ReactNode; detalhe?: string; destaque?: string; aoClicar?: () => void; selecionado?: boolean }) {
  return (
    <Card p="sm" className={aoClicar ? "clicavel" : undefined} data-selecionado={selecionado || undefined} {...(aoClicar ? { component: "button" as const, type: "button" as const, onClick: aoClicar, "aria-pressed": selecionado } : {})}>
      <Text size="xs" c="dimmed">{rotulo}</Text>
      <Text fz={24} fw={600} lh="32px" className="numero" style={destaque ? { color: destaque } : undefined}>{valor}</Text>
      {detalhe && <Text size="xs" c="dimmed">{detalhe}</Text>}
    </Card>
  );
}

const ICONES = { critica: "▲", alta: "◆", media: "●", baixa: "○" } as const;

/** Severidade nunca é só cor: leva também forma e texto. */
export function Severidade({ valor }: { valor: string }) {
  const s = SEVERIDADES[valor as keyof typeof SEVERIDADES] ?? SEVERIDADES.baixa;
  const icone = ICONES[valor as keyof typeof ICONES] ?? ICONES.baixa;
  return <Text span size="xs" fw={500} style={{ color: s.cor, whiteSpace: "nowrap" }}>{icone} {s.texto}</Text>;
}

const CORES_DE_ESTADO: Record<string, string> = { ativo: "green", ativa: "green", aplicada: "green", pronto: "green", pendente: "yellow", recusado: "red", recusada: "red", problema: "red" };

export function Estado({ tipo, children }: { tipo: string; children: ReactNode }) {
  return <Badge variant="light" size="sm" radius="sm" color={CORES_DE_ESTADO[tipo] ?? "gray"} tt="none" fw={500}>{children}</Badge>;
}

/** Data e hora nunca quebram em duas linhas. */
export function Data({ valor }: { valor: string | null | undefined }) {
  const eu = useEu();
  return <Text span size="sm" c="dimmed" className="numero" style={{ whiteSpace: "nowrap" }}>{quando(valor, eu.fuso)}</Text>;
}

export function Vazio({ children }: { children: ReactNode }) {
  return <Center py="xl"><Text size="sm" c="dimmed">{children}</Text></Center>;
}

export function Carregando({ erro }: { erro?: string | null }) {
  if (erro) return <Vazio>{erro}</Vazio>;
  return <Center py="xl"><Loader size="sm" color="gray" /></Center>;
}

/** Busca compacta e de largura fixa: aplica sozinha, um instante depois de parar de digitar. */
export function Busca({ valor, aoMudar, dica }: { valor: string; aoMudar: (v: string) => void; dica: string }) {
  const [texto, setTexto] = useState(valor);
  useEffect(() => {
    const t = setTimeout(() => { if (texto !== valor) aoMudar(texto); }, 300);
    return () => clearTimeout(t);
  }, [texto, valor, aoMudar]);
  return <TextInput w={280} leftSection={<IconSearch size={14} />} placeholder={dica} aria-label={dica} value={texto} onChange={(e) => setTexto(e.currentTarget.value)} type="search" />;
}

export interface Coluna<T> {
  titulo: string;
  celula: (linha: T) => ReactNode;
  alinhar?: "right";
  largura?: number | string;
}

export function Tabela<T>({ colunas, linhas, chave, vazio, aoClicarLinha }: { colunas: Coluna<T>[]; linhas: T[]; chave: (linha: T) => string | number; vazio: string; aoClicarLinha?: (linha: T) => void }) {
  if (!linhas.length) return <Vazio>{vazio}</Vazio>;
  return (
    <ScrollArea type="auto">
      <Table miw={560}>
        <Table.Thead>
          <Table.Tr>{colunas.map((c, i) => <Table.Th key={i} ta={c.alinhar} w={c.largura}>{c.titulo}</Table.Th>)}</Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {linhas.map((l) => (
            <Table.Tr
              key={chave(l)}
              className={aoClicarLinha ? "linha-clicavel" : undefined}
              {...(aoClicarLinha ? { tabIndex: 0, onClick: () => aoClicarLinha(l), onKeyDown: (e: KeyboardEvent) => { if (e.key === "Enter") aoClicarLinha(l); } } : {})}
            >{colunas.map((c, i) => <Table.Td key={i} ta={c.alinhar} className={c.alinhar ? "numero" : undefined}>{c.celula(l)}</Table.Td>)}</Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </ScrollArea>
  );
}

/** As ações de cada linha ficam num menu só, para a tabela não virar uma parede de botões. */
export function AcoesDaLinha({ rotulo, itens }: { rotulo: string; itens: { texto: string; aoClicar: () => void; perigo?: boolean; icone?: ReactNode }[] }) {
  if (!itens.length) return null;
  return (
    // O clique no menu não pode abrir também o que a linha abre.
    <Box onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
    <Menu position="bottom-end" shadow="md" withinPortal>
      <Menu.Target>
        <ActionIcon variant="subtle" color="gray" size="sm" aria-label={rotulo}><IconDots size={16} /></ActionIcon>
      </Menu.Target>
      <Menu.Dropdown>
        {itens.map((i) => <Menu.Item key={i.texto} fz="sm" leftSection={i.icone} color={i.perigo ? "red" : undefined} onClick={i.aoClicar}>{i.texto}</Menu.Item>)}
      </Menu.Dropdown>
    </Menu>
    </Box>
  );
}

export function BlocoDeComando({ texto }: { texto: string }) {
  return (
    <Box pos="relative">
      <Box component="pre" className="mono" m={0} p="sm" pr={44} style={{ background: "var(--mantine-color-dark-8)", border: "1px solid var(--roar-borda)", borderRadius: 6, whiteSpace: "pre-wrap" }}>{texto}</Box>
      <CopyButton value={texto}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? "Copiado" : "Copiar"}>
            <ActionIcon pos="absolute" top={8} right={8} size="sm" variant="default" onClick={copy} aria-label="Copiar o comando">{copied ? <IconCheck size={14} /> : <IconCopy size={14} />}</ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
    </Box>
  );
}

export function GavetaDoBruto({ evento, aoFechar }: { evento: number | null; aoFechar: () => void }) {
  const eu = useEu();
  const { dados, erro } = useDados<{ bruto: { rule?: { description?: string } } | null; origem_id: string; ocorrido_em: string }>(evento === null ? null : `/api/eventos/${evento}/bruto`);
  return (
    <Drawer opened={evento !== null} onClose={aoFechar} title="Alerta como chegou">
      {dados ? (
        <Stack gap="sm">
          <Group justify="flex-end"><BotaoDaCesta fonte="alertas" id={dados.origem_id} resumo={`${quando(dados.ocorrido_em, eu.fuso)} · ${dados.bruto?.rule?.description ?? "Alerta"}`} /></Group>
          <Box component="pre" className="mono" m={0} style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(dados.bruto, null, 2)}</Box>
        </Stack>
      ) : <Carregando erro={erro} />}
    </Drawer>
  );
}

interface EventoDaLista { id: number; ocorrido_em: string; severidade: string; regra_descricao: string | null; regra_id: string; ativo: string | null; usuario: string | null; ip_origem: string | null; pais: string | null; cidade: string | null; regiao: string | null; operadora: string | null }

export interface FiltroDeEventos { rotulo: string; consulta: Record<string, string> }

/** Todo número do panorama abre aqui os eventos que ele conta. */
export function GavetaDeEventos({ filtro, aoFechar }: { filtro: FiltroDeEventos | null; aoFechar: () => void }) {
  const pode = usePode();
  const [bruto, setBruto] = useState<number | null>(null);
  const consulta = filtro ? new URLSearchParams(filtro.consulta) : null;
  const { dados, erro } = useDados<{ eventos: EventoDaLista[]; ha_mais: boolean }>(consulta ? `/api/eventos?${consulta}` : null);
  return (
    <>
      <Drawer opened={filtro !== null} onClose={aoFechar} title={filtro?.rotulo ?? ""} size="60%">
        {!dados ? <Carregando erro={erro} /> : (
          <Stack gap="xs">
            <Tabela
              linhas={dados.eventos}
              chave={(e) => e.id}
              vazio="Nenhum evento no período."
              aoClicarLinha={pode("ver_bruto") ? (e) => setBruto(e.id) : undefined}
              colunas={[
                { titulo: "Quando", celula: (e) => <Data valor={e.ocorrido_em} /> },
                { titulo: "Severidade", celula: (e) => <Severidade valor={e.severidade} /> },
                { titulo: "Evento", celula: (e) => e.regra_descricao ?? e.regra_id },
                { titulo: "Ativo", celula: (e) => e.ativo ?? "-" },
                { titulo: "Origem", celula: (e) => <><span className="mono">{e.ip_origem ?? "-"}</span>{e.cidade && <Text size="xs" c="dimmed">{nomeDaCidade({ cidade: e.cidade, regiao: e.regiao, pais: e.pais })}</Text>}{!e.cidade && e.pais && <Text size="xs" c="dimmed">{nomeDoPais(e.pais)}</Text>}{e.operadora && <Text size="xs" c="dimmed">{e.operadora}</Text>}</> },
                { titulo: "", largura: 40, celula: (e) => <AcoesDaLinha rotulo="Ações do evento" itens={pode("ver_bruto") ? [{ texto: "Ver como chegou", aoClicar: () => setBruto(e.id) }] : []} /> },
              ]}
            />
            {dados.ha_mais && <Text size="xs" c="dimmed">Mostrando os mais recentes.</Text>}
          </Stack>
        )}
      </Drawer>
      <GavetaDoBruto evento={bruto} aoFechar={() => setBruto(null)} />
    </>
  );
}

export type Metal = readonly [string, string, string, string];
export const METAL_ROSA: Metal = ["#7d1257", "#ffc4e8", "#ff5fbd", "#8a1560"];
/** Cada severidade é um metal da própria cor: sombra nas bordas e brilho perto do centro. */
export const METAIS_DE_SEVERIDADE: Record<keyof typeof SEVERIDADES, Metal> = {
  critica: ["#7d1f1a", "#ffb3ae", "#ff5a52", "#8f2620"],
  alta: ["#804514", "#ffd9b0", "#ff9f43", "#8f4f18"],
  media: ["#806515", "#fff0bd", "#ffd24d", "#8f7218"],
  baixa: ["#27527d", "#d2e8fc", "#6db3f2", "#2d5d8f"],
};
export const ORDEM_DE_SEVERIDADE = ["critica", "alta", "media", "baixa"] as const;

export function AmostraDeMetal({ cores, rotulo }: { cores: Metal; rotulo: string }) {
  return (
    <Group gap={6} wrap="nowrap">
      <span className="amostra-metal" style={{ background: `linear-gradient(90deg, ${cores.join(", ")})` }} />
      <Text size="xs" c="dimmed">{rotulo}</Text>
    </Group>
  );
}

export interface SerieMetalica { nome: string; rotulo: string; metal: Metal }

/** O gráfico de barras da console: fino, metálico e clicável na coluna inteira. */
export function BarrasMetalicas({ dados, chave, series, altura = 200, empilhado, aoClicar, formatar = numero }: {
  dados: Record<string, unknown>[]; chave: string; series: SerieMetalica[]; altura?: number; empilhado?: boolean; aoClicar?: (rotulo: string) => void; formatar?: (v: number) => string;
}) {
  const id = useId().replace(/:/g, "");
  return (
    <BarChart
      h={altura}
      data={dados}
      dataKey={chave}
      type={empilhado ? "stacked" : "default"}
      gridAxis="x"
      strokeDasharray="0"
      gridColor="dark.5"
      tickLine="none"
      textColor="dark.2"
      xAxisProps={{ interval: "equidistantPreserveStart", minTickGap: 24 }}
      series={series.map((s) => ({ name: s.nome, label: s.rotulo, color: s.metal[2] }))}
      barProps={(s) => ({ isAnimationActive: false, maxBarSize: 7, radius: 1, fill: `url(#${id}-${s.name})` })}
      tooltipProps={{
        cursor: { fill: "rgb(255 255 255 / 4%)" },
        content: (p) => {
          if (!p.active || !p.payload?.length) return null;
          return (
            <div className="dica-grafico">
              <Text size="xs" fw={600} mb={4}>{String(p.label)}</Text>
              {series.map((s) => (
                <Group key={s.nome} justify="space-between" gap="lg" wrap="nowrap">
                  <AmostraDeMetal cores={s.metal} rotulo={s.rotulo} />
                  <Text size="xs" className="numero">{formatar(Number(p.payload?.find((i) => i.dataKey === s.nome)?.value ?? 0))}</Text>
                </Group>
              ))}
            </div>
          );
        },
      }}
      // O clique vale para a coluna inteira: a barra fina sozinha seria um alvo difícil.
      barChartProps={aoClicar ? { style: { cursor: "pointer" }, onClick: (estado: { activeLabel?: string | number }) => { if (estado?.activeLabel !== undefined) aoClicar(String(estado.activeLabel)); } } : undefined}
    >
      <defs>
        {series.map((s) => (
          <linearGradient key={s.nome} id={`${id}-${s.nome}`} x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor={s.metal[0]} />
            <stop offset="38%" stopColor={s.metal[1]} />
            <stop offset="62%" stopColor={s.metal[2]} />
            <stop offset="100%" stopColor={s.metal[3]} />
          </linearGradient>
        ))}
      </defs>
    </BarChart>
  );
}

/** Lista com barra fina metálica: lê melhor que um gráfico quando os rótulos são longos. */
export function Ranking({ itens, vazio, duasColunas, aoClicar, rotuloDoValor }: { itens: { rotulo: string; valor: number; chave?: string }[]; vazio: string; duasColunas?: boolean; aoClicar?: (chave: string, rotulo: string) => void; rotuloDoValor?: (v: number) => string }) {
  if (!itens.length) return <Vazio>{vazio}</Vazio>;
  const maior = Math.max(...itens.map((i) => i.valor));
  return (
    <div className={duasColunas ? "ranking-duplo" : undefined}>
      {itens.map((i) => (
        <button type="button" className="barra-linha" key={i.rotulo} onClick={() => aoClicar?.(i.chave ?? i.rotulo, i.rotulo)}>
          <span className="barra-rotulo" title={i.rotulo}>{i.rotulo}</span>
          <span className="barra-valor numero">{rotuloDoValor ? rotuloDoValor(i.valor) : numero(i.valor)}</span>
          <span className="barra-trilho"><span className="barra-cheia" style={{ width: `${Math.max(2, (100 * i.valor) / maior)}%` }} /></span>
        </button>
      ))}
    </div>
  );
}

