import { ActionIcon, Box, Button, Card, Drawer, Group, Modal, NumberInput, Select, SimpleGrid, Skeleton, Stack, Switch, Tabs, Text, Textarea, TextInput, Title, Tooltip, UnstyledButton } from "@mantine/core";
import { AreaChart, DonutChart } from "@mantine/charts";
import { IconArrowDownRight, IconArrowLeft, IconFileTypePdf, IconArrowRight, IconArrowUpRight, IconPencil, IconPlus, IconRefresh, IconTrash } from "@tabler/icons-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { detalhe, enviar, pedir, useDados, usePode } from "../api";
import { Cabecalho, Carregando, Data, Estado, Painel as Quadro, Tabela, Vazio } from "../componentes";
import { nomeDoPais, numero } from "../formato";
import { MapaOrigens } from "./MapaOrigens";
import { baixar } from "./Relatorios";

interface Bloco { titulo: string; tipo: string; texto: string; minutos: number; campo: string | null; tamanho: number; largura: number }
interface Modelo { nome: string; descricao: string; blocos: Bloco[] }
interface Opcoes { tipos: Record<string, string>; janelas: Record<string, string>; modelos: Record<string, Modelo> }
interface PainelSalvo { id: number; nome: string; blocos: Bloco[]; alterado_em: string }
interface Resultado {
  total: number; anterior?: number; pontos?: { quando: string; total: number; por?: Record<string, number> }[]; campo?: string | null; chave?: string;
  linhas?: Record<string, unknown>[]; outros?: number; colunas?: { campo: string; chave: string }[];
}
export interface Busca {
  id?: number; nome: string; texto: string; janela_minutos: number; a_cada_minutos: number | null; condicao: string; limite: number; ativa: boolean;
  ultima_em?: string | null; ultimo_total?: number | null; ultimo_erro?: string | null; proxima_em?: string | null; disparos_7_dias?: number;
}

const BLOCO_NOVO: Bloco = { titulo: "", tipo: "numero", texto: "", minutos: 10080, campo: null, tamanho: 8, largura: 3 };
const INTERVALOS = [{ value: "", label: "Não roda sozinha" }, { value: "5", label: "A cada 5 minutos" }, { value: "15", label: "A cada 15 minutos" },
  { value: "60", label: "A cada hora" }, { value: "360", label: "A cada 6 horas" }, { value: "1440", label: "Uma vez por dia" }];
const CONDICOES: Record<string, string> = { qualquer: "Achar alguma coisa", mais_de: "Achar mais que o limite", nenhum: "Não achar nada" };
const LARGURAS = [{ value: "3", label: "1/4" }, { value: "4", label: "1/3" }, { value: "6", label: "1/2" }, { value: "8", label: "2/3" }, { value: "12", label: "Inteira" }];
// Altura do conteúdo de cada tipo, sempre a mesma: carregando ou não, o bloco não muda de tamanho e a página não pula.
const ALTURA: Record<string, number> = { numero: 76, tabela: 290, barras: 290, top: 290, mapa: 290 };
// Os nomes que a pessoa usa na busca, no lugar dos nomes técnicos do log.
const NOMES_DE_CAMPO: Record<string, string> = {
  timestamp: "quando", "agent.name": "ativo", "rule.description": "descrição", "rule.level": "nível", "rule.id": "regra", "data.srcip": "origem", "data.dstip": "destino",
  "data.srcuser": "usuário", "data.dstuser": "usuário de destino", "GeoLocation.country_name": "país", "decoder.name": "tipo", location: "fonte",
  "syscheck.path": "arquivo", "syscheck.event": "mudança", "rule.groups": "grupo", "rule.mitre.technique": "técnica",
};
const nomeDoCampo = (campo: string) => NOMES_DE_CAMPO[campo] ?? campo;
/** O valor como a pessoa lê: país em português, o resto como veio. */
const valorDe = (campo: string | null | undefined, valor: unknown) => (valor == null ? "-" : campo === "GeoLocation.country_name" ? nomeDoPais(String(valor)) : String(valor));
const ALTURA_PADRAO = 250;
const CORES = ["#ff5fbd", "#a78bfa", "#38bdf8", "#fbbf24", "#34d399", "#f87171", "#94a3b8"];
const POR_CAMPO = new Set(["rosca", "barras", "top"]);
const opcoesDe = (r: Record<string, string>) => Object.entries(r).map(([value, label]) => ({ value, label }));
// A primeira versão guardava 1 (metade) e 2 (inteira).
const colunas = (b: Bloco) => (b.largura <= 2 ? b.largura * 6 : b.largura);
const alturaDe = (tipo: string) => ALTURA[tipo] ?? ALTURA_PADRAO;

function usarOpcoes() {
  return useDados<Opcoes>("/api/buscas/opcoes").dados;
}

// ------------------------------------------------------------------ desenho dos blocos

function Indicador({ r, janela }: { r: Resultado; janela: string }) {
  const antes = r.anterior ?? 0;
  const variacao = antes ? Math.round(((r.total - antes) / antes) * 100) : null;
  return (
    <Stack gap={2}>
      <Text fz={34} fw={700} lh={1.1} className="numero">{numero(r.total)}</Text>
      <Group gap={4} wrap="nowrap">
        {variacao !== null && variacao !== 0 && (variacao > 0 ? <IconArrowUpRight size={14} color="var(--mantine-color-pink-4)" /> : <IconArrowDownRight size={14} color="var(--mantine-color-teal-4)" />)}
        <Text size="xs" c="dimmed" truncate>
          {variacao === null ? (r.total ? "Nada no período anterior" : `Nada em ${janela}`) : variacao === 0 ? "Igual ao período anterior" : `${variacao > 0 ? "+" : ""}${variacao}% sobre o período anterior`}
        </Text>
      </Group>
    </Stack>
  );
}

function rotuloDoTempo(quando: string, minutos: number) {
  const d = new Date(quando);
  return minutos <= 1440 ? d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" });
}

function Serie({ r, minutos, altura }: { r: Resultado; minutos: number; altura: number }) {
  const pontos = r.pontos ?? [];
  // As linhas são os valores que mais aparecem no período inteiro, para a legenda não mudar de uma barra para outra.
  const nomes = useMemo(() => {
    if (!r.campo) return ["total"];
    const soma = new Map<string, number>();
    pontos.forEach((p) => Object.entries(p.por ?? {}).forEach(([k, v]) => soma.set(k, (soma.get(k) ?? 0) + v)));
    return [...soma.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k]) => k);
  }, [pontos, r.campo]);
  if (!pontos.length) return <Vazio>Nada no período.</Vazio>;
  const dados = pontos.map((p) => ({ quando: rotuloDoTempo(p.quando, minutos), ...(r.campo ? Object.fromEntries(nomes.map((n) => [n, p.por?.[n] ?? 0])) : { total: p.total }) }));
  return (
    <AreaChart h={altura} data={dados} dataKey="quando" type={r.campo ? "stacked" : "default"} curveType="monotone" withDots={false} withLegend={Boolean(r.campo)}
      legendProps={{ verticalAlign: "bottom", height: 30 }} gridAxis="y" tickLine="none" fillOpacity={0.35} valueFormatter={(v) => numero(v)}
      series={nomes.map((n, i) => ({ name: n, label: !r.campo ? "Logs" : r.campo === "rule.level" ? `nível ${n}` : valorDe(r.campo, n), color: CORES[i % CORES.length] }))} />
  );
}

function Rosca({ r, altura }: { r: Resultado; altura: number }) {
  const linhas = r.linhas ?? [];
  if (!linhas.length) return <Vazio>Nada no período.</Vazio>;
  const fatias = [...linhas.map((l, i) => ({ name: valorDe(r.campo, l[r.chave ?? ""]), value: Number(l.total), color: CORES[i % (CORES.length - 1)] })),
    ...(r.outros ? [{ name: "Outros", value: r.outros, color: CORES[CORES.length - 1] }] : [])];
  return (
    <Group gap="md" wrap="nowrap" h={altura} align="center">
      <DonutChart data={fatias} size={Math.min(170, altura - 20)} thickness={22} withTooltip tooltipDataSource="segment" valueFormatter={(v) => numero(v)}
        chartLabel={numero(fatias.reduce((t, f) => t + f.value, 0))} strokeWidth={0} />
      <Stack gap={6} style={{ flex: 1, minWidth: 0 }}>
        {fatias.map((f) => (
          <Group key={f.name} gap={8} wrap="nowrap">
            <Box w={10} h={10} style={{ borderRadius: 3, background: f.color, flex: "0 0 auto" }} />
            <Text size="xs" truncate style={{ flex: 1, minWidth: 0 }} title={f.name}>{f.name}</Text>
            <Text size="xs" c="dimmed" className="numero">{numero(f.value)}</Text>
          </Group>
        ))}
      </Stack>
    </Group>
  );
}

function Barras({ r, porcentagem }: { r: Resultado; porcentagem?: boolean }) {
  const linhas = r.linhas ?? [];
  if (!linhas.length) return <Vazio>Nada no período.</Vazio>;
  const maior = Math.max(1, ...linhas.map((l) => Number(l.total)));
  return (
    <Stack gap={7}>
      {linhas.map((l, i) => {
        const nome = valorDe(r.campo, l[r.chave ?? ""]);
        return (
          <Stack key={i} gap={3}>
            <Group justify="space-between" gap="sm" wrap="nowrap">
              <Text size="xs" truncate title={nome} style={{ minWidth: 0 }}>{nome}</Text>
              <Text size="xs" c="dimmed" className="numero" style={{ flex: "0 0 auto" }}>
                {numero(Number(l.total))}{porcentagem && r.total ? ` · ${Math.round((100 * Number(l.total)) / r.total)}%` : ""}
              </Text>
            </Group>
            <span className="barra-trilho" style={{ width: "100%" }}><span className="barra-cheia" style={{ width: `${(100 * Number(l.total)) / maior}%` }} /></span>
          </Stack>
        );
      })}
    </Stack>
  );
}

function TabelaDoBloco({ r }: { r: Resultado }) {
  return (
    <Tabela
      linhas={(r.linhas ?? []).map((l, i) => ({ ...l, _i: i }))}
      chave={(l) => Number(l._i)}
      vazio="Nada no período."
      colunas={(r.colunas ?? []).map((c) => ({
        titulo: nomeDoCampo(c.campo),
        celula: (l: Record<string, unknown>) => {
          const v = l[c.chave];
          if (c.campo === "timestamp" && typeof v === "string") return <Data valor={v} />;
          return <Text size="xs" className="mono" style={{ overflowWrap: "anywhere" }}>{valorDe(c.campo, v)}</Text>;
        },
      }))}
    />
  );
}

function Conteudo({ bloco, r, opcoes }: { bloco: Bloco; r: Resultado; opcoes: Opcoes }) {
  const altura = alturaDe(bloco.tipo);
  if (bloco.tipo === "numero") return <Indicador r={r} janela={opcoes.janelas[String(bloco.minutos)] ?? ""} />;
  if (bloco.tipo === "serie") return <Serie r={r} minutos={bloco.minutos} altura={altura} />;
  if (bloco.tipo === "rosca") return <Rosca r={r} altura={altura} />;
  if (bloco.tipo === "barras") return <Barras r={r} />;
  if (bloco.tipo === "top") return <Barras r={r} porcentagem />;
  if (bloco.tipo === "mapa") {
    const paises = (r.linhas ?? []).map((l) => ({ pais: String(l[r.chave ?? ""] ?? ""), total: Number(l.total), graves: 0 }));
    return paises.length ? <MapaOrigens paises={paises} cidades={[]} semCidade={0} aoEscolher={() => {}} altura={altura - 70} /> : <Vazio>Nada no período.</Vazio>;
  }
  return <TabelaDoBloco r={r} />;
}

/** Busca o resultado e guarda o último: ao atualizar, o desenho antigo fica até o novo chegar, sem piscar. */
function useResultado(bloco: Bloco, versao: number) {
  const [r, setR] = useState<Resultado | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const chave = JSON.stringify([bloco.texto, bloco.tipo, bloco.minutos, bloco.campo, bloco.tamanho]);
  useEffect(() => { setR(null); setErro(null); }, [chave]);
  useEffect(() => {
    let valendo = true;
    enviar("/api/buscas/bloco", { texto: bloco.texto, tipo: bloco.tipo, minutos: bloco.minutos, campo: bloco.campo, tamanho: bloco.tamanho })
      .then(async (resposta) => { if (!valendo) return; if (resposta.ok) { setR(await resposta.json()); setErro(null); } else setErro(await detalhe(resposta)); })
      .catch(() => valendo && setErro("Não foi possível consultar os logs."));
    return () => { valendo = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chave, versao]);
  return { r, erro };
}

function CartaoDoBloco({ bloco, opcoes, versao, acoes }: { bloco: Bloco; opcoes: Opcoes; versao: number; acoes?: React.ReactNode }) {
  const { r, erro } = useResultado(bloco, versao);
  const altura = alturaDe(bloco.tipo);
  return (
    <Card withBorder radius="md" p="md" h="100%">
      <Group justify="space-between" gap="xs" wrap="nowrap" mb="sm" h={24}>
        <Text size="sm" fw={600} truncate title={bloco.titulo}>{bloco.titulo}</Text>
        {acoes ?? <Text size="xs" c="dimmed" style={{ flex: "0 0 auto" }}>{opcoes.janelas[String(bloco.minutos)]}</Text>}
      </Group>
      <Box h={altura} style={{ overflow: ["tabela", "barras", "top"].includes(bloco.tipo) ? "auto" : "hidden" }}>
        {erro ? <Text size="sm" c="red">{erro}</Text>
          : !r ? (bloco.tipo === "numero" ? <Stack gap={8}><Skeleton h={34} w="60%" /><Skeleton h={12} w="80%" /></Stack> : <Skeleton h={altura} radius="md" />)
            : <Conteudo bloco={bloco} r={r} opcoes={opcoes} />}
      </Box>
    </Card>
  );
}

/** Grade de 12 colunas: no celular, tudo vira uma coluna. */
function Grade({ blocos, desenhar, fixa }: { blocos: Bloco[]; desenhar: (b: Bloco, i: number) => React.ReactNode; fixa?: boolean }) {
  return (
    <div className={fixa ? "grade-de-painel previa" : "grade-de-painel"}>
      {blocos.map((b, i) => <div key={i} style={{ gridColumn: `span ${colunas(b)}` }}>{desenhar(b, i)}</div>)}
    </div>
  );
}

// ------------------------------------------------------------------ editar

function EditorDeBloco({ bloco, opcoes, aoFechar, aoSalvar }: { bloco: Bloco | null; opcoes: Opcoes; aoFechar: () => void; aoSalvar: (b: Bloco) => void }) {
  const [b, setB] = useState<Bloco>(BLOCO_NOVO);
  const [previa, setPrevia] = useState<Bloco>(BLOCO_NOVO);
  useEffect(() => { if (bloco) { setB(bloco); setPrevia(bloco); } }, [bloco]);
  const mudar = (m: Partial<Bloco>) => setB((atual) => ({ ...atual, ...m }));
  const pedeCampo = POR_CAMPO.has(b.tipo);
  return (
    <Modal opened={bloco !== null} onClose={aoFechar} title={bloco?.titulo ? "Editar bloco" : "Novo bloco"} size="xl">
      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
        <Stack gap="sm">
          <TextInput label="Título" placeholder="Falhas de login" value={b.titulo} onChange={(e) => mudar({ titulo: e.currentTarget.value })} data-autofocus />
          <Textarea label="Busca" description="A mesma linguagem da tela Logs brutos. Vazia, conta todos os logs." autosize minRows={2} classNames={{ input: "mono" }}
            placeholder="grupo=authentication_failed" value={b.texto} onChange={(e) => mudar({ texto: e.currentTarget.value })} />
          <SimpleGrid cols={2} spacing="sm">
            <Select label="Mostrar como" allowDeselect={false} value={b.tipo} onChange={(v) => mudar({ tipo: v ?? "numero" })} data={opcoesDe(opcoes.tipos)} />
            <Select label="Período" allowDeselect={false} value={String(b.minutos)} onChange={(v) => mudar({ minutos: Number(v) })} data={opcoesDe(opcoes.janelas)} />
          </SimpleGrid>
          {(pedeCampo || b.tipo === "serie") && (
            <TextInput label={b.tipo === "serie" ? "Dividir as linhas por (opcional)" : "Agrupar pelo campo"} placeholder="usuario, origem, ativo, pais, nivel" classNames={{ input: "mono" }}
              value={b.campo ?? ""} onChange={(e) => mudar({ campo: e.currentTarget.value || null })} />
          )}
          <SimpleGrid cols={2} spacing="sm">
            <Select label="Largura" allowDeselect={false} value={String(colunas(b))} onChange={(v) => mudar({ largura: Number(v) })} data={LARGURAS} />
            {(pedeCampo || b.tipo === "tabela") && <NumberInput label="Quantos itens" min={1} max={50} value={b.tamanho} onChange={(v) => mudar({ tamanho: Number(v) || 8 })} />}
          </SimpleGrid>
          <Group justify="space-between" mt="xs">
            <Button variant="subtle" leftSection={<IconRefresh size={14} />} onClick={() => setPrevia({ ...b })}>Ver a prévia</Button>
            <Button variant="filled" disabled={!b.titulo.trim()} onClick={() => aoSalvar(b)}>Pronto</Button>
          </Group>
        </Stack>
        <Stack gap={6}>
          <Text size="xs" c="dimmed">Prévia</Text>
          <CartaoDoBloco bloco={{ ...previa, titulo: b.titulo || "Sem título" }} opcoes={opcoes} versao={0} />
        </Stack>
      </SimpleGrid>
    </Modal>
  );
}

function PainelAberto({ painel, opcoes, aoMudar }: { painel: PainelSalvo; opcoes: Opcoes; aoMudar: () => void }) {
  const pode = usePode();
  const [editando, setEditando] = useState(false);
  const [blocos, setBlocos] = useState<Bloco[]>(painel.blocos);
  const [bloco, setBloco] = useState<{ indice: number | null; bloco: Bloco } | null>(null);
  const [versao, setVersao] = useState(0);
  const [erro, setErro] = useState<string | null>(null);
  const [apagando, setApagando] = useState(false);
  const [gerando, setGerando] = useState(false);
  useEffect(() => { setBlocos(painel.blocos); setErro(null); setEditando(false); }, [painel]);
  const pdf = async () => {
    setGerando(true); setErro(null);
    await baixar(`/api/paineis/${painel.id}/pdf`, "painel.pdf").catch((e: Error) => setErro(e.message));
    setGerando(false);
  };
  const mover = (i: number, d: number) => setBlocos((bs) => { const n = [...bs]; [n[i], n[i + d]] = [n[i + d], n[i]]; return n; });
  const salvar = async () => {
    const r = await pedir(`/api/paineis/${painel.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ nome: painel.nome, blocos }) });
    if (r.ok) { setEditando(false); aoMudar(); } else setErro(await detalhe(r));
  };
  const apagar = async () => { await pedir(`/api/paineis/${painel.id}`, { method: "DELETE" }); setApagando(false); aoMudar(); };
  const novoBloco = () => { setEditando(true); setBloco({ indice: null, bloco: { ...BLOCO_NOVO } }); };
  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text size="xs" c="dimmed">Alterado em <Data valor={painel.alterado_em} /></Text>
        <Group gap="xs">
          {!editando && <Button variant="subtle" leftSection={<IconRefresh size={14} />} onClick={() => setVersao((v) => v + 1)}>Atualizar</Button>}
          {!editando && blocos.length > 0 && <Button leftSection={<IconFileTypePdf size={14} />} loading={gerando} onClick={pdf}>Baixar PDF</Button>}
          {pode("ver_bruto") && !editando && <Button leftSection={<IconPencil size={14} />} onClick={() => setEditando(true)}>Editar</Button>}
          {editando && (
            <>
              <Button leftSection={<IconPlus size={14} />} onClick={novoBloco}>Novo bloco</Button>
              <Button variant="subtle" color="red" onClick={() => setApagando(true)}>Apagar o painel</Button>
              <Button variant="subtle" onClick={() => { setBlocos(painel.blocos); setEditando(false); }}>Cancelar</Button>
              <Button variant="filled" onClick={salvar}>Salvar</Button>
            </>
          )}
        </Group>
      </Group>
      {erro && <Text size="sm" c="red">{erro}</Text>}
      {!blocos.length ? (
        <Card withBorder p="xl">
          <Stack align="center" gap="sm">
            <Text size="sm" c="dimmed" ta="center" maw={460}>Este painel ainda está vazio. Cada bloco é uma busca nos logs, mostrada como indicador, gráfico, mapa ou lista.</Text>
            {pode("ver_bruto") && <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={novoBloco}>Adicionar o primeiro bloco</Button>}
          </Stack>
        </Card>
      ) : (
        <Grade blocos={blocos} desenhar={(b, i) => (
          <CartaoDoBloco bloco={b} opcoes={opcoes} versao={versao} acoes={editando ? (
            <Group gap={0} wrap="nowrap">
              <ActionIcon variant="subtle" color="gray" size="sm" aria-label="Para trás" disabled={i === 0} onClick={() => mover(i, -1)}><IconArrowLeft size={14} /></ActionIcon>
              <ActionIcon variant="subtle" color="gray" size="sm" aria-label="Para a frente" disabled={i === blocos.length - 1} onClick={() => mover(i, 1)}><IconArrowRight size={14} /></ActionIcon>
              <ActionIcon variant="subtle" color="gray" size="sm" aria-label="Editar o bloco" onClick={() => setBloco({ indice: i, bloco: b })}><IconPencil size={14} /></ActionIcon>
              <ActionIcon variant="subtle" color="gray" size="sm" aria-label="Tirar o bloco" onClick={() => setBlocos((bs) => bs.filter((_, j) => j !== i))}><IconTrash size={14} /></ActionIcon>
            </Group>
          ) : undefined} />
        )} />
      )}
      <EditorDeBloco bloco={bloco?.bloco ?? null} opcoes={opcoes} aoFechar={() => setBloco(null)}
        aoSalvar={(novo) => { setBlocos((bs) => (bloco?.indice == null ? [...bs, novo] : bs.map((x, j) => (j === bloco.indice ? novo : x)))); setBloco(null); }} />
      <Modal opened={apagando} onClose={() => setApagando(false)} title="Apagar o painel?">
        <Stack gap="sm">
          <Text size="sm">O painel {painel.nome} e os blocos dele saem. As buscas salvas continuam.</Text>
          <Group justify="flex-end"><Button onClick={() => setApagando(false)}>Cancelar</Button><Button color="red" variant="filled" onClick={apagar}>Apagar</Button></Group>
        </Stack>
      </Modal>
    </Stack>
  );
}

// ------------------------------------------------------------------ galeria de modelos

// A prévia desenha o painel de verdade nesta largura e reduz até caber: fica igual ao que a pessoa vai ver.
const LARGURA_DA_PREVIA = 1280;

/** O painel do modelo com os dados da organização, reduzido. Não recebe clique: é uma foto que se mexe. */
function PreviaAoVivo({ blocos, opcoes, alturaMaxima }: { blocos: Bloco[]; opcoes: Opcoes; alturaMaxima?: number }) {
  const fora = useRef<HTMLDivElement>(null);
  const dentro = useRef<HTMLDivElement>(null);
  const [medidas, setMedidas] = useState({ escala: 0.25, altura: 0 });
  useEffect(() => {
    const medir = () => {
      if (!fora.current || !dentro.current) return;
      const escala = fora.current.clientWidth / LARGURA_DA_PREVIA;
      setMedidas({ escala, altura: dentro.current.scrollHeight * escala });
    };
    medir();
    const observador = new ResizeObserver(medir);
    if (fora.current) observador.observe(fora.current);
    if (dentro.current) observador.observe(dentro.current);
    return () => observador.disconnect();
  }, []);
  return (
    <div ref={fora} className="previa-ao-vivo" style={{ height: alturaMaxima ? Math.min(medidas.altura, alturaMaxima) : medidas.altura }} aria-hidden>
      <div ref={dentro} style={{ width: LARGURA_DA_PREVIA, transform: `scale(${medidas.escala})`, transformOrigin: "top left" }}>
        <Grade fixa blocos={blocos} desenhar={(b) => <CartaoDoBloco bloco={b} opcoes={opcoes} versao={0} />} />
      </div>
    </div>
  );
}

function Galeria({ aberta, opcoes, aoFechar, aoCriar }: { aberta: boolean; opcoes: Opcoes; aoFechar: () => void; aoCriar: (modelo: string, nome: string) => Promise<string | null> }) {
  const primeiro = Object.keys(opcoes.modelos)[0] ?? "";
  const [escolhido, setEscolhido] = useState(primeiro);
  const [nome, setNome] = useState(opcoes.modelos[primeiro]?.nome ?? "");
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => { if (aberta) { setEscolhido(primeiro); setNome(opcoes.modelos[primeiro]?.nome ?? ""); setErro(null); } }, [aberta, primeiro, opcoes]);
  const escolher = (chave: string) => { setEscolhido(chave); setNome(opcoes.modelos[chave]?.nome ?? ""); setErro(null); };
  const criar = async () => setErro(await aoCriar(escolhido, nome.trim()));
  const itens: [string, Modelo][] = [...Object.entries(opcoes.modelos), ["", { nome: "Painel vazio", descricao: "Comece do zero e monte os blocos um a um.", blocos: [] }]];
  const modelo = opcoes.modelos[escolhido];
  return (
    <Modal opened={aberta} onClose={aoFechar} title="Novo painel" size="95%">
      <div className="galeria">
        <Stack gap="xs" className="galeria-lista">
          <Text size="sm" c="dimmed" mb={4}>Escolha um modelo. A prévia ao lado já usa os dados desta organização.</Text>
          {itens.map(([chave, m]) => (
            <UnstyledButton key={chave || "vazio"} onClick={() => escolher(chave)} aria-pressed={escolhido === chave}>
              <Card withBorder radius="md" p="sm" className="cartao-de-modelo" data-escolhido={escolhido === chave || undefined}>
                <Text size="sm" fw={600}>{m.nome}</Text>
                <Text size="xs" c="dimmed">{m.descricao}</Text>
              </Card>
            </UnstyledButton>
          ))}
        </Stack>
        <Stack gap="sm" style={{ minWidth: 0 }}>
          <Group align="flex-end" gap="sm">
            <TextInput label="Nome do painel" style={{ flex: 1 }} value={nome} onChange={(e) => setNome(e.currentTarget.value)} />
            <Button variant="filled" disabled={!nome.trim()} onClick={criar}>Criar o painel</Button>
          </Group>
          {erro && <Text size="sm" c="red">{erro}</Text>}
          <Card withBorder radius="md" p="sm">
            {modelo ? <PreviaAoVivo key={escolhido} blocos={modelo.blocos} opcoes={opcoes} alturaMaxima={620} />
              : <Box h={240} className="miniatura-vazia"><Text size="sm" c="dimmed" ta="center" pt={100}>Você monta os blocos depois de criar.</Text></Box>}
          </Card>
        </Stack>
      </div>
    </Modal>
  );
}

function AbaDePaineis({ opcoes }: { opcoes: Opcoes }) {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<{ paineis: PainelSalvo[] }>("/api/paineis");
  const [escolhido, setEscolhido] = useState<number | null>(null);
  const [galeria, setGaleria] = useState(false);
  if (!dados) return <Carregando erro={erro} />;
  if (!pode("ver_bruto")) return <Vazio>Os painéis mostram o que está nos logs, e seu perfil não pode ver logs brutos.</Vazio>;
  const painel = dados.paineis.find((p) => p.id === escolhido) ?? dados.paineis[0];
  const criar = async (modelo: string, nome: string) => {
    const r = await enviar("/api/paineis", { nome, blocos: opcoes.modelos[modelo]?.blocos ?? [] });
    if (!r.ok) return detalhe(r);
    const { id } = await r.json();
    setGaleria(false); setEscolhido(id); recarregar();
    return null;
  };
  return (
    <Stack gap="md">
      <Group gap="sm">
        {dados.paineis.length > 0 && <Select w={280} allowDeselect={false} value={painel ? String(painel.id) : null} onChange={(v) => setEscolhido(Number(v))}
          data={dados.paineis.map((p) => ({ value: String(p.id), label: p.nome }))} aria-label="Painel" />}
        <Button leftSection={<IconPlus size={14} />} onClick={() => setGaleria(true)}>Novo painel</Button>
      </Group>
      {painel ? <PainelAberto painel={painel} opcoes={opcoes} aoMudar={recarregar} /> : (
        <Card withBorder p="xl">
          <Stack align="center" gap="sm">
            <Text size="sm" c="dimmed" ta="center" maw={480}>Um painel junta os indicadores e gráficos que você acompanha todo dia. Comece por um modelo pronto.</Text>
            <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setGaleria(true)}>Escolher um modelo</Button>
          </Stack>
        </Card>
      )}
      <Galeria aberta={galeria} opcoes={opcoes} aoFechar={() => setGaleria(false)} aoCriar={criar} />
    </Stack>
  );
}

// ------------------------------------------------------------------ buscas salvas

export function ModalDeBusca({ busca, aoFechar, aoSalvar }: { busca: Busca | null; aoFechar: () => void; aoSalvar: () => void }) {
  const opcoes = usarOpcoes();
  const [b, setB] = useState<Busca | null>(busca);
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => { setB(busca); setErro(null); }, [busca]);
  if (!b || !opcoes) return null;
  const mudar = (m: Partial<Busca>) => setB((atual) => (atual ? { ...atual, ...m } : atual));
  const salvar = async () => {
    const corpo = { nome: b.nome, texto: b.texto, janela_minutos: b.janela_minutos, a_cada_minutos: b.a_cada_minutos, condicao: b.condicao, limite: b.limite, ativa: b.ativa };
    const r = b.id ? await pedir(`/api/buscas/${b.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo) })
      : await enviar("/api/buscas", corpo);
    if (r.ok) aoSalvar(); else setErro(await detalhe(r));
  };
  return (
    <Modal opened={busca !== null} onClose={aoFechar} title={b.id ? "Editar busca" : "Salvar busca"} size="lg">
      <Stack gap="sm">
        <TextInput label="Nome" placeholder="Login de administrador fora do horário" value={b.nome} onChange={(e) => mudar({ nome: e.currentTarget.value })} data-autofocus />
        <Textarea label="Busca" autosize minRows={2} classNames={{ input: "mono" }} value={b.texto} onChange={(e) => mudar({ texto: e.currentTarget.value })} />
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
          <Select label="Olhar os últimos" allowDeselect={false} value={String(b.janela_minutos)} onChange={(v) => mudar({ janela_minutos: Number(v) })} data={opcoesDe(opcoes.janelas)} />
          <Select label="Rodar sozinha" allowDeselect={false} value={b.a_cada_minutos ? String(b.a_cada_minutos) : ""} onChange={(v) => mudar({ a_cada_minutos: v ? Number(v) : null })} data={INTERVALOS} />
        </SimpleGrid>
        {b.a_cada_minutos && (
          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
            <Select label="Avisar no sino quando" allowDeselect={false} value={b.condicao} onChange={(v) => mudar({ condicao: v ?? "qualquer" })} data={opcoesDe(CONDICOES)} />
            {b.condicao === "mais_de" && <NumberInput label="Limite" min={0} value={b.limite} onChange={(v) => mudar({ limite: Number(v) || 0 })} />}
          </SimpleGrid>
        )}
        {b.a_cada_minutos && <Text size="xs" c="dimmed">Para a janela, escolha pelo menos o intervalo: assim nenhum log fica entre uma rodada e outra.</Text>}
        {b.id && <Switch label="Ligada" checked={b.ativa} onChange={(e) => mudar({ ativa: e.currentTarget.checked })} />}
        {erro && <Text size="sm" c="red">{erro}</Text>}
        <Group justify="flex-end"><Button variant="filled" disabled={!b.nome.trim()} onClick={salvar}>Salvar</Button></Group>
      </Stack>
    </Modal>
  );
}

function descreverAgenda(b: Busca) {
  if (!b.a_cada_minutos) return "Só guardada";
  const intervalo = INTERVALOS.find((i) => i.value === String(b.a_cada_minutos))?.label ?? `A cada ${b.a_cada_minutos} minutos`;
  const quando = b.condicao === "mais_de" ? `passar de ${numero(b.limite)}` : b.condicao === "nenhum" ? "não achar nada" : "achar alguma coisa";
  return `${intervalo}, avisa se ${quando}`;
}

function AbaDeBuscas() {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<{ buscas: Busca[] }>("/api/buscas");
  const [editando, setEditando] = useState<Busca | null>(null);
  const [historico, setHistorico] = useState<Busca | null>(null);
  const { dados: execucoes } = useDados<{ execucoes: { em: string; total: number | null; disparou: boolean; erro: string | null }[] }>(historico?.id ? `/api/buscas/${historico.id}/execucoes` : null);
  const apagar = useCallback(async (b: Busca) => { await pedir(`/api/buscas/${b.id}`, { method: "DELETE" }); recarregar(); }, [recarregar]);
  if (!dados) return <Carregando erro={erro} />;
  return (
    <Quadro titulo="Buscas salvas" acao={pode("gerir_regras") && <Button leftSection={<IconPlus size={14} />} onClick={() => setEditando({ nome: "", texto: "", janela_minutos: 60, a_cada_minutos: null, condicao: "qualquer", limite: 0, ativa: true })}>Nova busca</Button>}>
      <Text size="sm" c="dimmed" mb="sm">Guarde as buscas que você repete. Agendada, a busca roda sozinha e avisa no sino quando acha o que procura. Também dá para salvar direto da tela Logs brutos.</Text>
      <Tabela
        linhas={dados.buscas}
        chave={(b) => b.id ?? 0}
        vazio="Nenhuma busca salva ainda."
        aoClicarLinha={(b) => setHistorico(b)}
        colunas={[
          { titulo: "Busca", celula: (b) => <><Text size="sm" fw={500}>{b.nome}</Text><Text size="xs" c="dimmed" className="mono" lineClamp={1}>{b.texto || "(todos os logs)"}</Text></> },
          { titulo: "Agenda", celula: (b) => (!b.ativa ? <Estado tipo="outro">Desligada</Estado> : <Text size="sm" c="dimmed">{descreverAgenda(b)}</Text>) },
          { titulo: "Última vez", celula: (b) => (b.ultimo_erro ? <Tooltip label={b.ultimo_erro}><span><Estado tipo="problema">Falhou</Estado></span></Tooltip>
            : b.ultima_em ? <><Text size="sm" className="numero">{numero(b.ultimo_total ?? 0)} logs</Text><Data valor={b.ultima_em} /></> : "-") },
          { titulo: "Avisos em 7 dias", alinhar: "right", largura: 130, celula: (b) => numero(b.disparos_7_dias ?? 0) },
          ...(pode("gerir_regras") ? [{ titulo: "", largura: 80, celula: (b: Busca) => (
            <Group gap={2} wrap="nowrap">
              <ActionIcon variant="subtle" color="gray" aria-label={`Editar ${b.nome}`} onClick={(e) => { e.stopPropagation(); setEditando(b); }}><IconPencil size={14} /></ActionIcon>
              <ActionIcon variant="subtle" color="gray" aria-label={`Apagar ${b.nome}`} onClick={(e) => { e.stopPropagation(); apagar(b); }}><IconTrash size={14} /></ActionIcon>
            </Group>
          ) }] : []),
        ]}
      />
      <ModalDeBusca busca={editando} aoFechar={() => setEditando(null)} aoSalvar={() => { setEditando(null); recarregar(); }} />
      <Drawer opened={historico !== null} onClose={() => setHistorico(null)} title={historico?.nome ?? ""} size="md">
        {historico && (
          <Stack gap="sm">
            <Text size="sm" className="mono" style={{ overflowWrap: "anywhere" }}>{historico.texto || "(todos os logs)"}</Text>
            <Text size="sm" c="dimmed">{descreverAgenda(historico)}{historico.proxima_em ? `. Próxima rodada: ` : ""}{historico.proxima_em && <Data valor={historico.proxima_em} />}</Text>
            <Title order={2}>Últimas rodadas</Title>
            {!execucoes ? <Carregando /> : (
              <Tabela
                linhas={execucoes.execucoes}
                chave={(e) => e.em}
                vazio={historico.a_cada_minutos ? "Ainda não rodou. A primeira rodada é em até um minuto." : "Esta busca não roda sozinha."}
                colunas={[
                  { titulo: "Quando", celula: (e) => <Data valor={e.em} /> },
                  { titulo: "Logs", alinhar: "right", celula: (e) => (e.total === null ? "-" : numero(e.total)) },
                  { titulo: "", celula: (e) => (e.erro ? <Estado tipo="problema">Falhou</Estado> : e.disparou ? <Estado tipo="pendente">Avisou</Estado> : null) },
                ]}
              />
            )}
          </Stack>
        )}
      </Drawer>
    </Quadro>
  );
}

export function Paineis() {
  const opcoes = usarOpcoes();
  const [aba, setAba] = useState<string | null>("paineis");
  return (
    <>
      <Cabecalho titulo="Painéis e buscas" ajuda="Monte painéis com os números e gráficos que você acompanha, e guarde buscas que rodam sozinhas e avisam no sino." />
      {!opcoes ? <Carregando /> : (
        <Tabs value={aba} onChange={setAba}>
          <Tabs.List mb="md">
            <Tabs.Tab value="paineis">Painéis</Tabs.Tab>
            <Tabs.Tab value="buscas">Buscas salvas</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="paineis"><AbaDePaineis opcoes={opcoes} /></Tabs.Panel>
          <Tabs.Panel value="buscas"><AbaDeBuscas /></Tabs.Panel>
        </Tabs>
      )}
    </>
  );
}
