import { ActionIcon, Anchor, Badge, Box, Drawer, Group, ScrollArea, SegmentedControl, SimpleGrid, Stack, Tabs, Text, Title, Tooltip, UnstyledButton } from "@mantine/core";
import { IconArrowLeft, IconExternalLink } from "@tabler/icons-react";
import { useState, type CSSProperties, type KeyboardEvent, type ReactNode } from "react";

import { useDados, usePode } from "../api";
import { AcoesDaLinha, Busca, Cabecalho, Carregando, Data, GavetaDeEventos, GavetaDoBruto, Numero, Painel, Severidade, Tabela, Vazio, type FiltroDeEventos } from "../componentes";
import { compacto, numero } from "../formato";

export function severidadeDoNivel(nivel: number) {
  if (nivel >= 15) return "critica";
  if (nivel >= 12) return "alta";
  if (nivel >= 7) return "media";
  return "baixa";
}

/** Rótulo e valor em duas colunas: o miolo das gavetas de detalhe. */
export function Fatos({ itens }: { itens: [string, ReactNode][] }) {
  return (
    <Box style={{ display: "grid", gridTemplateColumns: "minmax(110px, max-content) minmax(0, 1fr)", gap: "6px 16px" }}>
      {itens.map(([rotulo, valor]) => (
        <Box key={rotulo} style={{ display: "contents" }}>
          <Text size="xs" c="dimmed" lh="20px">{rotulo}</Text>
          <Text component="div" size="sm" lh="20px">{valor}</Text>
        </Box>
      ))}
    </Box>
  );
}

// ------------------------------------------------------------------ detalhe de uma regra

export const NOMES_DE_NORMAS: Record<string, string> = { pci_dss: "PCI DSS", gdpr: "GDPR", hipaa: "HIPAA", nist_800_53: "NIST 800-53", tsc: "TSC", gpg13: "GPG13" };

export interface DetalheDaRegra {
  regra: { regra_id: string; nivel: number; descricao: string | null; grupos: string[] | null; arquivo: string | null; ativa: boolean; normas: Record<string, string[]> | null };
  tecnicas: { tecnica: string; nome: string }[];
  disparos: { total: number; ultimo: string | null; ativos: number };
  recentes: { id: number; ocorrido_em: string; severidade: string; ativo: string | null; ip_origem: string | null; usuario: string | null }[];
}

export function GavetaDaRegra({ regra, dias, aoFechar, aoVerEventos, aoAbrirTecnica }: { regra: string | null; dias: string; aoFechar: () => void; aoVerEventos: (regra: string) => void; aoAbrirTecnica?: (tecnica: string) => void }) {
  const pode = usePode();
  const [bruto, setBruto] = useState<number | null>(null);
  const { dados, erro } = useDados<DetalheDaRegra>(regra === null ? null : `/api/regras/${encodeURIComponent(regra)}?dias=${dias}`);
  const pronto = dados && dados.regra.regra_id === regra ? dados : null;
  const normas = Object.entries(pronto?.regra.normas ?? {});
  return (
    <>
      <Drawer opened={regra !== null} onClose={aoFechar} title={`Regra ${regra ?? ""}`} size="lg">
        {!pronto ? <Carregando erro={erro} /> : (
          <Stack gap="md">
            <Group gap="sm" wrap="nowrap" align="flex-start" justify="space-between">
              <Text size="sm">{pronto.regra.descricao ?? "Sem descrição"}</Text>
              <Severidade valor={severidadeDoNivel(pronto.regra.nivel)} />
            </Group>
            <SimpleGrid cols={2}>
              <Numero rotulo={`Disparos em ${dias} dias`} valor={numero(pronto.disparos.total)} aoClicar={Number(pronto.disparos.total) > 0 ? () => aoVerEventos(pronto.regra.regra_id) : undefined} />
              <Numero rotulo="Ativos" valor={numero(pronto.disparos.ativos)} aoClicar={Number(pronto.disparos.ativos) > 0 ? () => aoVerEventos(pronto.regra.regra_id) : undefined} />
            </SimpleGrid>
            <Fatos itens={[
              ["Último disparo", <Data valor={pronto.disparos.ultimo} />],
              ["Situação", pronto.regra.ativa ? "Ativa" : "Inativa"],
              ["Arquivo", <span className="mono">{pronto.regra.arquivo ?? "-"}</span>],
              ...normas.map(([norma, controles]): [string, ReactNode] => [NOMES_DE_NORMAS[norma] ?? norma, <span className="mono">{controles.join(", ")}</span>]),
            ]} />
            {pronto.tecnicas.length > 0 && (
              <Stack gap={6}>
                <Title order={3}>Técnicas</Title>
                <Tabela
                  linhas={pronto.tecnicas}
                  chave={(t) => t.tecnica}
                  vazio=""
                  aoClicarLinha={aoAbrirTecnica ? (t) => aoAbrirTecnica(t.tecnica) : undefined}
                  colunas={[
                    { titulo: "Técnica", largura: 90, celula: (t) => <span className="mono">{t.tecnica}</span> },
                    { titulo: "Nome", celula: (t) => t.nome },
                  ]}
                />
              </Stack>
            )}
            {(pronto.regra.grupos ?? []).length > 0 && (
              <Stack gap={6}>
                <Title order={3}>Grupos</Title>
                <Group gap={4}>{pronto.regra.grupos?.map((g) => <Badge key={g} size="sm" radius="sm" variant="light" color="gray" tt="none" fw={500}>{g}</Badge>)}</Group>
              </Stack>
            )}
            {pronto.recentes.length > 0 && (
              <Stack gap={6}>
                <Title order={3}>Últimos eventos</Title>
                <Tabela
                  linhas={pronto.recentes}
                  chave={(e) => e.id}
                  vazio=""
                  aoClicarLinha={pode("ver_bruto") ? (e) => setBruto(e.id) : undefined}
                  colunas={[
                    { titulo: "Quando", celula: (e) => <Data valor={e.ocorrido_em} /> },
                    { titulo: "Ativo", celula: (e) => e.ativo ?? "-" },
                    { titulo: "Usuário", celula: (e) => e.usuario ?? "-" },
                    { titulo: "Origem", celula: (e) => <span className="mono">{e.ip_origem ?? "-"}</span> },
                  ]}
                />
              </Stack>
            )}
          </Stack>
        )}
      </Drawer>
      <GavetaDoBruto evento={bruto} aoFechar={() => setBruto(null)} />
    </>
  );
}

// ------------------------------------------------------------------ detalhe de uma técnica

const TATICAS_DE_DEFESA: Record<string, string> = { Model: "Conhecer", Harden: "Fortalecer", Detect: "Detectar", Isolate: "Isolar", Deceive: "Enganar", Evict: "Expulsar", Restore: "Restaurar" };

interface DetalheDaTecnica {
  tecnica: { tecnica: string; nome: string; taticas: string[]; endereco: string | null };
  match: { regra_id: string; descricao: string | null; nivel: number; disparos: number; ultimo: string | null }[];
  cobertura: { regra_id: string; descricao: string | null; nivel: number }[];
  subtecnicas: { tecnica: string; nome: string }[];
  defesas: { defesa_id: string; defesa_nome: string; tatica_defesa: string | null }[];
}

function Defesas({ defesas }: { defesas: DetalheDaTecnica["defesas"] }) {
  if (!defesas.length) return <Vazio>Sem defesas catalogadas para esta técnica.</Vazio>;
  const porTatica = new Map<string, DetalheDaTecnica["defesas"]>();
  defesas.forEach((d) => {
    const chave = d.tatica_defesa ?? "Outras";
    porTatica.set(chave, [...(porTatica.get(chave) ?? []), d]);
  });
  return (
    <Stack gap="md">
      {[...porTatica].map(([tatica, itens]) => (
        <Stack key={tatica} gap={6}>
          <Title order={3}>{TATICAS_DE_DEFESA[tatica] ?? tatica}</Title>
          <Group gap={4}>
            {itens.map((d) => <Tooltip key={d.defesa_id} label={d.defesa_id}><Badge size="sm" radius="sm" variant="light" color="gray" tt="none" fw={500}>{d.defesa_nome}</Badge></Tooltip>)}
          </Group>
        </Stack>
      ))}
    </Stack>
  );
}

function GavetaDaTecnica({ pilha, dias, nomesDasTaticas, aoAbrir, aoVoltar, aoFechar, aoVerEventos, aoVerRegra }: {
  pilha: string[]; dias: string; nomesDasTaticas: Map<string, string>; aoAbrir: (t: string) => void; aoVoltar: () => void; aoFechar: () => void; aoVerEventos: (regra: string) => void; aoVerRegra: (regra: string) => void;
}) {
  const atual = pilha[pilha.length - 1] ?? null;
  const { dados, erro } = useDados<DetalheDaTecnica>(atual === null ? null : `/api/mitre/tecnicas/${encodeURIComponent(atual)}?dias=${dias}`);
  // Ao navegar para uma subtécnica, a resposta anterior continua aqui até a nova chegar.
  const d = dados && dados.tecnica.tecnica === atual ? dados : null;
  return (
    <Drawer
      opened={atual !== null}
      onClose={aoFechar}
      size="xl"
      title={(
        <Group gap="xs" wrap="nowrap">
          {pilha.length > 1 && <ActionIcon variant="subtle" color="gray" size="sm" onClick={aoVoltar} aria-label="Voltar à técnica anterior"><IconArrowLeft size={16} /></ActionIcon>}
          <Text fw={600} size="sm"><span className="mono">{atual}</span> {d?.tecnica.nome}</Text>
        </Group>
      )}
    >
      {!d ? <Carregando erro={erro} /> : (
        <Stack gap="sm">
          <Group gap="md" justify="space-between">
            <Text size="xs" c="dimmed">{d.tecnica.taticas.map((t) => nomesDasTaticas.get(t) ?? t).join(", ")}</Text>
            {d.tecnica.endereco && <Anchor size="xs" href={d.tecnica.endereco} target="_blank" rel="noreferrer noopener"><Group gap={4} wrap="nowrap">Abrir no MITRE ATT&CK <IconExternalLink size={12} /></Group></Anchor>}
          </Group>
          <Tabs key={atual} defaultValue={d.match.length ? "disparos" : "defesas"}>
            <Tabs.List mb="sm">
              <Tabs.Tab value="disparos">Dispararam ({numero(d.match.length)})</Tabs.Tab>
              <Tabs.Tab value="defesas">Defesas D3FEND ({numero(d.defesas.length)})</Tabs.Tab>
              <Tabs.Tab value="cobertura">Ainda não dispararam ({numero(d.cobertura.length)})</Tabs.Tab>
              {d.subtecnicas.length > 0 && <Tabs.Tab value="subtecnicas">Subtécnicas ({numero(d.subtecnicas.length)})</Tabs.Tab>}
            </Tabs.List>
            <Tabs.Panel value="disparos">
              <Tabela
                linhas={d.match}
                chave={(m) => m.regra_id}
                vazio={`Nenhuma regra disparou para esta técnica em ${dias} dias.`}
                aoClicarLinha={(m) => aoVerEventos(m.regra_id)}
                colunas={[
                  { titulo: "Regra", largura: 80, celula: (m) => <span className="mono">{m.regra_id}</span> },
                  { titulo: "Severidade", largura: 90, celula: (m) => <Severidade valor={severidadeDoNivel(m.nivel)} /> },
                  { titulo: "O que detecta", celula: (m) => m.descricao ?? "-" },
                  { titulo: "Disparos", alinhar: "right", largura: 80, celula: (m) => numero(m.disparos) },
                  { titulo: "Último", largura: 130, celula: (m) => <Data valor={m.ultimo} /> },
                  { titulo: "", largura: 40, celula: (m) => <AcoesDaLinha rotulo={`Ações da regra ${m.regra_id}`} itens={[{ texto: "Ver eventos", aoClicar: () => aoVerEventos(m.regra_id) }, { texto: "Ver regra", aoClicar: () => aoVerRegra(m.regra_id) }]} /> },
                ]}
              />
            </Tabs.Panel>
            <Tabs.Panel value="defesas"><Defesas defesas={d.defesas} /></Tabs.Panel>
            <Tabs.Panel value="cobertura">
              <Tabela
                linhas={d.cobertura}
                chave={(c) => c.regra_id}
                vazio={d.match.length ? "Todas as regras desta técnica já dispararam." : "Nenhuma regra cobre esta técnica. Aqui existe um ponto cego."}
                aoClicarLinha={(c) => aoVerRegra(c.regra_id)}
                colunas={[
                  { titulo: "Regra", largura: 80, celula: (c) => <span className="mono">{c.regra_id}</span> },
                  { titulo: "Severidade", largura: 90, celula: (c) => <Severidade valor={severidadeDoNivel(c.nivel)} /> },
                  { titulo: "O que detecta", celula: (c) => c.descricao ?? "-" },
                ]}
              />
            </Tabs.Panel>
            <Tabs.Panel value="subtecnicas">
              <Tabela
                linhas={d.subtecnicas}
                chave={(s) => s.tecnica}
                vazio=""
                aoClicarLinha={(s) => aoAbrir(s.tecnica)}
                colunas={[
                  { titulo: "Subtécnica", largura: 100, celula: (s) => <span className="mono">{s.tecnica}</span> },
                  { titulo: "Nome", celula: (s) => s.nome },
                ]}
              />
            </Tabs.Panel>
          </Tabs>
        </Stack>
      )}
    </Drawer>
  );
}

// ------------------------------------------------------------------ matriz

interface Tecnica { tecnica: string; nome: string; taticas: string[]; observados: number; regras: number; defesas: number }
interface Matriz { taticas: { tatica: string; nome: string }[]; tecnicas: Tecnica[]; versao: string | null }

type Nivel = "muitos" | "varios" | "poucos" | "coberta" | "sem";

function nivelDaTecnica(t: Tecnica): Nivel {
  if (t.observados >= 50) return "muitos";
  if (t.observados >= 10) return "varios";
  if (t.observados > 0) return "poucos";
  return t.regras > 0 ? "coberta" : "sem";
}

// Rosa é a marca e aqui mede volume, não gravidade: a severidade fica no detalhe, com a cor dela.
const CORES_DA_CELULA: Record<Nivel, CSSProperties> = {
  muitos: { background: "linear-gradient(100deg, #7d1257, #c93d97 55%, #8a1560)", borderColor: "#c93d97", color: "#fff" },
  varios: { background: "rgb(214 19 138 / 38%)", borderColor: "rgb(214 19 138 / 55%)", color: "var(--mantine-color-dark-0)" },
  poucos: { background: "rgb(214 19 138 / 15%)", borderColor: "rgb(214 19 138 / 30%)", color: "var(--mantine-color-dark-0)" },
  coberta: { background: "var(--mantine-color-dark-5)", borderColor: "var(--mantine-color-dark-4)", color: "var(--mantine-color-dark-1)" },
  sem: { background: "transparent", borderColor: "var(--mantine-color-dark-4)", borderStyle: "dashed", color: "var(--mantine-color-dark-2)" },
};

const LEGENDA: [Nivel, string][] = [["muitos", "Muitos eventos"], ["varios", "Vários eventos"], ["poucos", "Poucos eventos"], ["coberta", "Tem regra, sem eventos"], ["sem", "Sem regra"]];

const LINHA_DA_DICA = { display: "flex", justifyContent: "space-between", gap: 16 };

function CelulaTecnica({ tecnica: t, coluna, linha, aoAbrir }: { tecnica: Tecnica; coluna: number; linha: number; aoAbrir: (t: string) => void }) {
  const [sobre, setSobre] = useState(false);
  const cores = CORES_DA_CELULA[nivelDaTecnica(t)];
  return (
    <Tooltip
      multiline
      w={240}
      position="right"
      events={{ hover: true, focus: true, touch: false }}
      label={(
        <>
          <Text size="xs" fw={600} mb={4}>{t.tecnica} {t.nome}</Text>
          <div style={LINHA_DA_DICA}><span>Eventos</span><span className="numero">{numero(t.observados)}</span></div>
          <div style={LINHA_DA_DICA}><span>Regras</span><span className="numero">{numero(t.regras)}</span></div>
          <div style={LINHA_DA_DICA}><span>Defesas</span><span className="numero">{numero(t.defesas)}</span></div>
        </>
      )}
    >
      <UnstyledButton
        className="clicavel"
        data-coluna={coluna}
        data-linha={linha}
        aria-label={`${t.tecnica} ${t.nome}: ${numero(t.observados)} eventos, ${numero(t.regras)} regras, ${numero(t.defesas)} defesas`}
        onClick={() => aoAbrir(t.tecnica)}
        onMouseEnter={() => setSobre(true)}
        onMouseLeave={() => setSobre(false)}
        style={{ display: "block", padding: "3px 6px", borderWidth: 1, borderStyle: "solid", borderRadius: 4, ...cores, ...(sobre ? { borderColor: "#ffc4e8" } : null) }}
      >
        <Group justify="space-between" wrap="nowrap" gap={4}>
          <span className="mono" style={{ fontSize: 11, fontWeight: 600 }}>{t.tecnica}</span>
          {t.observados > 0 && <span className="numero" style={{ fontSize: 11 }}>{compacto(Number(t.observados))}</span>}
        </Group>
        <Text fz={11} lh="14px" lineClamp={2} style={{ color: "inherit" }}>{t.nome}</Text>
      </UnstyledButton>
    </Tooltip>
  );
}

function Legenda() {
  return (
    <Group gap="md">
      {LEGENDA.map(([nivel, rotulo]) => (
        <Group key={nivel} gap={6} wrap="nowrap">
          <span style={{ display: "inline-block", width: 14, height: 10, borderWidth: 1, borderStyle: "solid", borderRadius: 2, ...CORES_DA_CELULA[nivel] }} />
          <Text size="xs" c="dimmed">{rotulo}</Text>
        </Group>
      ))}
    </Group>
  );
}

/** Setas andam pela matriz: com centenas de células, Tab sozinho não leva a lugar nenhum. */
function andarPelaMatriz(e: KeyboardEvent<HTMLDivElement>, colunas: number) {
  const alvo = e.target as HTMLElement;
  if (alvo.dataset.coluna === undefined) return;
  const coluna = Number(alvo.dataset.coluna);
  const linha = Number(alvo.dataset.linha);
  const celulas = (c: number) => e.currentTarget.querySelectorAll<HTMLElement>(`[data-coluna="${c}"]`);
  let destino: HTMLElement | undefined;
  if (e.key === "ArrowDown") destino = celulas(coluna)[linha + 1];
  else if (e.key === "ArrowUp") destino = celulas(coluna)[linha - 1];
  else if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
    const passo = e.key === "ArrowRight" ? 1 : -1;
    // Coluna vazia, com filtro ligado, fica para trás.
    for (let c = coluna + passo; c >= 0 && c < colunas && !destino; c += passo) {
      const lista = celulas(c);
      destino = lista[Math.min(linha, lista.length - 1)];
    }
  } else return;
  e.preventDefault();
  destino?.focus();
}

type Recorte = "" | "observadas" | "com_regra" | "sem_regra";
const NO_RECORTE: Record<Recorte, (t: Tecnica) => boolean> = {
  "": () => true,
  observadas: (t) => t.observados > 0,
  com_regra: (t) => t.regras > 0,
  sem_regra: (t) => t.regras === 0,
};

export function Ataques() {
  const [dias, setDias] = useState("30");
  const [busca, setBusca] = useState("");
  const [recorte, setRecorte] = useState<Recorte>("");
  const [pilha, setPilha] = useState<string[]>([]);
  const [regra, setRegra] = useState<string | null>(null);
  const [filtro, setFiltro] = useState<FiltroDeEventos | null>(null);
  const { dados, erro } = useDados<Matriz>(`/api/mitre/matriz?dias=${dias}`);

  const cabecalho = (
    <Cabecalho titulo="Ataque e defesa" ajuda="A matriz MITRE ATT&CK com o que foi observado e o que tem regra de detecção. Clique numa técnica para ver as regras, os eventos e as defesas do D3FEND.">
      <SegmentedControl size="xs" value={dias} onChange={setDias} data={[{ label: "7 dias", value: "7" }, { label: "30 dias", value: "30" }, { label: "90 dias", value: "90" }]} aria-label="Período" />
    </Cabecalho>
  );
  if (!dados) return <>{cabecalho}<Carregando erro={erro} /></>;

  const { taticas, tecnicas, versao } = dados;
  const termo = busca.trim().toLowerCase();
  const visivel = (t: Tecnica) => NO_RECORTE[recorte](t) && (!termo || t.tecnica.toLowerCase().includes(termo) || t.nome.toLowerCase().includes(termo));
  const alternar = (r: Recorte) => () => setRecorte((atual) => (atual === r ? "" : r));
  const contar = (r: Recorte) => tecnicas.filter(NO_RECORTE[r]).length;
  const verEventos = (id: string) => setFiltro({ rotulo: `Eventos da regra ${id}`, consulta: { regra: id, dias } });

  return (
    <>
      {cabecalho}
      <Stack gap="md">
        <SimpleGrid cols={{ base: 1, sm: 3 }}>
          <Numero rotulo={`Observadas em ${dias} dias`} valor={numero(contar("observadas"))} aoClicar={alternar("observadas")} selecionado={recorte === "observadas"} />
          <Numero rotulo="Com regra de detecção" valor={numero(contar("com_regra"))} detalhe={`de ${numero(tecnicas.length)} técnicas`} aoClicar={alternar("com_regra")} selecionado={recorte === "com_regra"} />
          <Numero rotulo="Sem regra" valor={numero(contar("sem_regra"))} aoClicar={alternar("sem_regra")} selecionado={recorte === "sem_regra"} />
        </SimpleGrid>

        <Painel p="sm">
          <Group justify="space-between" mb="sm" gap="sm">
            <Busca valor={busca} aoMudar={setBusca} dica="Técnica ou código" />
            <Legenda />
          </Group>
          {!tecnicas.length ? <Vazio>A matriz ainda não foi carregada.</Vazio> : (
            <ScrollArea type="auto" offsetScrollbars style={{ height: "max(420px, calc(100dvh - 330px))" }}>
              <Box role="group" aria-label="Matriz de técnicas de ataque" onKeyDown={(e: KeyboardEvent<HTMLDivElement>) => andarPelaMatriz(e, taticas.length)} style={{ display: "flex", gap: 4, width: "max-content" }}>
                {taticas.map((tatica, coluna) => {
                  const daTatica = tecnicas.filter((t) => t.taticas.includes(tatica.tatica) && visivel(t));
                  return (
                    <Stack key={tatica.tatica} gap={3} w={150}>
                      <Box pb={4} style={{ position: "sticky", top: 0, zIndex: 1, background: "var(--roar-painel)" }}>
                        <Text size="xs" fw={600} lineClamp={1} title={tatica.nome}>{tatica.nome}</Text>
                        <Text fz={11} c="dimmed" className="numero">{numero(daTatica.length)} técnicas</Text>
                      </Box>
                      {daTatica.map((t, linha) => <CelulaTecnica key={t.tecnica} tecnica={t} coluna={coluna} linha={linha} aoAbrir={(x) => setPilha([x])} />)}
                    </Stack>
                  );
                })}
              </Box>
            </ScrollArea>
          )}
        </Painel>

        {versao && <Text fz={11} c="dimmed">MITRE ATT&CK® v{versao} e MITRE D3FEND. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.</Text>}
      </Stack>

      <GavetaDaTecnica
        pilha={pilha}
        dias={dias}
        nomesDasTaticas={new Map(taticas.map((t) => [t.tatica, t.nome]))}
        aoAbrir={(t) => setPilha((p) => [...p, t])}
        aoVoltar={() => setPilha((p) => p.slice(0, -1))}
        aoFechar={() => setPilha([])}
        aoVerEventos={verEventos}
        aoVerRegra={setRegra}
      />
      <GavetaDaRegra regra={regra} dias={dias} aoFechar={() => setRegra(null)} aoVerEventos={verEventos} aoAbrirTecnica={(t) => { setRegra(null); setPilha((p) => [...p, t]); }} />
      <GavetaDeEventos filtro={filtro} aoFechar={() => setFiltro(null)} />
    </>
  );
}
