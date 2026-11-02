import { ActionIcon, Alert, Anchor, Box, Button, Drawer, Group, Popover, Select, SimpleGrid, Stack, Text, Textarea, Title } from "@mantine/core";
import { IconCheck, IconDownload, IconHelp, IconRadar } from "@tabler/icons-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";

import { detalhe, enviar, ler, useDados, usePode } from "../api";
import { AcoesDaLinha, Busca, Carregando, Data, Estado, Painel, Severidade, Tabela } from "../componentes";
import { numero } from "../formato";
import { SEVERIDADES } from "../tema";

export const ROTULO_ESTADO_ACHADO: Record<string, string> = { aberto: "Aberto", correcao_informada: "Correção informada", corrigido: "Corrigido", aceito: "Risco aceito", falso_positivo: "Falso positivo" };
const TIPO_DO_ESTADO: Record<string, string> = { aberto: "problema", correcao_informada: "pendente", corrigido: "aplicada" };

export interface Achado {
  id: number; ativo_id: number; host: string; ativo: string | null; peso: number; titulo: string; cves: string[]; cvss: number | null; severidade: string; porta: string | null; estado: string;
  primeira_vez: string; ultima_vez: string; corrigido_em: string | null; prioridade: string | null;
}
interface DetalheDoAchado extends Achado {
  solucao: string | null; evidencia: string | null;
  historico: { quando: string; de: string | null; para: string; por: string | null; varredura_id: number | null; motivo: string | null }[];
}

export function dataComAno(dia: string) {
  const [ano, mes, d] = dia.slice(0, 10).split("-");
  return `${d}/${mes}/${ano}`;
}

export function porcentoDeEpss(e: number | null | undefined) {
  if (e === null || e === undefined) return "-";
  return `${(Number(e) * 100).toLocaleString("pt-BR", { maximumFractionDigits: Number(e) < 0.01 ? 2 : 1 })}%`;
}

/** Baixa o arquivo pela sessão atual, sem expor a rota em um link. */
export async function baixar(rota: string, nome: string) {
  const r = await fetch(rota, { credentials: "same-origin" });
  if (!r.ok) return;
  const endereco = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = endereco;
  a.download = nome;
  a.click();
  URL.revokeObjectURL(endereco);
}

/** O enviar da api só faz POST; aqui também há PUT e DELETE. */
export async function chamar(rota: string, metodo: "PUT" | "DELETE", corpo?: unknown) {
  const r = await fetch(rota, { method: metodo, credentials: "same-origin", ...(corpo === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo) }) });
  if (r.status === 401) {
    window.location.assign("/");
    throw new Error("sem sessão");
  }
  return r;
}

export function Explica({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return (
    <Popover width={320} position="bottom-end" withArrow shadow="md">
      <Popover.Target><ActionIcon variant="subtle" color="gray" size="sm" aria-label={rotulo}><IconHelp size={16} /></ActionIcon></Popover.Target>
      <Popover.Dropdown><Text size="sm">{children}</Text></Popover.Dropdown>
    </Popover>
  );
}

export function Fato({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return (
    <div>
      <Text size="xs" c="dimmed">{rotulo}</Text>
      <Text size="sm" component="div">{children}</Text>
    </div>
  );
}

/** O componente comum não tem informativa, e achado sem nota não pode aparecer como Baixa. */
export function SeveridadeDoAchado({ valor }: { valor: string }) {
  if (valor === "informativa") return <Text span size="xs" fw={500} c="dimmed" style={{ whiteSpace: "nowrap" }}>○ Informativa</Text>;
  return <Severidade valor={valor} />;
}

const PRIORIDADES: Record<string, { texto: string; icone: string; cor: string; explica: string }> = {
  agora: { texto: "Agora", icone: "▲", cor: SEVERIDADES.critica.cor, explica: "Exploração confirmada no catálogo KEV da CISA." },
  alta: { texto: "Alta", icone: "◆", cor: SEVERIDADES.alta.cor, explica: "EPSS a partir de 50%, ou CVSS a partir de 9." },
  media: { texto: "Média", icone: "●", cor: SEVERIDADES.media.cor, explica: "EPSS a partir de 5%, ou CVSS a partir de 7." },
  baixa: { texto: "Baixa", icone: "○", cor: SEVERIDADES.baixa.cor, explica: "Tem nota, e está abaixo desses limites." },
  sem_dados: { texto: "Sem nota", icone: "○", cor: SEVERIDADES.baixa.cor, explica: "O registro não traz CVSS: falta de nota não é nota baixa." },
};
export const ORDEM_DE_PRIORIDADE = ["agora", "alta", "media", "baixa", "sem_dados"];
export const textoDaPrioridade = (p: string) => PRIORIDADES[p]?.texto ?? p;
export const explicaDaPrioridade = (p: string) => PRIORIDADES[p]?.explica;

export function Prioridade({ valor }: { valor: string }) {
  const p = PRIORIDADES[valor] ?? PRIORIDADES.sem_dados;
  return <Text span size="xs" fw={500} style={{ color: p.cor, whiteSpace: "nowrap" }}>{p.icone} {p.texto}</Text>;
}

// ------------------------------------------------------------------ CVE

interface DetalheDaCve {
  cve: string; publicado_em: string | null; rejeitado: boolean; titulo: string | null; descricao: string | null; produto: string | null; cvss: number | null; vetor: string | null;
  kev_desde: string | null; kev_ransomware: boolean | null; kev_prazo: string | null; epss: number | null; prioridade: string;
}

export function GavetaDaCve({ cve, aoFechar }: { cve: string | null; aoFechar: () => void }) {
  const { dados, erro } = useDados<DetalheDaCve>(cve ? `/api/cves/${encodeURIComponent(cve)}` : null);
  const c = dados?.cve === cve ? dados : null;
  return (
    <Drawer opened={cve !== null} onClose={aoFechar} title={cve ?? ""} zIndex={400}>
      {!c ? <Carregando erro={erro} /> : (
        <Stack gap="md">
          <div>
            <Title order={2}>{c.titulo ?? c.produto ?? c.cve}</Title>
            <Group gap="xs" mt={4}><Prioridade valor={c.prioridade} /><Text size="xs" c="dimmed">{explicaDaPrioridade(c.prioridade)}</Text></Group>
          </div>
          {c.rejeitado && <Alert color="red" variant="light" p="xs">O próprio programa CVE rejeitou este registro.</Alert>}
          <SimpleGrid cols={{ base: 2, sm: 3 }} spacing="sm">
            <Fato rotulo="CVSS">{c.cvss ?? "Sem nota"}</Fato>
            <Fato rotulo="EPSS">{porcentoDeEpss(c.epss)}</Fato>
            <Fato rotulo="Exploração confirmada">{c.kev_desde ? `Desde ${dataComAno(c.kev_desde)}` : "Não confirmada"}</Fato>
            <Fato rotulo="Ransomware">{c.kev_ransomware ? "Já usada" : "Sem registro"}</Fato>
            <Fato rotulo="Publicada"><Data valor={c.publicado_em} /></Fato>
            {c.kev_prazo && <Fato rotulo="Prazo da CISA para os órgãos dela">{dataComAno(c.kev_prazo)}</Fato>}
          </SimpleGrid>
          {c.produto && <Fato rotulo="Produto">{c.produto}</Fato>}
          {c.descricao && <Fato rotulo="Descrição, como publicada">{c.descricao}</Fato>}
          {c.vetor && <Fato rotulo="Vetor"><span className="mono">{c.vetor}</span></Fato>}
        </Stack>
      )}
    </Drawer>
  );
}

// ------------------------------------------------------------------ detalhe do achado

function PainelDeCorrecao({ achado, focar, aoMudar }: { achado: DetalheDoAchado; focar: boolean; aoMudar: () => void }) {
  const [motivo, setMotivo] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const [aviso, setAviso] = useState<string | null>(null);
  const [ocupado, setOcupado] = useState(false);

  const mudar = async (estado: string) => {
    setOcupado(true);
    setAviso(null);
    const r = await enviar(`/api/vuln/achados/${achado.id}/estado`, { estado, motivo });
    setOcupado(false);
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível mudar."));
      return;
    }
    setMotivo("");
    setErro(null);
    aoMudar();
  };
  const confirmar = async () => {
    setOcupado(true);
    setErro(null);
    const r = await enviar(`/api/vuln/achados/${achado.id}/confirmar`);
    setOcupado(false);
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível pedir a varredura."));
      return;
    }
    setAviso("Varredura pedida. O resultado aparece aqui quando ela terminar.");
  };

  const aberto = achado.estado === "aberto";
  const informada = achado.estado === "correcao_informada";
  return (
    <Painel titulo={aberto ? "Já corrigiu? Informe aqui" : informada ? "Falta confirmar a correção" : "O que fazer"}>
      <Stack gap="sm">
        {informada && <Text size="sm" c="dimmed">Ainda não foi provada: o risco continua contando até a varredura deixar de encontrar a falha.</Text>}
        <Textarea
          label={aberto ? "O que foi feito ou decidido" : "Motivo"}
          description={aberto ? "A próxima varredura confirma, ou reabre se ainda encontrar a falha." : undefined}
          placeholder="O que foi feito ou decidido, por quem e até quando"
          value={motivo}
          onChange={(e) => setMotivo(e.currentTarget.value)}
          maxLength={1000}
          autosize
          minRows={2}
          maxRows={6}
          error={erro}
          {...(focar && aberto ? { "data-autofocus": true } : {})}
        />
        {aviso && <Alert color="green" variant="light" p="xs">{aviso}</Alert>}
        <Group justify="flex-end" gap="xs">
          {aberto ? (
            <>
              <Button disabled={ocupado} onClick={() => mudar("aceito")}>Aceitar o risco</Button>
              <Button disabled={ocupado} onClick={() => mudar("falso_positivo")}>Falso positivo</Button>
              <Button variant="filled" leftSection={<IconCheck size={14} />} disabled={ocupado} onClick={() => mudar("correcao_informada")}>Informar correção</Button>
            </>
          ) : (
            <>
              <Button disabled={ocupado} onClick={() => mudar("aberto")} variant={informada ? "default" : "filled"}>Reabrir</Button>
              {informada && <Button variant="filled" leftSection={<IconRadar size={14} />} disabled={ocupado} onClick={confirmar}>Varrer agora para confirmar</Button>}
            </>
          )}
        </Group>
      </Stack>
    </Painel>
  );
}

export function GavetaDoAchado({ id, focar = false, aoFechar, aoMudar }: { id: number | null; focar?: boolean; aoFechar: () => void; aoMudar: () => void }) {
  const pode = usePode();
  const [cve, setCve] = useState<string | null>(null);
  const { dados, erro, recarregar } = useDados<DetalheDoAchado>(id === null ? null : `/api/vuln/achados/${id}`);
  const a = dados?.id === id ? dados : null;
  return (
    <>
      <Drawer opened={id !== null} onClose={aoFechar} title={a?.titulo ?? "Achado"} zIndex={300}>
        {!a ? <Carregando erro={erro} /> : (
          <Stack gap="md">
            <Group gap="sm">
              <SeveridadeDoAchado valor={a.severidade} />
              <Estado tipo={TIPO_DO_ESTADO[a.estado] ?? "outro"}>{ROTULO_ESTADO_ACHADO[a.estado] ?? a.estado}</Estado>
              {a.prioridade === "agora" && <Prioridade valor="agora" />}
            </Group>
            <SimpleGrid cols={{ base: 2, sm: 3 }} spacing="sm">
              <Fato rotulo="Ativo"><span className="mono">{a.ativo ?? a.host}</span></Fato>
              <Fato rotulo="Porta"><span className="mono">{a.porta ?? "-"}</span></Fato>
              <Fato rotulo="CVSS">{a.cvss === null ? "-" : Number(a.cvss).toFixed(1)}</Fato>
              <Fato rotulo="Visto pela primeira vez"><Data valor={a.primeira_vez} /></Fato>
              <Fato rotulo="Visto pela última vez"><Data valor={a.ultima_vez} /></Fato>
              {a.corrigido_em && <Fato rotulo="Corrigido em"><Data valor={a.corrigido_em} /></Fato>}
            </SimpleGrid>
            {a.cves.length > 0 && (
              <Fato rotulo="CVEs">
                <Group gap="sm">{a.cves.map((c) => <Anchor key={c} component="button" type="button" size="sm" className="mono" onClick={() => setCve(c)}>{c}</Anchor>)}</Group>
              </Fato>
            )}
            {pode("gerir_vulnerabilidades") && a.estado !== "corrigido" && <PainelDeCorrecao key={`${a.id}-${a.estado}`} achado={a} focar={focar} aoMudar={() => { recarregar(); aoMudar(); }} />}
            {a.solucao && <Fato rotulo="Como corrigir"><span style={{ whiteSpace: "pre-wrap" }}>{a.solucao}</span></Fato>}
            {a.evidencia && (
              <Fato rotulo="Evidência">
                <Box component="pre" className="mono" m={0} p="sm" style={{ background: "var(--mantine-color-dark-8)", border: "1px solid var(--roar-borda)", borderRadius: 6, whiteSpace: "pre-wrap" }}>{a.evidencia}</Box>
              </Fato>
            )}
            <div>
              <Title order={3} mb={4}>Histórico</Title>
              <Tabela
                linhas={a.historico}
                chave={(h) => `${h.quando}-${h.para}`}
                vazio="Sem mudanças ainda."
                colunas={[
                  { titulo: "Quando", largura: 150, celula: (h) => <Data valor={h.quando} /> },
                  { titulo: "Mudança", celula: (h) => `${h.de ? `${ROTULO_ESTADO_ACHADO[h.de] ?? h.de} para ` : ""}${ROTULO_ESTADO_ACHADO[h.para] ?? h.para}` },
                  { titulo: "Por", celula: (h) => h.por ?? (h.varredura_id ? `Varredura ${h.varredura_id}` : "-") },
                  { titulo: "Motivo", celula: (h) => h.motivo ?? "-" },
                ]}
              />
            </div>
          </Stack>
        )}
      </Drawer>
      <GavetaDaCve cve={cve} aoFechar={() => setCve(null)} />
    </>
  );
}

// ------------------------------------------------------------------ listas de achados

export function TabelaDeAchados({ achados, vazio, aoAbrir }: { achados: Achado[]; vazio: string; aoAbrir: (id: number, focar?: boolean) => void }) {
  const pode = usePode();
  return (
    <Tabela
      linhas={achados}
      chave={(a) => a.id}
      vazio={vazio}
      aoClicarLinha={(a) => aoAbrir(a.id)}
      colunas={[
        { titulo: "Severidade", largura: 100, celula: (a) => <SeveridadeDoAchado valor={a.severidade} /> },
        { titulo: "Achado", celula: (a) => a.titulo },
        { titulo: "Ativo", celula: (a) => <><span className="mono">{a.ativo ?? a.host}</span>{a.porta && <Text size="xs" c="dimmed" className="mono">Porta {a.porta}</Text>}</> },
        { titulo: "CVE", celula: (a) => <span className="mono" style={{ whiteSpace: "nowrap" }}>{a.cves[0] ?? "-"}{a.cves.length > 1 ? ` +${a.cves.length - 1}` : ""}</span> },
        { titulo: "CVSS", alinhar: "right", largura: 60, celula: (a) => (a.cvss === null ? "-" : Number(a.cvss).toFixed(1)) },
        { titulo: "Exploração", largura: 90, celula: (a) => (a.prioridade === "agora" ? <Prioridade valor="agora" /> : "-") },
        { titulo: "Situação", celula: (a) => <Estado tipo={TIPO_DO_ESTADO[a.estado] ?? "outro"}>{ROTULO_ESTADO_ACHADO[a.estado] ?? a.estado}</Estado> },
        { titulo: "Visto em", largura: 150, celula: (a) => <Data valor={a.primeira_vez} /> },
        { titulo: "", largura: 40, celula: (a) => (
          <AcoesDaLinha rotulo="Ações do achado" itens={[
            ...(pode("gerir_vulnerabilidades") && a.estado === "aberto" ? [{ texto: "Informar correção", aoClicar: () => aoAbrir(a.id, true) }] : []),
            ...(pode("gerir_vulnerabilidades") && a.estado === "correcao_informada" ? [{ texto: "Confirmar a correção", aoClicar: () => aoAbrir(a.id) }] : []),
            { texto: "Ver detalhes", aoClicar: () => aoAbrir(a.id) },
          ]} />
        ) },
      ]}
    />
  );
}

const PAGINAS_NO_MAXIMO = 50;

/** A rota não filtra por data nem por prioridade: para abrir exatamente o que um número conta, lê tudo e filtra aqui. */
export function useAchadosCompletos(consulta: string | null, versao = 0) {
  const [achados, setAchados] = useState<Achado[] | null>(null);
  const [cortado, setCortado] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => {
    if (consulta === null) return;
    let valendo = true;
    setAchados(null);
    setErro(null);
    (async () => {
      const todos: Achado[] = [];
      let tem = true;
      for (let pagina = 0; tem && pagina < PAGINAS_NO_MAXIMO && valendo; pagina += 1) {
        const d = await ler<{ achados: Achado[]; tem_mais: boolean }>(`/api/vuln/achados?${consulta}&deslocamento=${todos.length}`);
        todos.push(...d.achados);
        tem = d.tem_mais;
      }
      if (valendo) {
        setAchados(todos);
        setCortado(tem);
      }
    })().catch((e: Error) => { if (valendo) setErro(e.message); });
    return () => { valendo = false; };
  }, [consulta, versao]);
  return { achados, cortado, erro };
}

export interface PedidoDeAchados { titulo: string; consulta: string; filtro: (a: Achado) => boolean }

export function GavetaDeAchados({ pedido, aoFechar }: { pedido: PedidoDeAchados | null; aoFechar: () => void }) {
  const [aberto, setAberto] = useState<{ id: number; focar: boolean } | null>(null);
  const [versao, setVersao] = useState(0);
  const { achados, cortado, erro } = useAchadosCompletos(pedido?.consulta ?? null, versao);
  const linhas = achados && pedido ? achados.filter(pedido.filtro) : null;
  return (
    <>
      <Drawer opened={pedido !== null} onClose={aoFechar} title={pedido ? `${pedido.titulo}${linhas ? ` (${numero(linhas.length)})` : ""}` : ""} size="70%">
        {!linhas ? <Carregando erro={erro} /> : (
          <Stack gap="xs">
            <TabelaDeAchados achados={linhas} vazio="Nenhum achado." aoAbrir={(id, focar = false) => setAberto({ id, focar })} />
            {cortado && <Text size="xs" c="dimmed">Mostrando só o que coube na leitura: pode haver mais.</Text>}
          </Stack>
        )}
      </Drawer>
      <GavetaDoAchado id={aberto?.id ?? null} focar={aberto?.focar} aoFechar={() => setAberto(null)} aoMudar={() => setVersao((v) => v + 1)} />
    </>
  );
}

// ------------------------------------------------------------------ aba de achados

const OPCOES_DE_SEVERIDADE = [{ value: "todas", label: "Todas as severidades" }, { value: "critica", label: "Crítica" }, { value: "alta", label: "Alta" }, { value: "media", label: "Média" }, { value: "baixa", label: "Baixa" }, { value: "informativa", label: "Informativa" }];
const OPCOES_DE_SITUACAO = [{ value: "aberto", label: "Abertos" }, { value: "correcao_informada", label: "Correção informada" }, { value: "corrigido", label: "Corrigidos" }, { value: "aceito", label: "Riscos aceitos" }, { value: "falso_positivo", label: "Falsos positivos" }, { value: "todas", label: "Todas as situações" }];

export interface FiltroDeAchados { severidade: string; estado: string }

export function Achados({ filtro, aoMudarFiltro }: { filtro: FiltroDeAchados; aoMudarFiltro: (f: FiltroDeAchados) => void }) {
  const [busca, setBusca] = useState("");
  const [achados, setAchados] = useState<Achado[] | null>(null);
  const [temMais, setTemMais] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [versao, setVersao] = useState(0);
  const [aberto, setAberto] = useState<{ id: number; focar: boolean } | null>(null);
  const consulta = new URLSearchParams({ busca, severidade: filtro.severidade === "todas" ? "" : filtro.severidade, estado: filtro.estado === "todas" ? "" : filtro.estado }).toString();

  useEffect(() => {
    let valendo = true;
    ler<{ achados: Achado[]; tem_mais: boolean }>(`/api/vuln/achados?${consulta}`)
      .then((d) => { if (valendo) { setAchados(d.achados); setTemMais(d.tem_mais); setErro(null); } })
      .catch((e: Error) => { if (valendo) setErro(e.message); });
    return () => { valendo = false; };
  }, [consulta, versao]);

  const mais = async () => {
    const d = await ler<{ achados: Achado[]; tem_mais: boolean }>(`/api/vuln/achados?${consulta}&deslocamento=${achados?.length ?? 0}`);
    setAchados((a) => [...(a ?? []), ...d.achados]);
    setTemMais(d.tem_mais);
  };
  const abrir = useCallback((id: number, focar = false) => setAberto({ id, focar }), []);

  return (
    <Painel
      titulo="Achados"
      acao={(
        <Group gap="xs" wrap="wrap" justify="flex-end">
          <Busca valor={busca} aoMudar={setBusca} dica="Título, ativo, endereço ou CVE" />
          <Select w={170} aria-label="Severidade" allowDeselect={false} value={filtro.severidade} onChange={(v) => aoMudarFiltro({ ...filtro, severidade: v ?? "todas" })} data={OPCOES_DE_SEVERIDADE} />
          <Select w={170} aria-label="Situação" allowDeselect={false} value={filtro.estado} onChange={(v) => aoMudarFiltro({ ...filtro, estado: v ?? "aberto" })} data={OPCOES_DE_SITUACAO} />
          <Button leftSection={<IconDownload size={14} />} onClick={() => baixar(`/api/vuln/achados/exportar?${consulta}`, "vulnerabilidades-roar.csv")}>Exportar CSV</Button>
        </Group>
      )}
    >
      {!achados ? <Carregando erro={erro} /> : (
        <Stack gap="sm">
          <TabelaDeAchados achados={achados} vazio="Nenhum achado neste filtro." aoAbrir={abrir} />
          {temMais && <Group justify="center"><Button onClick={mais}>Carregar mais</Button></Group>}
        </Stack>
      )}
      <GavetaDoAchado id={aberto?.id ?? null} focar={aberto?.focar} aoFechar={() => setAberto(null)} aoMudar={() => setVersao((v) => v + 1)} />
    </Painel>
  );
}
