import { ActionIcon, Anchor, Box, Button, CopyButton, Drawer, Group, Pill, Select, SimpleGrid, Stack, Text, Tooltip } from "@mantine/core";
import { IconCheck, IconCopy } from "@tabler/icons-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { ler, useDados, useEu, usePode } from "../api";
import { BotaoDaCesta } from "../cesta";
import { AcoesDaLinha, Busca, Cabecalho, Carregando, Data, Painel, Severidade, Tabela, Vazio } from "../componentes";
import { diaCurto, nomeDaCidade, nomeDoPais, numero, quando, SINAIS } from "../formato";
import { SEVERIDADES } from "../tema";

// ------------------------------------------------------------------ peças usadas também por Fila e Logs

export function BlocoDeJson({ valor }: { valor: unknown }) {
  const texto = JSON.stringify(valor, null, 2);
  return (
    <Box pos="relative">
      <Box component="pre" className="mono" m={0} p="sm" pr={44} tabIndex={0} style={{ background: "var(--mantine-color-dark-8)", border: "1px solid var(--roar-borda)", borderRadius: 6, whiteSpace: "pre-wrap" }}>{texto}</Box>
      <CopyButton value={texto}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? "Copiado" : "Copiar"}>
            <ActionIcon pos="absolute" top={8} right={8} size="sm" variant="default" onClick={copy} aria-label="Copiar o documento">{copied ? <IconCheck size={14} /> : <IconCopy size={14} />}</ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
    </Box>
  );
}

/** Rótulo e valor; quando o valor leva a mais registros, ele é um link. */
export function Fato({ rotulo, valor, mono, aoClicar }: { rotulo: string; valor: ReactNode; mono?: boolean; aoClicar?: () => void }) {
  return (
    <div>
      <Text size="xs" c="dimmed">{rotulo}</Text>
      {aoClicar
        ? <Anchor component="button" type="button" size="sm" c="rosa.2" onClick={aoClicar} className={mono ? "mono" : undefined} ta="left">{valor}</Anchor>
        : <Text size="sm" className={mono ? "mono" : undefined} component="div">{valor}</Text>}
    </div>
  );
}

export interface EventoResumo {
  id: number;
  ocorrido_em?: string;
  severidade?: string;
  nivel?: number;
  regra_id?: string;
  regra_descricao?: string | null;
  mitre?: string[] | null;
  ativo?: string | null;
  usuario?: string | null;
  ip_origem?: string | null;
  pais?: string | null;
  cidade?: string | null;
  regiao?: string | null;
}

interface EventoBruto { id: number; origem_id: string; origem: string; ocorrido_em: string; recebido_em: string; bruto: { roar_truncado?: boolean; rule?: { description?: string } } & Record<string, unknown> }

export type FiltroDoEvento = { entidade: string } | { origem: string };

function localDoEvento(e: EventoResumo) {
  if (e.cidade) return nomeDaCidade({ cidade: e.cidade, regiao: e.regiao, pais: e.pais });
  return e.pais ? nomeDoPais(e.pais) : null;
}

function CorpoDoEvento({ evento, aoFiltrar }: { evento: EventoResumo; aoFiltrar?: (filtro: FiltroDoEvento) => void }) {
  const eu = useEu();
  const pode = usePode();
  const verBruto = pode("ver_bruto");
  const { dados, erro } = useDados<EventoBruto>(verBruto ? `/api/eventos/${evento.id}/bruto` : null);
  const local = localDoEvento(evento);
  const ir = (filtro: FiltroDoEvento) => (aoFiltrar ? () => aoFiltrar(filtro) : undefined);
  return (
    <Stack gap="md">
      <SimpleGrid cols={{ base: 2, sm: 3 }} spacing="sm">
        {evento.ocorrido_em && <Fato rotulo="Quando" valor={<Data valor={evento.ocorrido_em} />} />}
        {evento.severidade && <Fato rotulo="Severidade" valor={<Severidade valor={evento.severidade} />} />}
        {evento.regra_id && <Fato rotulo="Regra" valor={`${evento.regra_id}${evento.nivel !== undefined ? `, nível ${evento.nivel}` : ""}`} />}
        {evento.ativo && <Fato rotulo="Ativo" valor={evento.ativo} aoClicar={ir({ entidade: evento.ativo })} />}
        {evento.usuario && <Fato rotulo="Usuário" valor={evento.usuario} mono aoClicar={ir({ entidade: evento.usuario })} />}
        {evento.ip_origem && <Fato rotulo="Origem" valor={evento.ip_origem} mono aoClicar={ir({ origem: evento.ip_origem })} />}
        {local && <Fato rotulo="Local provável" valor={local} />}
        {evento.mitre && evento.mitre.length > 0 && <Fato rotulo="MITRE ATT&CK" valor={evento.mitre.join(", ")} mono />}
      </SimpleGrid>
      {verBruto && (dados ? (
        <>
          <Group justify="space-between" wrap="wrap" gap="xs">
            <Text size="xs" c="dimmed">
              Recebido em {quando(dados.recebido_em, eu.fuso)}, identificador <span className="mono">{dados.origem_id}</span>
              {dados.bruto?.roar_truncado ? ". Conteúdo grande: guardamos só o resumo e o hash" : ""}
            </Text>
            <BotaoDaCesta fonte="alertas" id={dados.origem_id} resumo={`${quando(dados.ocorrido_em, eu.fuso)} · ${dados.bruto?.rule?.description ?? "Alerta"}`} />
          </Group>
          <BlocoDeJson valor={dados.bruto} />
        </>
      ) : <Carregando erro={erro ? "Não foi possível abrir este alerta." : null} />)}
    </Stack>
  );
}

/** O detalhe de um evento: o que a linha já sabe e, para quem pode, o alerta como chegou. */
export function GavetaDoEvento({ evento, aoFechar, aoFiltrar }: { evento: EventoResumo | null; aoFechar: () => void; aoFiltrar?: (filtro: FiltroDoEvento) => void }) {
  return (
    <Drawer opened={evento !== null} onClose={aoFechar} title={evento?.regra_descricao ?? evento?.regra_id ?? "Evento"}>
      {evento && <CorpoDoEvento key={evento.id} evento={evento} aoFiltrar={aoFiltrar} />}
    </Drawer>
  );
}

// ------------------------------------------------------------------ filtros vindos da URL

const FILTROS_DE_CONTEXTO = ["pais", "cidade", "alertas", "dia", "severidades", "origem", "sinal", "entidade", "regra", "agente", "operadora"] as const;
type Contexto = Partial<Record<(typeof FILTROS_DE_CONTEXTO)[number], string>>;
interface Filtros { busca: string; severidade: string; dias: string; contexto: Contexto }

function filtrosDaUrl(): Filtros {
  const url = new URLSearchParams(window.location.search);
  const contexto: Contexto = {};
  FILTROS_DE_CONTEXTO.forEach((c) => {
    const v = url.get(c);
    if (v) contexto[c] = v;
  });
  const dias = url.get("dias") ?? "";
  return { busca: url.get("busca") ?? "", severidade: url.get("severidade") ?? "", dias: PERIODOS.some((p) => p.value === dias) ? dias : "30", contexto };
}

function consultaDosFiltros({ busca, severidade, dias, contexto }: Filtros) {
  const consulta = new URLSearchParams();
  if (busca) consulta.set("busca", busca);
  if (severidade) consulta.set("severidade", severidade);
  consulta.set("dias", dias);
  Object.entries(contexto).forEach(([c, v]) => consulta.set(c, v));
  return consulta.toString();
}

/** Outras telas chegam aqui com um filtro, como o país clicado no mapa ou a regra de uma técnica. */
export function irParaEventos(filtros: Record<string, string>) {
  window.history.pushState(null, "", `/novo/eventos?${new URLSearchParams(filtros)}`);
  // É o evento que a aplicação já escuta para trocar de tela.
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function rotuloDoContexto(chave: keyof Contexto, valor: string) {
  switch (chave) {
    case "pais": return `País: ${nomeDoPais(valor)}`;
    case "cidade": return `Cidade: ${valor}`;
    case "alertas": return "Só alertas";
    case "dia": return `Dia: ${diaCurto(valor)}`;
    case "severidades": return valor.split(",").map((s) => SEVERIDADES[s as keyof typeof SEVERIDADES]?.texto ?? s).join(" ou ");
    case "origem": return `Origem: ${valor}`;
    case "sinal": return `Sinal: ${SINAIS[valor] ?? valor}`;
    case "entidade": return `Ativo ou usuário: ${valor}`;
    case "regra": return `Regra: ${valor}`;
    case "operadora": return `Operadora: ${valor}`;
    case "agente": return `Ativo: ${valor}`;
  }
}

// ------------------------------------------------------------------ tela

const PERIODOS = [{ value: "1", label: "Último dia" }, { value: "7", label: "7 dias" }, { value: "30", label: "30 dias" }, { value: "90", label: "90 dias" }];
const OPCOES_DE_SEVERIDADE = [{ value: "todas", label: "Todas as severidades" }, ...Object.entries(SEVERIDADES).map(([value, s]) => ({ value, label: s.texto }))];

export function Eventos() {
  const pode = usePode();
  const [filtros, setFiltros] = useState(filtrosDaUrl);
  // A Busca guarda o próprio texto: quando o filtro muda por fora, ela precisa nascer de novo.
  const [versaoDaBusca, setVersaoDaBusca] = useState(0);
  const [eventos, setEventos] = useState<EventoResumo[]>([]);
  const [haMais, setHaMais] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [carregando, setCarregando] = useState(true);
  const [aberto, setAberto] = useState<EventoResumo | null>(null);
  const pedido = useRef(0);
  const consulta = useMemo(() => consultaDosFiltros(filtros), [filtros]);

  const buscar = useCallback(async (antesDe?: number) => {
    const este = ++pedido.current;
    setCarregando(true);
    try {
      const d = await ler<{ eventos: EventoResumo[]; ha_mais: boolean }>(`/api/eventos?${consulta}${antesDe ? `&antes_de=${antesDe}` : ""}`);
      if (este !== pedido.current) return;
      setEventos((atuais) => (antesDe ? [...atuais, ...d.eventos] : d.eventos));
      setHaMais(d.ha_mais);
      setErro(null);
    } catch (e) {
      if (este === pedido.current) setErro((e as Error).message);
    } finally {
      if (este === pedido.current) setCarregando(false);
    }
  }, [consulta]);

  useEffect(() => { buscar(); }, [buscar]);

  useEffect(() => {
    if (window.location.pathname.startsWith("/novo/eventos")) window.history.replaceState(null, "", `/novo/eventos?${consulta}`);
  }, [consulta]);

  useEffect(() => {
    const voltar = () => {
      if (!window.location.pathname.startsWith("/novo/eventos")) return;
      setFiltros(filtrosDaUrl());
      setVersaoDaBusca((v) => v + 1);
    };
    window.addEventListener("popstate", voltar);
    return () => window.removeEventListener("popstate", voltar);
  }, []);

  const mudarBusca = useCallback((busca: string) => setFiltros((f) => ({ ...f, busca })), []);
  const juntar = (novo: Contexto) => setFiltros((f) => ({ ...f, contexto: { ...f.contexto, ...novo } }));
  const tirar = (chave: keyof Contexto) => setFiltros((f) => {
    const contexto = { ...f.contexto };
    delete contexto[chave];
    // Cidade só existe dentro de um país: tirar qualquer um dos dois tira a localização.
    if (chave === "cidade" || chave === "pais") {
      delete contexto.cidade;
      delete contexto.pais;
    }
    return { ...f, contexto };
  });

  const chips = FILTROS_DE_CONTEXTO.filter((c) => filtros.contexto[c] && !(c === "pais" && filtros.contexto.cidade));

  return (
    <>
      <Cabecalho titulo="Eventos" ajuda="Todos os eventos, inclusive os normais, do mais novo para o mais antigo. Clique em um para ver o detalhe." />
      <Stack gap="sm">
        <Group justify="space-between" gap="xs" wrap="wrap">
          <Group gap="xs" wrap="wrap">
            <Busca key={versaoDaBusca} valor={filtros.busca} aoMudar={mudarBusca} dica="Usuário, IP, ativo ou regra" />
            <Select w={190} aria-label="Severidade" value={filtros.severidade || "todas"} onChange={(v) => setFiltros((f) => ({ ...f, severidade: !v || v === "todas" ? "" : v }))} allowDeselect={false} data={OPCOES_DE_SEVERIDADE} />
            <Select w={130} aria-label="Período" value={filtros.dias} onChange={(v) => setFiltros((f) => ({ ...f, dias: v ?? "30" }))} allowDeselect={false} data={PERIODOS} />
            {chips.map((c) => <Pill key={c} size="md" withRemoveButton onRemove={() => tirar(c)} removeButtonProps={{ "aria-label": `Tirar o filtro ${rotuloDoContexto(c, filtros.contexto[c]!)}` }}>{rotuloDoContexto(c, filtros.contexto[c]!)}</Pill>)}
          </Group>
          {eventos.length > 0 && <Text size="xs" c="dimmed" className="numero">{numero(eventos.length)}{haMais ? " carregados" : " eventos"}</Text>}
        </Group>
        <Painel p={0}>
          {erro && !eventos.length ? <Vazio>{erro}</Vazio> : carregando && !eventos.length ? <Carregando /> : (
            <Tabela
              linhas={eventos}
              chave={(e) => e.id}
              vazio="Nenhum evento encontrado."
              aoClicarLinha={setAberto}
              colunas={[
                { titulo: "Quando", largura: 150, celula: (e) => <Data valor={e.ocorrido_em} /> },
                { titulo: "Severidade", largura: 90, celula: (e) => <Severidade valor={e.severidade ?? "baixa"} /> },
                { titulo: "Evento", celula: (e) => e.regra_descricao ?? e.regra_id },
                { titulo: "Ativo", celula: (e) => e.ativo ?? "-" },
                { titulo: "Usuário", celula: (e) => <span className="mono">{e.usuario ?? "-"}</span> },
                { titulo: "Origem", celula: (e) => {
                  const local = localDoEvento(e);
                  return <><span className="mono">{e.ip_origem ?? "-"}</span>{local && <Text size="xs" c="dimmed">{local}</Text>}</>;
                } },
                { titulo: "", largura: 40, celula: (e) => (
                  <AcoesDaLinha rotulo="Ações do evento" itens={[
                    { texto: pode("ver_bruto") ? "Ver como chegou" : "Ver detalhe", aoClicar: () => setAberto(e) },
                    ...(e.ativo ? [{ texto: "Só este ativo", aoClicar: () => juntar({ entidade: e.ativo! }) }] : []),
                    ...(e.usuario ? [{ texto: "Só este usuário", aoClicar: () => juntar({ entidade: e.usuario! }) }] : []),
                    ...(e.ip_origem ? [{ texto: "Só esta origem", aoClicar: () => juntar({ origem: e.ip_origem! }) }] : []),
                  ]} />
                ) },
              ]}
            />
          )}
        </Painel>
        {erro && eventos.length > 0 && <Text size="xs" c="red.4">{erro}</Text>}
        {haMais && <Group justify="center"><Button loading={carregando} onClick={() => buscar(eventos[eventos.length - 1]?.id)}>Carregar mais</Button></Group>}
      </Stack>
      <GavetaDoEvento evento={aberto} aoFechar={() => setAberto(null)} aoFiltrar={(f) => { setAberto(null); juntar(f); }} />
    </>
  );
}
