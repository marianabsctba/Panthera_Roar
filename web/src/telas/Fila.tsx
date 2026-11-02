import { ActionIcon, Alert, Box, Button, Drawer, Group, List, Modal, NumberInput, Progress, ScrollArea, Select, SimpleGrid, Stack, Tabs, Text, TextInput, Title, Tooltip, UnstyledButton } from "@mantine/core";
import { useMediaQuery } from "@mantine/hooks";
import { IconRefresh } from "@tabler/icons-react";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import { detalhe, enviar, useDados, useEu, usePode } from "../api";
import { Busca, Cabecalho, Carregando, Data, GavetaDeEventos, Numero, Painel, Severidade, Tabela, Vazio, type FiltroDeEventos } from "../componentes";
import { numero, quando, SINAIS } from "../formato";
import { SEVERIDADES } from "../tema";
import { Fato, GavetaDoEvento, type EventoResumo } from "./Eventos";

type Aba = "riscos" | "grupos";

interface ItemDeRisco { id: number; severidade: string; risco_maximo: number; quando: string; estado: string; entidade_tipo: string; entidade: string; risco_atual: number; sinais: string[] | null }
interface ItemDeGrupo { id: number; severidade: string; nivel: number; total: number; regras: string[] | null; quando: string; primeira_em: string; ip_origem: string | null; agente_id: string; ativo: string | null; descricao: string | null }
interface DadosDaFila { riscos: ItemDeRisco[]; grupos: ItemDeGrupo[] }

type Detalhes = Record<string, string | number | null | undefined>;
interface Sinal { tipo: string; peso: number; ocorrido_em: string; detalhes: Detalhes | null; evento_id: number; regra_descricao: string | null; ativo: string | null; ip_origem: string | null; usuario: string | null }
interface DadosDoRisco {
  alerta: { id: number; severidade: string; risco_maximo: number; aberto_em: string; encerrado_em: string | null; estado: string; entidade_tipo: string; entidade: string; risco_atual: number };
  sinais: Sinal[];
}
interface DadosDoGrupo {
  grupo: { id: number; severidade: string; nivel: number; total: number; regras: string[] | null; primeira_em: string; ultima_em: string; ip_origem: string | null; agente_id: string };
  eventos: (EventoResumo & { id: number; ocorrido_em: string; severidade: string })[];
}

const LIMITE_DE_EVENTOS_DO_GRUPO = 200;

const TEXTOS_DOS_SINAIS: Record<string, (d: Detalhes) => string> = {
  sucesso_apos_falhas: (d) => `${d.falhas ?? "Várias"} tentativas falharam antes do acesso, vindas de ${d.ip ?? "um mesmo IP"}.`,
  viagem_impossivel: (d) => `${d.km ?? "?"} km em ${d.horas ?? "?"} h desde o acesso anterior${d.ip ? `, agora de ${d.ip}` : ""}.`,
  primeiro_privilegio: (d) => `Executou como ${d.como ?? "outro usuário"} em ${d.host ?? "um ativo"} pela primeira vez.`,
  pico_de_falhas: (d) => `${d.falhas_na_hora ?? "Muitas"} falhas em uma hora; o normal é ${d.mediana_historica ?? 0}.`,
  primeiro_host: (d) => `Primeiro acesso a ${d.host ?? "este ativo"}${d.ip ? `, vindo de ${d.ip}` : ""}.`,
  horario_incomum: (d) => `Acesso às ${String(d.hora_local ?? "?").padStart(2, "0")}h, hora local, em ${d.host ?? "um ativo"}.`,
  primeiro_ip: (d) => `Primeiro acesso vindo de ${d.ip ?? "um novo endereço"}.`,
  host_raro_no_cliente: (d) => `Quase ninguém na organização acessa ${d.host ?? "este ativo"}.`,
};

const tituloDoSinal = (tipo: string) => SINAIS[tipo] ?? tipo;
const textoDaSeveridade = (s: string) => SEVERIDADES[s as keyof typeof SEVERIDADES]?.texto ?? s;
const corDaSeveridade = (s: string) => SEVERIDADES[s as keyof typeof SEVERIDADES]?.cor ?? SEVERIDADES.baixa.cor;

// ------------------------------------------------------------------ automatizar

const SE_EXTERNO = { campo: "alvo_externo", op: "igual", valor: true };
const BLOQUEAR = { tipo: "acao", acao: "bloquear_ip", parametros: { duracao_minutos: 60, protegidos: [] } };
const AVISAR = { tipo: "acao", acao: "webhook", parametros: { url: "" } };
const APROVAR = { tipo: "aprovacao" };

interface Rascunho { nome: string; passos: string[]; precisaDeUrl: boolean; definicao: Record<string, unknown> }

function rascunhoDeGrupo({ grupo, eventos }: DadosDoGrupo): Rascunho {
  const regra = eventos[0]?.regra_id ?? grupo.regras?.[0] ?? "";
  const nome = `Responder a: ${eventos[0]?.regra_descricao ?? `regra ${regra}`}`.slice(0, 120);
  const quandoDispara = { tipo: "evento", regra_id: regra };
  if (grupo.ip_origem) {
    return {
      nome,
      precisaDeUrl: false,
      passos: [`Quando a regra ${regra} disparar, se o alvo for externo:`, "Pedir aprovação.", "Bloquear o endereço no ativo por 60 minutos."],
      definicao: { quando: quandoDispara, se: [SE_EXTERNO], blocos: [APROVAR, BLOQUEAR] },
    };
  }
  return { nome, precisaDeUrl: true, passos: [`Quando a regra ${regra} disparar:`, "Avisar um endereço web."], definicao: { quando: quandoDispara, se: [], blocos: [AVISAR] } };
}

function rascunhoDeRisco({ alerta }: DadosDoRisco): Rascunho {
  const severidade = textoDaSeveridade(alerta.severidade).toLowerCase();
  return {
    nome: `Responder a risco ${severidade}`,
    precisaDeUrl: true,
    passos: [`Quando abrir um risco ${severidade}:`, "Se o alvo for externo, pedir aprovação e bloquear o endereço por 60 minutos.", "Senão, avisar um endereço web."],
    definicao: { quando: { tipo: "risco", severidade: alerta.severidade }, se: [], blocos: [{ tipo: "se", condicao: SE_EXTERNO, entao: [APROVAR, BLOQUEAR], senao: [AVISAR] }] },
  };
}

function comEndereco(definicao: Record<string, unknown>, url: string) {
  return JSON.parse(JSON.stringify(definicao), (chave, valor) => (chave === "url" && valor === "" ? url : valor)) as Record<string, unknown>;
}

interface Simulacao { disparos: number; dias: number; limitado: boolean; analisados: number; recusas: number; alvos: { alvo: string; total: number }[] }

function ModalDeAutomacao({ rascunho, aoFechar }: { rascunho: Rascunho; aoFechar: () => void }) {
  const [nome, setNome] = useState(rascunho.nome);
  const [url, setUrl] = useState("");
  const [intervalo, setIntervalo] = useState<number | string>(60);
  const [erro, setErro] = useState<string | null>(null);
  const [simulacao, setSimulacao] = useState<Simulacao | null>(null);
  const [criado, setCriado] = useState(false);
  const faltaUrl = rascunho.precisaDeUrl && !url.trim();
  const corpo = () => ({ definicao: comEndereco(rascunho.definicao, url.trim()), intervalo_minutos: Number(intervalo) || 0 });

  const simular = async () => {
    setErro(null);
    const r = await enviar("/api/automacao/simular", corpo());
    if (!r.ok) {
      setSimulacao(null);
      setErro(await detalhe(r, "Não foi possível simular."));
      return;
    }
    setSimulacao(await r.json());
  };
  const criar = async () => {
    setErro(null);
    const r = await enviar("/api/automacao/playbooks", { nome: nome.trim(), ...corpo() });
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível criar o playbook."));
      return;
    }
    setCriado(true);
  };

  if (criado) {
    return (
      <Stack gap="sm">
        <Alert color="green" variant="light" p="xs" fz="sm">Playbook criado e ativo. Ele pode ser ajustado ou desligado em Automação.</Alert>
        <Group justify="flex-end"><Button onClick={aoFechar}>Fechar</Button></Group>
      </Stack>
    );
  }
  return (
    <Stack gap="sm">
      <TextInput label="Nome" value={nome} onChange={(e) => setNome(e.currentTarget.value)} maxLength={120} data-autofocus />
      <div>
        <Text size="xs" c="dimmed" mb={4}>{rascunho.passos[0]}</Text>
        <List size="sm" spacing={2}>{rascunho.passos.slice(1).map((p) => <List.Item key={p}>{p}</List.Item>)}</List>
      </div>
      {rascunho.precisaDeUrl && <TextInput label="Endereço web a avisar" type="url" placeholder="https://" value={url} onChange={(e) => setUrl(e.currentTarget.value)} spellCheck={false} />}
      <NumberInput label="Não repetir para o mesmo alvo por (minutos)" value={intervalo} onChange={setIntervalo} min={0} max={10080} allowDecimal={false} />
      {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
      {simulacao && (
        <Alert color="gray" variant="light" p="xs">
          <Text size="sm" fw={500}>
            {simulacao.disparos
              ? `Nos últimos ${simulacao.dias} dias, isto teria disparado ${simulacao.disparos === 1 ? "1 vez" : `${numero(simulacao.disparos)} vezes`}.`
              : `Nos últimos ${simulacao.dias} dias, isto não teria disparado nenhuma vez.`}
          </Text>
          {simulacao.limitado && <Text size="xs" c="dimmed">Olhei só os primeiros {numero(simulacao.analisados)} acontecimentos: o número real pode ser maior.</Text>}
          {simulacao.recusas > 0 && <Text size="xs" c="dimmed">{numero(simulacao.recusas)} bloqueios seriam recusados, por alvo protegido ou sem endereço público.</Text>}
          {simulacao.alvos.map((a) => <Group key={a.alvo} justify="space-between"><span className="mono">{a.alvo}</span><Text size="xs" className="numero">{numero(a.total)}</Text></Group>)}
        </Alert>
      )}
      <Group justify="flex-end">
        <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
        <Button onClick={simular} disabled={faltaUrl}>Simular</Button>
        <Button variant="filled" onClick={criar} disabled={faltaUrl || !nome.trim()}>Criar e ativar</Button>
      </Group>
    </Stack>
  );
}

function BotaoAutomatizar({ criar }: { criar: () => Rascunho }) {
  const pode = usePode();
  const [rascunho, setRascunho] = useState<Rascunho | null>(null);
  if (!pode("gerir_playbooks")) return null;
  return (
    <>
      <Button size="xs" onClick={() => setRascunho(criar())}>Automatizar isto</Button>
      <Modal opened={rascunho !== null} onClose={() => setRascunho(null)} title="Automatizar isto">
        {rascunho && <ModalDeAutomacao rascunho={rascunho} aoFechar={() => setRascunho(null)} />}
      </Modal>
    </>
  );
}

// ------------------------------------------------------------------ detalhes

function TopoDoDetalhe({ titulo, severidade, subtitulo, children }: { titulo: string; severidade: string; subtitulo?: string; children?: ReactNode }) {
  return (
    <Group justify="space-between" align="flex-start" wrap="wrap" gap="xs">
      <div style={{ minWidth: 0, flex: "1 1 240px" }}>
        <Group gap="xs" wrap="wrap"><Title order={2} style={{ overflowWrap: "anywhere" }}>{titulo}</Title><Severidade valor={severidade} /></Group>
        {subtitulo && <Text size="xs" c="dimmed" mt={2}>{subtitulo}</Text>}
      </div>
      <Group gap="xs">{children}</Group>
    </Group>
  );
}

function DetalheDoRisco({ id, aoAbrirEvento, aoAbrirEventos }: { id: number; aoAbrirEvento: (e: EventoResumo) => void; aoAbrirEventos: (f: FiltroDeEventos) => void }) {
  const eu = useEu();
  const { dados, erro } = useDados<DadosDoRisco>(`/api/riscos/${id}`);
  if (!dados) return <Carregando erro={erro ? "Este item não está mais disponível." : null} />;
  const { alerta, sinais } = dados;
  const atual = Math.round(Number(alerta.risco_atual));
  return (
    <Stack gap="md">
      <TopoDoDetalhe titulo={alerta.entidade} severidade={alerta.severidade} subtitulo={`${alerta.entidade_tipo === "ativo" ? "Ativo" : "Usuário"}, aberto em ${quando(alerta.aberto_em, eu.fuso)}`}>
        <Button size="xs" onClick={() => aoAbrirEventos({ rotulo: `Eventos de ${alerta.entidade}`, consulta: { entidade: alerta.entidade } })}>Ver eventos</Button>
        <BotaoAutomatizar criar={() => rascunhoDeRisco(dados)} />
      </TopoDoDetalhe>
      <div>
        <Group justify="space-between" mb={4}>
          <Text size="xs" c="dimmed" className="numero">Risco atual {numero(atual)}</Text>
          <Text size="xs" c="dimmed" className="numero">Máximo {numero(Math.round(Number(alerta.risco_maximo)))}</Text>
        </Group>
        <Progress size="sm" value={Math.min(100, atual)} color={corDaSeveridade(alerta.severidade)} aria-label="Risco atual" />
      </div>
      <div>
        <Title order={3} mb="xs">Por que este alerta existe</Title>
        {!sinais.length ? <Vazio>Nenhum sinal registrado.</Vazio> : (
          <Stack gap={4}>
            {sinais.map((s) => (
              <UnstyledButton
                key={`${s.evento_id}-${s.tipo}-${s.ocorrido_em}`}
                className="clicavel"
                p="xs"
                style={{ border: "1px solid var(--roar-borda)", borderRadius: 6 }}
                onClick={() => aoAbrirEvento({ id: s.evento_id, ocorrido_em: s.ocorrido_em, regra_descricao: s.regra_descricao, ativo: s.ativo, usuario: s.usuario, ip_origem: s.ip_origem })}
              >
                <Group justify="space-between" wrap="nowrap" gap="xs">
                  <Text size="sm" fw={500}>{tituloDoSinal(s.tipo)}</Text>
                  <Text size="xs" className="numero" fw={500}>+{Math.round(Number(s.peso))}</Text>
                </Group>
                <Text size="xs">{TEXTOS_DOS_SINAIS[s.tipo]?.(s.detalhes ?? {}) ?? s.regra_descricao ?? ""}</Text>
                <Text size="xs" c="dimmed">{quando(s.ocorrido_em, eu.fuso)}, {s.regra_descricao ?? "evento"}</Text>
              </UnstyledButton>
            ))}
          </Stack>
        )}
      </div>
    </Stack>
  );
}

function DetalheDoGrupo({ id, aoAbrirEvento, aoAbrirEventos }: { id: number; aoAbrirEvento: (e: EventoResumo) => void; aoAbrirEventos: (f: FiltroDeEventos) => void }) {
  const { dados, erro } = useDados<DadosDoGrupo>(`/api/grupos/${id}`);
  if (!dados) return <Carregando erro={erro ? "Este item não está mais disponível." : null} />;
  const { grupo, eventos } = dados;
  const ativo = eventos[0]?.ativo;
  const total = Number(grupo.total);
  return (
    <Stack gap="md">
      <TopoDoDetalhe titulo={eventos[0]?.regra_descricao ?? "Alerta"} severidade={grupo.severidade}>
        <BotaoAutomatizar criar={() => rascunhoDeGrupo(dados)} />
      </TopoDoDetalhe>
      <SimpleGrid cols={{ base: 2, sm: 3, xl: 5 }} spacing="sm">
        <Fato rotulo="Eventos" valor={numero(total)} />
        <Fato rotulo="Origem" valor={grupo.ip_origem ?? "Sem origem"} mono={Boolean(grupo.ip_origem)} aoClicar={grupo.ip_origem ? () => aoAbrirEventos({ rotulo: `Eventos vindos de ${grupo.ip_origem}`, consulta: { origem: grupo.ip_origem! } }) : undefined} />
        <Fato rotulo="Ativo" valor={ativo ?? grupo.agente_id} aoClicar={ativo ? () => aoAbrirEventos({ rotulo: `Eventos de ${ativo}`, consulta: { entidade: ativo } }) : undefined} />
        <Fato rotulo="Primeiro" valor={<Data valor={grupo.primeira_em} />} />
        <Fato rotulo="Último" valor={<Data valor={grupo.ultima_em} />} />
      </SimpleGrid>
      <div>
        <Group justify="space-between" mb="xs">
          <Title order={3}>Eventos recentes</Title>
          {total > LIMITE_DE_EVENTOS_DO_GRUPO && eventos.length >= LIMITE_DE_EVENTOS_DO_GRUPO && <Text size="xs" c="dimmed" className="numero">Os {numero(LIMITE_DE_EVENTOS_DO_GRUPO)} mais recentes de {numero(total)}</Text>}
        </Group>
        <Tabela
          linhas={eventos}
          chave={(e) => e.id}
          vazio="Nenhum evento neste grupo."
          aoClicarLinha={aoAbrirEvento}
          colunas={[
            { titulo: "Quando", largura: 150, celula: (e) => <Data valor={e.ocorrido_em} /> },
            { titulo: "Severidade", largura: 90, celula: (e) => <Severidade valor={e.severidade} /> },
            { titulo: "Evento", celula: (e) => e.regra_descricao ?? e.regra_id },
            { titulo: "Usuário", celula: (e) => <span className="mono">{e.usuario ?? "-"}</span> },
            { titulo: "Origem", celula: (e) => <span className="mono">{e.ip_origem ?? "-"}</span> },
          ]}
        />
      </div>
    </Stack>
  );
}

// ------------------------------------------------------------------ lista

function ItemDaLista({ titulo, severidade, linhas, atual, aoClicar }: { titulo: string; severidade: string; linhas: string[]; atual: boolean; aoClicar: () => void }) {
  return (
    <UnstyledButton className="clicavel" data-selecionado={atual || undefined} aria-current={atual || undefined} onClick={aoClicar} px="xs" py={6} style={{ border: "1px solid transparent", borderRadius: 6 }}>
      <Group justify="space-between" wrap="nowrap" gap="xs">
        <Text size="sm" fw={500} truncate title={titulo}>{titulo}</Text>
        <Severidade valor={severidade} />
      </Group>
      {linhas.map((l) => <Text key={l} size="xs" c="dimmed" truncate title={l}>{l}</Text>)}
    </UnstyledButton>
  );
}

const contem = (busca: string, ...valores: (string | null | undefined)[]) => valores.some((v) => v?.toLowerCase().includes(busca));

const OPCOES_DE_SEVERIDADE = [{ value: "todas", label: "Todas as severidades" }, ...Object.entries(SEVERIDADES).map(([value, s]) => ({ value, label: s.texto }))];

// ------------------------------------------------------------------ tela

export function Fila() {
  const eu = useEu();
  const largo = useMediaQuery("(min-width: 62em)", true, { getInitialValueInEffect: false });
  const { dados, erro, recarregar } = useDados<DadosDaFila>("/api/fila");
  const [aba, setAba] = useState<Aba>("riscos");
  const [busca, setBusca] = useState("");
  const [severidade, setSeveridade] = useState("");
  const [selecionado, setSelecionado] = useState<{ aba: Aba; id: number } | null>(null);
  const [versao, setVersao] = useState(0);
  const [evento, setEvento] = useState<EventoResumo | null>(null);
  const [filtro, setFiltro] = useState<FiltroDeEventos | null>(null);
  const lista = useRef<HTMLDivElement>(null);

  const termo = busca.trim().toLowerCase();
  const riscos = useMemo(() => (dados?.riscos ?? []).filter((r) => (!severidade || r.severidade === severidade) && (!termo || contem(termo, r.entidade, ...(r.sinais ?? []).map(tituloDoSinal)))), [dados, severidade, termo]);
  const grupos = useMemo(() => (dados?.grupos ?? []).filter((g) => (!severidade || g.severidade === severidade) && (!termo || contem(termo, g.descricao, g.ativo, g.agente_id, g.ip_origem))), [dados, severidade, termo]);
  const itens: { id: number }[] = aba === "riscos" ? riscos : grupos;

  // Em tela larga o detalhe está sempre aberto: quem opera a fila não deve precisar clicar para ver o primeiro.
  useEffect(() => {
    if (!largo || !dados) return;
    if (!selecionado || selecionado.aba !== aba || !itens.some((i) => i.id === selecionado.id)) {
      setSelecionado(itens[0] ? { aba, id: itens[0].id } : null);
    }
  }, [largo, dados, aba, itens, selecionado]);

  const atalhos = (e: KeyboardEvent) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const atual = itens.findIndex((i) => selecionado?.aba === aba && i.id === selecionado.id);
    const proximo = Math.max(0, Math.min(itens.length - 1, atual + (e.key === "ArrowDown" ? 1 : -1)));
    if (!itens[proximo]) return;
    setSelecionado({ aba, id: itens[proximo].id });
    lista.current?.querySelectorAll("button")[proximo]?.focus();
  };

  const atualizar = () => {
    recarregar();
    setVersao((v) => v + 1);
  };

  const filtrarPorNumero = (novaAba: Aba, novaSeveridade: string) => {
    setAba(novaAba);
    setSeveridade((atual) => (aba === novaAba && atual === novaSeveridade && novaSeveridade ? "" : novaSeveridade));
  };

  const detalheAberto = selecionado && (
    selecionado.aba === "riscos"
      ? <DetalheDoRisco key={`r${selecionado.id}-${versao}`} id={selecionado.id} aoAbrirEvento={setEvento} aoAbrirEventos={setFiltro} />
      : <DetalheDoGrupo key={`g${selecionado.id}-${versao}`} id={selecionado.id} aoAbrirEvento={setEvento} aoAbrirEventos={setFiltro} />
  );

  const cabecalho = (
    <Cabecalho titulo="Fila" ajuda="O que pede atenção agora: pessoas e ativos com risco aberto e alertas agrupados. Use as setas para andar pela lista.">
      <Tooltip label="Atualizar"><ActionIcon variant="subtle" color="gray" onClick={atualizar} aria-label="Atualizar a fila"><IconRefresh size={16} /></ActionIcon></Tooltip>
    </Cabecalho>
  );

  if (!dados) return <>{cabecalho}<Carregando erro={erro} /></>;

  return (
    <>
      {cabecalho}
      <Stack gap="sm">
        <SimpleGrid cols={{ base: 2, md: 4 }} spacing="sm">
          <Numero rotulo="Riscos críticos" valor={numero(dados.riscos.filter((r) => r.severidade === "critica").length)} aoClicar={() => filtrarPorNumero("riscos", "critica")} selecionado={aba === "riscos" && severidade === "critica"} />
          <Numero rotulo="Riscos altos" valor={numero(dados.riscos.filter((r) => r.severidade === "alta").length)} aoClicar={() => filtrarPorNumero("riscos", "alta")} selecionado={aba === "riscos" && severidade === "alta"} />
          <Numero rotulo="Grupos de alertas" valor={numero(dados.grupos.length)} aoClicar={() => filtrarPorNumero("grupos", "")} selecionado={aba === "grupos" && !severidade} />
          <Numero rotulo="Eventos nos alertas" valor={numero(dados.grupos.reduce((t, g) => t + Number(g.total), 0))} aoClicar={() => filtrarPorNumero("grupos", "")} selecionado={aba === "grupos" && !severidade} />
        </SimpleGrid>

        <Group gap="xs" wrap="wrap">
          <Busca valor={busca} aoMudar={setBusca} dica="Filtrar a lista" />
          <Select w={190} aria-label="Severidade" value={severidade || "todas"} onChange={(v) => setSeveridade(!v || v === "todas" ? "" : v)} allowDeselect={false} data={OPCOES_DE_SEVERIDADE} />
        </Group>

        <Box style={largo ? { display: "grid", gridTemplateColumns: "minmax(300px, 400px) minmax(0, 1fr)", gap: 12, alignItems: "start" } : undefined}>
          <Painel p="xs">
            <Tabs value={aba} onChange={(v) => setAba((v as Aba) ?? "riscos")}>
              <Tabs.List mb="xs">
                <Tabs.Tab value="riscos">Risco</Tabs.Tab>
                <Tabs.Tab value="grupos">Alertas</Tabs.Tab>
              </Tabs.List>
            </Tabs>
            <ScrollArea.Autosize mah={largo ? "calc(100vh - 340px)" : undefined} type="auto" offsetScrollbars>
              <Stack gap={2} ref={lista} onKeyDown={atalhos}>
                {!itens.length && <Vazio>{aba === "riscos" ? "Nenhum risco aberto." : "Nenhum alerta."}</Vazio>}
                {aba === "riscos" && riscos.map((r) => (
                  <ItemDaLista
                    key={r.id}
                    titulo={r.entidade}
                    severidade={r.severidade}
                    atual={selecionado?.aba === "riscos" && selecionado.id === r.id}
                    aoClicar={() => setSelecionado({ aba: "riscos", id: r.id })}
                    linhas={[(r.sinais ?? []).map(tituloDoSinal).join(", ") || "Sem sinais recentes", `Risco ${numero(Math.round(Number(r.risco_maximo)))}, ${quando(r.quando, eu.fuso)}`]}
                  />
                ))}
                {aba === "grupos" && grupos.map((g) => (
                  <ItemDaLista
                    key={g.id}
                    titulo={g.descricao ?? "Alerta"}
                    severidade={g.severidade}
                    atual={selecionado?.aba === "grupos" && selecionado.id === g.id}
                    aoClicar={() => setSelecionado({ aba: "grupos", id: g.id })}
                    linhas={[`${g.ativo ?? g.agente_id}, ${g.ip_origem ? `de ${g.ip_origem}` : "sem origem"}`, `${Number(g.total) === 1 ? "1 evento" : `${numero(g.total)} eventos`}, ${quando(g.quando, eu.fuso)}`]}
                  />
                ))}
              </Stack>
            </ScrollArea.Autosize>
          </Painel>

          {largo && (
            <Painel>
              <ScrollArea.Autosize mah="calc(100vh - 305px)" type="auto" offsetScrollbars>
                {detalheAberto || <Vazio>Selecione um item da fila.</Vazio>}
              </ScrollArea.Autosize>
            </Painel>
          )}
        </Box>
      </Stack>

      {!largo && <Drawer opened={selecionado !== null} onClose={() => setSelecionado(null)} title={selecionado?.aba === "riscos" ? "Risco" : "Alerta"}>{detalheAberto}</Drawer>}
      <GavetaDoEvento evento={evento} aoFechar={() => setEvento(null)} />
      <GavetaDeEventos filtro={filtro} aoFechar={() => setFiltro(null)} />
    </>
  );
}
