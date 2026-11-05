import { ActionIcon, Alert, Badge, Box, Button, Drawer, Group, List, Modal, NumberInput, Progress, Radio, ScrollArea, Select, SimpleGrid, Stack, Tabs, Text, Textarea, TextInput, Title, Tooltip, UnstyledButton } from "@mantine/core";
import { PainelDeContexto } from "./Contexto";
import { useMediaQuery } from "@mantine/hooks";
import { IconRefresh } from "@tabler/icons-react";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import { detalhe, enviar, pedir, useDados, useEu, usePode } from "../api";
import { Busca, Cabecalho, Carregando, Data, GavetaDeEventos, Numero, Painel, Severidade, Tabela, Vazio, type FiltroDeEventos } from "../componentes";
import { CRITICIDADES, duracao, nomeDaTatica, numero, quando, SINAIS } from "../formato";
import { SEVERIDADES } from "../tema";
import { Fato, GavetaDoEvento, type EventoResumo } from "./Eventos";

type Aba = "riscos" | "grupos";

interface ItemDeRisco { id: number; severidade: string; risco_maximo: number; quando: string; estado: string; entidade_tipo: string; entidade: string; risco_atual: number; sinais: string[] | null }
interface ItemDeGrupo { id: number; severidade: string; nivel: number; total: number; regras: string[] | null; quando: string; primeira_em: string; ip_origem: string | null; agente_id: string; ativo: string | null; descricao: string | null }
interface DadosDaFila { riscos: ItemDeRisco[]; grupos: ItemDeGrupo[] }

type Detalhes = Record<string, string | number | null | undefined>;
interface Sinal { tipo: string; peso: number; ocorrido_em: string; detalhes: Detalhes | null; evento_id: number; regra_descricao: string | null; ativo: string | null; ip_origem: string | null; usuario: string | null; pais: string | null;
  risco_depois: number; tecnica: { codigo: string; nome: string; tatica: string } | null }
interface Silencio { id: number; tipo: string; motivo: string; criado_por_nome: string | null; criado_em: string; expira_em: string | null }
interface DadosDoRisco {
  alerta: {
    id: number; entidade_id: number; severidade: string; risco_maximo: number; aberto_em: string; encerrado_em: string | null; estado: string; entidade_tipo: string; entidade: string; risco_atual: number; criticidade?: string | null;
    motivo: string | null; nota: string | null; decidido_por_nome: string | null;
  };
  sinais: Sinal[];
  pares: { entidade: string; semelhanca: number }[];
  silencios: Silencio[];
  limites: { alto: number; critico: number; meia_vida_horas: number };
}
interface DadosDoGrupo {
  grupo: { id: number; severidade: string; nivel: number; total: number; regras: string[] | null; primeira_em: string; ultima_em: string; ip_origem: string | null; agente_id: string };
  eventos: (EventoResumo & { id: number; ocorrido_em: string; severidade: string })[];
}

const LIMITE_DE_EVENTOS_DO_GRUPO = 200;

interface Visto { contagem: number; primeira_vez?: string }
interface DadosDoNormal {
  entidade: { entidade_tipo: string; entidade: string; primeira_vista: string; sucessos: number };
  horas?: { hora: number; contagem: number; incomum: boolean }[];
  total_de_acessos?: number;
  horario_conhecido?: boolean;
  aprendizado?: { aprendendo: boolean; ate: string; acessos_faltando: number };
  ativos?: (Visto & { ativo: string })[];
  total_de_ativos?: number;
  ips?: (Visto & { ip: string })[];
  total_de_ips?: number;
  privilegios?: (Visto & { ativo: string; como: string })[];
  total_de_privilegios?: number;
  cria_conta?: (Visto & { ativo: string })[];
  pessoas?: (Visto & { usuario: string })[];
  total_de_pessoas?: number;
}

const TEXTOS_DOS_SINAIS: Record<string, (d: Detalhes) => string> = {
  sucesso_apos_falhas: (d) => `${d.falhas ?? "Várias"} tentativas falharam antes do acesso, vindas de ${d.ip ?? "um mesmo IP"}.`,
  viagem_impossivel: (d) => `${d.km ?? "?"} km em ${d.horas ?? "?"} h desde o acesso anterior${d.ip ? `, agora de ${d.ip}` : ""}.`,
  primeiro_privilegio: (d) => `Executou como ${d.como ?? "outro usuário"} em ${d.host ?? "um ativo"} pela primeira vez.`,
  pico_de_falhas: (d) => `${d.falhas_na_hora ?? "Muitas"} falhas em uma hora; o normal é ${d.mediana_historica ?? 0}.`,
  primeiro_host: (d) => `Primeiro acesso a ${d.host ?? "este ativo"}${d.ip ? `, vindo de ${d.ip}` : ""}.`,
  horario_incomum: (d) => `Acesso às ${String(d.hora_local ?? "?").padStart(2, "0")}h, hora local, em ${d.host ?? "um ativo"}.`,
  primeiro_ip: (d) => `Primeiro acesso vindo de ${d.ip ?? "um novo endereço"}.`,
  host_raro_no_cliente: (d) => `Quase ninguém na organização acessa ${d.host ?? "este ativo"}.`,
  ioc_tocado: (d) => `${d.host ?? "Um ativo"} falou com ${d.ip ?? "um endereço"}, que está na inteligência de ameaças${d.descricao ? `: ${d.descricao}` : ""}.`,
  grupo_administrativo: (d) => `${d.membro ?? "Alguém"} entrou no grupo ${d.grupo ?? "administrativo"} em ${d.host ?? "um ativo"}${d.por ? `, por ${d.por}` : ""}.`,
  arquivo_sensivel: (d) => `${d.arquivo ?? "Um arquivo sensível"} mudou em ${d.host ?? "um ativo"}${d.quem ? `, por ${d.quem}` : ""}.`,
  conta_criada: (d) => `Conta ${d.conta ?? "nova"} criada em ${d.host ?? "um ativo"}.`,
  pessoa_em_risco: (d) => `${d.usuario ?? "Uma pessoa"} entrou com risco ${d.risco ?? "alto"}.`,
  ativo_em_risco: (d) => `Entrou em ${d.host ?? "um ativo"}, que estava com risco ${d.risco ?? "alto"}.`,
};

const tituloDoSinal = (tipo: string) => SINAIS[tipo] ?? tipo;

const MOTIVOS: Record<string, { texto: string; explica: string }> = {
  resolvido: { texto: "Era real e foi tratado", explica: "O risco zera. Nada é aprendido: se acontecer de novo, soma de novo." },
  falso_positivo: { texto: "Falso positivo", explica: "O risco zera, e o ativo, o IP e o privilégio deste alerta passam a ser normais para a pessoa." },
  esperado: { texto: "Esperado", explica: "Era uma mudança combinada, como troca de função. O risco zera e o que apareceu passa a ser normal." },
  risco_caiu: { texto: "Encerrado sozinho", explica: "O risco caiu abaixo da metade do limite." },
};
const PRAZOS = [{ value: "7", label: "Por 7 dias" }, { value: "30", label: "Por 30 dias" }, { value: "90", label: "Por 90 dias" }, { value: "", label: "Sem prazo" }];
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

function EncerrarRisco({ alerta, aoEncerrar }: { alerta: DadosDoRisco["alerta"]; aoEncerrar: () => void }) {
  const [aberto, setAberto] = useState(false);
  const [motivo, setMotivo] = useState("falso_positivo");
  const [nota, setNota] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const encerrar = async () => {
    setErro(null);
    const r = await enviar(`/api/riscos/${alerta.id}/decisao`, { motivo, nota });
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível encerrar."));
      return;
    }
    setAberto(false);
    aoEncerrar();
  };
  return (
    <>
      <Button size="xs" onClick={() => setAberto(true)}>Encerrar</Button>
      <Modal opened={aberto} onClose={() => setAberto(false)} title={`Encerrar o risco de ${alerta.entidade}`}>
        <Stack gap="sm">
          <Radio.Group value={motivo} onChange={setMotivo} label="O que era">
            <Stack gap="xs" mt={4}>
              {["falso_positivo", "esperado", "resolvido"].map((m) => <Radio key={m} value={m} label={MOTIVOS[m].texto} description={MOTIVOS[m].explica} />)}
            </Stack>
          </Radio.Group>
          <Textarea label="Nota" description="Opcional. Fica no risco e ajuda quem olhar depois." value={nota} onChange={(e) => setNota(e.currentTarget.value)} maxLength={500} autosize minRows={2} />
          {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={() => setAberto(false)}>Cancelar</Button>
            <Button variant="filled" onClick={encerrar}>Encerrar</Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

function Silencios({ entidade, nome, silencios, tipos, aoMudar }: { entidade: number; nome: string; silencios: Silencio[]; tipos: string[]; aoMudar: () => void }) {
  const eu = useEu();
  const pode = usePode();
  const [aberto, setAberto] = useState(false);
  const [tipo, setTipo] = useState<string | null>(tipos[0] ?? null);
  const [motivo, setMotivo] = useState("");
  const [prazo, setPrazo] = useState("30");
  const [erro, setErro] = useState<string | null>(null);
  const gerir = pode("gerir_regras");
  if (!silencios.length && !gerir) return null;
  const silenciar = async () => {
    setErro(null);
    const r = await enviar("/api/silencios", { tipo, entidade_id: entidade, motivo, dias: prazo ? Number(prazo) : null });
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível silenciar."));
      return;
    }
    setAberto(false);
    setMotivo("");
    aoMudar();
  };
  const remover = async (s: Silencio) => {
    const r = await pedir(`/api/silencios/${s.id}`, { method: "DELETE" });
    if (r.ok) aoMudar();
  };
  return (
    <div>
      <Group justify="space-between" mb="xs">
        <Title order={3}>Sinais silenciados</Title>
        {gerir && tipos.length > 0 && <Button size="xs" variant="subtle" onClick={() => setAberto(true)}>Silenciar um sinal</Button>}
      </Group>
      {!silencios.length ? <Text size="xs" c="dimmed">Nenhum. Todos os sinais somam para {nome}.</Text> : (
        <Stack gap={4}>
          {silencios.map((s) => (
            <Group key={s.id} justify="space-between" wrap="nowrap" gap="xs">
              <div style={{ minWidth: 0 }}>
                <Text size="sm" fw={500}>{tituloDoSinal(s.tipo)}</Text>
                <Text size="xs" c="dimmed">{s.motivo}. {s.criado_por_nome ?? "Alguém"}, {quando(s.criado_em, eu.fuso)}{s.expira_em ? `, até ${quando(s.expira_em, eu.fuso)}` : ", sem prazo"}.</Text>
              </div>
              {gerir && <Button size="xs" variant="subtle" color="red" onClick={() => remover(s)}>Tirar</Button>}
            </Group>
          ))}
        </Stack>
      )}
      <Modal opened={aberto} onClose={() => setAberto(false)} title={`Silenciar um sinal de ${nome}`}>
        <Stack gap="sm">
          <Text size="sm">O sinal deixa de somar no risco desta pessoa daqui para frente. O que já somou continua.</Text>
          <Select label="Sinal" data={tipos.map((t) => ({ value: t, label: tituloDoSinal(t) }))} value={tipo} onChange={setTipo} allowDeselect={false} />
          <TextInput label="Por quê" placeholder="Ex.: trabalha de madrugada no plantão" value={motivo} onChange={(e) => setMotivo(e.currentTarget.value)} maxLength={500} />
          <Select label="Prazo" data={PRAZOS} value={prazo} onChange={(v) => setPrazo(v ?? "")} allowDeselect={false} />
          {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={() => setAberto(false)}>Cancelar</Button>
            <Button variant="filled" onClick={silenciar} disabled={!tipo || !motivo.trim()}>Silenciar</Button>
          </Group>
        </Stack>
      </Modal>
    </div>
  );
}

function DetalheDoRisco({ id, aoAbrirEvento, aoAbrirEventos, aoEncerrar }: { id: number; aoAbrirEvento: (e: EventoResumo) => void; aoAbrirEventos: (f: FiltroDeEventos) => void; aoEncerrar: () => void }) {
  const eu = useEu();
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<DadosDoRisco>(`/api/riscos/${id}`);
  if (!dados) return <Carregando erro={erro ? "Este item não está mais disponível." : null} />;
  const { alerta, sinais, limites, pares, silencios } = dados;
  const tiposDosSinais = [...new Set(sinais.map((s) => s.tipo))];
  const atual = Math.round(Number(alerta.risco_atual));
  return (
    <Stack gap="md">
      <TopoDoDetalhe titulo={alerta.entidade} severidade={alerta.severidade} subtitulo={`${alerta.entidade_tipo === "ativo" ? `Ativo${alerta.criticidade && alerta.criticidade !== "normal" ? ` de criticidade ${CRITICIDADES[alerta.criticidade]?.texto.toLowerCase()}` : ""}` : "Usuário"}, aberto em ${quando(alerta.aberto_em, eu.fuso)}`}>
        <Button size="xs" onClick={() => aoAbrirEventos({ rotulo: `Eventos de ${alerta.entidade}`, consulta: { entidade: alerta.entidade } })}>Ver eventos</Button>
        <BotaoAutomatizar criar={() => rascunhoDeRisco(dados)} />
        {alerta.estado === "aberto" && pode("triar") && <EncerrarRisco alerta={alerta} aoEncerrar={aoEncerrar} />}
      </TopoDoDetalhe>
      {alerta.estado !== "aberto" && alerta.motivo && (
        <Alert color="gray" variant="light" p="xs">
          <Text size="sm" fw={500}>{MOTIVOS[alerta.motivo]?.texto ?? alerta.motivo}{alerta.encerrado_em ? `, em ${quando(alerta.encerrado_em, eu.fuso)}` : ""}{alerta.decidido_por_nome ? `, por ${alerta.decidido_por_nome}` : ""}.</Text>
          {alerta.nota && <Text size="sm">{alerta.nota}</Text>}
        </Alert>
      )}
      <div>
        <Group justify="space-between" mb={4}>
          <Text size="xs" c="dimmed" className="numero">Risco atual {numero(atual)}</Text>
          <Text size="xs" c="dimmed" className="numero">Máximo {numero(Math.round(Number(alerta.risco_maximo)))}</Text>
        </Group>
        <Progress size="sm" value={Math.min(100, atual)} color={corDaSeveridade(alerta.severidade)} aria-label="Risco atual" />
      </div>
      <div>
        <Title order={3} mb={2}>Como o risco chegou aqui</Title>
        <Text size="xs" c="dimmed" mb="xs">Cada sinal soma ao risco, e o risco cai pela metade a cada {numero(limites.meia_vida_horas)} h. Acima de {numero(limites.alto)} abre alerta; acima de {numero(limites.critico)}, crítico.</Text>
        {!sinais.length ? <Vazio>Nenhum sinal registrado.</Vazio> : <LinhaDoTempo sinais={sinais} limites={limites} fuso={eu.fuso} aoAbrirEvento={aoAbrirEvento} />}
      </div>
      <NormalDaEntidade entidade={alerta.entidade_id} nome={alerta.entidade} />
      {alerta.entidade_tipo === "usuario" && (
        <div>
          <Title order={3} mb={2}>Pares</Title>
          <Text size="xs" c="dimmed" mb="xs">Quem mais acessa os mesmos ativos. Quando a primeira vez de {alerta.entidade} já é rotina dos pares, soma menos.</Text>
          {!pares.length ? <Text size="xs" c="dimmed">Ainda sem pares: são calculados uma vez por dia, com quem divide ativos.</Text> : (
            <Group gap={6}>{pares.map((p) => <Badge key={p.entidade} size="sm" radius="sm" variant="light" color="gray" tt="none" fw={500}>{p.entidade} · {numero(Math.round(p.semelhanca * 100))}%</Badge>)}</Group>
          )}
        </div>
      )}
      <Silencios entidade={alerta.entidade_id} nome={alerta.entidade} silencios={silencios} tipos={tiposDosSinais} aoMudar={recarregar} />
    </Stack>
  );
}

function Fichas({ rotulo, itens, total }: { rotulo: string; itens: { texto: string; contagem: number }[]; total?: number }) {
  if (!itens.length) return null;
  const resto = (total ?? itens.length) - itens.length;
  return (
    <div>
      <Text size="xs" c="dimmed" mb={4}>{rotulo}</Text>
      <Group gap={6}>
        {itens.map((i) => <Badge key={i.texto} size="sm" radius="sm" variant="light" color="gray" tt="none" fw={500}>{i.texto} · {numero(i.contagem)}</Badge>)}
        {resto > 0 && <Text size="xs" c="dimmed">e mais {numero(resto)}</Text>}
      </Group>
    </div>
  );
}

function HorasDoNormal({ horas, conhecido }: { horas: NonNullable<DadosDoNormal["horas"]>; conhecido: boolean }) {
  const maior = Math.max(1, ...horas.map((h) => h.contagem));
  return (
    <div>
      <Text size="xs" c="dimmed" mb={4}>Horário dos acessos, na hora local da organização{conhecido ? ". As horas apagadas soam estranhas para o motor." : ". Ainda poucos acessos para dizer o que é estranho."}</Text>
      <Group gap={2} align="flex-end" wrap="nowrap" h={48} role="img" aria-label="Acessos por hora do dia">
        {horas.map((h) => (
          <Tooltip key={h.hora} label={`${String(h.hora).padStart(2, "0")}h: ${numero(h.contagem)} acesso${h.contagem === 1 ? "" : "s"}${h.incomum ? ", incomum" : ""}`}>
            <Box style={{ flex: 1, height: `${Math.max(4, (h.contagem / maior) * 100)}%`, borderRadius: 2,
              background: h.contagem ? "var(--mantine-color-rosa-5)" : "var(--mantine-color-dark-5)", opacity: h.incomum ? 0.35 : 1 }} />
          </Tooltip>
        ))}
      </Group>
      <Group justify="space-between" mt={2}>{[0, 6, 12, 18, 23].map((h) => <Text key={h} size="xs" c="dimmed">{String(h).padStart(2, "0")}h</Text>)}</Group>
    </div>
  );
}

function NormalDaEntidade({ entidade, nome }: { entidade: number; nome: string }) {
  const eu = useEu();
  const { dados, erro } = useDados<DadosDoNormal>(`/api/entidades/${entidade}/normal`);
  if (!dados) return <Carregando erro={erro} />;
  if (dados.pessoas) {
    return (
      <div>
        <Title order={3} mb={2}>Quem costuma entrar</Title>
        <Text size="xs" c="dimmed" mb="xs">Pessoas para quem {nome} já é rotina. Para elas, entrar aqui não é primeira vez.</Text>
        {!dados.pessoas.length ? <Text size="xs" c="dimmed">Ninguém ainda: nenhum acesso aprendido neste ativo.</Text>
          : <Fichas rotulo="Pessoa e acessos" itens={dados.pessoas.map((p) => ({ texto: p.usuario, contagem: p.contagem }))} total={dados.total_de_pessoas} />}
      </div>
    );
  }
  const aprendizado = dados.aprendizado;
  return (
    <div>
      <Title order={3} mb={2}>O normal de {nome}</Title>
      <Text size="xs" c="dimmed" mb="xs">
        {aprendizado?.aprendendo
          ? `Ainda aprendendo: primeira vez e horário só somam a partir de ${quando(aprendizado.ate, eu.fuso)}${aprendizado.acessos_faltando ? ` e depois de mais ${numero(aprendizado.acessos_faltando)} acessos` : ""}.`
          : `Aprendido com ${numero(dados.entidade.sucessos)} acessos desde ${quando(dados.entidade.primeira_vista, eu.fuso)}. Cada sinal de primeira vez é medido contra isto.`}
      </Text>
      <Stack gap="sm">
        {dados.horas && dados.total_de_acessos ? <HorasDoNormal horas={dados.horas} conhecido={!!dados.horario_conhecido} /> : null}
        <Fichas rotulo="Ativos" itens={(dados.ativos ?? []).map((a) => ({ texto: a.ativo, contagem: a.contagem }))} total={dados.total_de_ativos} />
        <Fichas rotulo="Endereços de origem" itens={(dados.ips ?? []).map((i) => ({ texto: i.ip, contagem: i.contagem }))} total={dados.total_de_ips} />
        <Fichas rotulo="Executa como outro usuário" itens={(dados.privilegios ?? []).map((p) => ({ texto: `${p.como} em ${p.ativo}`, contagem: p.contagem }))} total={dados.total_de_privilegios} />
        <Fichas rotulo="Cria contas em" itens={(dados.cria_conta ?? []).map((c) => ({ texto: c.ativo, contagem: c.contagem }))} />
        {!dados.total_de_acessos && !dados.total_de_ativos && <Text size="xs" c="dimmed">Nada aprendido ainda.</Text>}
      </Stack>
    </div>
  );
}

function corDoRisco(risco: number, limites: DadosDoRisco["limites"]) {
  if (risco >= limites.critico) return SEVERIDADES.critica.cor;
  if (risco >= limites.alto) return SEVERIDADES.alta.cor;
  return "var(--mantine-color-dark-2)";
}

function LinhaDoTempo({ sinais, limites, fuso, aoAbrirEvento }: { sinais: Sinal[]; limites: DadosDoRisco["limites"]; fuso?: string; aoAbrirEvento: (e: EventoResumo) => void }) {
  const escala = Math.max(limites.critico, ...sinais.map((s) => s.risco_depois)) * 1.1;
  return (
    <Stack gap={0}>
      {sinais.map((s, i) => {
        const anterior = sinais[i - 1];
        const cor = corDoRisco(s.risco_depois, limites);
        const cruzou = anterior && [limites.alto, limites.critico].find((l) => anterior.risco_depois < l && s.risco_depois >= l);
        return (
          <div key={`${s.evento_id}-${s.tipo}-${s.ocorrido_em}`}>
            {anterior && (
              <Text size="xs" c="dimmed" pl={18} py={2} style={{ borderLeft: "2px solid var(--roar-borda)", marginLeft: 5 }}>
                {duracao(new Date(s.ocorrido_em).getTime() - new Date(anterior.ocorrido_em).getTime())} depois
              </Text>
            )}
            <Group gap="xs" wrap="nowrap" align="flex-start">
              <Box mt={14} style={{ flex: "0 0 12px", height: 12, borderRadius: 6, background: cor }} aria-hidden />
              <UnstyledButton
                className="clicavel"
                p="xs"
                style={{ border: "1px solid var(--roar-borda)", borderRadius: 6, minWidth: 0 }}
                onClick={() => aoAbrirEvento({ id: s.evento_id, ocorrido_em: s.ocorrido_em, regra_descricao: s.regra_descricao, ativo: s.ativo, usuario: s.usuario, ip_origem: s.ip_origem })}
              >
                <Group justify="space-between" wrap="nowrap" gap="xs">
                  <Text size="sm" fw={500}>{tituloDoSinal(s.tipo)}</Text>
                  <Text size="xs" className="numero" fw={500}>+{numero(Math.round(Number(s.peso)))}</Text>
                </Group>
                <Text size="xs">{TEXTOS_DOS_SINAIS[s.tipo]?.(s.detalhes ?? {}) ?? s.regra_descricao ?? ""}</Text>
                {s.detalhes?.criticidade && <Text size="xs" c="dimmed">Ativo de criticidade {CRITICIDADES[s.detalhes.criticidade]?.texto.toLowerCase() ?? s.detalhes.criticidade}: pesa {CRITICIDADES[s.detalhes.criticidade]?.fator ?? "diferente"}.</Text>}
                {Number(s.detalhes?.pares) > 0 && <Text size="xs" c="dimmed">{s.detalhes?.pares === 1 ? "Um par já faz isto" : `${s.detalhes?.pares} pares já fazem isto`}: soma menos.</Text>}
                {s.tecnica && (
                  <Tooltip label={`${s.tecnica.codigo}, ${s.tecnica.nome}`}>
                    <Badge mt={4} size="sm" radius="sm" variant="light" color="gray" tt="none" fw={500}>{nomeDaTatica(s.tecnica.tatica)}: {s.tecnica.nome}</Badge>
                  </Tooltip>
                )}
                <Group gap="xs" mt={6} wrap="nowrap">
                  <Progress size="xs" style={{ flex: 1 }} value={(s.risco_depois / escala) * 100} color={cor} aria-label="Risco depois do sinal" />
                  <Text size="xs" className="numero" fw={500} c={cruzou ? cor : undefined}>{numero(Math.round(s.risco_depois))}</Text>
                </Group>
                {cruzou && <Text size="xs" fw={500} c={cor}>Aqui passou de {numero(cruzou)}{cruzou === limites.critico ? " e ficou crítico" : " e abriu o alerta"}.</Text>}
                <Text size="xs" c="dimmed">{quando(s.ocorrido_em, fuso)}, {s.regra_descricao ?? "evento"}{s.pais ? `, ${s.pais}` : ""}</Text>
              </UnstyledButton>
            </Group>
          </div>
        );
      })}
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
      {eventos[0] && <PainelDeContexto evento={eventos[0].id} />}
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
      ? <DetalheDoRisco key={`r${selecionado.id}-${versao}`} id={selecionado.id} aoAbrirEvento={setEvento} aoAbrirEventos={setFiltro} aoEncerrar={() => { setSelecionado(null); recarregar(); }} />
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
