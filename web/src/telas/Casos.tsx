import { Alert, Badge, Button, Drawer, Group, Modal, Radio, SegmentedControl, Select, Stack, Text, Textarea, TextInput, Title } from "@mantine/core";
import { useState } from "react";

import { detalhe, enviar, pedir, useDados, useEu, usePode } from "../api";
import { AcoesDaLinha, Cabecalho, Carregando, Data, Estado, Painel, Severidade, Tabela, Vazio } from "../componentes";
import { numero, quando } from "../formato";
import { EvidenciasDoCaso, FatosEHipoteses, PassarPlantao, ResumoDoPlantao, TIPOS_DE_NOTA, type EvidenciaDoCaso, type NotaDoCaso } from "./CasosParte2";

interface Responsavel { id: string; nome: string }
interface ResumoDoCaso {
  id: number; titulo: string; severidade: string; estado: string; desfecho: string | null; responsavel_nome: string | null;
  criado_por_nome: string; criado_em: string; atualizado_em: string; prazo: string; encerrado_em: string | null; atrasado: boolean;
  itens: number; notas: number;
}
interface ItemDoCaso {
  tipo: "grupo" | "risco" | "evento"; id: number; severidade: string; quando: string; adicionado_por_nome: string;
  descricao?: string | null; ativo?: string | null; regras?: string[]; total?: number; ip_origem?: string | null; usuario?: string | null;
  entidade?: string; entidade_tipo?: string; risco_maximo?: number; estado?: string;
}
interface DadosDoCaso { caso: ResumoDoCaso & { responsavel_id: string | null }; itens: ItemDoCaso[]; notas: NotaDoCaso[]; evidencias: EvidenciaDoCaso[]; responsaveis: Responsavel[] }

const SEVERIDADES = [{ value: "critica", label: "Crítica" }, { value: "alta", label: "Alta" }, { value: "media", label: "Média" }, { value: "baixa", label: "Baixa" }];
const ESTADOS: Record<string, { texto: string; tipo: string }> = {
  aberto: { texto: "Aberto", tipo: "pendente" }, investigando: { texto: "Investigando", tipo: "ativo" }, encerrado: { texto: "Encerrado", tipo: "outro" },
};
const DESFECHOS: Record<string, { texto: string; explica: string }> = {
  incidente: { texto: "Incidente confirmado", explica: "Foi um ataque ou uma falha de segurança de verdade." },
  falso_positivo: { texto: "Falso positivo", explica: "Os alertas não indicavam nada de errado." },
  sem_acao: { texto: "Sem ação necessária", explica: "Era real, mas não pedia nada: teste, mudança planejada ou risco aceito." },
};
const TIPOS_DE_ITEM: Record<string, string> = { grupo: "Alerta", risco: "Risco", evento: "Evento" };

async function mandar(rota: string, metodo: string, corpo: unknown) {
  return pedir(rota, { method: metodo, headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo) });
}

function Prazo({ caso }: { caso: ResumoDoCaso }) {
  if (caso.estado === "encerrado") return <Text size="sm" c="dimmed">{caso.desfecho ? DESFECHOS[caso.desfecho]?.texto : "-"}</Text>;
  return caso.atrasado ? <Estado tipo="problema">Atrasado</Estado> : <Data valor={caso.prazo} />;
}

function textoDoItem(i: ItemDoCaso) {
  if (i.tipo === "risco") return `${i.entidade_tipo === "ativo" ? "Ativo" : "Pessoa"} ${i.entidade}, risco ${numero(Math.round(Number(i.risco_maximo)))}`;
  if (i.tipo === "grupo") return `${i.descricao ?? `Regra ${i.regras?.join(", ")}`}${i.ativo ? ` em ${i.ativo}` : ""}, ${numero(Number(i.total))} vez${Number(i.total) === 1 ? "" : "es"}`;
  return `${i.descricao ?? "Evento"}${i.ativo ? ` em ${i.ativo}` : ""}${i.usuario ? `, ${i.usuario}` : ""}`;
}

function EncerrarCaso({ caso, aoMudar }: { caso: ResumoDoCaso; aoMudar: () => void }) {
  const [aberto, setAberto] = useState(false);
  const [desfecho, setDesfecho] = useState("incidente");
  const [nota, setNota] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const encerrar = async () => {
    setErro(null);
    if (nota.trim()) {
      const r = await enviar(`/api/casos/${caso.id}/notas`, { texto: nota });
      if (!r.ok) return setErro(await detalhe(r));
    }
    const r = await mandar(`/api/casos/${caso.id}`, "PATCH", { estado: "encerrado", desfecho });
    if (!r.ok) return setErro(await detalhe(r, "Não foi possível encerrar."));
    setAberto(false);
    aoMudar();
  };
  return (
    <>
      <Button size="xs" onClick={() => setAberto(true)}>Encerrar</Button>
      <Modal opened={aberto} onClose={() => setAberto(false)} title={`Encerrar o caso ${caso.id}`}>
        <Stack gap="sm">
          <Radio.Group value={desfecho} onChange={setDesfecho} label="Como terminou">
            <Stack gap="xs" mt={4}>
              {Object.entries(DESFECHOS).map(([valor, d]) => <Radio key={valor} value={valor} label={d.texto} description={d.explica} />)}
            </Stack>
          </Radio.Group>
          <Textarea label="Conclusão" description="Opcional. Entra no histórico do caso." value={nota} onChange={(e) => setNota(e.currentTarget.value)} maxLength={4000} autosize minRows={2} />
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

function DetalheDoCaso({ id, aoMudar }: { id: number; aoMudar: () => void }) {
  const eu = useEu();
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<DadosDoCaso>(`/api/casos/${id}`);
  const [nota, setNota] = useState("");
  const [tipoDaNota, setTipoDaNota] = useState("nota");
  const [falha, setFalha] = useState<string | null>(null);
  if (!dados) return <Carregando erro={erro ? "Este caso não está mais disponível." : null} />;
  const { caso, itens, notas, evidencias, responsaveis } = dados;
  const triar = pode("triar");
  const atualizar = () => { recarregar(); aoMudar(); };
  const mudar = async (corpo: Record<string, string>) => {
    setFalha(null);
    const r = await mandar(`/api/casos/${caso.id}`, "PATCH", corpo);
    if (!r.ok) return setFalha(await detalhe(r));
    atualizar();
  };
  const anotar = async () => {
    setFalha(null);
    const r = await enviar(`/api/casos/${caso.id}/notas`, { texto: nota, tipo: tipoDaNota });
    if (!r.ok) return setFalha(await detalhe(r));
    setNota("");
    atualizar();
  };
  const tirar = async (i: ItemDoCaso) => {
    if ((await pedir(`/api/casos/${caso.id}/itens/${i.tipo}/${i.id}`, { method: "DELETE" })).ok) atualizar();
  };
  const encerrado = caso.estado === "encerrado";
  return (
    <Stack gap="md">
      <Group gap="xs">
        <Severidade valor={caso.severidade} />
        <Estado tipo={ESTADOS[caso.estado]?.tipo ?? "outro"}>{ESTADOS[caso.estado]?.texto ?? caso.estado}</Estado>
        {caso.atrasado && <Estado tipo="problema">Atrasado</Estado>}
      </Group>
      <Text size="xs" c="dimmed">
        Aberto por {caso.criado_por_nome} em {quando(caso.criado_em, eu.fuso)}.{" "}
        {encerrado ? `Encerrado em ${quando(caso.encerrado_em ?? caso.atualizado_em, eu.fuso)}: ${DESFECHOS[caso.desfecho ?? ""]?.texto.toLowerCase() ?? ""}.`
          : `Prazo: ${quando(caso.prazo, eu.fuso)}, pela severidade.`}
      </Text>
      {triar && (
        <Group gap="sm" align="flex-end">
          <Select label="Responsável" size="xs" w={200} clearable placeholder="Ninguém" value={caso.responsavel_id}
            data={responsaveis.map((r) => ({ value: r.id, label: r.nome }))} onChange={(v) => mudar({ responsavel_id: v ?? "" })} />
          <Select label="Severidade" size="xs" w={120} allowDeselect={false} value={caso.severidade} data={SEVERIDADES} onChange={(v) => v && mudar({ severidade: v })} />
          {!encerrado && caso.estado === "aberto" && <Button size="xs" variant="default" onClick={() => mudar({ estado: "investigando" })}>Começar a investigar</Button>}
          {!encerrado && <PassarPlantao casoId={caso.id} responsaveis={responsaveis} aoMudar={atualizar} />}
          {!encerrado && <EncerrarCaso caso={caso} aoMudar={atualizar} />}
          {encerrado && <Button size="xs" variant="default" onClick={() => mudar({ estado: "investigando" })}>Reabrir</Button>}
        </Group>
      )}
      {falha && <Alert color="red" variant="light" p="xs" fz="sm">{falha}</Alert>}

      <div>
        <Title order={3} mb="xs">Itens</Title>
        {!itens.length ? <Vazio>Nenhum item. Use "Pôr num caso" no detalhe de um alerta ou risco da Fila.</Vazio> : (
          <Stack gap={6}>
            {itens.map((i) => (
              <Group key={`${i.tipo}-${i.id}`} justify="space-between" wrap="nowrap" gap="xs" p="xs" style={{ border: "1px solid var(--roar-borda)", borderRadius: 6 }}>
                <Stack gap={2} style={{ minWidth: 0 }}>
                  <Group gap={6}>
                    <Badge size="sm" radius="sm" variant="light" color="gray" tt="none" fw={500}>{TIPOS_DE_ITEM[i.tipo]} {i.id}</Badge>
                    <Severidade valor={i.severidade} />
                  </Group>
                  <Text size="sm" style={{ overflowWrap: "anywhere" }}>{textoDoItem(i)}</Text>
                  <Text size="xs" c="dimmed">{quando(i.quando, eu.fuso)}, incluído por {i.adicionado_por_nome}</Text>
                </Stack>
                {triar && <AcoesDaLinha rotulo="Ações do item" itens={[{ texto: "Tirar do caso", perigo: true, aoClicar: () => tirar(i) }]} />}
              </Group>
            ))}
          </Stack>
        )}
      </div>

      <FatosEHipoteses casoId={caso.id} notas={notas} aoMudar={atualizar} />
      <EvidenciasDoCaso casoId={caso.id} evidencias={evidencias} aoMudar={atualizar} encerrado={encerrado} />

      <div>
        <Title order={3} mb="xs">Histórico</Title>
        <Stack gap={8}>
          {notas.map((n) => (
            <div key={n.id}>
              <Group gap={6}>
                <Text size="xs" c="dimmed">{quando(n.criado_em, eu.fuso)} · {n.autor_nome}</Text>
                {n.tipo !== "nota" && <Badge size="xs" radius="sm" variant="light" color={TIPOS_DE_NOTA[n.tipo]?.cor ?? "gray"} tt="none">{TIPOS_DE_NOTA[n.tipo]?.texto ?? n.tipo}</Badge>}
              </Group>
              <Text size="sm" c={n.automatica ? "dimmed" : undefined} fs={n.automatica ? "italic" : undefined} style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{n.texto}</Text>
            </div>
          ))}
          {!notas.length && <Text size="xs" c="dimmed">Nada anotado ainda.</Text>}
          {triar && (
            <Stack gap={6}>
              <SegmentedControl size="xs" value={tipoDaNota} onChange={setTipoDaNota}
                data={[{ value: "nota", label: "Nota" }, { value: "fato", label: "Fato: o que foi visto" }, { value: "hipotese", label: "Hipótese: o que se acha" }]} />
              <Textarea placeholder={tipoDaNota === "fato" ? "Ex.: a conta admin entrou de 203.0.113.9 às 02:14" : tipoDaNota === "hipotese" ? "Ex.: a senha vazou no phishing de ontem" : "O que você viu ou fez"}
                value={nota} onChange={(e) => setNota(e.currentTarget.value)} maxLength={4000} autosize minRows={2} />
              <Group justify="flex-end"><Button size="xs" disabled={!nota.trim()} onClick={anotar}>Anotar</Button></Group>
            </Stack>
          )}
        </Stack>
      </div>
    </Stack>
  );
}

export function PorNumCaso({ tipo, id, titulo, severidade }: { tipo: "grupo" | "risco" | "evento"; id: number; titulo: string; severidade: string }) {
  const pode = usePode();
  const [aberto, setAberto] = useState(false);
  if (!pode("triar")) return null;
  return (
    <>
      <Button size="xs" variant="default" onClick={() => setAberto(true)}>Pôr num caso</Button>
      {aberto && <JanelaDoCaso tipo={tipo} id={id} titulo={titulo} severidade={severidade} aoFechar={() => setAberto(false)} />}
    </>
  );
}

function JanelaDoCaso({ tipo, id, titulo, severidade, aoFechar }: { tipo: "grupo" | "risco" | "evento"; id: number; titulo: string; severidade: string; aoFechar: () => void }) {
  const { dados: abertos } = useDados<{ casos: ResumoDoCaso[] }>("/api/casos");
  const { dados: onde } = useDados<{ casos: { id: number; titulo: string; estado: string }[] }>(`/api/casos/do-item?tipo=${tipo}&id=${id}`);
  const [modo, setModo] = useState("novo");
  const [novoTitulo, setNovoTitulo] = useState(titulo.slice(0, 200));
  const [novaSeveridade, setNovaSeveridade] = useState(SEVERIDADES.some((s) => s.value === severidade) ? severidade : "media");
  const [existente, setExistente] = useState<string | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [feito, setFeito] = useState<number | null>(null);
  const confirmar = async () => {
    setErro(null);
    const r = modo === "novo"
      ? await enviar("/api/casos", { titulo: novoTitulo, severidade: novaSeveridade, itens: [{ tipo, id }] })
      : await enviar(`/api/casos/${existente}/itens`, { tipo, id });
    if (!r.ok) return setErro(await detalhe(r));
    setFeito(modo === "novo" ? (await r.json()).id : Number(existente));
  };
  return (
    <Modal opened onClose={aoFechar} title="Pôr num caso">
      {feito ? (
        <Stack gap="sm">
          <Text size="sm">Pronto: está no caso {feito}. Ele aparece em Casos, no menu.</Text>
          <Group justify="flex-end"><Button onClick={aoFechar}>Fechar</Button></Group>
        </Stack>
      ) : (
        <Stack gap="sm">
          {!!onde?.casos.length && (
            <Alert variant="light" color="gray" p="xs" fz="sm">Já está em: {onde.casos.map((c) => `caso ${c.id} (${c.titulo}${c.estado === "encerrado" ? ", encerrado" : ""})`).join("; ")}.</Alert>
          )}
          <SegmentedControl size="xs" value={modo} onChange={setModo} data={[{ value: "novo", label: "Caso novo" }, { value: "existente", label: "Caso aberto" }]} />
          {modo === "novo" ? (
            <>
              <TextInput label="Título" value={novoTitulo} onChange={(e) => setNovoTitulo(e.currentTarget.value)} maxLength={200} />
              <Select label="Severidade" description="Define o prazo: crítica 4 h, alta 24 h, média 3 dias, baixa 7 dias." allowDeselect={false}
                value={novaSeveridade} data={SEVERIDADES} onChange={(v) => v && setNovaSeveridade(v)} />
            </>
          ) : (
            <Select label="Caso" placeholder={abertos?.casos.length ? "Escolha" : "Nenhum caso aberto"} searchable value={existente} onChange={setExistente}
              data={(abertos?.casos ?? []).map((c) => ({ value: String(c.id), label: `${c.id} · ${c.titulo}` }))} />
          )}
          {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
            <Button variant="filled" disabled={modo === "novo" ? !novoTitulo.trim() : !existente} onClick={confirmar}>{modo === "novo" ? "Abrir caso" : "Incluir"}</Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}

export function Casos() {
  const [estado, setEstado] = useState("abertos");
  const { dados, erro, recarregar } = useDados<{ casos: ResumoDoCaso[] }>(`/api/casos?estado=${estado}`);
  const [aberto, setAberto] = useState<ResumoDoCaso | null>(null);
  const atrasados = dados?.casos.filter((c) => c.atrasado).length ?? 0;
  return (
    <>
      <Cabecalho titulo="Casos" ajuda="Cada caso junta os alertas, riscos e eventos de um mesmo incidente, com responsável, prazo e histórico. Abra um caso pelo botão &quot;Pôr num caso&quot; na Fila." />
      <Painel titulo={estado === "abertos" ? `Em andamento${atrasados ? ` · ${numero(atrasados)} atrasado${atrasados === 1 ? "" : "s"}` : ""}` : "Encerrados"}
        acao={<Group gap="xs"><ResumoDoPlantao /><SegmentedControl size="xs" value={estado} onChange={setEstado} data={[{ value: "abertos", label: "Em andamento" }, { value: "encerrados", label: "Encerrados" }]} /></Group>}>
        {!dados ? <Carregando erro={erro} /> : (
          <Tabela
            linhas={dados.casos}
            chave={(c) => c.id}
            vazio={estado === "abertos" ? "Nenhum caso em andamento." : "Nenhum caso encerrado."}
            aoClicarLinha={setAberto}
            colunas={[
              { titulo: "Caso", largura: 70, celula: (c) => <span className="numero">{c.id}</span> },
              { titulo: "Título", celula: (c) => <Text size="sm" fw={500}>{c.titulo}</Text> },
              { titulo: "Severidade", largura: 110, celula: (c) => <Severidade valor={c.severidade} /> },
              { titulo: "Estado", largura: 120, celula: (c) => <Estado tipo={ESTADOS[c.estado]?.tipo ?? "outro"}>{ESTADOS[c.estado]?.texto ?? c.estado}</Estado> },
              { titulo: "Responsável", celula: (c) => c.responsavel_nome ?? <Text size="sm" c="dimmed">Ninguém</Text> },
              { titulo: estado === "abertos" ? "Prazo" : "Desfecho", largura: 160, celula: (c) => <Prazo caso={c} /> },
              { titulo: "Itens", alinhar: "right", largura: 70, celula: (c) => numero(Number(c.itens)) },
            ]}
          />
        )}
      </Painel>
      <Drawer opened={aberto !== null} onClose={() => setAberto(null)} title={aberto ? `Caso ${aberto.id}: ${aberto.titulo}` : ""} size="lg">
        {aberto && <DetalheDoCaso id={aberto.id} aoMudar={recarregar} />}
      </Drawer>
    </>
  );
}
