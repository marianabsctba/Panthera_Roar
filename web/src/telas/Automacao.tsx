import { Alert, Badge, Box, Button, Drawer, Group, SimpleGrid, Stack, Tabs, Text, Textarea, Title } from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { useState, type ReactNode } from "react";

import { detalhe, enviar, useDados, usePode } from "../api";
import { AcoesDaLinha, Cabecalho, Carregando, Data, Estado, Painel, Tabela } from "../componentes";
import { numero } from "../formato";
import { contarAcoes, descreverCondicao, descreverGatilho, EditorDePlaybook, NOMES_DE_ACAO, type AberturaDoPlaybook, type Bloco, type Definicao } from "./AutomacaoEditor";

interface Playbook { id: number; nome: string; ativo: boolean; definicao: Definicao; intervalo_minutos: number; criado_em: string; alterado_em: string | null; execucoes: number }
interface Passo { acao?: string; erro?: string; aprovacao?: string; resultado?: { enviado?: string } }
interface Execucao {
  id: number; playbook_id: number; playbook: string; origem_tipo: string; origem_id: number | string | null; alvo: string | null; agente_id: string | null; titulo: string | null;
  estado: string; resultado: Passo[] | unknown; criada_em: string; concluida_em: string | null; bloqueio_confirmado: boolean;
}
interface Aprovacao { id: number; execucao_id: number; descricao: string | null; estado: string; motivo: string | null; criada_em: string; decidida_em: string | null; decidida_por: string | null; alvo: string | null; titulo: string | null; playbook: string }
interface Dados { playbooks: Playbook[]; execucoes: Execucao[]; aprovacoes: Aprovacao[] }

const ESTADOS_DE_EXECUCAO: Record<string, string> = { nova: "Iniciando", executando: "Executando", aguardando_aprovacao: "Aguardando decisão", concluida: "Concluída", falhou: "Falhou", recusada: "Recusada" };
const TIPO_DA_EXECUCAO: Record<string, string> = { nova: "outro", executando: "outro", aguardando_aprovacao: "pendente", concluida: "pronto", falhou: "problema", recusada: "recusada" };
const ESTADOS_DE_APROVACAO: Record<string, string> = { pendente: "Aguardando", aprovada: "Aprovada", recusada: "Recusada", expirada: "Ninguém decidiu a tempo" };
const TIPO_DA_APROVACAO: Record<string, string> = { pendente: "pendente", aprovada: "aplicada", recusada: "recusada" };
const ORIGENS: Record<string, string> = { evento: "Alerta de regra", risco: "Risco", indicador: "Indicador de ameaça" };

function descreverAcoes(texto: string | null) {
  return (texto ?? "").split(",").filter(Boolean).map((a) => NOMES_DE_ACAO[a] ?? a).join(", ") || "Nenhuma ação";
}

function passosDoResultado(x: Execucao) {
  const partes: string[] = [];
  for (const p of (Array.isArray(x.resultado) ? x.resultado : []) as Passo[]) {
    if (p.erro) partes.push(`${NOMES_DE_ACAO[p.acao ?? ""] ?? p.acao}: ${p.erro}`);
    else if (p.acao === "bloquear_ip") partes.push(x.bloqueio_confirmado ? "Bloqueio confirmado pelo ativo" : "Bloqueio enviado, sem confirmação do ativo ainda");
    else if (p.acao === "desativar_conta") partes.push(`Desativação da conta ${p.resultado?.enviado ?? ""} enviada ao ativo, sem confirmação`);
    else if (p.acao) partes.push(`${NOMES_DE_ACAO[p.acao] ?? p.acao}: feito`);
    else if (p.aprovacao) partes.push(({ aprovada: "Aprovada", recusada: "Recusada", expirada: "Ninguém decidiu a tempo" } as Record<string, string>)[p.aprovacao] ?? p.aprovacao);
  }
  return partes;
}

function Fato({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return (
    <div>
      <Text size="xs" c="dimmed">{rotulo}</Text>
      <Text size="sm" component="div">{children}</Text>
    </div>
  );
}

// ------------------------------------------------------------------ execuções

function TabelaDeExecucoes({ linhas, decisores, aoAbrir }: { linhas: Execucao[]; decisores: Map<number, string>; aoAbrir: (x: Execucao) => void }) {
  return (
    <Tabela
      linhas={linhas}
      chave={(x) => x.id}
      vazio="Nenhuma execução ainda."
      aoClicarLinha={aoAbrir}
      colunas={[
        { titulo: "Quando", largura: 150, celula: (x) => <Data valor={x.criada_em} /> },
        { titulo: "Playbook", celula: (x) => x.playbook },
        { titulo: "Alvo", celula: (x) => <span className="mono">{x.alvo ?? "-"}</span> },
        { titulo: "Estado", celula: (x) => <Estado tipo={TIPO_DA_EXECUCAO[x.estado] ?? "outro"}>{ESTADOS_DE_EXECUCAO[x.estado] ?? x.estado}</Estado> },
        { titulo: "Decidido por", celula: (x) => decisores.get(x.id) ?? "-" },
        { titulo: "Resultado", celula: (x) => <Text size="xs" lineClamp={2}>{passosDoResultado(x).join(", ") || "-"}</Text> },
      ]}
    />
  );
}

function GavetaDaExecucao({ execucao: x, decisores, aoFechar }: { execucao: Execucao | null; decisores: Map<number, string>; aoFechar: () => void }) {
  const pode = usePode();
  const [bruto, setBruto] = useState<number | null>(null);
  const { dados: alerta, erro: erroDoAlerta } = useDados<{ bruto: unknown }>(bruto === null ? null : `/api/eventos/${bruto}/bruto`);
  const passos = x ? passosDoResultado(x) : [];
  return (
    <>
      <Drawer opened={x !== null} onClose={aoFechar} title={x ? `Execução de ${x.playbook}` : ""} size="lg" zIndex={300}>
        {x && (
          <Stack gap="md">
            <Group gap="sm"><Estado tipo={TIPO_DA_EXECUCAO[x.estado] ?? "outro"}>{ESTADOS_DE_EXECUCAO[x.estado] ?? x.estado}</Estado></Group>
            {x.titulo && <Text size="sm">{x.titulo}</Text>}
            <SimpleGrid cols={2} spacing="sm">
              <Fato rotulo="Alvo"><span className="mono">{x.alvo ?? "-"}</span></Fato>
              <Fato rotulo="Ativo"><span className="mono">{x.agente_id ?? "-"}</span></Fato>
              <Fato rotulo="O que disparou">{ORIGENS[x.origem_tipo] ?? x.origem_tipo}</Fato>
              <Fato rotulo="Decidido por">{decisores.get(x.id) ?? "-"}</Fato>
              <Fato rotulo="Começou em"><Data valor={x.criada_em} /></Fato>
              <Fato rotulo="Terminou em"><Data valor={x.concluida_em} /></Fato>
            </SimpleGrid>
            <div>
              <Title order={3} mb={4}>Resultado</Title>
              {passos.length ? <Stack gap={4}>{passos.map((p, i) => <Text key={i} size="sm">{p}</Text>)}</Stack> : <Text size="sm" c="dimmed">Sem resultado ainda.</Text>}
            </div>
            {x.origem_tipo === "evento" && x.origem_id !== null && pode("ver_bruto") && <Group><Button onClick={() => setBruto(Number(x.origem_id))}>Ver o alerta que disparou</Button></Group>}
          </Stack>
        )}
      </Drawer>
      {/* A gaveta comum abre por baixo desta, que já está sobre a do playbook. */}
      <Drawer opened={bruto !== null} onClose={() => setBruto(null)} title="Alerta como chegou" zIndex={400}>
        {alerta ? <Box component="pre" className="mono" m={0} style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(alerta.bruto, null, 2)}</Box> : <Carregando erro={erroDoAlerta} />}
      </Drawer>
    </>
  );
}

// ------------------------------------------------------------------ aprovações

function GavetaDaAprovacao({ aprovacao: a, aoFechar, aoDecidir }: { aprovacao: Aprovacao | null; aoFechar: () => void; aoDecidir: (a: Aprovacao, decisao: "aprovar" | "recusar", motivo: string) => void }) {
  const pode = usePode();
  const [motivo, setMotivo] = useState("");
  const decidir = (decisao: "aprovar" | "recusar") => {
    if (!a) return;
    aoDecidir(a, decisao, motivo);
    setMotivo("");
  };
  return (
    <Drawer opened={a !== null} onClose={aoFechar} title={a?.playbook ?? ""} size="lg">
      {a && (
        <Stack gap="md">
          <Group gap="sm"><Estado tipo={TIPO_DA_APROVACAO[a.estado] ?? "outro"}>{ESTADOS_DE_APROVACAO[a.estado] ?? a.estado}</Estado></Group>
          {a.titulo && <Text size="sm">{a.titulo}</Text>}
          <SimpleGrid cols={2} spacing="sm">
            <Fato rotulo="Alvo"><span className="mono">{a.alvo ?? "-"}</span></Fato>
            <Fato rotulo="Vai fazer">{descreverAcoes(a.descricao)}</Fato>
            <Fato rotulo="Pedida em"><Data valor={a.criada_em} /></Fato>
            {a.decidida_em && <Fato rotulo="Decidida em"><Data valor={a.decidida_em} /></Fato>}
            {a.decidida_por && <Fato rotulo="Decidida por">{a.decidida_por}</Fato>}
            {a.motivo && <Fato rotulo="Motivo">{a.motivo}</Fato>}
          </SimpleGrid>
          {a.estado === "pendente" && (pode("aprovar") ? (
            <>
              <Alert color="yellow" variant="light" p="xs">Confira o alvo antes de aprovar: a origem de um log pode ter sido forjada.</Alert>
              <Textarea label="Motivo (opcional)" maxLength={500} autosize minRows={2} value={motivo} onChange={(e) => setMotivo(e.currentTarget.value)} />
              <Group justify="flex-end" gap="xs">
                <Button onClick={() => decidir("recusar")}>Recusar</Button>
                <Button variant="filled" onClick={() => decidir("aprovar")}>Aprovar</Button>
              </Group>
            </>
          ) : <Text size="sm" c="dimmed">Seu perfil não decide.</Text>)}
        </Stack>
      )}
    </Drawer>
  );
}

function Aprovacoes({ aprovacoes, aoDecidir }: { aprovacoes: Aprovacao[]; aoDecidir: (a: Aprovacao, decisao: "aprovar" | "recusar", motivo: string) => void }) {
  const pode = usePode();
  const [aberta, setAberta] = useState<Aprovacao | null>(null);
  const pendentes = aprovacoes.filter((a) => a.estado === "pendente");
  const decididas = aprovacoes.filter((a) => a.estado !== "pendente");
  return (
    <Stack gap="md">
      <Painel titulo="Aguardando sua decisão">
        <Tabela
          linhas={pendentes}
          chave={(a) => a.id}
          vazio="Nenhuma decisão pendente."
          aoClicarLinha={setAberta}
          colunas={[
            { titulo: "Quando", largura: 150, celula: (a) => <Data valor={a.criada_em} /> },
            { titulo: "Playbook", celula: (a) => a.playbook },
            { titulo: "O que aconteceu", celula: (a) => a.titulo ?? "-" },
            { titulo: "Alvo", celula: (a) => <span className="mono">{a.alvo ?? "-"}</span> },
            { titulo: "Vai fazer", celula: (a) => descreverAcoes(a.descricao) },
            { titulo: "", largura: 40, celula: (a) => <AcoesDaLinha rotulo="Decidir" itens={pode("aprovar") ? [{ texto: "Aprovar", aoClicar: () => aoDecidir(a, "aprovar", "") }, { texto: "Recusar", aoClicar: () => aoDecidir(a, "recusar", "") }] : []} /> },
          ]}
        />
      </Painel>
      <Painel titulo="Já decididas">
        <Tabela
          linhas={decididas}
          chave={(a) => a.id}
          vazio="Nenhuma decisão ainda."
          aoClicarLinha={setAberta}
          colunas={[
            { titulo: "Pedida em", largura: 150, celula: (a) => <Data valor={a.criada_em} /> },
            { titulo: "Playbook", celula: (a) => a.playbook },
            { titulo: "Alvo", celula: (a) => <span className="mono">{a.alvo ?? "-"}</span> },
            { titulo: "Decisão", celula: (a) => <Estado tipo={TIPO_DA_APROVACAO[a.estado] ?? "outro"}>{ESTADOS_DE_APROVACAO[a.estado] ?? a.estado}</Estado> },
            { titulo: "Por", celula: (a) => a.decidida_por ?? "-" },
            { titulo: "Decidida em", largura: 150, celula: (a) => <Data valor={a.decidida_em} /> },
          ]}
        />
      </Painel>
      <GavetaDaAprovacao aprovacao={aberta} aoFechar={() => setAberta(null)} aoDecidir={(a, d, m) => { setAberta(null); aoDecidir(a, d, m); }} />
    </Stack>
  );
}

// ------------------------------------------------------------------ playbooks

function ResumoDosBlocos({ blocos }: { blocos: Bloco[] }) {
  if (!blocos.length) return <Text size="sm" c="dimmed">Nada.</Text>;
  return (
    <Stack gap={4}>
      {blocos.map((b, i) => {
        if (b.tipo === "aprovacao") return <Text key={i} size="sm">Pedir aprovação</Text>;
        if (b.tipo === "acao") return <Text key={i} size="sm">{NOMES_DE_ACAO[b.acao] ?? b.acao}</Text>;
        if (b.tipo === "se") {
          return (
            <Box key={i}>
              <Text size="sm">{`Se ${descreverCondicao(b.condicao).toLowerCase()}`}</Text>
              <Box pl="sm" my={2} style={{ borderLeft: "2px solid var(--roar-borda)" }}><ResumoDosBlocos blocos={b.entao} /></Box>
              {(b.senao ?? []).length > 0 && <><Text size="sm">Senão</Text><Box pl="sm" my={2} style={{ borderLeft: "2px solid var(--roar-borda)" }}><ResumoDosBlocos blocos={b.senao ?? []} /></Box></>}
            </Box>
          );
        }
        return (
          <Box key={i}>
            <Text size="sm">Ao mesmo tempo</Text>
            {b.ramos.map((r, j) => <Box key={j} pl="sm" my={2} style={{ borderLeft: "2px solid var(--roar-borda)" }}><ResumoDosBlocos blocos={r} /></Box>)}
          </Box>
        );
      })}
    </Stack>
  );
}

const pedeAprovacao = (p: Playbook) => JSON.stringify(p.definicao.blocos).includes('"aprovacao"');

function Playbooks({ dados, decisores, aoEditar, aoLigar, aoAbrirExecucao }: { dados: Dados; decisores: Map<number, string>; aoEditar: (p: Playbook) => void; aoLigar: (p: Playbook) => void; aoAbrirExecucao: (x: Execucao) => void }) {
  const pode = usePode();
  const gerir = pode("gerir_playbooks");
  const [abertoId, setAbertoId] = useState<number | null>(null);
  const aberto = dados.playbooks.find((p) => p.id === abertoId) ?? null;
  return (
    <Painel p={0}>
      <Tabela
        linhas={dados.playbooks}
        chave={(p) => p.id}
        vazio="Nenhum playbook criado. Comece por um modelo, ou abra um alerta e clique em Automatizar isto."
        aoClicarLinha={(p) => setAbertoId(p.id)}
        colunas={[
          { titulo: "Nome", celula: (p) => <Text size="sm" fw={500}>{p.nome}</Text> },
          { titulo: "Quando", celula: (p) => descreverGatilho(p.definicao) },
          { titulo: "Então", celula: (p) => contarAcoes(p.definicao.blocos).join(", ") || "-" },
          { titulo: "Aprovação", celula: (p) => (pedeAprovacao(p) ? "Pede aprovação" : "Automático") },
          { titulo: "Execuções", alinhar: "right", largura: 80, celula: (p) => numero(p.execucoes) },
          { titulo: "Estado", largura: 100, celula: (p) => <Estado tipo={p.ativo ? "ativo" : "outro"}>{p.ativo ? "Ativo" : "Desativado"}</Estado> },
          { titulo: "", largura: 40, celula: (p) => <AcoesDaLinha rotulo={`Ações de ${p.nome}`} itens={gerir ? [{ texto: "Editar", aoClicar: () => aoEditar(p) }, { texto: p.ativo ? "Desativar" : "Ativar", aoClicar: () => aoLigar(p) }] : []} /> },
        ]}
      />
      <Drawer opened={aberto !== null} onClose={() => setAbertoId(null)} title={aberto?.nome ?? ""} size="70%">
        {aberto && (
          <Stack gap="md">
            <Group justify="space-between">
              <Estado tipo={aberto.ativo ? "ativo" : "outro"}>{aberto.ativo ? "Ativo" : "Desativado"}</Estado>
              {gerir && (
                <Group gap="xs">
                  <Button onClick={() => aoLigar(aberto)}>{aberto.ativo ? "Desativar" : "Ativar"}</Button>
                  <Button variant="filled" onClick={() => { setAbertoId(null); aoEditar(aberto); }}>Editar</Button>
                </Group>
              )}
            </Group>
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <Fato rotulo="Quando">{descreverGatilho(aberto.definicao)}</Fato>
              <Fato rotulo="Não repetir para o mesmo alvo por">{`${numero(aberto.intervalo_minutos)} minutos`}</Fato>
              <Fato rotulo="Criado em"><Data valor={aberto.criado_em} /></Fato>
              <Fato rotulo="Alterado em"><Data valor={aberto.alterado_em} /></Fato>
            </SimpleGrid>
            <div><Title order={3} mb={4}>Então</Title><ResumoDosBlocos blocos={aberto.definicao.blocos} /></div>
            <div>
              <Title order={3} mb={4}>Execuções ({numero(aberto.execucoes)})</Title>
              <TabelaDeExecucoes linhas={dados.execucoes.filter((x) => x.playbook_id === aberto.id)} decisores={decisores} aoAbrir={aoAbrirExecucao} />
            </div>
          </Stack>
        )}
      </Drawer>
    </Painel>
  );
}

// ------------------------------------------------------------------ tela

export function Automacao() {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<Dados>("/api/automacao");
  const [aba, setAba] = useState<string | null>(null);
  const [editor, setEditor] = useState<AberturaDoPlaybook | null>(null);
  const [execucao, setExecucao] = useState<Execucao | null>(null);
  const [erroDeAcao, setErroDeAcao] = useState<string | null>(null);

  const cabecalho = (
    <Cabecalho titulo="Automação" ajuda="Playbooks respondem sozinhos a alertas, riscos e indicadores de ameaça. Ações sensíveis esperam a sua aprovação aqui.">
      {pode("gerir_playbooks") && <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setEditor({})}>Novo playbook</Button>}
    </Cabecalho>
  );
  const editorDePlaybook = <EditorDePlaybook abertura={editor} aoFechar={() => setEditor(null)} aoSalvar={() => { setAba("playbooks"); recarregar(); }} />;
  if (!dados) return <>{cabecalho}<Carregando erro={erro} />{editorDePlaybook}</>;

  const pendentes = dados.aprovacoes.filter((a) => a.estado === "pendente").length;
  // Decisão parada tem prazo: é o que a tela mostra primeiro, se houver.
  const abaAtual = aba ?? (pendentes ? "aprovacoes" : "playbooks");
  const decisores = new Map(dados.aprovacoes.filter((a) => a.decidida_por).map((a) => [a.execucao_id, a.decidida_por as string]));

  const decidir = async (a: Aprovacao, decisao: "aprovar" | "recusar", motivo: string) => {
    const r = await enviar(`/api/automacao/aprovacoes/${a.id}/${decisao}`, { motivo });
    // 409 é outra pessoa ter decidido antes: basta atualizar a lista.
    if (!r.ok && r.status !== 409) setErroDeAcao(await detalhe(r, "Não foi possível registrar a decisão."));
    else setErroDeAcao(null);
    recarregar();
  };
  const ligar = async (p: Playbook) => {
    const r = await enviar(`/api/automacao/playbooks/${p.id}/${p.ativo ? "desativar" : "ativar"}`);
    if (!r.ok) setErroDeAcao(await detalhe(r));
    else setErroDeAcao(null);
    recarregar();
  };

  return (
    <>
      {cabecalho}
      {erroDeAcao && <Alert color="red" variant="light" p="xs" mb="md" withCloseButton onClose={() => setErroDeAcao(null)}>{erroDeAcao}</Alert>}
      <Tabs value={abaAtual} onChange={setAba}>
        <Tabs.List mb="md">
          <Tabs.Tab value="playbooks">Playbooks</Tabs.Tab>
          <Tabs.Tab value="aprovacoes" rightSection={pendentes > 0 ? <Badge size="xs" circle color="yellow" variant="filled" autoContrast>{pendentes}</Badge> : undefined}>Aprovações</Tabs.Tab>
          <Tabs.Tab value="execucoes">Execuções</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="playbooks"><Playbooks dados={dados} decisores={decisores} aoEditar={(p) => setEditor({ id: p.id, nome: p.nome, definicao: p.definicao, intervalo_minutos: p.intervalo_minutos })} aoLigar={ligar} aoAbrirExecucao={setExecucao} /></Tabs.Panel>
        <Tabs.Panel value="aprovacoes"><Aprovacoes aprovacoes={dados.aprovacoes} aoDecidir={decidir} /></Tabs.Panel>
        <Tabs.Panel value="execucoes"><Painel p={0}><TabelaDeExecucoes linhas={dados.execucoes} decisores={decisores} aoAbrir={setExecucao} /></Painel></Tabs.Panel>
      </Tabs>
      {editorDePlaybook}
      <GavetaDaExecucao execucao={execucao} decisores={decisores} aoFechar={() => setExecucao(null)} />
    </>
  );
}
