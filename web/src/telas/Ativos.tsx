import { Button, Drawer, Group, SegmentedControl, SimpleGrid, Stack, Text, Title, Tooltip } from "@mantine/core";
import { useMemo, useState, type ReactNode } from "react";

import { pedir, useDados, usePode } from "../api";
import { AcoesDaLinha, Busca, Cabecalho, Carregando, Data, Estado, GavetaDeEventos, Numero, Painel, Tabela, type FiltroDeEventos } from "../componentes";
import { CRITICIDADES, numero } from "../formato";

interface Ativo {
  gerenciador_id: string;
  agente_id: string;
  nome: string | null;
  ip: string | null;
  sistema: string | null;
  versao: string | null;
  estado: string | null;
  grupos: string[] | null;
  ultima_conexao: string | null;
  sca_politica: string | null;
  sca_nota: number | null;
  sca_aprovados: number | null;
  sca_reprovados: number | null;
  alertas_7_dias: number;
  criticidade: string;
}

const SITUACOES: Record<string, { texto: string; tipo: string; plural: string }> = {
  active: { texto: "Conectado", tipo: "ativo", plural: "Conectados" },
  disconnected: { texto: "Desconectado", tipo: "problema", plural: "Desconectados" },
  never_connected: { texto: "Nunca conectou", tipo: "outro", plural: "Nunca conectaram" },
  pending: { texto: "Pendente", tipo: "pendente", plural: "Pendentes" },
};

const nomeDoAtivo = (a: Ativo) => a.nome ?? a.agente_id;

function Situacao({ estado }: { estado: string | null }) {
  const s = SITUACOES[estado ?? ""];
  return <Estado tipo={s?.tipo ?? "outro"}>{s?.texto ?? estado ?? "-"}</Estado>;
}

function BarraDeNota({ nota, largura }: { nota: number; largura: number }) {
  return (
    <Group gap={8} wrap="nowrap">
      <span className="barra-trilho" style={{ width: largura }}><span className="barra-cheia" style={{ width: `${Math.min(100, Math.max(2, Number(nota)))}%` }} /></span>
      <Text span size="xs" className="numero">{Number(nota)}%</Text>
    </Group>
  );
}

function Fato({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return (
    <Group justify="space-between" gap="lg" wrap="nowrap" align="flex-start">
      <Text size="sm" c="dimmed" style={{ whiteSpace: "nowrap" }}>{rotulo}</Text>
      <Text span size="sm" ta="right" style={{ overflowWrap: "anywhere" }}>{children}</Text>
    </Group>
  );
}

function Criticidade({ ativo, aoMudar }: { ativo: Ativo; aoMudar: (criticidade: string) => void }) {
  const pode = usePode();
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const mudar = async (criticidade: string) => {
    setSalvando(true);
    setErro(null);
    const resposta = await pedir("/api/ativos/criticidade", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ gerenciador_id: ativo.gerenciador_id, agente_id: ativo.agente_id, criticidade }),
    });
    setSalvando(false);
    if (resposta.ok) aoMudar(criticidade);
    else setErro("Não foi possível mudar a criticidade.");
  };
  return (
    <Stack gap={8}>
      <Title order={2}>Criticidade</Title>
      <Text size="xs" c="dimmed">Todo sinal de comportamento neste ativo pesa {CRITICIDADES[ativo.criticidade]?.fator ?? "o normal"} no risco, para a pessoa e para o ativo.</Text>
      <SegmentedControl size="xs" value={ativo.criticidade} onChange={mudar} disabled={!pode("gerir_regras") || salvando}
        data={Object.entries(CRITICIDADES).map(([valor, c]) => ({ value: valor, label: c.texto }))} />
      {erro && <Text size="xs" c="red">{erro}</Text>}
    </Stack>
  );
}

function GavetaDoAtivo({ ativo, aoFechar, aoVerEventos, aoMudarCriticidade }: {
  ativo: Ativo | null; aoFechar: () => void; aoVerEventos: (a: Ativo, soAlertas: boolean) => void; aoMudarCriticidade: (a: Ativo, criticidade: string) => void;
}) {
  return (
    <Drawer opened={ativo !== null} onClose={aoFechar} title={ativo ? nomeDoAtivo(ativo) : ""} size="md">
      {ativo && (
        <Stack gap="md">
          <Group gap="xs"><Situacao estado={ativo.estado} /></Group>
          <SimpleGrid cols={2} spacing="sm">
            <Numero rotulo="Alertas em 7 dias" valor={numero(ativo.alertas_7_dias)} aoClicar={ativo.nome ? () => aoVerEventos(ativo, true) : undefined} />
            <Numero rotulo="Configuração segura" valor={ativo.sca_nota === null ? "-" : `${Number(ativo.sca_nota)}%`} />
          </SimpleGrid>
          <Stack gap={8}>
            <Title order={2}>Identificação</Title>
            <Fato rotulo="Sistema">{ativo.sistema ?? "-"}</Fato>
            <Fato rotulo="Endereço"><span className="mono">{ativo.ip ?? "-"}</span></Fato>
            <Fato rotulo="Identificador"><span className="mono">{ativo.agente_id}</span></Fato>
            <Fato rotulo="Versão do agente">{ativo.versao?.replace(/^\D+/, "") ?? "-"}</Fato>
            <Fato rotulo="Grupos">{ativo.grupos?.length ? ativo.grupos.join(", ") : "-"}</Fato>
            <Fato rotulo="Última conexão"><Data valor={ativo.ultima_conexao} /></Fato>
          </Stack>
          <Criticidade ativo={ativo} aoMudar={(c) => aoMudarCriticidade(ativo, c)} />
          {ativo.sca_nota !== null && (
            <Stack gap={8}>
              <Title order={2}>Configuração segura</Title>
              <BarraDeNota nota={ativo.sca_nota} largura={200} />
              <Fato rotulo="Política">{ativo.sca_politica ?? "-"}</Fato>
              <Fato rotulo="Aprovados">{numero(ativo.sca_aprovados ?? 0)}</Fato>
              <Fato rotulo="Reprovados">{numero(ativo.sca_reprovados ?? 0)}</Fato>
            </Stack>
          )}
          {ativo.nome && <Group><Button onClick={() => aoVerEventos(ativo, false)}>Ver todos os eventos</Button></Group>}
        </Stack>
      )}
    </Drawer>
  );
}

export function Ativos() {
  const { dados, erro, recarregar } = useDados<{ ativos: Ativo[] }>("/api/ativos");
  const [busca, setBusca] = useState("");
  const [situacao, setSituacao] = useState<string | null>(null);
  const [aberto, setAberto] = useState<Ativo | null>(null);
  const [filtro, setFiltro] = useState<FiltroDeEventos | null>(null);

  const ativos = useMemo(() => dados?.ativos ?? [], [dados]);
  const linhas = useMemo(() => {
    const termo = busca.trim().toLowerCase();
    return ativos.filter((a) => (!situacao || a.estado === situacao)
      && (!termo || [a.nome, a.agente_id, a.ip, a.sistema, ...(a.grupos ?? [])].some((v) => v?.toLowerCase().includes(termo))));
  }, [ativos, busca, situacao]);

  const verEventos = (a: Ativo, soAlertas: boolean) => {
    if (!a.nome) return;
    setAberto(null);
    setFiltro(soAlertas
      ? { rotulo: `Alertas de ${a.nome} em 7 dias`, consulta: { alertas: "true", dias: "7", agente: a.agente_id, gerenciador: a.gerenciador_id } }
      : { rotulo: `Eventos de ${a.nome} em 30 dias`, consulta: { dias: "30", agente: a.agente_id, gerenciador: a.gerenciador_id } });
  };
  const contar = (estado: string) => ativos.filter((a) => a.estado === estado).length;
  const mudarCriticidade = (a: Ativo, criticidade: string) => {
    setAberto({ ...a, criticidade });
    recarregar();
  };

  return (
    <>
      <Cabecalho titulo="Ativos" ajuda="Os servidores e estações que mandam dados, se estão conectados e a nota de configuração segura de cada um." />
      {!dados ? <Carregando erro={erro} /> : (
        <Stack gap="md">
          <SimpleGrid cols={{ base: 2, sm: 3, lg: 5 }} spacing="md">
            <Numero rotulo="Todos" valor={numero(ativos.length)} aoClicar={() => setSituacao(null)} selecionado={situacao === null} />
            {Object.entries(SITUACOES).map(([estado, s]) => (
              <Numero key={estado} rotulo={s.plural} valor={numero(contar(estado))} aoClicar={() => setSituacao((atual) => (atual === estado ? null : estado))} selecionado={situacao === estado} />
            ))}
          </SimpleGrid>
          <Painel titulo={situacao ? SITUACOES[situacao].plural : "Todos os ativos"} acao={<Busca valor={busca} aoMudar={setBusca} dica="Nome, endereço, sistema ou grupo" />}>
            <Tabela
              linhas={linhas}
              chave={(a) => `${a.gerenciador_id}/${a.agente_id}`}
              vazio={ativos.length ? "Nenhum ativo com esse filtro." : "Nenhum ativo inscrito ainda."}
              aoClicarLinha={setAberto}
              colunas={[
                { titulo: "Ativo", celula: (a) => <Text size="sm" fw={500}>{nomeDoAtivo(a)}</Text> },
                { titulo: "Situação", largura: 130, celula: (a) => <Situacao estado={a.estado} /> },
                { titulo: "Criticidade", largura: 110, celula: (a) => (a.criticidade === "normal" ? <Text size="sm" c="dimmed">Normal</Text>
                  : <Estado tipo={a.criticidade === "baixa" ? "outro" : "problema"}>{CRITICIDADES[a.criticidade]?.texto ?? a.criticidade}</Estado>) },
                { titulo: "Sistema", celula: (a) => <Text size="sm" c="dimmed">{a.sistema ?? "-"}</Text> },
                { titulo: "Endereço", celula: (a) => <span className="mono">{a.ip ?? "-"}</span> },
                { titulo: "Configuração segura", largura: 160, celula: (a) => (a.sca_nota === null ? "-" : (
                  <Tooltip label={`${a.sca_politica ?? ""}: ${a.sca_aprovados ?? 0} aprovados, ${a.sca_reprovados ?? 0} reprovados`}>
                    <span><BarraDeNota nota={a.sca_nota} largura={72} /></span>
                  </Tooltip>
                )) },
                { titulo: "Alertas em 7 dias", alinhar: "right", largura: 120, celula: (a) => numero(a.alertas_7_dias) },
                { titulo: "Última conexão", largura: 150, celula: (a) => <Data valor={a.ultima_conexao} /> },
                { titulo: "", largura: 40, celula: (a) => (
                  <AcoesDaLinha rotulo={`Ações de ${nomeDoAtivo(a)}`} itens={[
                    { texto: "Ver detalhes", aoClicar: () => setAberto(a) },
                    ...(a.nome ? [
                      { texto: "Ver alertas de 7 dias", aoClicar: () => verEventos(a, true) },
                      { texto: "Ver todos os eventos", aoClicar: () => verEventos(a, false) },
                    ] : []),
                  ]} />
                ) },
              ]}
            />
          </Painel>
        </Stack>
      )}
      <GavetaDoAtivo ativo={aberto} aoFechar={() => setAberto(null)} aoVerEventos={verEventos} aoMudarCriticidade={mudarCriticidade} />
      <GavetaDeEventos filtro={filtro} aoFechar={() => setFiltro(null)} />
    </>
  );
}
