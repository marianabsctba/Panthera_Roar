import { Drawer, Grid, Group, SegmentedControl, SimpleGrid, Stack, Tabs } from "@mantine/core";
import { useState } from "react";

import { useDados, useEu } from "../api";
import { AmostraDeMetal, BarrasMetalicas, Cabecalho, Carregando, GavetaDeEventos, METAL_ROSA, METAIS_DE_SEVERIDADE, Numero, ORDEM_DE_SEVERIDADE, Painel, Ranking, Tabela, Vazio, type FiltroDeEventos, type Metal } from "../componentes";
import { compacto, diaCurto, numero, quando, SINAIS, tamanho } from "../formato";
import { SEVERIDADES } from "../tema";
import { MapaOrigens, type Cidade, type Pais } from "./MapaOrigens";

interface Dia { dia: string; baixa: number; media: number; alta: number; critica: number }
interface PanoramaDados {
  por_dia: Dia[];
  sinais: { tipo: string; total: number }[];
  origens: { origem: string; total: number }[];
  riscos: { entidade: string; tipo: string; risco: number }[];
  paises: Pais[];
  cidades: Cidade[];
  sem_cidade: number;
}
interface Volume {
  dias: number;
  ocupado_bytes: number;
  ocupado: { logs: number; alertas: number; retencao_dias: number; por_dia: { dia: string; logs: number; alertas: number }[] } | null;
  logs: { total: number; eps_agora: number; eps_medio: number; eps_pico: number; pico_em: string | null; eps_por_hora: { hora: string; medio: number; pico: number }[]; por_dia: { dia: string; eventos: number; bytes_estimados: number }[]; ativos: { nome: string; eventos: number }[]; origens: { nome: string; eventos: number }[] } | null;
}

function GavetaDeEps({ aberta, aoFechar, volume, aoEscolherAtivo }: { aberta: boolean; aoFechar: () => void; volume: Volume | null; aoEscolherAtivo: (ativo: string) => void }) {
  const eu = useEu();
  const logs = volume?.logs;
  if (!logs || !volume) return <Drawer opened={aberta} onClose={aoFechar} title="Eventos por segundo" size="xl"><Vazio>Nenhuma fonte conectada ainda.</Vazio></Drawer>;
  const segundos = volume.dias * 86400;
  // O histograma só traz horas com evento: completa com zero, para o silêncio aparecer no gráfico.
  const presentes = new Map(logs.eps_por_hora.map((h) => [h.hora, h]));
  const agora = new Date();
  const horas = Array.from({ length: 48 }, (_, i) => {
    const instante = new Date(agora.getTime() - (47 - i) * 3600000);
    const chave = instante.toISOString().slice(0, 13);
    return { rotulo: instante.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", timeZone: eu.fuso }), pico: presentes.get(chave)?.pico ?? 0, medio: presentes.get(chave)?.medio ?? 0 };
  });
  return (
    <Drawer opened={aberta} onClose={aoFechar} title="Eventos por segundo" size="xl">
      <Stack gap="md">
        <SimpleGrid cols={3}>
          <Numero rotulo="Agora" valor={eps(logs.eps_agora)} detalhe="média dos últimos 5 minutos" />
          <Numero rotulo="Média do período" valor={eps(logs.eps_medio)} detalhe={`${volume.dias} dias`} />
          <Numero rotulo="Pico" valor={eps(logs.eps_pico)} detalhe={logs.pico_em ? quando(logs.pico_em, eu.fuso) : undefined} />
        </SimpleGrid>
        <Painel titulo="Pico em cada hora, últimas 48 horas">
          <BarrasMetalicas altura={180} dados={horas} chave="rotulo" series={[{ nome: "pico", rotulo: "Pico por segundo", metal: METAL_ROSA }]} formatar={eps} />
        </Painel>
        <Painel titulo="Quem mais manda">
          <Ranking itens={logs.ativos.map((a) => ({ rotulo: a.nome, valor: a.eventos }))} rotuloDoValor={(v) => `${eps(v / segundos)}/s`} vazio="Sem dados." aoClicar={aoEscolherAtivo} />
        </Painel>
        <Painel titulo="Por tipo de log">
          <Ranking itens={logs.origens.map((a) => ({ rotulo: a.nome, valor: a.eventos }))} rotuloDoValor={(v) => `${eps(v / segundos)}/s`} vazio="Sem dados." />
        </Painel>
      </Stack>
    </Drawer>
  );
}

const METAL_PRATA: Metal = ["#55555c", "#ececee", "#a8a8b0", "#5f5f66"];

function GavetaDeDisco({ aberta, aoFechar, volume, aoEscolherDia }: { aberta: boolean; aoFechar: () => void; volume: Volume | null; aoEscolherDia: (iso: string, rotulo: string) => void }) {
  const o = volume?.ocupado;
  if (!o || !volume) return <Drawer opened={aberta} onClose={aoFechar} title="Ocupado em disco" size="xl"><Vazio>Não foi possível medir o disco agora.</Vazio></Drawer>;
  // Hoje ainda está crescendo: entra no gráfico, mas não na média.
  const fechados = o.por_dia.slice(0, -1);
  const porDia = fechados.length ? fechados.reduce((t, d) => t + d.logs + d.alertas, 0) / fechados.length : null;
  const dias = o.por_dia.map((d) => ({ ...d, rotulo: diaCurto(d.dia) }));
  return (
    <Drawer opened={aberta} onClose={aoFechar} title="Ocupado em disco" size="xl">
      <Stack gap="md">
        <SimpleGrid cols={3}>
          <Numero rotulo="Ocupado agora" valor={tamanho(volume.ocupado_bytes)} />
          <Numero rotulo="Cresce por dia" valor={tamanho(porDia)} detalhe={porDia === null ? "precisa de um dia inteiro" : `média de ${fechados.length} ${fechados.length === 1 ? "dia" : "dias"}`} />
          <Numero rotulo={`Com retenção de ${o.retencao_dias} dias`} valor={tamanho(porDia === null ? null : porDia * o.retencao_dias)} detalhe="estimativa, se o ritmo seguir" />
        </SimpleGrid>
        <Painel titulo="O que ocupa">
          <Ranking itens={[{ rotulo: "Logs", valor: o.logs }, { rotulo: "Alertas", valor: o.alertas }]} rotuloDoValor={tamanho} vazio="Sem dados." />
        </Painel>
        <Painel titulo="Por dia" acao={<Group gap="md"><AmostraDeMetal cores={METAL_ROSA} rotulo="Logs" /><AmostraDeMetal cores={METAL_PRATA} rotulo="Alertas" /></Group>}>
          <BarrasMetalicas
            altura={180}
            dados={dias}
            chave="rotulo"
            empilhado
            series={[{ nome: "logs", rotulo: "Logs", metal: METAL_ROSA }, { nome: "alertas", rotulo: "Alertas", metal: METAL_PRATA }]}
            formatar={tamanho}
            aoClicar={(r) => { const d = dias.find((x) => x.rotulo === r); if (d) aoEscolherDia(d.dia, d.rotulo); }}
          />
        </Painel>
      </Stack>
    </Drawer>
  );
}

function GavetaDoVolume({ aberta, aoFechar, volume, aoEscolherAtivo }: { aberta: boolean; aoFechar: () => void; volume: Volume | null; aoEscolherAtivo: (ativo: string) => void }) {
  const logs = volume?.logs;
  return (
    <Drawer opened={aberta} onClose={aoFechar} title="De onde vem o volume" size="lg">
      {logs && (
        <Tabs defaultValue="ativos">
          <Tabs.List mb="sm">
            <Tabs.Tab value="ativos">Por ativo</Tabs.Tab>
            <Tabs.Tab value="tipos">Por tipo de log</Tabs.Tab>
            <Tabs.Tab value="dias">Por dia</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="ativos"><Ranking itens={logs.ativos.map((a) => ({ rotulo: a.nome, valor: a.eventos }))} vazio="Sem dados." aoClicar={aoEscolherAtivo} /></Tabs.Panel>
          <Tabs.Panel value="tipos"><Ranking itens={logs.origens.map((a) => ({ rotulo: a.nome, valor: a.eventos }))} vazio="Sem dados." /></Tabs.Panel>
          <Tabs.Panel value="dias">
            <Tabela
              linhas={[...logs.por_dia].reverse()}
              chave={(d) => d.dia}
              vazio="Sem dados."
              colunas={[
                { titulo: "Dia", celula: (d) => diaCurto(d.dia) },
                { titulo: "Eventos", alinhar: "right", celula: (d) => numero(d.eventos) },
                { titulo: "Tamanho estimado", alinhar: "right", celula: (d) => tamanho(d.bytes_estimados) },
              ]}
            />
          </Tabs.Panel>
        </Tabs>
      )}
    </Drawer>
  );
}

// Servidor quieto manda bem menos de um evento por segundo: arredondar mostraria zero, e zero quer dizer parado.
const eps = (v: number) => {
  if (v > 0 && v < 0.01) return "< 0,01";
  return v.toLocaleString("pt-BR", { minimumFractionDigits: v < 10 ? 2 : 0, maximumFractionDigits: v < 10 ? 2 : 1 });
};

export function Panorama() {
  const [dias, setDias] = useState("30");
  const [filtro, setFiltro] = useState<FiltroDeEventos | null>(null);
  const [verVolume, setVerVolume] = useState(false);
  const [verEps, setVerEps] = useState(false);
  const [verDisco, setVerDisco] = useState(false);
  const { dados, erro } = useDados<PanoramaDados>(`/api/panorama?dias=${dias}`);
  const { dados: volume } = useDados<Volume>(`/api/volume?dias=${Math.min(Number(dias), 30)}`);

  if (!dados) return <><Cabecalho titulo="Panorama" ajuda="" /><Carregando erro={erro} /></>;

  const soma = (campos: (keyof Omit<Dia, "dia">)[]) => dados.por_dia.reduce((t, d) => t + campos.reduce((s, c) => s + Number(d[c]), 0), 0);
  const logs = volume?.logs;
  const porDia = logs ? logs.por_dia.reduce((t, x) => t + x.bytes_estimados, 0) / volume.dias : null;
  const graficoDias = dados.por_dia.map((d) => ({ ...d, dia: diaCurto(d.dia), iso: d.dia.slice(0, 10) }));
  const abrir = (rotulo: string, consulta: Record<string, string>) => setFiltro({ rotulo, consulta: { dias, ...consulta } });

  return (
    <>
      <Cabecalho titulo="Panorama" ajuda="A visão geral do período: quantos alertas chegaram, de onde vêm e quem está com maior risco agora.">
        <SegmentedControl size="xs" value={dias} onChange={setDias} data={[{ label: "7 dias", value: "7" }, { label: "30 dias", value: "30" }, { label: "90 dias", value: "90" }]} aria-label="Período" />
      </Cabecalho>

      <Stack gap="md">
        <SimpleGrid cols={{ base: 2, md: 3, lg: 5 }} spacing="md">
          <Numero rotulo="Alertas no período" valor={compacto(soma(["baixa", "media", "alta", "critica"]))} aoClicar={() => abrir("Alertas no período", { alertas: "true" })} />
          <Numero rotulo="Altos e críticos" valor={compacto(soma(["alta", "critica"]))} destaque={soma(["critica"]) > 0 ? SEVERIDADES.critica.cor : undefined} aoClicar={() => abrir("Alertas altos e críticos", { alertas: "true", severidades: "alta,critica" })} />
          <Numero rotulo="Eventos por segundo" valor={logs ? eps(logs.eps_agora) : "-"} detalhe={logs ? `pico de ${eps(logs.eps_pico)}` : undefined} aoClicar={() => setVerEps(true)} />
          <Numero rotulo="Volume por dia" valor={tamanho(porDia)} detalhe="estimado" aoClicar={() => setVerVolume(true)} />
          <Numero rotulo="Ocupado em disco" valor={tamanho(volume?.ocupado_bytes)} aoClicar={() => setVerDisco(true)} />
        </SimpleGrid>

        <Painel
          titulo="Alertas por dia"
          acao={(
            // A biblioteca ordena a legenda por nome; aqui a ordem é a da gravidade.
            <Group gap="md">
              {ORDEM_DE_SEVERIDADE.map((s) => <AmostraDeMetal key={s} cores={METAIS_DE_SEVERIDADE[s]} rotulo={SEVERIDADES[s].texto} />)}
            </Group>
          )}
        >
          <BarrasMetalicas
            altura={200}
            dados={graficoDias}
            chave="dia"
            series={ORDEM_DE_SEVERIDADE.map((s) => ({ nome: s, rotulo: SEVERIDADES[s].texto, metal: METAIS_DE_SEVERIDADE[s] }))}
            empilhado
            aoClicar={(l) => {
              const dia = graficoDias.find((d) => d.dia === l);
              if (dia) abrir(`Alertas de ${dia.dia}`, { alertas: "true", dia: dia.iso });
            }}
          />
        </Painel>

        <Grid gap="md">
          <Grid.Col span={{ base: 12, lg: 8 }}>
            <Stack gap="md">
              <Painel titulo="De onde vêm os alertas">
                {dados.paises.length ? (
                  <MapaOrigens paises={dados.paises} cidades={dados.cidades} semCidade={dados.sem_cidade} aoEscolher={(f) => abrir(`Alertas de ${f.rotulo}`, { alertas: "true", pais: f.pais, ...(f.cidade ? { cidade: f.cidade } : {}) })} />
                ) : <Vazio>Nenhum alerta com endereço externo no período.</Vazio>}
              </Painel>
            <Painel titulo="Sinais de comportamento">
              {dados.sinais.length ? (
                <Ranking duasColunas itens={dados.sinais.map((s) => ({ rotulo: SINAIS[s.tipo] ?? s.tipo, valor: s.total, chave: s.tipo }))} vazio="" aoClicar={(tipo, rotulo) => abrir(`Eventos com o sinal: ${rotulo}`, { sinal: tipo })} />
              ) : <Vazio>Nenhum sinal no período.</Vazio>}
            </Painel>
            </Stack>
          </Grid.Col>
          <Grid.Col span={{ base: 12, lg: 4 }}>
            <Stack gap="md" h="100%">
              <Painel titulo="Maior risco agora">
                <Ranking itens={dados.riscos.map((r) => ({ rotulo: r.entidade, valor: Math.round(r.risco) }))} vazio="Ninguém com risco no momento." aoClicar={(e) => abrir(`Eventos de ${e}`, { entidade: e })} />
              </Painel>
              <Painel titulo="Principais origens">
                <Ranking itens={dados.origens.slice(0, 6).map((o) => ({ rotulo: o.origem, valor: o.total }))} vazio="Nenhuma origem no período." aoClicar={(o) => abrir(`Alertas vindos de ${o}`, { alertas: "true", origem: o })} />
              </Painel>
            </Stack>
          </Grid.Col>
        </Grid>

      </Stack>

      <GavetaDeEventos filtro={filtro} aoFechar={() => setFiltro(null)} />
      <GavetaDeEps aberta={verEps} aoFechar={() => setVerEps(false)} volume={volume} aoEscolherAtivo={(a) => { setVerEps(false); abrir(`Eventos de ${a}`, { entidade: a }); }} />
      <GavetaDeDisco aberta={verDisco} aoFechar={() => setVerDisco(false)} volume={volume} aoEscolherDia={(iso, r) => { setVerDisco(false); abrir(`Eventos de ${r}`, { dia: iso }); }} />
      <GavetaDoVolume aberta={verVolume} aoFechar={() => setVerVolume(false)} volume={volume} aoEscolherAtivo={(a) => { setVerVolume(false); abrir(`Eventos de ${a}`, { entidade: a }); }} />
    </>
  );
}
