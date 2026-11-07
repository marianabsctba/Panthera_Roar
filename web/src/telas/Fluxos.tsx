import { Button, Group, SegmentedControl, SimpleGrid, Stack, Text, TextInput } from "@mantine/core";
import { useState } from "react";

import { useDados } from "../api";
import { BarrasMetalicas, Cabecalho, Carregando, Data, METAL_ROSA, Numero, Painel, Ranking, Tabela, Vazio } from "../componentes";
import { numero, tamanho } from "../formato";

interface Maior { valor: string | number; bytes: number; fluxos: number }
interface Fluxo { quando: string; exportador: string; origem: string; destino: string; porta_origem: number; porta_destino: number; protocolo: string; bytes: number; pacotes: number; pais: string; operadora: string }
interface Visao {
  disponivel: boolean;
  total?: { fluxos: number; bytes: number; pacotes: number; exportadores: number };
  horas?: { hora: string; bytes: number; fluxos: number }[];
  origens?: Maior[]; destinos?: Maior[]; portas?: Maior[]; paises?: Maior[];
  recentes?: Fluxo[];
}

const PERIODOS = [{ value: "1", label: "1 hora" }, { value: "24", label: "24 horas" }, { value: "168", label: "7 dias" }, { value: "720", label: "30 dias" }];
const ENDERECO = /^[0-9a-fA-F.:]+$/;

function lista(itens: Maior[] | undefined) {
  return (itens ?? []).map((i) => ({ rotulo: String(i.valor), valor: i.bytes }));
}

export function Fluxos() {
  const [horas, setHoras] = useState("24");
  const [ip, setIp] = useState("");
  const [digitado, setDigitado] = useState("");
  const parametros = new URLSearchParams({ horas, ...(ip ? { ip } : {}) });
  const { dados, erro } = useDados<Visao>(`/api/fluxos?${parametros}`);
  const filtrar = (valor: string) => { setIp(valor); setDigitado(valor); };
  const cabecalho = <Cabecalho titulo="Fluxos de rede" ajuda="Quem conversou com quem na rede, por qual porta e quanto, vindo do NetFlow, IPFIX e sFlow dos equipamentos. O país e a operadora são do lado de fora da rede." />;
  if (!dados) return <Stack>{cabecalho}<Carregando erro={erro} /></Stack>;
  if (!dados.disponivel) {
    return <Stack>{cabecalho}<Vazio>Os fluxos de rede ficam no armazém novo. Ligue a leitura do armazém em Armazenamento e cadastre um exportador em Fontes de dados.</Vazio></Stack>;
  }
  const total = dados.total!;
  // Em megabytes: o eixo com bytes crus fica com números longos demais.
  const porHora = (dados.horas ?? []).map((h) => ({ ...h, mb: Math.round(h.bytes / 1e6), rotulo: `${h.hora.slice(8, 10)}/${h.hora.slice(5, 7)} ${h.hora.slice(11, 13)}h` }));
  return (
    <Stack>
      {cabecalho}
      <Group gap="sm" wrap="wrap">
        <SegmentedControl size="xs" value={horas} onChange={setHoras} data={PERIODOS} aria-label="Período" />
        <form onSubmit={(e) => { e.preventDefault(); if (!digitado.trim() || ENDERECO.test(digitado.trim())) setIp(digitado.trim()); }}>
          <Group gap="xs">
            <TextInput size="xs" w={200} placeholder="Endereço IP" aria-label="Filtrar por endereço" value={digitado} onChange={(e) => setDigitado(e.currentTarget.value)} />
            <Button size="xs" type="submit">Filtrar</Button>
            {ip && <Button size="xs" variant="subtle" color="gray" onClick={() => filtrar("")}>Tirar o filtro</Button>}
          </Group>
        </form>
      </Group>
      {erro && <Text size="sm" c="red">{erro}</Text>}
      <SimpleGrid cols={{ base: 2, md: 4 }} spacing="md">
        <Numero rotulo="Fluxos" valor={numero(total.fluxos)} />
        <Numero rotulo="Volume" valor={tamanho(total.bytes)} detalhe="como o equipamento mediu (com amostragem, é uma fração)" />
        <Numero rotulo="Pacotes" valor={numero(total.pacotes)} />
        <Numero rotulo="Exportadores" valor={numero(total.exportadores)} />
      </SimpleGrid>
      {!total.fluxos ? (
        <Vazio>{ip ? `Nenhum fluxo com ${ip} neste período.` : "Nenhum fluxo neste período. Cadastre um exportador em Fontes de dados, no cartão NetFlow, IPFIX e sFlow."}</Vazio>
      ) : (
        <>
          <Painel titulo="Volume por hora, em MB">
            <BarrasMetalicas dados={porHora} chave="rotulo" series={[{ nome: "mb", rotulo: "Volume (MB)", metal: METAL_ROSA }]} formatar={(v) => tamanho(v * 1e6)} />
          </Painel>
          <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
            <Painel titulo="Quem mais recebe"><Ranking itens={lista(dados.destinos)} vazio="Nada." rotuloDoValor={(v) => tamanho(v)} aoClicar={filtrar} /></Painel>
            <Painel titulo="Quem mais manda"><Ranking itens={lista(dados.origens)} vazio="Nada." rotuloDoValor={(v) => tamanho(v)} aoClicar={filtrar} /></Painel>
            <Painel titulo="Portas de destino"><Ranking itens={lista(dados.portas)} vazio="Nada." rotuloDoValor={(v) => tamanho(v)} /></Painel>
            <Painel titulo="Países do lado de fora"><Ranking itens={lista(dados.paises)} vazio="Nenhum endereço de fora com país conhecido." rotuloDoValor={(v) => tamanho(v)} /></Painel>
          </SimpleGrid>
          <Painel titulo="Mais recentes">
            <Tabela
              linhas={dados.recentes ?? []}
              chave={(f) => `${f.quando}-${f.origem}-${f.porta_origem}-${f.destino}-${f.porta_destino}`}
              vazio="Nada."
              aoClicarLinha={(f) => filtrar(f.destino)}
              colunas={[
                { titulo: "Quando", largura: 150, celula: (f) => <Data valor={f.quando.replace(" ", "T") + "Z"} /> },
                { titulo: "Origem", celula: (f) => <span className="mono">{f.origem}:{f.porta_origem}</span> },
                { titulo: "Destino", celula: (f) => <span className="mono">{f.destino}:{f.porta_destino}</span> },
                { titulo: "Protocolo", celula: (f) => f.protocolo },
                { titulo: "Volume", alinhar: "right", celula: (f) => tamanho(f.bytes) },
                { titulo: "Fora da rede", celula: (f) => [f.pais, f.operadora].filter(Boolean).join(" · ") || "-" },
                { titulo: "Exportador", celula: (f) => <span className="mono">{f.exportador}</span> },
              ]}
            />
          </Painel>
        </>
      )}
    </Stack>
  );
}
