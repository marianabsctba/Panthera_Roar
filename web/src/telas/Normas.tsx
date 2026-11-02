import { Alert, Drawer, Group, Loader, SegmentedControl, SimpleGrid, Stack, Text } from "@mantine/core";
import { useEffect, useRef, useState } from "react";

import { ler, useDados } from "../api";
import { AcoesDaLinha, Cabecalho, Carregando, Data, GavetaDeEventos, Numero, Painel, Severidade, Tabela, type FiltroDeEventos } from "../componentes";
import { numero } from "../formato";
import { GavetaDaRegra, severidadeDoNivel, type DetalheDaRegra } from "./Ataques";

interface Controle { controle: string; total: number; nivel: number; ultimo: string | null; ativos: number }
interface VisaoDaNorma { norma: string; normas: Record<string, string>; controles: Controle[]; regras_da_norma: number }

const PAGINA_DE_REGRAS = 100;
const LOTE = 8;

/**
 * Nenhuma rota lista o que está por trás de um controle: quem diz quais controles uma regra cita é o
 * detalhe de cada regra. Vai das que mais dispararam para as que menos e para quando a soma dos
 * disparos alcança o total do controle, o que costuma resolver em poucos pedidos.
 */
function useRegrasDoControle(norma: string, controle: Controle | null, dias: string) {
  const [regras, setRegras] = useState<DetalheDaRegra[]>([]);
  const [procurando, setProcurando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const guardadas = useRef(new Map<string, DetalheDaRegra>());

  useEffect(() => {
    if (!controle) return;
    let valendo = true;
    const detalheDe = async (id: string) => {
      const chave = `${dias}:${id}`;
      const guardada = guardadas.current.get(chave);
      if (guardada) return guardada;
      // Regra que saiu do catálogo não impede de mostrar as outras.
      const d = await ler<DetalheDaRegra>(`/api/regras/${encodeURIComponent(id)}?dias=${dias}`).catch(() => null);
      if (d) guardadas.current.set(chave, d);
      return d;
    };
    const procurar = async () => {
      const achadas: DetalheDaRegra[] = [];
      let soma = 0;
      let deslocamento = 0;
      for (;;) {
        const pagina = await ler<{ regras: { regra_id: string }[]; total_filtrado: number }>(`/api/regras?so_disparadas=true&dias=${dias}&deslocamento=${deslocamento}`);
        const ids = [...new Set(pagina.regras.map((r) => r.regra_id))];
        for (let i = 0; i < ids.length && soma < Number(controle.total); i += LOTE) {
          const lote = await Promise.all(ids.slice(i, i + LOTE).map(detalheDe));
          if (!valendo) return;
          for (const d of lote) {
            if (d?.regra.normas?.[norma]?.includes(controle.controle)) {
              achadas.push(d);
              soma += Number(d.disparos.total);
            }
          }
          setRegras([...achadas]);
        }
        deslocamento += PAGINA_DE_REGRAS;
        if (soma >= Number(controle.total) || deslocamento >= Number(pagina.total_filtrado) || !pagina.regras.length) return;
      }
    };
    setRegras([]);
    setErro(null);
    setProcurando(true);
    procurar()
      .catch((e: Error) => { if (valendo) setErro(e.message); })
      .finally(() => { if (valendo) setProcurando(false); });
    return () => { valendo = false; };
  }, [norma, controle, dias]);

  return { regras, procurando, erro };
}

function GavetaDoControle({ norma, rotuloDaNorma, controle, dias, aoFechar, aoVerEventos, aoVerRegra }: {
  norma: string; rotuloDaNorma: string; controle: Controle | null; dias: string; aoFechar: () => void; aoVerEventos: (regra: string) => void; aoVerRegra: (regra: string) => void;
}) {
  const { regras, procurando, erro } = useRegrasDoControle(norma, controle, dias);
  const achados = regras.reduce((t, r) => t + Number(r.disparos.total), 0);
  return (
    <Drawer opened={controle !== null} onClose={aoFechar} title={controle ? `${rotuloDaNorma}: ${controle.controle}` : ""} size="xl">
      {controle && (
        <Stack gap="md">
          <SimpleGrid cols={{ base: 2, sm: 4 }}>
            <Numero rotulo={`Alertas em ${dias} dias`} valor={numero(controle.total)} />
            <Numero rotulo="Ativos" valor={numero(controle.ativos)} />
            <Numero rotulo="Maior severidade" valor={<Severidade valor={severidadeDoNivel(controle.nivel)} />} />
            <Numero rotulo="Último" valor={<Data valor={controle.ultimo} />} />
          </SimpleGrid>
          {erro && <Alert color="red" variant="light" p="xs" fz="sm" role="alert">{erro}</Alert>}
          <Painel
            titulo="Regras que geraram esses alertas"
            acao={procurando && <Group gap={6} wrap="nowrap"><Loader size="xs" color="gray" /><Text size="xs" c="dimmed">Procurando</Text></Group>}
          >
            <Tabela
              linhas={regras}
              chave={(r) => r.regra.regra_id}
              vazio={procurando ? "Procurando as regras deste controle." : "Nenhuma regra do catálogo cita este controle."}
              aoClicarLinha={(r) => aoVerEventos(r.regra.regra_id)}
              colunas={[
                { titulo: "Regra", largura: 80, celula: (r) => <span className="mono">{r.regra.regra_id}</span> },
                { titulo: "Severidade", largura: 90, celula: (r) => <Severidade valor={severidadeDoNivel(r.regra.nivel)} /> },
                { titulo: "O que detecta", celula: (r) => r.regra.descricao ?? "-" },
                { titulo: "Disparos", alinhar: "right", largura: 80, celula: (r) => numero(r.disparos.total) },
                { titulo: "Ativos", alinhar: "right", largura: 70, celula: (r) => numero(r.disparos.ativos) },
                { titulo: "Último", largura: 130, celula: (r) => <Data valor={r.disparos.ultimo} /> },
                { titulo: "", largura: 40, celula: (r) => <AcoesDaLinha rotulo={`Ações da regra ${r.regra.regra_id}`} itens={[{ texto: "Ver eventos", aoClicar: () => aoVerEventos(r.regra.regra_id) }, { texto: "Ver regra", aoClicar: () => aoVerRegra(r.regra.regra_id) }]} /> },
              ]}
            />
            {!procurando && !erro && achados < Number(controle.total) && <Text size="xs" c="dimmed" mt="xs">Estas regras explicam {numero(achados)} de {numero(controle.total)} alertas. As outras saíram do catálogo ou mudaram de controle.</Text>}
          </Painel>
        </Stack>
      )}
    </Drawer>
  );
}

export function Normas() {
  const [norma, setNorma] = useState("gdpr");
  const [dias, setDias] = useState("30");
  const [controle, setControle] = useState<Controle | null>(null);
  const [regra, setRegra] = useState<string | null>(null);
  const [filtro, setFiltro] = useState<FiltroDeEventos | null>(null);
  const { dados, erro } = useDados<VisaoDaNorma>(`/api/normas?${new URLSearchParams({ norma, dias })}`);
  const verEventos = (id: string) => setFiltro({ rotulo: `Eventos da regra ${id}`, consulta: { regra: id, dias } });
  const trocar = (mudar: (v: string) => void) => (v: string) => {
    setControle(null);
    mudar(v);
  };
  return (
    <>
      <Cabecalho titulo="Normas" ajuda="Os alertas agrupados pelos controles de cada norma, como as regras os marcam. Clique num controle para ver as regras e os eventos por trás dele.">
        <SegmentedControl size="xs" value={dias} onChange={trocar(setDias)} data={[{ label: "7 dias", value: "7" }, { label: "30 dias", value: "30" }, { label: "90 dias", value: "90" }]} aria-label="Período" />
      </Cabecalho>
      {!dados ? <Carregando erro={erro} /> : (
        <Stack gap="md">
          <SegmentedControl size="xs" style={{ alignSelf: "flex-start" }} value={norma} onChange={trocar(setNorma)} data={Object.entries(dados.normas).map(([value, label]) => ({ value, label }))} aria-label="Norma" />
          <SimpleGrid cols={{ base: 2, sm: 4 }}>
            <Numero rotulo={`Controles com alertas em ${dias} dias`} valor={numero(dados.controles.length)} />
            <Numero rotulo="Regras que cobrem esta norma" valor={numero(dados.regras_da_norma)} />
          </SimpleGrid>
          <Painel p={0}>
            <Tabela
              linhas={dados.controles}
              chave={(c) => c.controle}
              vazio="Nenhum alerta ligado a esta norma no período."
              aoClicarLinha={setControle}
              colunas={[
                { titulo: "Controle", celula: (c) => <span className="mono">{c.controle}</span> },
                { titulo: "Maior severidade", largura: 130, celula: (c) => <Severidade valor={severidadeDoNivel(c.nivel)} /> },
                { titulo: "Alertas", alinhar: "right", largura: 90, celula: (c) => numero(c.total) },
                { titulo: "Ativos", alinhar: "right", largura: 80, celula: (c) => numero(c.ativos) },
                { titulo: "Último", largura: 140, celula: (c) => <Data valor={c.ultimo} /> },
              ]}
            />
          </Painel>
        </Stack>
      )}
      <GavetaDoControle
        norma={dados?.norma ?? norma}
        rotuloDaNorma={dados?.normas[dados.norma] ?? norma}
        controle={controle}
        dias={dias}
        aoFechar={() => setControle(null)}
        aoVerEventos={verEventos}
        aoVerRegra={setRegra}
      />
      <GavetaDaRegra regra={regra} dias={dias} aoFechar={() => setRegra(null)} aoVerEventos={verEventos} />
      <GavetaDeEventos filtro={filtro} aoFechar={() => setFiltro(null)} />
    </>
  );
}
