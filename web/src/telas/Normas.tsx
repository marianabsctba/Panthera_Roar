import { Alert, Button, Drawer, Group, Loader, Modal, SegmentedControl, SimpleGrid, Stack, Text } from "@mantine/core";
import { useEffect, useRef, useState } from "react";

import { ler, useDados } from "../api";
import { AcoesDaLinha, Cabecalho, Carregando, Data, GavetaDeEventos, Numero, Painel, Severidade, Tabela, type FiltroDeEventos } from "../componentes";
import { numero } from "../formato";
import { GavetaDaRegra, severidadeDoNivel, type DetalheDaRegra } from "./Ataques";

interface Controle { controle: string; nome: string | null; total: number; nivel: number; ultimo: string | null; ativos: number; origens: string[] }
interface VisaoDaNorma { norma: string; chave: string; derivada_de: string | null; so_pelas_checagens: boolean; normas: Record<string, string>; controles: Controle[]; regras_da_norma: number }

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
            if (d && controle.origens.some((o) => d.regra.normas?.[norma]?.includes(o))) {
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
    <Drawer opened={controle !== null} onClose={aoFechar} title={controle ? `${rotuloDaNorma}: ${controle.controle}${controle.nome ? ` · ${controle.nome}` : ""}` : ""} size="xl">
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

function RelatorioDaNorma({ norma, rotulo }: { norma: string; rotulo: string }) {
  const [aberto, setAberto] = useState(false);
  const [dias, setDias] = useState("90");
  const [formato, setFormato] = useState("pdf");
  const [gerando, setGerando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [resumo, setResumo] = useState<string | null>(null);
  const gerar = async () => {
    setErro(null);
    setResumo(null);
    setGerando(true);
    try {
      const r = await fetch(`/api/normas/relatorio?${new URLSearchParams({ norma, dias, formato })}`, { credentials: "same-origin" });
      if (r.status === 401) {
        window.location.assign("/");
        return;
      }
      if (!r.ok) throw new Error("falhou");
      const link = document.createElement("a");
      link.href = URL.createObjectURL(await r.blob());
      link.download = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") ?? "")?.[1] ?? `relatorio-${norma}.${formato}`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 10000);
      setResumo(r.headers.get("X-Resumo-SHA256"));
    } catch {
      setErro("Não foi possível gerar o relatório. Tente de novo em instantes.");
    } finally {
      setGerando(false);
    }
  };
  return (
    <>
      <Button variant="filled" onClick={() => { setResumo(null); setAberto(true); }}>Gerar relatório</Button>
      <Modal opened={aberto} onClose={() => setAberto(false)} title={`Relatório de ${rotulo}`}>
        <Stack gap="sm">
          <Text size="sm">Evidência para a auditoria: alertas por controle, controles cobertos sem alerta, checagens de configuração reprovadas por controle, e a guarda e a integridade dos registros.</Text>
          <SegmentedControl size="xs" value={dias} onChange={setDias} data={[{ label: "30 dias", value: "30" }, { label: "90 dias", value: "90" }, { label: "1 ano", value: "365" }]} aria-label="Período do relatório" />
          <SegmentedControl size="xs" value={formato} onChange={setFormato} data={[{ label: "PDF", value: "pdf" }, { label: "Dados em JSON", value: "json" }]} aria-label="Formato" />
          {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
          {resumo && <Text size="xs" c="dimmed">Gerado e guardado em Relatórios, no menu. Resumo SHA-256 do arquivo, também na auditoria: <span className="mono" style={{ overflowWrap: "anywhere" }}>{resumo}</span></Text>}
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={() => setAberto(false)}>Fechar</Button>
            <Button variant="filled" loading={gerando} onClick={gerar}>Gerar</Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

export function Normas() {
  const [norma, setNorma] = useState("lgpd");
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
        {dados && <RelatorioDaNorma norma={dados.norma} rotulo={dados.normas[dados.norma] ?? norma} />}
      </Cabecalho>
      {!dados ? <Carregando erro={erro} /> : (
        <Stack gap="md">
          <SegmentedControl size="xs" style={{ alignSelf: "flex-start" }} value={norma} onChange={trocar(setNorma)} data={Object.entries(dados.normas).map(([value, label]) => ({ value, label }))} aria-label="Norma" />
          {dados.so_pelas_checagens && (
            <Text size="xs" c="dimmed">As regras não marcam a {dados.normas[dados.norma]}: os controles vêm das checagens de configuração segura de cada ativo. Ainda não há regra que cubra esta norma.</Text>
          )}
          {dados.derivada_de && (
            <Text size="xs" c="dimmed">As regras não marcam a {dados.normas[dados.norma]}. Os controles saem do {dados.derivada_de}, artigo por artigo, pelo mesmo fundamento: Art. 5(1)(f) no Art. 6, VII; Art. 30 no Art. 37; Art. 32 no Art. 46; Art. 35 no Art. 38.</Text>
          )}
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
                { titulo: "Controle", largura: 130, celula: (c) => <span className="mono">{c.controle}</span> },
                { titulo: "O que pede", celula: (c) => <Text size="sm">{c.nome ?? "-"}</Text> },
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
        norma={dados?.chave ?? norma}
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
