import { Alert, Button, Card, Drawer, Group, List, Modal, SegmentedControl, SimpleGrid, Stack, Text } from "@mantine/core";
import { IconCheck, IconDownload, IconFileText, IconListNumbers, IconPresentation } from "@tabler/icons-react";
import { useState, type ReactNode } from "react";

import { detalhe, pedir, useDados } from "../api";
import { AcoesDaLinha, Cabecalho, Carregando, Data, Painel, Tabela } from "../componentes";
import { numero } from "../formato";

interface RelatorioGuardado {
  id: number; tipo: string; norma: string | null; norma_nome: string | null; dias: number; formato: string; nome: string; tamanho: number;
  sha256: string; mascarado: boolean; gerado_por_nome: string; gerado_em: string; pode_apagar: boolean; pode_baixar: boolean;
}

const tituloDoGuardado = (r: RelatorioGuardado) => (r.tipo === "norma" ? `Norma ${r.norma_nome ?? r.norma}` : r.tipo === "completo" ? "Completo" : "Executivo");
const tamanho = (bytes: number) => (bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1).replace(".", ",")} MB` : `${numero(Math.max(1, Math.round(bytes / 1024)))} KB`);

async function baixar(rota: string, nomePadrao: string) {
  const r = await pedir(rota);
  if (!r.ok) throw new Error(await detalhe(r, "Não foi possível baixar."));
  const link = document.createElement("a");
  link.href = URL.createObjectURL(await r.blob());
  link.download = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") ?? "")?.[1] ?? nomePadrao;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 10000);
}

/** Os relatórios gerados ficam guardados até alguém apagar. A auditoria registra quem baixou e quem apagou. */
export function HistoricoDeRelatorios({ versao }: { versao: number }) {
  const { dados, erro, recarregar } = useDados<{ relatorios: RelatorioGuardado[] }>(`/api/relatorios/historico?v=${versao}`);
  const [apagar, setApagar] = useState<RelatorioGuardado | null>(null);
  const [falha, setFalha] = useState<string | null>(null);
  const confirmar = async () => {
    if (!apagar) return;
    const r = await pedir(`/api/relatorios/historico/${apagar.id}`, { method: "DELETE" });
    if (!r.ok) setFalha(await detalhe(r, "Não foi possível apagar."));
    setApagar(null);
    recarregar();
  };
  return (
    <Painel titulo="Relatórios gerados">
      {falha && <Alert color="red" variant="light" p="xs" fz="sm" mb="sm">{falha}</Alert>}
      {!dados ? <Carregando erro={erro} /> : (
        <Tabela
          linhas={dados.relatorios}
          chave={(r) => r.id}
          vazio="Nenhum relatório gerado ainda."
          colunas={[
            { titulo: "Gerado em", largura: 150, celula: (r) => <Data valor={r.gerado_em} /> },
            { titulo: "Relatório", celula: (r) => <Text size="sm" fw={500}>{tituloDoGuardado(r)}</Text> },
            { titulo: "Período", largura: 90, celula: (r) => (r.dias === 365 ? "1 ano" : `${numero(r.dias)} dias`) },
            { titulo: "Formato", largura: 80, celula: (r) => r.formato.toUpperCase() },
            { titulo: "Por", celula: (r) => <>{r.gerado_por_nome}{r.mascarado && <Text size="xs" c="dimmed">Com dado pessoal mascarado</Text>}</> },
            { titulo: "Tamanho", alinhar: "right", largura: 90, celula: (r) => tamanho(r.tamanho) },
            { titulo: "", largura: 40, celula: (r) => (
              <AcoesDaLinha rotulo={`Ações do relatório ${r.nome}`} itens={[
                ...(r.pode_baixar ? [{ texto: "Baixar", aoClicar: () => { setFalha(null); baixar(`/api/relatorios/historico/${r.id}`, r.nome).catch((e: Error) => setFalha(e.message)); } }] : []),
                ...(r.pode_apagar ? [{ texto: "Apagar", perigo: true, aoClicar: () => setApagar(r) }] : []),
              ]} />
            ) },
          ]}
        />
      )}
      <Modal opened={apagar !== null} onClose={() => setApagar(null)} title="Apagar o relatório?">
        <Stack gap="sm">
          <Text size="sm">{apagar && `${tituloDoGuardado(apagar)}, gerado em ${new Date(apagar.gerado_em).toLocaleString("pt-BR")}.`} O arquivo some daqui. A auditoria continua registrando que ele foi gerado, com o resumo SHA-256.</Text>
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={() => setApagar(null)}>Cancelar</Button>
            <Button color="red" onClick={confirmar}>Apagar</Button>
          </Group>
        </Stack>
      </Modal>
    </Painel>
  );
}

const TIPOS: { valor: string; titulo: string; resumo: string; icone: ReactNode }[] = [
  { valor: "completo", titulo: "Completo", resumo: "Todos os capítulos", icone: <IconFileText size={20} stroke={1.5} /> },
  { valor: "executivo", titulo: "Executivo", resumo: "Resumo para a direção", icone: <IconPresentation size={20} stroke={1.5} /> },
];
const PERIODOS = [{ label: "7 dias", value: "7" }, { label: "30 dias", value: "30" }, { label: "90 dias", value: "90" }, { label: "1 ano", value: "365" }];
const FORMATOS = [{ label: "PDF", value: "pdf" }, { label: "Dados em JSON", value: "json" }];
const CAPITULOS = [
  "Resumo executivo, comparado ao período anterior", "Alertas: regras, ativos, origens, países e contas", "Risco de comportamento", "Técnicas de ataque e defesas relacionadas",
  "Integridade de arquivos", "Vulnerabilidades", "Automação e resposta, com quem decidiu", "Inventário de ativos", "Fontes de dados e detecção", "Conformidade por norma",
  "Trilha de auditoria e acessos", "Apêndices: números por dia, método e limites",
];

function Campo({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return <Stack gap={6}><Text size="xs" c="dimmed">{rotulo}</Text>{children}</Stack>;
}

export function Relatorios() {
  const [tipo, setTipo] = useState("completo");
  const [dias, setDias] = useState("30");
  const [formato, setFormato] = useState("pdf");
  const [gerando, setGerando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [gerado, setGerado] = useState<{ nome: string; resumo: string | null } | null>(null);
  const [verCapitulos, setVerCapitulos] = useState(false);
  const [versao, setVersao] = useState(0);

  const gerar = async () => {
    setErro(null);
    setGerado(null);
    setGerando(true);
    try {
      const r = await fetch(`/api/relatorios?${new URLSearchParams({ tipo, formato, dias })}`, { credentials: "same-origin" });
      if (r.status === 401) {
        window.location.assign("/");
        return;
      }
      if (!r.ok) throw new Error("falhou");
      const nome = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") ?? "")?.[1] ?? `relatorio-${tipo}.${formato}`;
      const link = document.createElement("a");
      link.href = URL.createObjectURL(await r.blob());
      link.download = nome;
      link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 10000);
      setGerado({ nome, resumo: r.headers.get("X-Resumo-SHA256") });
      setVersao((v) => v + 1);
    } catch {
      setErro("Não foi possível gerar o relatório. Tente de novo em instantes.");
    } finally {
      setGerando(false);
    }
  };

  return (
    <>
      <Cabecalho titulo="Relatórios" ajuda="O relatório sai em PDF, com capa e sumário, ou em dados JSON. Cada geração fica registrada na auditoria.">
        <Button leftSection={<IconListNumbers size={14} />} onClick={() => setVerCapitulos(true)}>Ver capítulos</Button>
      </Cabecalho>

      <Painel>
        <Stack gap="md" maw={640}>
          <Campo rotulo="Tipo">
            <SimpleGrid cols={{ base: 1, xs: 2 }} spacing="sm">
              {TIPOS.map((t) => (
                <Card key={t.valor} component="button" type="button" className="clicavel" p="sm" onClick={() => setTipo(t.valor)} aria-pressed={tipo === t.valor} data-selecionado={tipo === t.valor || undefined}>
                  <Group gap="sm" wrap="nowrap">
                    {t.icone}
                    <div>
                      <Text size="sm" fw={600}>{t.titulo}</Text>
                      <Text size="xs" c="dimmed">{t.resumo}</Text>
                    </div>
                  </Group>
                </Card>
              ))}
            </SimpleGrid>
          </Campo>
          <Group gap="xl" wrap="wrap" align="flex-start">
            <Campo rotulo="Período"><SegmentedControl size="xs" value={dias} onChange={setDias} data={PERIODOS} aria-label="Período" /></Campo>
            <Campo rotulo="Formato"><SegmentedControl size="xs" value={formato} onChange={setFormato} data={FORMATOS} aria-label="Formato" /></Campo>
          </Group>
          {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
          {gerado && (
            <Alert color="green" variant="light" p="xs" fz="sm" icon={<IconCheck size={16} />}>
              {gerado.nome}
              {gerado.resumo && <Text span size="xs" c="dimmed" display="block" className="mono">SHA-256 {gerado.resumo}</Text>}
            </Alert>
          )}
          <Group justify="space-between" wrap="wrap" gap="sm">
            <Text size="xs" c="dimmed">Traz nomes de pessoas e endereços: compartilhe só com quem precisa.</Text>
            <Button variant="filled" leftSection={<IconDownload size={14} />} loading={gerando} onClick={gerar}>Gerar relatório</Button>
          </Group>
        </Stack>
      </Painel>
      <div style={{ marginTop: 16 }}><HistoricoDeRelatorios versao={versao} /></div>

      <Drawer opened={verCapitulos} onClose={() => setVerCapitulos(false)} title="O que vem no relatório completo" size="md">
        <List type="ordered" size="sm" spacing="xs">
          {CAPITULOS.map((c) => <List.Item key={c}>{c}</List.Item>)}
        </List>
      </Drawer>
    </>
  );
}
