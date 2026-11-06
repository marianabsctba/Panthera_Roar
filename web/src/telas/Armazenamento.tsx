import { Alert, Button, Group, Select, SimpleGrid, Stack, Switch, Text, TextInput } from "@mantine/core";
import { useEffect, useState } from "react";

import { detalhe, enviar, pedir, useDados } from "../api";
import { AcoesDaLinha, Cabecalho, Carregando, Data, Estado, Numero, Painel, Tabela } from "../componentes";
import { tamanho } from "../formato";

interface Configuracao {
  retencao_alertas_dias: number; retencao_logs_dias: number; guardar_logs: boolean; estado: string; mensagem: string | null;
  arquivo: { ultima: string | null; copias: number; dias: number } | null;
  ler_do_armazem: boolean; armazem_disponivel: boolean;
}

/** Durante a migração para o armazém novo: de onde a tela de logs, os painéis e as buscas agendadas leem. */
function LeituraDoArmazem({ ler, aoMudar }: { ler: boolean; aoMudar: () => void }) {
  const [aviso, setAviso] = useState<string | null>(null);
  const trocar = async (valor: boolean) => {
    const r = await pedir("/api/organizacao/armazenamento/leitura", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ler: valor }) });
    setAviso(r.ok ? null : await detalhe(r));
    aoMudar();
  };
  return (
    <Painel titulo="Armazém novo">
      <Stack gap="xs">
        <Text size="sm">Os logs desta organização já chegam também ao armazém novo, feito para volumes grandes. Os dois guardam os mesmos logs, então dá para trocar e voltar quando quiser.</Text>
        <Switch label="Ler logs, painéis e buscas agendadas do armazém novo" checked={ler} onChange={(e) => trocar(e.currentTarget.checked)} />
        <Text size="xs" c="dimmed">Em teste. Também passam a ler de lá a caça de indicadores, a saúde das fontes e o volume. O pacote de perícia e os relatórios ainda leem do armazenamento atual.</Text>
        {aviso && <Alert color="red" variant="light" p="xs"><Text size="sm">{aviso}</Text></Alert>}
      </Stack>
    </Painel>
  );
}
interface Volume { ocupado: { logs: number; alertas: number; por_dia: { dia: string; logs: number; alertas: number }[] } | null }

const PRAZOS = [7, 30, 90, 180, 365, 730, 1825];
const rotuloDoPrazo = (d: number) => (d % 365 === 0 ? `${d / 365} ${d === 365 ? "ano" : "anos"}` : `${d} dias`);
const opcoes = (minimo: number) => PRAZOS.filter((d) => d >= minimo).map((d) => ({ value: String(d), label: rotuloDoPrazo(d) }));
const ESTADOS: Record<string, [string, string]> = { pendente: ["pendente", "Aplicando"], aplicado: ["ativa", "Aplicado"], falhou: ["recusada", "Falhou"] };

interface Pedido { id: number; de: string; ate: string; tipo: string; dias_de_consulta: number; estado: string; mensagem: string | null; indices: number; criado_em: string; expira_em: string | null }
interface Copia { disponivel: { alertas: string[]; logs: string[] } | null; pedidos: Pedido[] }

const TIPOS = [{ value: "ambos", label: "Alertas e logs brutos" }, { value: "alertas", label: "Só alertas" }, { value: "logs", label: "Só logs brutos" }];
const ESTADOS_DO_PEDIDO: Record<string, [string, string]> = {
  pendente: ["pendente", "Na fila"], em_andamento: ["pendente", "Voltando"], pronto: ["ativa", "Disponível"], falhou: ["recusada", "Falhou"],
  devolver: ["pendente", "Devolvendo"], devolvido: ["outro", "Devolvido"],
};
const diaBr = (iso: string) => iso.slice(0, 10).split("-").reverse().join("/");

/** Dias seguidos viram um trecho só: "01/09 a 30/09" lê melhor que trinta datas. */
function trechos(dias: string[]) {
  const saida: [string, string][] = [];
  for (const d of dias) {
    const ultimo = saida[saida.length - 1];
    if (ultimo && (new Date(d).getTime() - new Date(ultimo[1]).getTime()) === 86400000) ultimo[1] = d;
    else saida.push([d, d]);
  }
  return saida;
}

function Recuperar() {
  const { dados, recarregar } = useDados<Copia>("/api/organizacao/copia-fria");
  const [de, setDe] = useState("");
  const [ate, setAte] = useState("");
  const [tipo, setTipo] = useState("ambos");
  const [prazo, setPrazo] = useState("7");
  const [aviso, setAviso] = useState<string | null>(null);

  const andando = dados?.pedidos.some((p) => ["pendente", "em_andamento", "devolver"].includes(p.estado));
  useEffect(() => {
    if (!andando) return;
    const t = setInterval(recarregar, 5000);
    return () => clearInterval(t);
  }, [andando, recarregar]);

  if (!dados) return null;
  const dias = [...new Set([...(dados.disponivel?.alertas ?? []), ...(dados.disponivel?.logs ?? [])])].sort();

  const pedirDeVolta = async () => {
    const r = await enviar("/api/organizacao/copia-fria", { de, ate, tipo, dias_de_consulta: Number(prazo) });
    setAviso(r.ok ? null : await detalhe(r));
    recarregar();
  };
  const devolverAgora = async (id: number) => {
    await enviar(`/api/organizacao/copia-fria/${id}/devolver`);
    recarregar();
  };

  return (
    <Painel titulo="Trazer de volta da cópia fria">
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          {dias.length ? <>Fora do índice, mas na cópia: {trechos(dias).map(([a, b]) => (a === b ? diaBr(a) : `${diaBr(a)} a ${diaBr(b)}`)).join(", ")}.</> : "Nenhum dia fora do índice está na cópia fria ainda."}
          {" "}O que voltar aparece nas telas de sempre pelo prazo escolhido, e depois sai sozinho.
        </Text>
        <Group grow align="flex-end">
          <TextInput type="date" label="De" value={de} onChange={(e) => setDe(e.currentTarget.value)} />
          <TextInput type="date" label="Até" value={ate} onChange={(e) => setAte(e.currentTarget.value)} />
          <Select label="O quê" allowDeselect={false} value={tipo} onChange={(v) => setTipo(v ?? tipo)} data={TIPOS} />
          <Select label="Fica disponível por" allowDeselect={false} value={prazo} onChange={(v) => setPrazo(v ?? prazo)} data={["1", "3", "7", "15", "30"].map((d) => ({ value: d, label: `${d} ${d === "1" ? "dia" : "dias"}` }))} />
          <Button variant="filled" disabled={!de || !ate || andando} onClick={pedirDeVolta}>Trazer de volta</Button>
        </Group>
        {aviso && <Alert color="red" variant="light" p="xs"><Text size="sm">{aviso}</Text></Alert>}
        {dados.pedidos.length > 0 && (
          <Tabela
            linhas={dados.pedidos}
            chave={(p) => p.id}
            vazio=""
            colunas={[
              { titulo: "Período", celula: (p) => `${diaBr(p.de)} a ${diaBr(p.ate)}` },
              { titulo: "O quê", celula: (p) => TIPOS.find((t) => t.value === p.tipo)?.label ?? p.tipo },
              { titulo: "Situação", celula: (p) => { const [t, x] = ESTADOS_DO_PEDIDO[p.estado] ?? ["outro", p.estado]; return <Group gap="xs" wrap="nowrap"><Estado tipo={t}>{x}</Estado>{p.mensagem && <Text size="xs" c="dimmed">{p.mensagem}</Text>}</Group>; } },
              { titulo: "Sai em", largura: 150, celula: (p) => (p.estado === "pronto" ? <Data valor={p.expira_em} /> : "-") },
              { titulo: "", largura: 40, celula: (p) => <AcoesDaLinha rotulo="Ações da recuperação" itens={p.estado === "pronto" ? [{ texto: "Devolver agora", aoClicar: () => devolverAgora(p.id) }] : []} /> },
            ]}
          />
        )}
      </Stack>
    </Painel>
  );
}

export function Armazenamento() {
  const { dados, erro, recarregar } = useDados<Configuracao>("/api/organizacao/armazenamento");
  const { dados: volume } = useDados<Volume>("/api/volume?dias=30");
  const [alertas, setAlertas] = useState("180");
  const [logs, setLogs] = useState("180");
  const [guardar, setGuardar] = useState(true);
  const [aviso, setAviso] = useState<string | null>(null);

  useEffect(() => {
    if (!dados) return;
    setAlertas(String(dados.retencao_alertas_dias));
    setLogs(String(dados.retencao_logs_dias));
    setGuardar(dados.guardar_logs);
  }, [dados]);

  // Aplicar pede uma volta do serviço que configura o indexador e os gerenciadores.
  useEffect(() => {
    if (dados?.estado !== "pendente") return;
    const t = setInterval(recarregar, 10000);
    return () => clearInterval(t);
  }, [dados?.estado, recarregar]);

  if (!dados) return <><Cabecalho titulo="Armazenamento" ajuda="" /><Carregando erro={erro} /></>;

  const o = volume?.ocupado;
  // Hoje ainda está crescendo: fica fora da média.
  const fechados = o?.por_dia.slice(0, -1) ?? [];
  const media = (campo: "logs" | "alertas") => (fechados.length ? fechados.reduce((t, d) => t + d[campo], 0) / fechados.length : null);
  const logsPorDia = media("logs");
  const alertasPorDia = media("alertas");
  const estimativa = logsPorDia === null || alertasPorDia === null ? null : (guardar ? logsPorDia * Number(logs) : 0) + alertasPorDia * Number(alertas);
  const mudou = String(dados.retencao_alertas_dias) !== alertas || String(dados.retencao_logs_dias) !== logs || dados.guardar_logs !== guardar;
  const [tipo, texto] = ESTADOS[dados.estado] ?? ["outro", dados.estado];

  const salvar = async () => {
    const r = await pedir("/api/organizacao/armazenamento", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ retencao_alertas_dias: Number(alertas), retencao_logs_dias: Number(logs), guardar_logs: guardar }),
    });
    setAviso(r.ok ? null : await detalhe(r));
    recarregar();
  };

  return (
    <>
      <Cabecalho titulo="Armazenamento" ajuda="Quanto tempo esta organização guarda alertas e logs brutos, e se guarda os logs brutos. É isso que mais pesa no disco." />
      <Stack gap="md">
        <SimpleGrid cols={{ base: 1, sm: 3 }}>
          <Numero rotulo="Ocupado agora" valor={tamanho(o ? o.logs + o.alertas : null)} />
          <Numero rotulo="Cresce por dia" valor={tamanho(logsPorDia === null || alertasPorDia === null ? null : logsPorDia + alertasPorDia)} detalhe={fechados.length ? `média de ${fechados.length} ${fechados.length === 1 ? "dia" : "dias"}` : "precisa de um dia inteiro"} />
          <Numero rotulo="Com os prazos escolhidos" valor={tamanho(estimativa)} detalhe="estimativa, se o ritmo seguir" />
        </SimpleGrid>
        <Painel titulo="Prazos" acao={<Group gap="xs"><Estado tipo={tipo}>{texto}</Estado>{dados.mensagem && <Text size="xs" c="dimmed">{dados.mensagem}</Text>}</Group>}>
          <Stack gap="md">
            <Group grow align="flex-start">
              <Select label="Alertas" description="O que virou alerta, com o detalhe de cada um." allowDeselect={false} value={alertas} onChange={(v) => setAlertas(v ?? alertas)} data={opcoes(30)} />
              <Select label="Logs brutos" description="Tudo o que chega, inclusive o que não virou alerta." allowDeselect={false} value={logs} onChange={(v) => setLogs(v ?? logs)} data={opcoes(7)} disabled={!guardar} />
            </Group>
            <Switch label="Guardar os logs brutos e selar cada um" checked={guardar} onChange={(e) => setGuardar(e.currentTarget.checked)} />
            {!guardar && (
              <Alert color="yellow" variant="light" p="xs">
                <Text size="sm">Sem os logs brutos, só os alertas ficam guardados e selados. Não dá para investigar o que não virou alerta, nem provar depois o que chegou fora deles. Os logs brutos já guardados ficam até vencer o prazo.</Text>
              </Alert>
            )}
            <Text size="xs" c="dimmed">Seis meses é o padrão, o mesmo prazo que o Marco Civil pede a provedor de aplicação. Confira o que a sua organização precisa cumprir.</Text>
            {aviso && <Alert color="red" variant="light" p="xs"><Text size="sm">{aviso}</Text></Alert>}
            <Group justify="flex-end"><Button variant="filled" disabled={!mudou} onClick={salvar}>Salvar</Button></Group>
          </Stack>
        </Painel>
        <Painel titulo="Cópia fria">
          {!dados.arquivo ? <Text size="sm" c="dimmed">Esta instalação ainda não faz cópia fria.</Text> : (
            <Stack gap={6}>
              <Group gap="xs">
                <Text size="sm">Última cópia:</Text>
                {dados.arquivo.ultima ? <Data valor={dados.arquivo.ultima} /> : <Text size="sm" c="dimmed">ainda não feita, roda de madrugada</Text>}
              </Group>
              <Text size="sm" c="dimmed">Todo dia, alertas e logs brutos são copiados para fora do índice, e cada cópia fica {dados.arquivo.dias} dias. Depois que o prazo daqui apaga um dia, ele ainda pode voltar da cópia, e os selos continuam valendo para conferir.</Text>
            </Stack>
          )}
        </Painel>
        {dados.arquivo && <Recuperar />}
        {dados.armazem_disponivel && <LeituraDoArmazem ler={dados.ler_do_armazem} aoMudar={recarregar} />}
      </Stack>
    </>
  );
}
