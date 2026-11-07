import { Alert, Anchor, Badge, Box, Button, Group, List, Paper, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { IconAlertTriangle, IconArrowDown, IconInfoCircle, IconSparkles } from "@tabler/icons-react";
import { useState } from "react";

import { detalhe, enviar, useDados, useEu, usePode } from "../api";
import { Data, GavetaDoBruto } from "../componentes";
import { quando } from "../formato";

interface Citado { id: number; quando: string; descricao: string; ip: string | null; usuario: string | null; ativo: string | null }
interface Pergunta { id: string; pergunta: string; resposta: string; tom: "agrava" | "atenua" | "informa"; como: string; eventos: Citado[] }
interface Pacote { perguntas: Pergunta[]; armazem: boolean | null }

const TONS = {
  agrava: { cor: "red", icone: <IconAlertTriangle size={14} />, rotulo: "Pesa contra" },
  atenua: { cor: "teal", icone: <IconArrowDown size={14} />, rotulo: "Alivia" },
  informa: { cor: "gray", icone: <IconInfoCircle size={14} />, rotulo: "Informa" },
} as const;

/** As perguntas de um analista sobre o alerta, já respondidas, com os alertas que provam cada resposta (api/roar_api/investigacao.py). */
export function PainelDeInvestigacao({ evento }: { evento: number }) {
  const eu = useEu();
  const pode = usePode();
  const [bruto, setBruto] = useState<number | null>(null);
  const { dados } = useDados<Pacote>(`/api/eventos/${evento}/investigacao`);
  if (!dados || !dados.perguntas.length) return null;
  return (
    <Stack gap="xs">
      <div>
        <Title order={3}>Investigação</Title>
        <Text size="xs" c="dimmed">O Roar olhou as 24 horas antes e depois deste alerta. Cada resposta traz como foi achada e os alertas que a provam.</Text>
      </div>
      {dados.perguntas.map((p) => {
        const tom = TONS[p.tom];
        return (
          <Paper key={p.id} withBorder p="sm" radius="md">
            <Group gap="sm" align="flex-start" wrap="nowrap">
              <ThemeIcon variant="light" color={tom.cor} size="md" radius="xl" title={tom.rotulo}>{tom.icone}</ThemeIcon>
              <Box style={{ flex: 1, minWidth: 0 }}>
                <Text size="sm" fw={600}>{p.pergunta}</Text>
                <Text size="sm">{p.resposta}</Text>
                <Text size="xs" c="dimmed" mt={2}>{p.como}</Text>
                {p.eventos.length > 0 && (
                  <Stack gap={0} mt={4}>
                    {p.eventos.map((c) => {
                      const texto = `${quando(c.quando, eu.fuso)} · ${c.descricao}${c.usuario ? ` · ${c.usuario}` : ""}${c.ip ? ` · ${c.ip}` : ""}`;
                      return pode("ver_bruto")
                        ? <Anchor key={c.id} component="button" type="button" size="xs" ta="left" onClick={() => setBruto(c.id)}>{texto}</Anchor>
                        : <Text key={c.id} size="xs" c="dimmed">{texto}</Text>;
                    })}
                  </Stack>
                )}
              </Box>
            </Group>
          </Paper>
        );
      })}
      {dados.armazem === false && <Text size="xs" c="dimmed">O armazém não respondeu agora: os logs e os fluxos de rede ficaram de fora.</Text>}
      <ParecerDaIa evento={evento} perguntas={dados.perguntas} aoAbrir={pode("ver_bruto") ? setBruto : undefined} />
      <GavetaDoBruto evento={bruto} aoFechar={() => setBruto(null)} />
    </Stack>
  );
}

interface Motivo { texto: string; perguntas: string[]; alertas: number[] }
interface Parecer {
  veredito: "ataque" | "suspeito" | "benigno" | "inconclusivo";
  confianca: "baixa" | "media" | "alta";
  resumo: string;
  motivos: Motivo[];
  proximos_passos: string[];
  avisos: string[];
  segundos: number;
  modelo: string;
  criado_em: string;
  pedido_por_nome: string | null;
}
interface RespostaDoParecer { disponivel: boolean; modelo: string | null; parecer: Parecer | null }

const VEREDITOS = {
  ataque: { cor: "red", texto: "Ataque" },
  suspeito: { cor: "orange", texto: "Suspeito" },
  benigno: { cor: "teal", texto: "Benigno" },
  inconclusivo: { cor: "gray", texto: "Inconclusivo" },
} as const;
const CONFIANCAS = { baixa: "confiança baixa", media: "confiança média", alta: "confiança alta" } as const;

/** A IA local lê as perguntas acima e dá um parecer. O Roar já tirou o que ela não conseguiu provar (api/roar_api/parecer.py). */
function ParecerDaIa({ evento, perguntas, aoAbrir }: { evento: number; perguntas: Pergunta[]; aoAbrir?: (id: number) => void }) {
  const { dados, recarregar } = useDados<RespostaDoParecer>(`/api/eventos/${evento}/parecer`);
  const [pensando, setPensando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  if (!dados || !dados.disponivel) return null;
  const pedirParecer = async () => {
    setPensando(true);
    setErro(null);
    try {
      const r = await enviar(`/api/eventos/${evento}/parecer`);
      if (!r.ok) setErro(await detalhe(r));
      recarregar();
    } finally {
      setPensando(false);
    }
  };
  const p = dados.parecer;
  const nomeDaPergunta = (id: string) => perguntas.find((q) => q.id === id)?.pergunta ?? id;
  return (
    <Paper withBorder p="sm" radius="md">
      <Stack gap="xs">
        <Group justify="space-between" wrap="nowrap">
          <Group gap="xs">
            <ThemeIcon variant="light" color="grape" size="md" radius="xl"><IconSparkles size={14} /></ThemeIcon>
            <Text size="sm" fw={600}>Parecer da IA</Text>
          </Group>
          <Button size="xs" variant={p ? "default" : "filled"} loading={pensando} onClick={pedirParecer}>{p ? "Pedir de novo" : "Pedir parecer da IA"}</Button>
        </Group>
        {!p && !pensando && (
          <Text size="xs" c="dimmed">A IA roda no próprio servidor ({dados.modelo}) e lê só as respostas acima, com contas e endereços trocados por apelidos. Nada sai do servidor.</Text>
        )}
        {pensando && <Text size="xs" c="dimmed">A IA está lendo as provas. Pode levar de alguns segundos a um minuto.</Text>}
        {erro && <Text size="xs" c="red">{erro}</Text>}
        {p && (
          <>
            <Group gap="xs">
              <Badge color={VEREDITOS[p.veredito].cor} variant="filled" radius="sm">{VEREDITOS[p.veredito].texto}</Badge>
              <Text size="xs" c="dimmed">{CONFIANCAS[p.confianca]}</Text>
            </Group>
            <Text size="sm">{p.resumo}</Text>
            {p.motivos.length > 0 && (
              <List size="sm" spacing={4}>
                {p.motivos.map((m, i) => (
                  <List.Item key={i}>
                    {m.texto}
                    <Text size="xs" c="dimmed" component="div">
                      {m.perguntas.map(nomeDaPergunta).join(" · ")}
                      {m.alertas.length > 0 && <>{m.perguntas.length > 0 && " · "}alertas {m.alertas.map((a, j) => (
                        <span key={a}>{j > 0 && ", "}{aoAbrir ? <Anchor component="button" type="button" size="xs" onClick={() => aoAbrir(a)}>nº {a}</Anchor> : `nº ${a}`}</span>
                      ))}</>}
                    </Text>
                  </List.Item>
                ))}
              </List>
            )}
            {p.proximos_passos.length > 0 && (
              <div>
                <Text size="xs" fw={600}>Próximos passos</Text>
                <List size="sm" type="ordered" spacing={2}>{p.proximos_passos.map((x, i) => <List.Item key={i}>{x}</List.Item>)}</List>
              </div>
            )}
            {p.avisos.length > 0 && (
              <Alert color="yellow" variant="light" p="xs" icon={<IconAlertTriangle size={14} />}>
                <Stack gap={2}>{p.avisos.map((a) => <Text key={a} size="xs">{a}</Text>)}</Stack>
              </Alert>
            )}
            <Text size="xs" c="dimmed">
              {p.modelo} no próprio servidor, em {String(p.segundos).replace(".", ",")} s · <Data valor={p.criado_em} />{p.pedido_por_nome ? ` · pedido por ${p.pedido_por_nome}` : ""}. A IA pode errar: confira as provas antes de decidir.
            </Text>
          </>
        )}
      </Stack>
    </Paper>
  );
}
