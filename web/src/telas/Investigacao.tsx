import { Anchor, Box, Group, Paper, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { IconAlertTriangle, IconArrowDown, IconInfoCircle } from "@tabler/icons-react";
import { useState } from "react";

import { useDados, useEu, usePode } from "../api";
import { GavetaDoBruto } from "../componentes";
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
      <GavetaDoBruto evento={bruto} aoFechar={() => setBruto(null)} />
    </Stack>
  );
}
