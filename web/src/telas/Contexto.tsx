import { Anchor, Badge, Group, Stack, Text, Title } from "@mantine/core";
import { IconAlertTriangle, IconArrowDown, IconInfoCircle } from "@tabler/icons-react";

import { useDados } from "../api";
import { numero } from "../formato";

interface Sinal { tom: "agrava" | "atenua" | "informa"; texto: string; detalhe?: string | null; endereco?: string | null }
interface DadosDoContexto {
  sinais: Sinal[];
  origem: { ip: string | null; operadora: string | null; asn: string | null; local: string | null; vezes: number; ativos: number; primeira_em: string | null } | null;
  grupos: { tecnica: string; grupos: string; total: string | null; endereco: string | null }[];
}

const TONS = {
  agrava: { cor: "red", icone: <IconAlertTriangle size={12} /> },
  atenua: { cor: "teal", icone: <IconArrowDown size={12} /> },
  informa: { cor: "gray", icone: <IconInfoCircle size={12} /> },
} as const;

/** O que se sabe em volta do alerta, para ninguém precisar abrir cinco abas. */
export function PainelDeContexto({ evento }: { evento: number }) {
  const { dados } = useDados<DadosDoContexto>(`/api/eventos/${evento}/contexto`);
  if (!dados) return null;
  const { sinais, origem, grupos } = dados;
  if (!sinais.length && !origem && !grupos.length) return null;
  return (
    <Stack gap="xs">
      <Title order={3}>Contexto</Title>
      {sinais.length > 0 && (
        <Group gap={6}>
          {sinais.map((s) => {
            const tom = TONS[s.tom];
            const selo = <Badge key={s.texto} variant="light" radius="sm" tt="none" fw={500} color={tom.cor} leftSection={tom.icone} title={s.detalhe ?? undefined} style={s.endereco ? { cursor: "pointer" } : undefined}>{s.texto}</Badge>;
            return s.endereco ? <Anchor key={s.texto} href={s.endereco} target="_blank" rel="noreferrer noopener" underline="never">{selo}</Anchor> : selo;
          })}
        </Group>
      )}
      {origem && (
        <Text size="sm" c="dimmed">
          {[origem.operadora && `${origem.operadora}${origem.asn ? ` (AS${origem.asn})` : ""}`, origem.local, `${numero(origem.vezes)} ${origem.vezes === 1 ? "evento" : "eventos"} desta origem em 30 dias, em ${numero(origem.ativos)} ${origem.ativos === 1 ? "ativo" : "ativos"}`].filter(Boolean).join(" · ")}
        </Text>
      )}
      {grupos.map((g) => (
        <Text key={g.tecnica} size="xs" c="dimmed">
          <Anchor href={g.endereco ?? undefined} target="_blank" rel="noreferrer noopener" size="xs" className="mono">{g.tecnica}</Anchor> usada por {g.grupos}{Number(g.total) > 12 ? ` e mais ${Number(g.total) - 12}` : ""}
        </Text>
      ))}
    </Stack>
  );
}
