import { Alert, Badge, Button, Group, Select, SimpleGrid, Stack, Switch, Text } from "@mantine/core";
import { useEffect, useState } from "react";

import { detalhe, pedir, useDados, usePode } from "../api";
import { Cabecalho, Carregando, Numero, Painel } from "../componentes";

interface SituacaoDaIa {
  instalada: boolean;
  no_ar?: boolean;
  modelo?: string;
  /** Quanto do modelo em uso está na placa de vídeo, em %; null quando ele não está carregado agora. */
  na_placa?: number | null;
  /** Só para quem administra a instalação. */
  modelos?: string[];
  plataforma: boolean;
  organizacao: { ligada: boolean; automatico_nivel: number | null };
  semana: { pareceres: number; automaticos: number; segundos_medios: number | null };
}

const NIVEIS = [
  { value: "", label: "Só quando alguém pedir" },
  { value: "12", label: "Nível 12 ou mais (críticos)" },
  { value: "10", label: "Nível 10 ou mais (altos e críticos)" },
  { value: "7", label: "Nível 7 ou mais (médios para cima)" },
];

async function gravar(rota: string, corpo: unknown) {
  const r = await pedir(rota, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo) });
  return r.ok ? null : detalhe(r);
}

/** Liga e desliga a IA da organização e o parecer automático. A instalação (modelo) só quem administra o servidor muda. */
export function IaLocal() {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<SituacaoDaIa>("/api/ia");
  const [aviso, setAviso] = useState<string | null>(null);
  const [modelo, setModelo] = useState<string | null>(null);
  useEffect(() => { if (dados?.modelo) setModelo(dados.modelo); }, [dados?.modelo]);
  if (!dados) return <><Cabecalho titulo="IA local" ajuda="" /><Carregando erro={erro} /></>;
  const org = dados.organizacao;
  const podeMudar = pode("gerir_usuarios");
  const mudar = async (ligada: boolean, nivel: number | null) => {
    setAviso(await gravar("/api/organizacao/ia", { ligada, automatico_nivel: ligada ? nivel : null }));
    recarregar();
  };
  const trocarModelo = async () => {
    if (!modelo) return;
    setAviso(await gravar("/api/ia/modelo", { modelo }));
    recarregar();
  };
  const situacao = !dados.instalada ? { cor: "gray", texto: "Não instalada" } : dados.no_ar ? { cor: "teal", texto: "No ar" } : { cor: "red", texto: "Fora do ar" };
  return (
    <Stack gap="md">
      <Cabecalho titulo="IA local" ajuda="A IA lê a investigação de um alerta e dá um parecer: ataque, suspeito, benigno ou inconclusivo, com os motivos. Ela roda no próprio servidor; nada sai dele." />
      {aviso && <Alert color="red" variant="light">{aviso}</Alert>}
      <Painel titulo="Nesta organização">
        <Stack gap="sm">
          <Switch
            label="Usar a IA nos alertas desta organização"
            description="Desligada, o botão Pedir parecer da IA some e nenhum alerta é lido pela IA."
            checked={org.ligada}
            disabled={!podeMudar || !dados.instalada}
            onChange={(e) => mudar(e.currentTarget.checked, org.automatico_nivel)}
          />
          <Select
            label="Parecer automático"
            description="A IA dá o parecer sozinha nos alertas que chegarem a partir deste nível, um por grupo da Fila, os mais graves primeiro. Só vale para o que chegar depois de ligar."
            data={NIVEIS}
            value={org.automatico_nivel ? String(org.automatico_nivel) : ""}
            disabled={!podeMudar || !dados.instalada || !org.ligada}
            allowDeselect={false}
            w={420}
            onChange={(v) => mudar(true, v ? Number(v) : null)}
          />
          {!podeMudar && <Text size="xs" c="dimmed">Só a administração da organização muda estas opções.</Text>}
        </Stack>
      </Painel>
      <Painel titulo="Últimos 7 dias">
        <SimpleGrid cols={{ base: 1, sm: 3 }}>
          <Numero rotulo="Pareceres" valor={dados.semana.pareceres} />
          <Numero rotulo="Automáticos" valor={dados.semana.automaticos} />
          <Numero rotulo="Tempo médio" valor={dados.semana.segundos_medios === null ? "-" : `${String(dados.semana.segundos_medios).replace(".", ",")} s`} />
        </SimpleGrid>
      </Painel>
      <Painel titulo="Na instalação">
        <Stack gap="sm">
          <Group gap="xs">
            <Badge color={situacao.cor} variant="light" radius="sm">{situacao.texto}</Badge>
            {dados.modelo && <Text size="sm">Modelo <b>{dados.modelo}</b></Text>}
            {dados.na_placa !== undefined && dados.na_placa !== null && (
              <Text size="sm" c="dimmed">· {dados.na_placa}% na placa de vídeo{dados.na_placa < 100 ? ", o resto no processador" : ""}</Text>
            )}
          </Group>
          {!dados.instalada && (
            <Text size="sm" c="dimmed">Esta instalação não tem IA. Quem administra o servidor liga com IA_MODELO no arquivo .env e roda infra/servicos.sh de novo.</Text>
          )}
          {dados.instalada && !dados.no_ar && <Text size="sm" c="red">O serviço roar-ia não respondeu. Quem administra o servidor precisa conferir o contêiner.</Text>}
          {dados.plataforma && dados.modelos && dados.modelos.length > 0 && (
            <Group align="flex-end" gap="xs">
              <Select label="Modelo da instalação inteira" data={dados.modelos} value={modelo} onChange={setModelo} allowDeselect={false} w={280} />
              <Button size="sm" variant="default" disabled={!modelo || modelo === dados.modelo} onClick={trocarModelo}>Trocar</Button>
            </Group>
          )}
          {dados.plataforma && dados.instalada && (
            <Text size="xs" c="dimmed">Aparecem só os modelos já baixados no servidor. Para outro, baixe com docker exec roar-ia ollama pull nome-do-modelo e volte aqui.</Text>
          )}
        </Stack>
      </Painel>
    </Stack>
  );
}
