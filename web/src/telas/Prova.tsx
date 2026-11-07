import { ActionIcon, Alert, Button, CopyButton, Drawer, Group, SimpleGrid, Stack, Text, Tooltip } from "@mantine/core";
import { IconCheck, IconCopy, IconFileZip, IconTrash } from "@tabler/icons-react";
import { useState } from "react";

import { detalhe, enviar, useDados, useEu, usePode } from "../api";
import { cesta, useCesta } from "../cesta";
import { AcoesDaLinha, Cabecalho, Carregando, Data, Estado, Numero, Painel, Tabela } from "../componentes";
import { numero, quando } from "../formato";
import { Fatos } from "./Ataques";

const ACHADOS: Record<string, string> = {
  evento_alterado: "Evento alterado depois da selagem", evento_apagado: "Evento apagado depois da selagem", evento_sem_selo: "Evento que entrou sem selo",
  selo_faltando: "Selo faltando na sequência", selo_alterado: "Selo alterado", cadeia_quebrada: "Sequência de selos quebrada", assinatura_invalida: "Assinatura inválida",
  chave_desconhecida: "Selo feito com outra chave", folhas_alteradas: "Dados do selo alterados", folhas_faltando: "Dados do selo faltando",
  bloco_alterado: "Bloco de eventos alterado depois da selagem", eventos_sem_selo: "Eventos que entraram sem selo",
};
const FONTES: Record<string, string> = { alertas: "Alertas", logs: "Logs" };

/** Em volume alto o selo é em blocos: o achado diz o bloco e quantos eventos ele tinha e tem, em vez do evento. */
interface Achado { tipo: string; n?: number | null; evento?: string | null; bloco?: number; eventos_selados?: number; eventos_hoje?: number; quantos?: number }

function oQueMudou(a: Achado) {
  if (a.evento) return <span className="mono">{a.evento}</span>;
  if (a.bloco !== undefined) return `Bloco ${numero(a.bloco)}: ${numero(a.eventos_selados ?? 0)} eventos selados, ${numero(a.eventos_hoje ?? 0)} hoje`;
  if (a.quantos !== undefined) return `${numero(a.quantos)} eventos`;
  return "-";
}
interface Situacao {
  selos: { selos: number; eventos: number; tardios: number; ultimo: string | null; coberto_ate: string | null };
  verificacao: { quando: string; completa: boolean; selos_conferidos: number; eventos_conferidos: number; estado: string; achados: Achado[] | null } | null;
  ancoras: { total: number; ultima: string | null };
  impressao: string | null;
}

/** O navegador só baixa um arquivo gerado em memória por um link temporário. */
export function salvarArquivo(conteudo: Blob, nome: string) {
  const endereco = URL.createObjectURL(conteudo);
  const a = document.createElement("a");
  a.href = endereco;
  a.download = nome;
  a.click();
  URL.revokeObjectURL(endereco);
}

function Copiavel({ texto }: { texto: string }) {
  return (
    <Group gap={4} wrap="nowrap" align="flex-start">
      <span className="mono">{texto}</span>
      <CopyButton value={texto}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? "Copiado" : "Copiar"}>
            <ActionIcon size="xs" variant="subtle" color="gray" onClick={copy} aria-label="Copiar">{copied ? <IconCheck size={12} /> : <IconCopy size={12} />}</ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
    </Group>
  );
}

function EstadoDaCadeia({ dados }: { dados: Situacao }) {
  const eu = useEu();
  const v = dados.verificacao;
  if (!dados.selos.selos) return <Alert color="gray" variant="light" p="xs" fz="sm">Ainda sem selos: os primeiros saem em até 30 minutos depois da chegada dos eventos.</Alert>;
  if (!v) return <Alert color="gray" variant="light" p="xs" fz="sm">A cadeia está sendo selada e ainda não passou pela primeira conferência.</Alert>;
  if (v.estado === "violada") return <Alert color="red" variant="light" p="xs" fz="sm" role="alert">Violação encontrada na conferência de {quando(v.quando, eu.fuso)}. Preserve o ambiente e trate como incidente.</Alert>;
  return <Alert color="green" variant="light" p="xs" fz="sm">Tudo confere. Última conferência em {quando(v.quando, eu.fuso)}: {numero(v.selos_conferidos)} selos e {numero(v.eventos_conferidos)} eventos.</Alert>;
}

function GavetaDaCadeia({ aberta, dados, aoFechar }: { aberta: boolean; dados: Situacao; aoFechar: () => void }) {
  const v = dados.verificacao;
  return (
    <Drawer opened={aberta} onClose={aoFechar} title="Cadeia de selos" size="lg">
      <Fatos itens={[
        ["Selos na cadeia", numero(dados.selos.selos)],
        ["Eventos selados", numero(dados.selos.eventos)],
        ["Selado até", <Data valor={dados.selos.coberto_ate} />],
        ["Último selo", <Data valor={dados.selos.ultimo} />],
        ["Depois da janela", numero(dados.selos.tardios)],
        ["Âncoras públicas", numero(dados.ancoras.total)],
        ["Última âncora", <Data valor={dados.ancoras.ultima} />],
        ["Última conferência", v ? <Data valor={v.quando} /> : "-"],
        ["O que conferiu", v ? (v.completa ? "A cadeia inteira" : "Só os selos recentes") : "-"],
        ["Selos conferidos", v ? numero(v.selos_conferidos) : "-"],
        ["Eventos conferidos", v ? numero(v.eventos_conferidos) : "-"],
        ["Chave pública", dados.impressao ? <Copiavel texto={dados.impressao} /> : "Indisponível"],
      ]} />
    </Drawer>
  );
}

function GavetaDoAchado({ achado, aoFechar }: { achado: Achado | null; aoFechar: () => void }) {
  return (
    <Drawer opened={achado !== null} onClose={aoFechar} title={achado ? ACHADOS[achado.tipo] ?? achado.tipo : ""}>
      {achado && (
        <Fatos itens={[
          ["Selo", achado.n === null || achado.n === undefined ? "-" : numero(achado.n)],
          ["Evento", achado.evento ? <Copiavel texto={achado.evento} /> : oQueMudou(achado)],
        ]} />
      )}
    </Drawer>
  );
}

function PacoteDeEvidencia() {
  const c = useCesta();
  const [gerando, setGerando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [resumo, setResumo] = useState<string | null>(null);
  const gerar = async () => {
    setErro(null);
    setResumo(null);
    setGerando(true);
    try {
      const r = await enviar("/api/integridade/evidencia", { fonte: c.fonte, ids: c.itens.map((i) => i.id) });
      if (!r.ok) {
        setErro(await detalhe(r, "Não foi possível gerar o pacote."));
        return;
      }
      salvarArquivo(await r.blob(), "evidencia-roar.zip");
      setResumo(r.headers.get("X-Resumo-SHA256"));
      cesta.esvaziar();
    } catch {
      setErro("Não foi possível gerar o pacote.");
    } finally {
      setGerando(false);
    }
  };
  return (
    <Painel
      titulo="Pacote de evidência"
      acao={(
        <Group gap="xs" wrap="nowrap">
          {c.fonte && c.itens.length > 0 && <Estado tipo="outro">{FONTES[c.fonte] ?? c.fonte}</Estado>}
          {c.itens.length > 0 && <Button leftSection={<IconTrash size={14} />} onClick={() => cesta.esvaziar()}>Esvaziar</Button>}
          <Button variant="filled" leftSection={<IconFileZip size={14} />} disabled={!c.itens.length} loading={gerando} onClick={gerar}>Gerar pacote</Button>
        </Group>
      )}
    >
      <Stack gap="sm">
        {erro && <Alert color="red" variant="light" p="xs" fz="sm" role="alert">{erro}</Alert>}
        {resumo && <Alert color="green" variant="light" p="xs" fz="sm"><Group gap="xs" wrap="nowrap"><Text size="sm" style={{ whiteSpace: "nowrap" }}>Pacote gerado. SHA-256:</Text><Copiavel texto={resumo} /></Group></Alert>}
        <Tabela
          linhas={c.itens}
          chave={(i) => i.id}
          vazio={'Nenhum evento escolhido. Em Logs brutos ou no alerta bruto, use "Incluir na evidência".'}
          colunas={[
            { titulo: "Evento", celula: (i) => i.resumo },
            { titulo: "Identificador", celula: (i) => <Copiavel texto={i.id} /> },
            { titulo: "", largura: 40, celula: (i) => <AcoesDaLinha rotulo="Ações do evento" itens={[{ texto: "Tirar do pacote", perigo: true, aoClicar: () => cesta.tirar(i.id) }]} /> },
          ]}
        />
      </Stack>
    </Painel>
  );
}

export function Prova() {
  const pode = usePode();
  const { dados, erro } = useDados<Situacao>("/api/integridade");
  const [verCadeia, setVerCadeia] = useState(false);
  const [achado, setAchado] = useState<Achado | null>(null);
  const abrir = () => setVerCadeia(true);
  const achados = dados?.verificacao?.achados ?? [];
  return (
    <>
      <Cabecalho titulo="Prova e evidência" ajuda="Cada janela de logs e alertas é selada numa cadeia assinada: quem mexer num evento depois quebra a prova. O selo mostra que o registro não mudou desde a selagem, não que o conteúdo do log é verdadeiro. O pacote leva os eventos escolhidos, um só tipo por vez, com a prova, um laudo em PDF e um programa para qualquer pessoa conferir sem o Roar." />
      {!dados ? <Carregando erro={erro} /> : (
        <Stack gap="md">
          <EstadoDaCadeia dados={dados} />
          <SimpleGrid cols={{ base: 2, md: 3, lg: 5 }}>
            <Numero rotulo="Eventos selados" valor={numero(dados.selos.eventos)} aoClicar={abrir} />
            <Numero rotulo="Selos na cadeia" valor={numero(dados.selos.selos)} aoClicar={abrir} />
            <Numero rotulo="Selado até" valor={<Data valor={dados.selos.coberto_ate} />} aoClicar={abrir} />
            <Numero rotulo="Chegaram depois da janela" valor={numero(dados.selos.tardios)} aoClicar={abrir} />
            <Numero rotulo="Âncoras públicas" valor={numero(dados.ancoras.total)} aoClicar={abrir} />
          </SimpleGrid>
          {achados.length > 0 && (
            <Painel titulo="O que a conferência achou">
              <Tabela
                linhas={achados.map((a, i) => ({ ...a, i }))}
                chave={(a) => a.i}
                vazio=""
                aoClicarLinha={setAchado}
                colunas={[
                  { titulo: "O que foi achado", celula: (a) => ACHADOS[a.tipo] ?? a.tipo },
                  { titulo: "Selo", alinhar: "right", largura: 90, celula: (a) => (a.n === null || a.n === undefined ? "-" : numero(a.n)) },
                  { titulo: "Evento", celula: oQueMudou },
                ]}
              />
            </Painel>
          )}
          {pode("ver_bruto") && <PacoteDeEvidencia />}
          <GavetaDaCadeia aberta={verCadeia} dados={dados} aoFechar={() => setVerCadeia(false)} />
          <GavetaDoAchado achado={achado} aoFechar={() => setAchado(null)} />
        </Stack>
      )}
    </>
  );
}
