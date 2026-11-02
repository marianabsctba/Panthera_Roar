import { ActionIcon, Alert, Box, Button, Group, Modal, SegmentedControl, Select, Stack, Text, Textarea, TextInput, Title } from "@mantine/core";
import { IconPlus, IconX } from "@tabler/icons-react";
import { useState } from "react";

import { detalhe, enviar } from "../api";

export interface RegraPropria { id: number; titulo: string; formato: string; estado: string; mensagem: string | null; criada_em: string; aplicada_em: string | null; origem: string }

/** De onde o editor abriu: é isso que decide para qual rota a regra vai ao salvar. */
export type AberturaDoEditor =
  | { tipo: "nova" }
  | { tipo: "propria"; regra: RegraPropria }
  | { tipo: "catalogo"; regraId: string; xml: string }
  | { tipo: "base"; xml: string };

type Modo = "guiada" | "sigma" | "xml";
interface Condicao { campo: string; operador: string; valor: string }

const CAMPOS_DA_ORIGEM: Record<string, { value: string; label: string }[]> = {
  windows_processo: [
    { value: "Image", label: "Programa" }, { value: "CommandLine", label: "Linha de comando" }, { value: "ParentImage", label: "Programa pai" }, { value: "ParentCommandLine", label: "Linha de comando do pai" },
    { value: "User", label: "Usuário" }, { value: "OriginalFileName", label: "Nome original do arquivo" }, { value: "CurrentDirectory", label: "Pasta atual" },
  ],
  windows_seguranca: [
    { value: "EventID", label: "Número do evento" }, { value: "TargetUserName", label: "Conta afetada" }, { value: "SubjectUserName", label: "Conta que agiu" }, { value: "IpAddress", label: "Endereço" },
    { value: "LogonType", label: "Tipo de logon" }, { value: "WorkstationName", label: "Estação" }, { value: "ServiceName", label: "Serviço" },
  ],
};
const OPERADORES = [{ value: "contem", label: "contém" }, { value: "igual", label: "é igual a" }, { value: "comeca", label: "começa com" }, { value: "termina", label: "termina com" }];
const CONDICOES_NO_MAXIMO = 10;
const novaCondicao = (origem: string): Condicao => ({ campo: CAMPOS_DA_ORIGEM[origem]?.[0].value ?? "", operador: "contem", valor: "" });
const ESTILO_DE_CODIGO = { input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 12 } };

const EXEMPLO_SIGMA = "title: Minha regra\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selecao:\n    Image|endswith: '\\powershell.exe'\n  condition: selecao\nlevel: high";
const EXEMPLO_XML = "<group name=\"minhas_regras,\">\n  <rule id=\"100001\" level=\"10\">\n    <if_sid>5710</if_sid>\n    <srcip>203.0.113.5</srcip>\n    <description>Tentativa vinda de endereço conhecido</description>\n  </rule>\n</group>";

function modoInicial(a: AberturaDoEditor): Modo {
  if (a.tipo === "catalogo" || a.tipo === "base") return "xml";
  // A regra guiada fica guardada em Sigma, então volta a abrir em Sigma; XML volta a abrir em XML.
  if (a.tipo === "propria") return a.regra.formato === "xml" ? "xml" : "sigma";
  return "guiada";
}

function Formulario({ abertura, aoFechar, aoSalvar }: { abertura: AberturaDoEditor; aoFechar: () => void; aoSalvar: () => void }) {
  const [modo, setModo] = useState<Modo>(modoInicial(abertura));
  const [titulo, setTitulo] = useState("");
  const [origem, setOrigem] = useState("windows_processo");
  const [nivel, setNivel] = useState("medium");
  const [tecnica, setTecnica] = useState("");
  const [condicoes, setCondicoes] = useState<Condicao[]>([novaCondicao("windows_processo")]);
  const [sigma, setSigma] = useState(abertura.tipo === "propria" && abertura.regra.formato !== "xml" ? abertura.regra.origem : "");
  const [xml, setXml] = useState(() => {
    if (abertura.tipo === "catalogo") return abertura.xml;
    if (abertura.tipo === "base") return `<group name="personalizadas,">\n  ${abertura.xml}\n</group>`;
    return abertura.tipo === "propria" && abertura.regra.formato === "xml" ? abertura.regra.origem : "";
  });
  const [erro, setErro] = useState<string | null>(null);
  const [previa, setPrevia] = useState<{ titulo: string; xml: string } | null>(null);
  const linux = origem === "linux_syslog";

  const corpo = () => {
    if (modo === "sigma") return { formato: "sigma", sigma };
    if (modo === "xml") return { formato: "xml", xml };
    const t = tecnica.trim().toUpperCase();
    return {
      formato: "guiada", titulo, origem, nivel, tecnicas: t ? [t] : [],
      condicoes: condicoes.map((c) => (linux ? { valor: c.valor } : c)),
    };
  };
  const trocarOrigem = (v: string | null) => {
    const nova = v ?? "windows_processo";
    setOrigem(nova);
    setCondicoes([novaCondicao(nova)]);
  };
  const mudarCondicao = (i: number, parte: Partial<Condicao>) => setCondicoes((l) => l.map((c, j) => (j === i ? { ...c, ...parte } : c)));

  const ver = async () => {
    setErro(null);
    const r = await enviar("/api/regras/converter", corpo());
    if (!r.ok) {
      setPrevia(null);
      setErro(await detalhe(r, "Confira os campos da regra."));
      return;
    }
    const d = await r.json();
    setPrevia({ titulo: `Como a regra fica (${d.regras_geradas} ${d.regras_geradas === 1 ? "regra gerada" : "regras geradas"})`, xml: d.xml });
  };
  const salvar = async () => {
    setErro(null);
    const opcoes = { method: "PUT", credentials: "same-origin" as const, headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo()) };
    let r: Response;
    if (abertura.tipo === "catalogo") r = await fetch(`/api/regras/${encodeURIComponent(abertura.regraId)}/versao`, opcoes);
    else if (abertura.tipo === "propria") r = await fetch(`/api/regras/proprias/${abertura.regra.id}`, opcoes);
    else r = await enviar("/api/regras/proprias", corpo());
    if (r.status === 401) {
      window.location.assign("/");
      return;
    }
    if (!r.ok) {
      setPrevia(null);
      setErro(await detalhe(r, "Confira os campos da regra."));
      return;
    }
    aoSalvar();
    aoFechar();
  };

  return (
    <Stack gap="sm">
      {/* A versão de uma regra do catálogo só existe em XML: a rota não aceita outro formato. */}
      {abertura.tipo !== "catalogo" && (
        <SegmentedControl value={modo} onChange={(v) => { setModo(v as Modo); setPrevia(null); setErro(null); }} aria-label="Como criar" data={[{ value: "guiada", label: "Guiada" }, { value: "sigma", label: "Colar Sigma" }, { value: "xml", label: "Escrever à mão" }]} />
      )}

      {modo === "guiada" && (
        <>
          <TextInput label="O que esta regra detecta" placeholder="Ex.: PowerShell iniciado pelo Excel" maxLength={200} value={titulo} onChange={(e) => setTitulo(e.currentTarget.value)} data-autofocus />
          <Group grow align="flex-start">
            <Select label="Onde olhar" allowDeselect={false} value={origem} onChange={trocarOrigem} data={[{ value: "windows_processo", label: "Windows: processos iniciados" }, { value: "windows_seguranca", label: "Windows: log de segurança" }, { value: "linux_syslog", label: "Linux: logs do sistema" }]} />
            <Select label="Severidade" allowDeselect={false} value={nivel} onChange={(v) => setNivel(v ?? "medium")} data={[{ value: "low", label: "Baixa" }, { value: "medium", label: "Média" }, { value: "high", label: "Alta" }, { value: "critical", label: "Crítica" }]} />
            <TextInput label="Técnica MITRE (opcional)" placeholder="T1059.001" maxLength={9} value={tecnica} onChange={(e) => setTecnica(e.currentTarget.value)} />
          </Group>
          <Title order={3}>Quando</Title>
          <Stack gap="xs">
            {condicoes.map((c, i) => (
              <Group key={i} gap="xs" wrap="nowrap">
                {!linux && <Select w={200} aria-label="Campo" allowDeselect={false} value={c.campo} onChange={(v) => mudarCondicao(i, { campo: v ?? c.campo })} data={CAMPOS_DA_ORIGEM[origem]} />}
                {!linux && <Select w={140} aria-label="Operador" allowDeselect={false} value={c.operador} onChange={(v) => mudarCondicao(i, { operador: v ?? c.operador })} data={OPERADORES} />}
                <TextInput style={{ flex: 1 }} aria-label="Valor" placeholder={linux ? "Texto que aparece no log" : "Valor"} maxLength={500} value={c.valor} onChange={(e) => mudarCondicao(i, { valor: e.currentTarget.value })} />
                <ActionIcon variant="subtle" color="gray" aria-label="Remover condição" onClick={() => setCondicoes((l) => l.filter((_, j) => j !== i))}><IconX size={16} /></ActionIcon>
              </Group>
            ))}
          </Stack>
          <Group><Button leftSection={<IconPlus size={14} />} disabled={condicoes.length >= CONDICOES_NO_MAXIMO} onClick={() => setCondicoes((l) => [...l, novaCondicao(origem)])}>Adicionar condição</Button></Group>
        </>
      )}
      {modo === "sigma" && <Textarea label="Regra Sigma" placeholder={EXEMPLO_SIGMA} value={sigma} onChange={(e) => setSigma(e.currentTarget.value)} autosize minRows={12} maxRows={22} spellCheck={false} styles={ESTILO_DE_CODIGO} data-autofocus />}
      {modo === "xml" && <Textarea label="Regra em XML" description="Os números das regras são ajustados automaticamente na hora de instalar." placeholder={EXEMPLO_XML} value={xml} onChange={(e) => setXml(e.currentTarget.value)} autosize minRows={12} maxRows={22} spellCheck={false} styles={ESTILO_DE_CODIGO} data-autofocus />}

      {erro && <Alert color="red" variant="light" p="xs">{erro}</Alert>}
      <Group justify="flex-end">
        <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
        <Button onClick={ver}>Ver como fica</Button>
        <Button variant="filled" onClick={salvar}>{abertura.tipo === "catalogo" || abertura.tipo === "propria" ? "Salvar" : "Criar regra"}</Button>
      </Group>
      {previa && (
        <div>
          <Text size="xs" c="dimmed" mb={4}>{previa.titulo}</Text>
          <Box component="pre" className="mono" m={0} p="sm" style={{ background: "var(--mantine-color-dark-8)", border: "1px solid var(--roar-borda)", borderRadius: 6, whiteSpace: "pre-wrap" }}>{previa.xml}</Box>
        </div>
      )}
    </Stack>
  );
}

function tituloDoEditor(a: AberturaDoEditor | null) {
  if (a?.tipo === "catalogo") return `Editar a regra ${a.regraId}`;
  if (a?.tipo === "propria") return `Editar: ${a.regra.titulo}`;
  return "Nova regra";
}

export function EditorDeRegra({ abertura, aoFechar, aoSalvar }: { abertura: AberturaDoEditor | null; aoFechar: () => void; aoSalvar: () => void }) {
  return (
    <Modal opened={abertura !== null} onClose={aoFechar} title={tituloDoEditor(abertura)} size="xl">
      {abertura && <Formulario abertura={abertura} aoFechar={aoFechar} aoSalvar={aoSalvar} />}
    </Modal>
  );
}
