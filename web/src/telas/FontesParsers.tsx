import { ActionIcon, Autocomplete, Button, Code, Drawer, Group, Modal, SegmentedControl, Select, SimpleGrid, Stack, Table, Text, Textarea, TextInput, Title } from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { detalhe, enviar, pedir, useDados, usePode } from "../api";
import { AcoesDaLinha, Carregando, Data, Estado, Painel, Tabela } from "../componentes";

interface Campo { nome: string; antes: string; tipo: string }
interface Definicao { reconhecer: "programa" | "texto"; valor: string; campos: Campo[] }
interface Parser {
  id: number; nome: string; titulo: string; modo: "guiado" | "xml"; definicao: Definicao | null; xml: string; exemplo: string;
  ativo: boolean; estado: string; mensagem: string | null; alterado_em: string; aplicado_em: string | null;
}
export interface Leitura { decodificador: string | null; pai: string | null; campos: Record<string, unknown>; previo: Record<string, string>; regra: { id: string; nivel: number; descricao: string } | null }
interface ResultadoDoTeste { hoje: Leitura; novo: Leitura | null; avisos: string[]; xml: string | null }
interface Visao { parsers: Parser[]; valores: Record<string, string>; campos: string[] }

const SITUACAO: Record<string, { texto: string; tipo: string }> = {
  aplicado: { texto: "Valendo", tipo: "ativo" }, pendente: { texto: "Chegando ao servidor", tipo: "pendente" }, recusado: { texto: "Recusado", tipo: "problema" },
};
const CAMPO_VAZIO: Campo = { nome: "", antes: "", tipo: "palavra" };
const nomeDoTitulo = (titulo: string) => titulo.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 41);

/** Campos aninhados, como os de JSON, viram "pai.filho" para caber numa tabela. */
function achatar(campos: Record<string, unknown>, prefixo = ""): [string, string][] {
  return Object.entries(campos).flatMap(([k, v]) => (v && typeof v === "object" && !Array.isArray(v)
    ? achatar(v as Record<string, unknown>, `${prefixo}${k}.`) : [[`${prefixo}${k}`, Array.isArray(v) ? v.join(", ") : String(v)] as [string, string]]));
}

export function ComoLe({ titulo, leitura }: { titulo: string; leitura: Leitura }) {
  const campos = achatar(leitura.campos);
  return (
    <Stack gap={6}>
      <Text size="sm" fw={600}>{titulo}</Text>
      <Text size="xs" c="dimmed">
        {leitura.decodificador ? <>Lido como <span className="mono">{leitura.pai ?? leitura.decodificador}</span></> : "Nenhum parser reconheceu este log."}
        {leitura.previo.program_name && <> · programa <span className="mono">{leitura.previo.program_name}</span></>}
      </Text>
      {campos.length ? (
        <Table withRowBorders={false} verticalSpacing={2} fz="sm">
          <Table.Tbody>{campos.map(([k, v]) => <Table.Tr key={k}><Table.Td className="mono" c="dimmed" w="40%">{k}</Table.Td><Table.Td className="mono" style={{ overflowWrap: "anywhere" }}>{v}</Table.Td></Table.Tr>)}</Table.Tbody>
        </Table>
      ) : <Text size="sm" c="dimmed">Nenhum campo tirado.</Text>}
      {leitura.regra && <Text size="xs" c="dimmed">Regra {leitura.regra.id}, nível {leitura.regra.nivel}: {leitura.regra.descricao}</Text>}
    </Stack>
  );
}

function Editor({ aberto, parser, visao, aoFechar, aoSalvar }: { aberto: boolean; parser: Parser | null; visao: Visao; aoFechar: () => void; aoSalvar: () => void }) {
  const [titulo, setTitulo] = useState("");
  const [nome, setNome] = useState("");
  const [nomeMexido, setNomeMexido] = useState(false);
  const [exemplo, setExemplo] = useState("");
  const [modo, setModo] = useState<"guiado" | "xml">("guiado");
  const [definicao, setDefinicao] = useState<Definicao>({ reconhecer: "programa", valor: "", campos: [{ ...CAMPO_VAZIO }] });
  const [xml, setXml] = useState("");
  const [teste, setTeste] = useState<ResultadoDoTeste | null>(null);
  const [testando, setTestando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => {
    if (!aberto) return;
    setTitulo(parser?.titulo ?? ""); setNome(parser?.nome ?? ""); setNomeMexido(Boolean(parser)); setExemplo(parser?.exemplo ?? "");
    setModo(parser?.modo ?? "guiado"); setDefinicao(parser?.definicao ?? { reconhecer: "programa", valor: "", campos: [{ ...CAMPO_VAZIO }] });
    setXml(parser?.xml ?? ""); setTeste(null); setErro(null);
  }, [aberto, parser]);
  const nomeFinal = nomeMexido ? nome : nomeDoTitulo(titulo);
  const pedido = () => ({ nome: nomeFinal, modo, definicao: modo === "guiado" ? definicao : null, xml: modo === "xml" ? xml : null });
  const mudarCampo = (i: number, mudanca: Partial<Campo>) => setDefinicao((d) => ({ ...d, campos: d.campos.map((c, j) => (j === i ? { ...c, ...mudanca } : c)) }));

  const testar = async (comParser: boolean) => {
    setTestando(true); setErro(null);
    const r = await enviar("/api/parsers/testar", { log: exemplo, parser: comParser ? pedido() : null });
    setTestando(false);
    if (!r.ok) { setErro(await detalhe(r)); return; }
    const resultado: ResultadoDoTeste = await r.json();
    setTeste(resultado);
    // Primeira leitura: o nome do programa que o servidor viu já serve para reconhecer o log.
    const programa = resultado.hoje.previo.program_name;
    if (!comParser && programa && !definicao.valor) setDefinicao((d) => ({ ...d, reconhecer: "programa", valor: programa }));
  };
  const salvar = async () => {
    setErro(null);
    const corpo = { ...pedido(), titulo, exemplo };
    const r = parser ? await pedir(`/api/parsers/${parser.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo) })
      : await enviar("/api/parsers", corpo);
    if (r.ok) aoSalvar();
    else setErro(await detalhe(r));
  };

  return (
    <Drawer opened={aberto} onClose={aoFechar} title={parser ? parser.titulo : "Novo parser"} size="80%">
      <Stack gap="md">
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
          <TextInput label="Título" placeholder="Firewall da matriz" value={titulo} onChange={(e) => setTitulo(e.currentTarget.value)} />
          <TextInput label="Nome" description="Não muda depois de criado." classNames={{ input: "mono" }} disabled={Boolean(parser)}
            value={nomeFinal} onChange={(e) => { setNomeMexido(true); setNome(e.currentTarget.value); }} />
        </SimpleGrid>
        <Textarea label="Um log de exemplo" description="Cole uma linha do jeito que o equipamento manda." autosize minRows={2} maxRows={6} classNames={{ input: "mono" }}
          value={exemplo} onChange={(e) => setExemplo(e.currentTarget.value)} />
        <Group gap="sm"><Button onClick={() => testar(false)} loading={testando} disabled={!exemplo.trim()}>Ver como o servidor lê hoje</Button></Group>

        <SegmentedControl value={modo} onChange={(v) => setModo(v as "guiado" | "xml")} data={[{ value: "guiado", label: "Guiado" }, { value: "xml", label: "Escrever em XML" }]} />
        {modo === "guiado" ? (
          <Stack gap="sm">
            <Title order={2}>Como reconhecer o log</Title>
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <Select allowDeselect={false} value={definicao.reconhecer} onChange={(v) => setDefinicao((d) => ({ ...d, reconhecer: (v ?? "programa") as Definicao["reconhecer"] }))}
                data={[{ value: "programa", label: "Pelo nome do programa" }, { value: "texto", label: "Por um texto que sempre aparece" }]} />
              <TextInput classNames={{ input: "mono" }} placeholder={definicao.reconhecer === "programa" ? "fw-matriz" : "FWX:"} value={definicao.valor}
                onChange={(e) => { const v = e.currentTarget.value; setDefinicao((d) => ({ ...d, valor: v })); }} />
            </SimpleGrid>
            <Title order={2}>Campos para tirar</Title>
            <Text size="xs" c="dimmed">Para cada campo, o texto que vem logo antes dele no log. Os campos podem vir em qualquer ordem.</Text>
            {definicao.campos.map((c, i) => (
              <Group key={i} gap="xs" wrap="nowrap" align="flex-end">
                <Autocomplete label={i === 0 ? "Nome do campo" : undefined} placeholder="srcip" data={visao.campos} classNames={{ input: "mono" }} style={{ flex: 1 }}
                  value={c.nome} onChange={(v) => mudarCampo(i, { nome: v })} />
                <TextInput label={i === 0 ? "Texto antes" : undefined} placeholder="src=" classNames={{ input: "mono" }} style={{ flex: 1 }}
                  value={c.antes} onChange={(e) => mudarCampo(i, { antes: e.currentTarget.value })} />
                <Select label={i === 0 ? "O valor é" : undefined} allowDeselect={false} style={{ flex: 1 }} value={c.tipo} onChange={(v) => mudarCampo(i, { tipo: v ?? "palavra" })}
                  data={Object.entries(visao.valores).map(([value, label]) => ({ value, label }))} />
                <ActionIcon variant="subtle" color="gray" size="lg" aria-label="Tirar o campo" disabled={definicao.campos.length === 1}
                  onClick={() => setDefinicao((d) => ({ ...d, campos: d.campos.filter((_, j) => j !== i) }))}><IconTrash size={16} /></ActionIcon>
              </Group>
            ))}
            <Group><Button variant="subtle" leftSection={<IconPlus size={14} />} onClick={() => setDefinicao((d) => ({ ...d, campos: [...d.campos, { ...CAMPO_VAZIO }] }))}>Mais um campo</Button></Group>
          </Stack>
        ) : (
          <Textarea label="Decodificadores" description={`Todo decodificador se chama roar_${nomeFinal || "nome"} ou começa com roar_${nomeFinal || "nome"}_.`}
            autosize minRows={8} maxRows={24} classNames={{ input: "mono" }} value={xml} onChange={(e) => setXml(e.currentTarget.value)} />
        )}

        <Group gap="sm">
          <Button onClick={() => testar(true)} loading={testando} disabled={!exemplo.trim() || !nomeFinal}>Testar com o exemplo</Button>
          <Button variant="filled" onClick={salvar} disabled={!titulo.trim() || !nomeFinal}>{parser ? "Salvar" : "Criar parser"}</Button>
        </Group>
        {erro && <Text size="sm" c="red">{erro}</Text>}

        {teste && (
          <Painel titulo="Resultado do teste">
            <SimpleGrid cols={{ base: 1, md: teste.novo ? 2 : 1 }} spacing="lg">
              <ComoLe titulo="Como o servidor lê hoje" leitura={teste.hoje} />
              {teste.novo && <ComoLe titulo="Com este parser" leitura={teste.novo} />}
            </SimpleGrid>
            {teste.novo && !teste.novo.decodificador?.startsWith("roar_") && teste.hoje.decodificador && (
              <Text size="sm" c="yellow" mt="sm">Um parser que já vem com o servidor reconhece este log primeiro. Para ler com o seu, reconheça por um texto mais específico.</Text>
            )}
            {teste.avisos.length > 0 && <Text size="xs" c="dimmed" mt="sm">{teste.avisos.join(" ")}</Text>}
            {teste.xml && <><Text size="xs" c="dimmed" mt="sm" mb={4}>O que vai para o servidor</Text><Code block>{teste.xml}</Code></>}
          </Painel>
        )}
      </Stack>
    </Drawer>
  );
}

export function Parsers() {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<Visao>("/api/parsers");
  const [editando, setEditando] = useState<Parser | null>(null);
  const [novo, setNovo] = useState(false);
  const [apagar, setApagar] = useState<Parser | null>(null);
  if (!dados) return <Carregando erro={erro} />;
  const ligar = async (p: Parser, ligado: boolean) => { await enviar(`/api/parsers/${p.id}/ativo?ligado=${ligado}`); recarregar(); };
  const confirmarApagar = async () => { if (apagar) await pedir(`/api/parsers/${apagar.id}`, { method: "DELETE" }); setApagar(null); recarregar(); };
  return (
    <>
      <Painel titulo="Parsers próprios" acao={pode("gerir_regras") && <Button leftSection={<IconPlus size={14} />} onClick={() => setNovo(true)}>Novo parser</Button>}>
        <Text size="sm" c="dimmed" mb="sm">Ensinam o servidor a ler um formato de log que ele não conhece, tirando campos como endereço, usuário e ação. Teste com um log de exemplo antes de salvar.</Text>
        <Tabela
          linhas={dados.parsers}
          chave={(p) => p.id}
          vazio="Nenhum parser próprio ainda."
          aoClicarLinha={pode("gerir_regras") ? setEditando : undefined}
          colunas={[
            { titulo: "Parser", celula: (p) => <><Text size="sm" fw={500}>{p.titulo}</Text><Text size="xs" c="dimmed" className="mono">roar_{p.nome}</Text></> },
            { titulo: "Feito", celula: (p) => <Text size="sm" c="dimmed">{p.modo === "guiado" ? "Guiado" : "Em XML"}</Text> },
            { titulo: "Situação", celula: (p) => (!p.ativo ? <Estado tipo="outro">Desligado</Estado>
              : <><Estado tipo={SITUACAO[p.estado]?.tipo ?? "outro"}>{SITUACAO[p.estado]?.texto ?? p.estado}</Estado>{p.mensagem && <Text size="xs" c="dimmed">{p.mensagem}</Text>}</>) },
            { titulo: "Alterado em", largura: 150, celula: (p) => <Data valor={p.alterado_em} /> },
            ...(pode("gerir_regras") ? [{ titulo: "", largura: 40, celula: (p: Parser) => (
              <AcoesDaLinha rotulo={`Ações de ${p.titulo}`} itens={[
                { texto: "Editar", aoClicar: () => setEditando(p) },
                { texto: p.ativo ? "Desligar" : "Ligar", aoClicar: () => ligar(p, !p.ativo) },
                { texto: "Apagar", aoClicar: () => setApagar(p) },
              ]} />
            ) }] : []),
          ]}
        />
      </Painel>
      <Editor aberto={novo || editando !== null} parser={editando} visao={dados} aoFechar={() => { setNovo(false); setEditando(null); }}
        aoSalvar={() => { setNovo(false); setEditando(null); recarregar(); }} />
      <Modal opened={apagar !== null} onClose={() => setApagar(null)} title="Apagar o parser?">
        <Stack gap="sm">
          <Text size="sm">O servidor deixa de ler os logs de {apagar?.titulo} com ele. Regra que usa os campos dele para de disparar.</Text>
          <Group justify="flex-end"><Button onClick={() => setApagar(null)}>Cancelar</Button><Button color="red" variant="filled" onClick={confirmarApagar}>Apagar</Button></Group>
        </Stack>
      </Modal>
    </>
  );
}
