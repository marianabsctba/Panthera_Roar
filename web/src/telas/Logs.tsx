import { ActionIcon, Alert, Autocomplete, Box, Button, Checkbox, Drawer, Grid, Group, Modal, Pill, Popover, ScrollArea, Select, Stack, Table, Tabs, Text, TextInput, Title, Tooltip, UnstyledButton } from "@mantine/core";
import { IconArrowRight, IconHelp, IconMinus, IconSearch } from "@tabler/icons-react";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import { detalhe, enviar, ler, useEu, usePode } from "../api";
import { BotaoDaCesta } from "../cesta";
import { AcoesDaLinha, BarrasMetalicas, Cabecalho, Carregando, Data, METAL_ROSA, Numero, Painel, Ranking, Tabela, Vazio, type Coluna } from "../componentes";
import { numero, quando } from "../formato";
import { BlocoDeJson } from "./Eventos";
import { salvarArquivo } from "./Prova";

const LIMITE_DO_PACOTE = 10000;

/** Leva o que a tela mostra: a mesma busca, os mesmos filtros e o mesmo período, com a prova de cada log. */
function PacoteDePericia({ aberto, aoFechar, consulta, dias, filtros, total, exato }: {
  aberto: boolean; aoFechar: () => void; consulta: string; dias: string; filtros: FiltroDeCampo[]; total: number; exato: boolean;
}) {
  const [gerando, setGerando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [pronto, setPronto] = useState<{ logs: string; fora: string; resumo: string } | null>(null);
  const grande = total > LIMITE_DO_PACOTE || !exato;
  const fechar = () => { setErro(null); setPronto(null); aoFechar(); };

  const gerar = async () => {
    setGerando(true);
    setErro(null);
    const r = await enviar("/api/logs/evidencia", { busca: consulta, dias: Number(dias), filtros: JSON.stringify(filtros) });
    setGerando(false);
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível gerar o pacote."));
      return;
    }
    salvarArquivo(await r.blob(), r.headers.get("Content-Disposition")?.match(/filename="([^"]+)"/)?.[1] ?? "pericia-roar.zip");
    setPronto({ logs: r.headers.get("X-Logs") ?? "", fora: r.headers.get("X-Fora-Do-Pacote") ?? "0", resumo: r.headers.get("X-Resumo-SHA256") ?? "" });
  };

  return (
    <Modal opened={aberto} onClose={fechar} title="Pacote para perícia" size="lg">
      {pronto ? (
        <Stack gap="sm">
          <Text size="sm">Pacote baixado com {numero(Number(pronto.logs))} logs.{pronto.fora !== "0" && ` Ficaram de fora ${numero(Number(pronto.fora))} logs dos últimos minutos, que ainda não foram selados.`}</Text>
          <Text size="xs" c="dimmed">Resumo do arquivo, para anotar junto da cadeia de custódia:</Text>
          <Text size="xs" className="mono" style={{ overflowWrap: "anywhere" }}>{pronto.resumo}</Text>
          <Group justify="flex-end"><Button variant="filled" onClick={fechar}>Fechar</Button></Group>
        </Stack>
      ) : (
        <Stack gap="sm">
          <Text size="sm">Leva os logs desta busca, {dias === "1" ? "do último dia" : `dos últimos ${dias} dias`}, com a prova de cada um e um programa que confere tudo sem depender do Roar. Os logs vizinhos não vão junto.</Text>
          <Text size="sm" c="dimmed">{consulta ? <>Busca: <span className="mono">{consulta}</span></> : "Sem busca: todos os logs do período."}{filtros.length > 0 && ` ${filtros.length} filtro(s) de campo.`}</Text>
          {grande && <Alert color="yellow" variant="light" p="xs"><Text size="sm">A busca acha mais de {numero(LIMITE_DO_PACOTE)} logs. Diminua o período ou refine a busca antes de gerar.</Text></Alert>}
          <Alert color="pink" variant="light" p="xs"><Text size="sm">O pacote contém dados pessoais e sai do sistema. Fica na auditoria quem gerou, o que pediu e o resumo do arquivo.</Text></Alert>
          {erro && <Alert color="red" variant="light" p="xs"><Text size="sm">{erro}</Text></Alert>}
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={fechar}>Cancelar</Button>
            <Button variant="filled" loading={gerando} disabled={grande || total === 0} onClick={gerar}>Gerar e baixar</Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}

// ------------------------------------------------------------------ campos

const ROTULOS_DE_CAMPO: Record<string, string> = {
  timestamp: "Quando", "agent.name": "Ativo", location: "Fonte", "decoder.name": "Tipo de log", "data.srcip": "Origem",
  "data.srcuser": "Usuário", "data.dstuser": "Usuário de destino", "data.protocol": "Protocolo",
  "predecoder.program_name": "Programa", full_log: "Log",
};
const COLUNAS_PADRAO = ["timestamp", "agent.name", "decoder.name", "data.srcip", "data.srcuser", "full_log"];
const CHAVE_DAS_COLUNAS = "roar-colunas-logs";
const rotuloDoCampo = (campo: string) => ROTULOS_DE_CAMPO[campo] ?? campo;

function colunasSalvas() {
  try {
    const salvas = JSON.parse(localStorage.getItem(CHAVE_DAS_COLUNAS) ?? "null");
    if (Array.isArray(salvas) && salvas.length && salvas.every((c) => typeof c === "string")) return salvas as string[];
  } catch { /* preferência é só conveniência */ }
  return COLUNAS_PADRAO;
}

function guardarColunas(colunas: string[]) {
  try { localStorage.setItem(CHAVE_DAS_COLUNAS, JSON.stringify(colunas)); } catch { /* idem */ }
}

type ValorDeCampo = string | number | boolean | null;
type Plano = Record<string, ValorDeCampo>;

// O documento vira pares "campo.subcampo": valor, que é o que a tabela e os filtros usam.
function achatar(objeto: Record<string, unknown> | null | undefined, prefixo = "", saida: Plano = {}) {
  for (const [chave, valor] of Object.entries(objeto ?? {})) {
    const nome = prefixo ? `${prefixo}.${chave}` : chave;
    if (valor && typeof valor === "object" && !Array.isArray(valor)) achatar(valor as Record<string, unknown>, nome, saida);
    else if (Array.isArray(valor)) saida[nome] = valor.map((v) => (v && typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ");
    else saida[nome] = (valor ?? null) as ValorDeCampo;
  }
  return saida;
}

// A API só aceita filtrar por texto ou número, com até mil caracteres.
function podeFiltrar(campo: string, valor: ValorDeCampo): valor is string | number {
  if (campo === "full_log" || campo === "timestamp") return false;
  return (typeof valor === "string" || typeof valor === "number") && String(valor).length <= 1000;
}

// ------------------------------------------------------------------ linguagem de consulta

// Os mesmos apelidos de api/roar_api/consulta.py.
const CAMPOS_DA_CONSULTA: { nome: string; campo: string }[] = [
  { nome: "ativo", campo: "agent.name" }, { nome: "origem", campo: "data.srcip" }, { nome: "destino", campo: "data.dstip" }, { nome: "usuario", campo: "data.srcuser" },
  { nome: "usuario_destino", campo: "data.dstuser" }, { nome: "fonte", campo: "location" }, { nome: "tipo", campo: "decoder.name" }, { nome: "programa", campo: "predecoder.program_name" },
  { nome: "protocolo", campo: "data.protocol" }, { nome: "log", campo: "full_log" }, { nome: "quando", campo: "timestamp" }, { nome: "regra", campo: "rule.id" }, { nome: "nivel", campo: "rule.level" },
  { nome: "pais", campo: "GeoLocation.country_name" }, { nome: "cidade", campo: "GeoLocation.city_name" }, { nome: "estado", campo: "GeoLocation.region_name" },
];
const COMANDOS = [
  { texto: "contar por ", dica: "quantos logs por valor" }, { texto: "top ", dica: "os valores mais comuns" }, { texto: "campos ", dica: "quais colunas mostrar" },
  { texto: "ordenar -quando", dica: "ordem, com - para decrescente" }, { texto: "limite 10", dica: "quantos resultados" },
];
const CONECTORES = [{ texto: "E ", dica: "as duas condições" }, { texto: "OU ", dica: "qualquer uma" }, { texto: "NAO ", dica: "o contrário" }, { texto: "| ", dica: "contar, ordenar, limitar" }];
const EXEMPLOS = [
  { texto: "sshd falha", dica: "logs com as duas palavras" }, { texto: '"falha de login"', dica: "a frase exata" }, { texto: "ativo=srv-rh", dica: "igual a" },
  { texto: "origem!=10.*", dica: "diferente de, com * como curinga" }, { texto: "usuario~mar", dica: "contém" }, { texto: "nivel>=10", dica: "maior ou igual; também >, < e <=" },
  { texto: "a=1 E (b=2 OU NAO c=3)", dica: "E, OU, NAO e parênteses, ou AND, OR, NOT" }, { texto: "pais=Brazil", dica: "país provável da origem, em inglês; também cidade" },
  { texto: "| contar por usuario", dica: "quantos logs por valor; ou stats count by, top" }, { texto: "| campos ativo, origem", dica: "quais colunas mostrar; ou fields" },
  { texto: "| ordenar -quando", dica: "ordem, com - para decrescente; ou sort" }, { texto: "| limite 10", dica: "quantos resultados; ou head" },
];

interface Sugestao { valor: string; rotulo: string; dica?: string }
type ValoresPorCampo = Record<string, { valor: string | number; total: number }[]>;

function sugerir(texto: string, campos: ValoresPorCampo): Sugestao[] {
  // Dentro de aspas a pessoa está escrevendo um valor livre.
  if ((texto.match(/"/g)?.length ?? 0) % 2) return [];
  const pedaco = /[^\s|(,]*$/.exec(texto)?.[0] ?? "";
  const base = texto.slice(0, texto.length - pedaco.length);
  const dePedaco = (rotulo: string, dica?: string): Sugestao => ({ valor: base + rotulo, rotulo, dica });

  const barra = texto.lastIndexOf("|");
  if (barra >= 0) {
    const comando = texto.slice(barra + 1).trimStart();
    const inicio = texto.slice(0, texto.length - comando.length);
    if (/^(contar por|stats count by|count by|campos|fields|ordenar|sort|top|maiores)\s/i.test(comando)) {
      const sinal = pedaco.startsWith("-") ? "-" : "";
      const nome = pedaco.slice(sinal.length).toLowerCase();
      return CAMPOS_DA_CONSULTA.filter((c) => c.nome.startsWith(nome) && c.nome !== nome).map((c) => dePedaco(sinal + c.nome));
    }
    return COMANDOS.filter((c) => c.texto.startsWith(comando.toLowerCase()) && c.texto !== comando).map((c) => ({ valor: inicio + c.texto, rotulo: c.texto, dica: c.dica }));
  }

  const comparacao = /^([^=!<>~]+)(!=|=|~)(.*)$/.exec(pedaco);
  if (comparacao) {
    const [, nome, operador, parte] = comparacao;
    const campo = CAMPOS_DA_CONSULTA.find((c) => c.nome === nome.toLowerCase())?.campo ?? nome;
    return (campos[campo] ?? [])
      .filter((v) => String(v.valor).toLowerCase().includes(parte.toLowerCase()) && String(v.valor) !== parte)
      .map((v) => {
        const valor = /[\s()=!<>~",|]/.test(String(v.valor)) ? `"${String(v.valor).replace(/(["\\])/g, "\\$1")}"` : String(v.valor);
        return { valor: `${base}${nome}${operador}${valor} `, rotulo: valor, dica: numero(v.total) };
      });
  }

  if (!pedaco && base.trim() && !/\b(e|ou|nao|não|and|or|not)\s*$/i.test(base) && !/\(\s*$/.test(base)) return CONECTORES.map((c) => dePedaco(c.texto, c.dica));
  return CAMPOS_DA_CONSULTA.filter((c) => c.nome.startsWith(pedaco.toLowerCase()) || c.campo.toLowerCase().startsWith(pedaco.toLowerCase())).map((c) => dePedaco(`${c.nome}=`, c.campo));
}

function separarComandos(texto: string) {
  const partes: string[] = [];
  let atual = "";
  let emAspas = false;
  let escapado = false;
  for (const c of texto) {
    if (escapado) escapado = false;
    else if (c === "\\" && emAspas) escapado = true;
    else if (c === '"') emAspas = !emAspas;
    else if (c === "|" && !emAspas) {
      partes.push(atual);
      atual = "";
      continue;
    }
    atual += c;
  }
  partes.push(atual);
  return { filtro: partes[0].trim(), comandos: partes.slice(1).map((p) => p.trim()) };
}

/** Restringe a consulta ao trecho da barra clicada, trocando o trecho anterior se já houver um. */
function comPeriodo(texto: string, de: string, ate: string | undefined) {
  const { filtro, comandos } = separarComandos(texto);
  const semPeriodo = filtro.replace(/(?:\s+E\s+)?quando>=\S+(?:\s+E\s+quando<\S+)?/i, "").trim().replace(/^E\s+/i, "");
  const base = /\b(ou|or)\b/i.test(semPeriodo) ? `(${semPeriodo})` : semPeriodo;
  const periodo = [`quando>=${de}`, ...(ate ? [`quando<${ate}`] : [])];
  return [[...(base ? [base] : []), ...periodo].join(" E "), ...comandos].join(" | ");
}

function AjudaDaConsulta({ aoEscolher }: { aoEscolher: (exemplo: string) => void }) {
  return (
    <Popover width={460} position="bottom-end" withArrow shadow="md">
      <Popover.Target>
        <Tooltip label="Como escrever uma consulta"><ActionIcon variant="subtle" color="gray" size="lg" aria-label="Como escrever uma consulta"><IconHelp size={16} /></ActionIcon></Tooltip>
      </Popover.Target>
      <Popover.Dropdown>
        <Text size="xs" c="dimmed" mb="xs">Em português ou inglês. Clique em um exemplo para usar.</Text>
        <Table verticalSpacing={2} horizontalSpacing={6} highlightOnHover={false}>
          <Table.Tbody>
            {EXEMPLOS.map((e) => (
              <Table.Tr key={e.texto}>
                <Table.Td style={{ whiteSpace: "nowrap" }}><UnstyledButton className="mono" c="rosa.2" onClick={() => aoEscolher(e.texto)}>{e.texto}</UnstyledButton></Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{e.dica}</Text></Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        <Text size="xs" c="dimmed" mt="xs">Campos com nome simples: {CAMPOS_DA_CONSULTA.map((c) => c.nome).join(", ")}. Qualquer outro vale pelo nome técnico, como data.win.system.eventID.</Text>
      </Popover.Dropdown>
    </Popover>
  );
}

// ------------------------------------------------------------------ dados

interface FiltroDeCampo { campo: string; valor: string | number; negar: boolean }
interface LogBruto { id: string; bruto: Record<string, unknown> & { timestamp?: string; full_log?: string; agent?: { name?: string } } }
interface RespostaDeLogs {
  logs: LogBruto[];
  proximo: string | null;
  colunas: string[];
  contagem: { campo: string | null; linhas: { valor: string | number; total: number }[] } | null;
  total: number;
  total_exato?: boolean;
  linha_do_tempo: { quando: string; total: number }[];
  campos: ValoresPorCampo;
}

const PERIODOS = [{ value: "1", label: "Último dia" }, { value: "7", label: "7 dias" }, { value: "30", label: "30 dias" }, { value: "90", label: "90 dias" }];

// ------------------------------------------------------------------ partes da tela

function LinhaDoTempo({ pontos, aoClicar }: { pontos: RespostaDeLogs["linha_do_tempo"]; aoClicar: (indice: number) => void }) {
  const eu = useEu();
  const dados = useMemo(() => {
    const instantes = pontos.map((p) => new Date(p.quando).getTime());
    // Os rótulos identificam a barra clicada: faixas de segundos precisam mostrar os segundos.
    const curto = instantes.length > 1 && instantes[1] - instantes[0] < 60000;
    return pontos.map((p, i) => ({ rotulo: new Date(instantes[i]).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: curto ? "medium" : "short", timeZone: eu.fuso }), total: p.total }));
  }, [pontos, eu.fuso]);
  return (
    <BarrasMetalicas
      altura={90}
      dados={dados}
      chave="rotulo"
      series={[{ nome: "total", rotulo: "Logs", metal: METAL_ROSA }]}
      aoClicar={(rotulo) => {
        const i = dados.findIndex((d) => d.rotulo === rotulo);
        if (i >= 0) aoClicar(i);
      }}
    />
  );
}

function ValoresDosCampos({ campos, aoFiltrar }: { campos: ValoresPorCampo; aoFiltrar: (campo: string, valor: string | number, negar: boolean) => void }) {
  const blocos = Object.entries(campos).filter(([, valores]) => valores.length);
  if (!blocos.length) return <Vazio>Sem campos para mostrar.</Vazio>;
  return (
    <Stack gap="sm">
      {blocos.map(([campo, valores]) => (
        <div key={campo}>
          <Title order={3} mb={2}>{rotuloDoCampo(campo)}</Title>
          {valores.map((v) => (
            <Group key={String(v.valor)} gap={4} wrap="nowrap">
              <UnstyledButton style={{ flex: "1 1 0", minWidth: 0 }} title={`Filtrar por ${v.valor}`} onClick={() => aoFiltrar(campo, v.valor, false)}>
                <Text size="xs" truncate className="mono">{String(v.valor)}</Text>
              </UnstyledButton>
              <Text size="xs" c="dimmed" className="numero">{numero(v.total)}</Text>
              <Tooltip label="Excluir"><ActionIcon size="xs" variant="subtle" color="gray" aria-label={`Excluir ${v.valor}`} onClick={() => aoFiltrar(campo, v.valor, true)}><IconMinus size={12} /></ActionIcon></Tooltip>
            </Group>
          ))}
        </div>
      ))}
    </Stack>
  );
}

function EscolhaDeColunas({ aberto, aoFechar, colunas, logs, aoAlternar, aoRestaurar }: { aberto: boolean; aoFechar: () => void; colunas: string[]; logs: { plano: Plano }[]; aoAlternar: (campo: string) => void; aoRestaurar: () => void }) {
  const [filtro, setFiltro] = useState("");
  const disponiveis = useMemo(() => {
    if (!aberto) return [];
    const todas = new Set([...COLUNAS_PADRAO, ...colunas]);
    logs.forEach((l) => Object.keys(l.plano).forEach((c) => todas.add(c)));
    return [...todas].sort();
    // Sem `colunas` nas dependências: se a lista mudasse enquanto a pessoa marca, a caixa fugiria debaixo do ponteiro.
  }, [aberto, logs]);
  const termo = filtro.trim().toLowerCase();
  return (
    <Modal opened={aberto} onClose={aoFechar} title="Colunas da tabela">
      <Stack gap="sm">
        <TextInput placeholder="Filtrar campos" aria-label="Filtrar campos" value={filtro} onChange={(e) => setFiltro(e.currentTarget.value)} data-autofocus />
        <ScrollArea.Autosize mah={360} type="auto">
          <Stack gap={6}>
            {disponiveis.filter((c) => !termo || c.toLowerCase().includes(termo)).map((c) => <Checkbox key={c} size="xs" label={<span className="mono">{c}</span>} checked={colunas.includes(c)} onChange={() => aoAlternar(c)} />)}
          </Stack>
        </ScrollArea.Autosize>
        <Group justify="flex-end"><Button variant="subtle" color="gray" onClick={aoRestaurar}>Restaurar o padrão</Button></Group>
      </Stack>
    </Modal>
  );
}

function GavetaDoLog({ item, colunas, aoFechar, aoFiltrar, aoAlternarColuna }: { item: (LogBruto & { plano: Plano }) | null; colunas: string[]; aoFechar: () => void; aoFiltrar: (campo: string, valor: string | number, negar: boolean) => void; aoAlternarColuna: (campo: string) => void }) {
  const eu = useEu();
  const campos = item ? Object.keys(item.plano).sort() : [];
  return (
    <Drawer opened={item !== null} onClose={aoFechar} title="Campos do log" size="70%">
      {item && (
        <Stack gap="sm">
          <Group justify="space-between" wrap="wrap" gap="xs">
            <Text size="xs" c="dimmed"><Data valor={item.bruto.timestamp} />, identificador <span className="mono">{item.id}</span></Text>
            <BotaoDaCesta fonte="logs" id={item.id} resumo={`${quando(item.bruto.timestamp, eu.fuso)} · ${item.bruto.agent?.name ?? ""} ${String(item.bruto.full_log ?? "").slice(0, 80)}`} />
          </Group>
          <Tabs defaultValue="campos">
            <Tabs.List mb="sm">
              <Tabs.Tab value="campos">Campos</Tabs.Tab>
              <Tabs.Tab value="documento">Documento original</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="campos">
              <Tabela
                linhas={campos}
                chave={(c) => c}
                vazio="Este log não tem campos."
                colunas={[
                  { titulo: "Campo", celula: (c) => <span className="mono">{c}</span> },
                  { titulo: "Valor", celula: (c) => <span className="mono">{String(item.plano[c])}</span> },
                  { titulo: "", largura: 40, celula: (c) => {
                    const valor = item.plano[c];
                    return (
                      <AcoesDaLinha rotulo={`Ações de ${c}`} itens={[
                        ...(podeFiltrar(c, valor) ? [
                          { texto: "Filtrar", aoClicar: () => aoFiltrar(c, valor, false) },
                          { texto: "Excluir", aoClicar: () => aoFiltrar(c, valor, true) },
                        ] : []),
                        { texto: colunas.includes(c) ? "Tirar coluna" : "Mostrar como coluna", aoClicar: () => aoAlternarColuna(c) },
                      ]} />
                    );
                  } },
                ]}
              />
            </Tabs.Panel>
            <Tabs.Panel value="documento"><BlocoDeJson valor={item.bruto} /></Tabs.Panel>
          </Tabs>
        </Stack>
      )}
    </Drawer>
  );
}

function celulaDeCampo(plano: Plano, campo: string) {
  const valor = plano[campo];
  if (campo === "timestamp") return <Data valor={valor === null || valor === undefined ? null : String(valor)} />;
  if (valor === null || valor === undefined) return "-";
  if (campo === "full_log") return <Text span size="xs" className="mono" lineClamp={2} style={{ minWidth: 240 }}>{String(valor)}</Text>;
  return <span className="mono" style={{ whiteSpace: "nowrap" }}>{String(valor)}</span>;
}

// ------------------------------------------------------------------ tela

export function Logs() {
  const pode = usePode();
  const [texto, setTexto] = useState("");
  // A consulta só vai quando a pessoa confirma: cada busca entra na auditoria, e meia consulta seria um erro de escrita.
  const [consulta, setConsulta] = useState("");
  const [dias, setDias] = useState("7");
  const [filtros, setFiltros] = useState<FiltroDeCampo[]>([]);
  const [versao, setVersao] = useState(0);
  const [resposta, setResposta] = useState<RespostaDeLogs | null>(null);
  const [logs, setLogs] = useState<(LogBruto & { plano: Plano })[]>([]);
  const [erro, setErro] = useState<string | null>(null);
  const [carregando, setCarregando] = useState(false);
  const [colunasEscolhidas, setColunasEscolhidas] = useState(colunasSalvas);
  const [escolhendo, setEscolhendo] = useState(false);
  const [aberto, setAberto] = useState<(LogBruto & { plano: Plano }) | null>(null);
  const [pericia, setPericia] = useState(false);
  const pedido = useRef(0);
  const verBruto = pode("ver_bruto");

  const buscar = useCallback(async (depoisDe?: string) => {
    const este = ++pedido.current;
    setCarregando(true);
    setErro(null);
    const parametros = new URLSearchParams({ busca: consulta, dias, filtros: JSON.stringify(filtros) });
    if (depoisDe) parametros.set("depois_de", depoisDe);
    try {
      const d = await ler<RespostaDeLogs>(`/api/logs?${parametros}`);
      if (este !== pedido.current) return;
      const novos = d.logs.map((l) => ({ ...l, plano: achatar(l.bruto) }));
      setLogs((atuais) => (depoisDe ? [...atuais, ...novos] : novos));
      // Só a primeira página traz total, linha do tempo e campos.
      setResposta((anterior) => (depoisDe && anterior ? { ...anterior, proximo: d.proximo } : d));
    } catch (e) {
      // O resultado anterior fica na tela para a pessoa corrigir a consulta olhando para ele.
      if (este === pedido.current) setErro((e as Error).message === "Unprocessable Entity" ? "Este filtro não pode ser usado." : (e as Error).message);
    } finally {
      if (este === pedido.current) setCarregando(false);
    }
  }, [consulta, dias, filtros]);

  useEffect(() => {
    if (verBruto) buscar();
    // `versao` repete a mesma busca quando a pessoa confirma de novo.
  }, [buscar, versao, verBruto]);

  const aplicar = (novo: string) => {
    setTexto(novo);
    setConsulta(novo);
    setVersao((v) => v + 1);
  };
  const enviarConsulta = (e: FormEvent) => {
    e.preventDefault();
    aplicar(texto);
  };

  const alternarFiltro = useCallback((campo: string, valor: string | number, negar: boolean) => {
    setFiltros((atuais) => [...atuais.filter((f) => !(f.campo === campo && f.valor === valor)), { campo, valor, negar }]);
  }, []);

  const alternarColuna = useCallback((campo: string) => {
    setColunasEscolhidas((atuais) => {
      const novas = atuais.includes(campo) ? atuais.filter((c) => c !== campo) : [...atuais, campo];
      const finais = novas.length ? novas : COLUNAS_PADRAO;
      guardarColunas(finais);
      return finais;
    });
  }, []);
  const restaurarColunas = () => {
    guardarColunas(COLUNAS_PADRAO);
    setColunasEscolhidas(COLUNAS_PADRAO);
  };

  const sugestoes = useMemo(() => sugerir(texto, resposta?.campos ?? {}).slice(0, 10), [texto, resposta]);
  const porValor = useMemo(() => new Map(sugestoes.map((s) => [s.valor, s])), [sugestoes]);

  const colunasDaConsulta = resposta?.colunas?.length ? resposta.colunas : null;
  const colunas: Coluna<(typeof logs)[number]>[] = (colunasDaConsulta ?? colunasEscolhidas).map((c) => ({ titulo: rotuloDoCampo(c), celula: (l) => celulaDeCampo(l.plano, c) }));
  const contagem = resposta?.contagem ?? null;
  const pontos = resposta?.linha_do_tempo ?? [];

  if (!verBruto) {
    return (
      <>
        <Cabecalho titulo="Logs brutos" ajuda="Logs como chegaram. Podem ter dado pessoal, por isso dependem de permissão." />
        <Vazio>Seu perfil não pode ver logs brutos.</Vazio>
      </>
    );
  }

  return (
    <>
      <Cabecalho titulo="Logs brutos" ajuda="Logs como chegaram, inclusive os que não viraram alerta. Clique numa linha para ver os campos. Cada busca fica registrada na auditoria." />
      <Stack gap="sm">
        <Group gap="xs" wrap="wrap" align="flex-start">
          <Box component="form" onSubmit={enviarConsulta} role="search" style={{ flex: "1 1 320px", maxWidth: 640 }}>
            <Autocomplete
              aria-label="Consulta nos logs"
              placeholder="ativo=srv-rh E origem!=10.* | contar por usuario"
              leftSection={<IconSearch size={14} />}
              value={texto}
              onChange={setTexto}
              data={sugestoes.map((s) => s.valor)}
              filter={({ options }) => options}
              limit={10}
              maxDropdownHeight={280}
              spellCheck={false}
              error={erro && resposta ? erro : undefined}
              styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 12 } }}
              rightSection={<ActionIcon type="submit" variant="subtle" color="gray" size="sm" aria-label="Aplicar a consulta"><IconArrowRight size={14} /></ActionIcon>}
              rightSectionPointerEvents="all"
              renderOption={({ option }) => {
                const s = porValor.get(option.value);
                return (
                  <Group justify="space-between" gap="md" wrap="nowrap" w="100%">
                    <span className="mono">{s?.rotulo ?? option.value}</span>
                    {s?.dica && <Text size="xs" c="dimmed" truncate>{s.dica}</Text>}
                  </Group>
                );
              }}
            />
          </Box>
          <AjudaDaConsulta aoEscolher={setTexto} />
          <Select w={130} aria-label="Período" value={dias} onChange={(v) => setDias(v ?? "7")} allowDeselect={false} data={PERIODOS} />
          <Button onClick={() => setEscolhendo(true)} disabled={Boolean(colunasDaConsulta) || Boolean(contagem)} title={colunasDaConsulta ? "A consulta já escolhe as colunas" : undefined}>Colunas</Button>
          <Button onClick={() => setPericia(true)} disabled={!resposta || Boolean(contagem) || !resposta.total} title={contagem ? "Tire a contagem da consulta" : undefined}>Pacote para perícia</Button>
        </Group>

        {filtros.length > 0 && (
          <Group gap={6} wrap="wrap">
            {filtros.map((f) => {
              const rotulo = `${f.negar ? "não " : ""}${rotuloDoCampo(f.campo)}: ${f.valor}`;
              return <Pill key={`${f.campo}=${f.valor}`} size="md" withRemoveButton onRemove={() => setFiltros((atuais) => atuais.filter((o) => o !== f))} removeButtonProps={{ "aria-label": `Tirar o filtro ${rotulo}` }} style={f.negar ? { color: "var(--mantine-color-red-3)" } : undefined}>{rotulo}</Pill>;
            })}
          </Group>
        )}

        {!resposta ? <Carregando erro={erro} /> : contagem ? (
          <Painel titulo={contagem.campo ? `${numero(resposta.total)} logs, em ${numero(contagem.linhas.length)} valores de ${rotuloDoCampo(contagem.campo)}` : undefined}>
            {contagem.campo ? (
              <Ranking
                itens={contagem.linhas.map((l) => ({ rotulo: String(l.valor), valor: l.total }))}
                vazio="Nenhum valor encontrado para este campo."
                aoClicar={(_, rotulo) => {
                  const linha = contagem.linhas.find((l) => String(l.valor) === rotulo);
                  if (!linha || !contagem.campo) return;
                  alternarFiltro(contagem.campo, linha.valor, false);
                  aplicar(separarComandos(texto).filtro);
                }}
              />
            ) : <Numero rotulo="Logs" valor={`${resposta.total_exato === false ? "Mais de " : ""}${numero(resposta.total)}`} aoClicar={() => aplicar(separarComandos(texto).filtro)} />}
          </Painel>
        ) : (
          <>
            {pontos.length > 0 && (
              <Painel p="xs">
                <Text size="xs" c="dimmed" mb={4} className="numero">{resposta.total_exato === false ? "Mais de " : ""}{numero(resposta.total)} logs</Text>
                <LinhaDoTempo pontos={pontos} aoClicar={(i) => aplicar(comPeriodo(texto, pontos[i].quando, pontos[i + 1]?.quando))} />
              </Painel>
            )}
            <Grid gap="sm">
              <Grid.Col span={{ base: 12, lg: 3 }}>
                <Painel p="sm"><ValoresDosCampos campos={resposta.campos ?? {}} aoFiltrar={alternarFiltro} /></Painel>
              </Grid.Col>
              <Grid.Col span={{ base: 12, lg: 9 }}>
                <Stack gap="sm">
                  <Painel p={0}><Tabela linhas={logs} chave={(l) => l.id} vazio="Nenhum log encontrado." aoClicarLinha={setAberto} colunas={colunas} /></Painel>
                  {resposta.proximo && <Group justify="center"><Button loading={carregando} onClick={() => buscar(resposta.proximo ?? undefined)}>Carregar mais</Button></Group>}
                </Stack>
              </Grid.Col>
            </Grid>
          </>
        )}
      </Stack>

      <EscolhaDeColunas aberto={escolhendo} aoFechar={() => setEscolhendo(false)} colunas={colunasEscolhidas} logs={logs} aoAlternar={alternarColuna} aoRestaurar={restaurarColunas} />
      <GavetaDoLog
        item={aberto}
        colunas={colunasEscolhidas}
        aoFechar={() => setAberto(null)}
        aoFiltrar={(campo, valor, negar) => { setAberto(null); alternarFiltro(campo, valor, negar); }}
        aoAlternarColuna={alternarColuna}
      />
      <PacoteDePericia aberto={pericia} aoFechar={() => setPericia(false)} consulta={consulta} dias={dias} filtros={filtros} total={resposta?.total ?? 0} exato={resposta?.total_exato !== false} />
    </>
  );
}
