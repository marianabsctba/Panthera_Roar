import { Alert, Badge, Button, Drawer, Group, Modal, NumberInput, PasswordInput, SegmentedControl, Select, Stack, Text, Textarea, TextInput, Title } from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { useState, type ReactNode } from "react";

import { detalhe, enviar, useDados, usePode } from "../api";
import { AcoesDaLinha, Busca, Cabecalho, Carregando, Data, Estado, GavetaDoBruto, Painel, Severidade, Tabela } from "../componentes";
import { numero } from "../formato";
import { Fatos } from "./Ataques";
import { recomecar } from "../rota";

interface Fonte { id: number; nome: string; tipo: string; endereco: string; colecao: string | null; com_credencial: boolean; ativa: boolean; interna: boolean; a_cada_minutos: number; proxima_em: string | null; ultima_em: string | null; ultimo_erro: string | null; indicadores: number }
interface Ocorrencia { evento_id: number; ocorrido_em: string; encontrada_em: string | null; no_passado: boolean; tipo: string; valor: string; descricao: string | null; fonte: string; regra_descricao: string | null; severidade: string; ativo: string | null }
interface Visao { fontes: Fonte[]; ocorrencias: Ocorrencia[]; conferencia: { ate: string; eventos_30_dias: number; indicadores: number } | null }

interface IndicadorCacado { tipo: string; valor: string; eventos: number; logs: number | null; vigiado: boolean }
interface Achado { id: number; ocorrido_em: string; severidade: string; regra_descricao: string | null; ativo: string | null; usuario: string | null; ip_origem: string | null; tipo: string; indicador: string }
interface ResultadoDaCaca { dias: number; ignorados: string[]; indicadores: IndicadorCacado[]; achados: Achado[] }

const TIPOS_DE_INDICADOR: Record<string, string> = { ip: "IP", dominio: "Domínio", url: "URL", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256" };

function CacaDeIndicadores({ aoVigiar, aoVerBruto }: { aoVigiar: () => void; aoVerBruto?: (evento: number) => void }) {
  const pode = usePode();
  const [texto, setTexto] = useState("");
  const [dias, setDias] = useState("30");
  const [cacando, setCacando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [resultado, setResultado] = useState<ResultadoDaCaca | null>(null);
  const [aviso, setAviso] = useState<string | null>(null);
  const cacar = async () => {
    setCacando(true);
    setErro(null);
    setAviso(null);
    const r = await enviar("/api/inteligencia/cacar", { texto, dias: Number(dias) });
    setCacando(false);
    if (!r.ok) return setErro(await detalhe(r, "Não foi possível caçar agora."));
    setResultado(await r.json());
  };
  const novos = resultado?.indicadores.filter((i) => !i.vigiado) ?? [];
  const vigiar = async () => {
    setErro(null);
    const r = await enviar("/api/inteligencia/vigiar", { indicadores: novos.map((i) => ({ tipo: i.tipo, valor: i.valor })) });
    if (!r.ok) return setErro(await detalhe(r, "Não foi possível vigiar."));
    const corpo = await r.json();
    setAviso(`${numero(corpo.vigiados)} indicador${corpo.vigiados === 1 ? "" : "es"} na Lista manual: todo evento novo é conferido contra ele${corpo.vigiados === 1 ? "" : "s"}.${corpo.recusados.length ? ` ${numero(corpo.recusados.length)} endereço${corpo.recusados.length === 1 ? " interno ou reservado ficou" : "s internos ou reservados ficaram"} de fora.` : ""}`);
    setResultado((atual) => atual && { ...atual, indicadores: atual.indicadores.map((i) => ({ ...i, vigiado: i.vigiado || corpo.vigiados > 0 })) });
    aoVigiar();
  };
  return (
    <Painel titulo="Caçar indicadores" p="md">
      <Stack gap="sm">
        <Text size="xs" c="dimmed">Cole IPs, domínios, URLs ou resumos de arquivo, de um relatório ou de um alerta de outro lugar. Vale o formato desarmado, como hxxp e 1.2.3[.]4. O Roar procura nos eventos do período e conta quantas vezes cada um aparece nos logs brutos.</Text>
        <Textarea placeholder={"185.220.101.4\nmal-exemplo[.]com\nd41d8cd98f00b204e9800998ecf8427e"} value={texto} onChange={(e) => setTexto(e.currentTarget.value)} autosize minRows={3} maxRows={10} maxLength={20000} spellCheck={false} className="mono" />
        <Group justify="space-between">
          <SegmentedControl size="xs" value={dias} onChange={setDias} data={[{ value: "7", label: "7 dias" }, { value: "30", label: "30 dias" }, { value: "90", label: "90 dias" }]} />
          <Button variant="filled" loading={cacando} disabled={!texto.trim()} onClick={cacar}>Caçar</Button>
        </Group>
        {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
        {aviso && <Alert color="gray" variant="light" p="xs" fz="sm">{aviso}</Alert>}
        {resultado && (
          <Stack gap="sm">
            <Tabela
              linhas={resultado.indicadores}
              chave={(i) => `${i.tipo}-${i.valor}`}
              vazio="Nenhum indicador."
              colunas={[
                { titulo: "Tipo", largura: 90, celula: (i) => TIPOS_DE_INDICADOR[i.tipo] ?? i.tipo },
                { titulo: "Indicador", celula: (i) => <Group gap={6} wrap="nowrap"><span className="mono" style={{ overflowWrap: "anywhere" }}>{i.valor}</span>{i.vigiado && <Badge size="xs" radius="sm" variant="light" color="gray" tt="none">Vigiado</Badge>}</Group> },
                { titulo: `Eventos em ${resultado.dias} dias`, alinhar: "right", largura: 140, celula: (i) => (i.eventos ? <Text size="sm" fw={600}>{numero(i.eventos)}</Text> : <Text size="sm" c="dimmed">0</Text>) },
                { titulo: "Nos logs brutos", alinhar: "right", largura: 130, celula: (i) => (i.logs === null ? <Text size="sm" c="dimmed">-</Text> : numero(i.logs)) },
              ]}
            />
            {!!resultado.ignorados.length && <Text size="xs" c="dimmed">Não reconhecidos: {resultado.ignorados.join(", ")}.</Text>}
            {pode("gerir_fontes") && novos.length > 0 && (
              <Group justify="flex-end">
                <Text size="xs" c="dimmed">Para avisar quando aparecerem em evento novo:</Text>
                <Button size="xs" onClick={vigiar}>Vigiar {numero(novos.length)} indicador{novos.length === 1 ? "" : "es"}</Button>
              </Group>
            )}
            {resultado.achados.length > 0 && (
              <Tabela
                linhas={resultado.achados}
                chave={(a) => `${a.id}-${a.tipo}-${a.indicador}`}
                vazio=""
                aoClicarLinha={aoVerBruto ? (a) => aoVerBruto(a.id) : undefined}
                colunas={[
                  { titulo: "Quando", largura: 150, celula: (a) => <Data valor={a.ocorrido_em} /> },
                  { titulo: "Indicador", celula: (a) => <span className="mono" style={{ overflowWrap: "anywhere" }}>{a.indicador}</span> },
                  { titulo: "Evento", celula: (a) => <Text size="sm">{a.regra_descricao ?? "-"}</Text> },
                  { titulo: "Ativo", celula: (a) => a.ativo ?? "-" },
                  { titulo: "Usuário", celula: (a) => a.usuario ?? "-" },
                  { titulo: "Severidade", largura: 110, celula: (a) => <Severidade valor={a.severidade} /> },
                ]}
              />
            )}
            {resultado.indicadores.every((i) => !i.eventos) && <Text size="sm" c="dimmed">Nenhum evento do período tem estes indicadores.</Text>}
          </Stack>
        )}
      </Stack>
    </Painel>
  );
}

const chaveDaOcorrencia = (o: Ocorrencia) => `${o.evento_id}-${o.fonte}-${o.tipo}-${o.valor}`;
const comoFoiAchado = (o: Ocorrencia) => (o.no_passado ? "Olhando para trás" : "Na chegada");

function NovaFonte({ aberto, aoFechar, aoCriar }: { aberto: boolean; aoFechar: () => void; aoCriar: () => void }) {
  const [nome, setNome] = useState("");
  const [tipo, setTipo] = useState("misp");
  const [minutos, setMinutos] = useState<string | number>(60);
  const [endereco, setEndereco] = useState("");
  const [colecao, setColecao] = useState("");
  const [credencial, setCredencial] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const taxii = tipo === "taxii";
  const fechar = () => {
    // A credencial não fica guardada na tela nem quando a pessoa desiste.
    setCredencial("");
    setErro(null);
    aoFechar();
  };
  const salvar = async () => {
    const r = await enviar("/api/inteligencia/fontes", { nome: nome.trim(), tipo, endereco: endereco.trim(), colecao: taxii ? colecao.trim() || null : null, credencial: credencial || null, a_cada_minutos: Number(minutos) });
    setCredencial("");
    if (!r.ok) {
      setErro(await detalhe(r, "Confira o nome e o endereço."));
      return;
    }
    setNome("");
    setEndereco("");
    setColecao("");
    setErro(null);
    aoCriar();
    aoFechar();
  };
  return (
    <Modal opened={aberto} onClose={fechar} title="Nova fonte de inteligência" size="lg">
      <Stack gap="sm">
        <TextInput label="Nome" value={nome} onChange={(e) => setNome(e.currentTarget.value)} maxLength={120} data-autofocus />
        <Group grow>
          <Select label="Tipo" value={tipo} onChange={(v) => setTipo(v ?? "misp")} allowDeselect={false} data={[{ value: "misp", label: "MISP" }, { value: "taxii", label: "TAXII 2.1" }]} />
          <NumberInput label="Buscar a cada (minutos)" value={minutos} onChange={setMinutos} min={5} max={10080} allowDecimal={false} />
        </Group>
        <TextInput label={taxii ? "Raiz da API" : "Endereço completo"} value={endereco} onChange={(e) => setEndereco(e.currentTarget.value)} spellCheck={false} placeholder="https://" maxLength={500} />
        {taxii && <TextInput label="Identificador da coleção" value={colecao} onChange={(e) => setColecao(e.currentTarget.value)} spellCheck={false} maxLength={200} />}
        <PasswordInput
          label={taxii ? "Valor do cabeçalho Authorization" : "Chave de acesso"}
          description="Fica cifrada e não volta para a tela. Use uma conta só de leitura."
          value={credencial}
          onChange={(e) => setCredencial(e.currentTarget.value)}
          autoComplete="new-password"
        />
        {erro && <Alert color="red" variant="light" p="xs" fz="sm" role="alert">{erro}</Alert>}
        <Group justify="flex-end" mt="xs">
          <Button variant="subtle" color="gray" onClick={fechar}>Cancelar</Button>
          <Button variant="filled" onClick={salvar} disabled={!nome.trim() || !endereco.trim() || (taxii && !colecao.trim())}>Criar</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function ConfirmarDesativar({ fonte, aoFechar, aoDesativar }: { fonte: Fonte | null; aoFechar: () => void; aoDesativar: () => void }) {
  const [erro, setErro] = useState<string | null>(null);
  const desativar = async () => {
    // O envio da API só cobre POST, e esta rota é DELETE.
    const r = await fetch(`/api/inteligencia/fontes/${fonte?.id}`, { method: "DELETE", credentials: "same-origin" });
    if (r.status === 401) {
      recomecar("/");
      return;
    }
    if (!r.ok) {
      setErro(await detalhe(r));
      return;
    }
    setErro(null);
    aoDesativar();
    aoFechar();
  };
  return (
    <Modal opened={fonte !== null} onClose={aoFechar} title={`Desativar ${fonte?.nome ?? ""}`}>
      <Stack gap="sm">
        <Text size="sm">Para de buscar nesta fonte. O que já foi encontrado continua na lista.</Text>
        {erro && <Alert color="red" variant="light" p="xs" fz="sm" role="alert">{erro}</Alert>}
        <Group justify="flex-end">
          <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
          <Button variant="filled" onClick={desativar}>Desativar</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function SituacaoDaFonte({ fonte, pedida }: { fonte: Fonte; pedida: boolean }) {
  if (fonte.ultimo_erro) return <span title={fonte.ultimo_erro}><Estado tipo="problema">Com problema</Estado></span>;
  if (pedida) return <Estado tipo="pendente">Busca pedida</Estado>;
  if (fonte.tipo === "manual") return <Estado tipo="ativo">Vigiando</Estado>;
  return fonte.ultima_em ? <Estado tipo="ativo">Funcionando</Estado> : <Estado tipo="outro">Aguardando a primeira busca</Estado>;
}

function TabelaDeOcorrencias({ linhas, vazio, aoAbrir, aoVerBruto }: { linhas: Ocorrencia[]; vazio: string; aoAbrir: (o: Ocorrencia) => void; aoVerBruto?: (evento: number) => void }) {
  return (
    <Tabela
      linhas={linhas}
      chave={chaveDaOcorrencia}
      vazio={vazio}
      aoClicarLinha={aoAbrir}
      colunas={[
        { titulo: "Quando", largura: 130, celula: (o) => <Data valor={o.ocorrido_em} /> },
        { titulo: "Indicador", celula: (o) => <span className="mono">{o.valor}</span> },
        { titulo: "Fonte", celula: (o) => o.fonte },
        { titulo: "Severidade", largura: 90, celula: (o) => <Severidade valor={o.severidade} /> },
        { titulo: "Evento", celula: (o) => o.regra_descricao ?? "-" },
        { titulo: "Ativo", celula: (o) => o.ativo ?? "-" },
        { titulo: "Como foi achado", largura: 130, celula: comoFoiAchado },
        { titulo: "", largura: 40, celula: (o) => <AcoesDaLinha rotulo="Ações da ocorrência" itens={aoVerBruto ? [{ texto: "Ver como chegou", aoClicar: () => aoVerBruto(o.evento_id) }] : []} /> },
      ]}
    />
  );
}

function GavetaDaOcorrencia({ ocorrencia: o, aoFechar, aoVerBruto }: { ocorrencia: Ocorrencia | null; aoFechar: () => void; aoVerBruto?: (evento: number) => void }) {
  return (
    <Drawer opened={o !== null} onClose={aoFechar} title="Evento que bateu com um indicador" size="lg">
      {o && (
        <Stack gap="md">
          <Fatos itens={[
            ["Indicador", <span className="mono">{o.valor}</span>],
            ["Tipo", <span className="mono">{o.tipo}</span>],
            ["O que a fonte diz", o.descricao ?? "-"],
            ["Fonte", o.fonte],
            ["Evento", o.regra_descricao ?? "-"],
            ["Severidade", <Severidade valor={o.severidade} />],
            ["Ativo", o.ativo ?? "-"],
            ["Quando ocorreu", <Data valor={o.ocorrido_em} />],
            ["Quando foi achado", <Data valor={o.encontrada_em} />],
            ["Como foi achado", comoFoiAchado(o)],
          ]} />
          {aoVerBruto && <Group><Button onClick={() => aoVerBruto(o.evento_id)}>Ver como chegou</Button></Group>}
        </Stack>
      )}
    </Drawer>
  );
}

function GavetaDaFonte({ fonte: f, aoFechar, aoAbrirOcorrencia, aoVerBruto }: { fonte: Fonte | null; aoFechar: () => void; aoAbrirOcorrencia: (o: Ocorrencia) => void; aoVerBruto?: (evento: number) => void }) {
  // Sem a busca da tela: aqui contam todas as ocorrências desta fonte, não só as que batem com o que foi digitado.
  const { dados, erro } = useDados<Visao>(f ? "/api/inteligencia" : null);
  return (
    <Drawer opened={f !== null} onClose={aoFechar} title={f?.nome ?? ""} size="xl">
      {f && (
        <Stack gap="md">
          {f.ultimo_erro && <Alert color="red" variant="light" p="xs" fz="sm">{f.ultimo_erro}</Alert>}
          <Fatos itens={[
            ["Tipo", f.tipo.toUpperCase()],
            ["Endereço", <span className="mono">{f.endereco}</span>],
            ...(f.colecao ? [["Coleção", <span className="mono">{f.colecao}</span>] as [string, ReactNode]] : []),
            ["Credencial", f.com_credencial ? "Guardada" : "Sem credencial"],
            ["Indicadores", numero(f.indicadores)],
            ["Busca a cada", `${numero(f.a_cada_minutos)} minutos`],
            ["Última busca", <Data valor={f.ultima_em} />],
            ["Próxima busca", <Data valor={f.proxima_em} />],
          ]} />
          <Stack gap={6}>
            <Title order={3}>Ocorrências recentes</Title>
            {!dados ? <Carregando erro={erro} /> : <TabelaDeOcorrencias linhas={dados.ocorrencias.filter((o) => o.fonte === f.nome)} vazio="Nenhum evento bateu com esta fonte." aoAbrir={aoAbrirOcorrencia} aoVerBruto={aoVerBruto} />}
          </Stack>
        </Stack>
      )}
    </Drawer>
  );
}

export function Inteligencia() {
  const pode = usePode();
  const [busca, setBusca] = useState("");
  const [nova, setNova] = useState(false);
  const [desativar, setDesativar] = useState<Fonte | null>(null);
  const [fonteAberta, setFonteAberta] = useState<number | null>(null);
  const [ocorrencia, setOcorrencia] = useState<Ocorrencia | null>(null);
  const [bruto, setBruto] = useState<number | null>(null);
  const [pedidas, setPedidas] = useState<Record<number, boolean>>({});
  const { dados, erro, recarregar } = useDados<Visao>(`/api/inteligencia?${new URLSearchParams({ busca })}`);
  const verBruto = pode("ver_bruto") ? setBruto : undefined;

  const buscarAgora = async (f: Fonte) => {
    const r = await enviar(`/api/inteligencia/fontes/${f.id}/sincronizar`);
    if (r.ok) setPedidas((p) => ({ ...p, [f.id]: true }));
    recarregar();
  };

  return (
    <>
      <Cabecalho titulo="Inteligência" ajuda="A plataforma local já vem ligada, e dá para desligar se você usa outra. Os indicadores vêm para o Roar e são comparados com os eventos, inclusive os antigos. Nada volta para a fonte, e nada é bloqueado sozinho.">
        {pode("gerir_fontes") && <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setNova(true)}>Nova fonte</Button>}
      </Cabecalho>
      {!dados ? <Carregando erro={erro} /> : (
        <Stack gap="md">
          <CacaDeIndicadores aoVigiar={recarregar} aoVerBruto={verBruto} />
          <Painel titulo="Fontes" p="md">
            <Tabela
              linhas={dados.fontes}
              chave={(f) => f.id}
              vazio="Nenhuma fonte ligada. O Roar funciona normalmente sem nenhuma."
              aoClicarLinha={(f) => setFonteAberta(f.id)}
              colunas={[
                { titulo: "Fonte", celula: (f) => <Group gap={6}><Text size="sm" fw={500}>{f.nome}</Text>{f.interna && <Estado tipo={f.ativa ? "ativa" : "outro"}>{f.ativa ? "Incluída" : "Desligada"}</Estado>}</Group> },
                { titulo: "Tipo", largura: 80, celula: (f) => (f.tipo === "manual" ? "Manual" : f.tipo.toUpperCase()) },
                { titulo: "Indicadores", alinhar: "right", largura: 100, celula: (f) => numero(f.indicadores) },
                { titulo: "Última busca", largura: 130, celula: (f) => <Data valor={f.ultima_em} /> },
                { titulo: "Situação", largura: 200, celula: (f) => <SituacaoDaFonte fonte={f} pedida={Boolean(pedidas[f.id])} /> },
                { titulo: "", largura: 40, celula: (f) => (
                  <AcoesDaLinha rotulo={`Ações de ${f.nome}`} itens={!pode("gerir_fontes") ? [] : f.ativa ? [
                    ...(f.tipo === "manual" ? [] : [{ texto: "Buscar agora", aoClicar: () => buscarAgora(f) }]),
                    { texto: f.interna ? "Desligar" : "Desativar", perigo: true, aoClicar: () => setDesativar(f) },
                  ] : [{ texto: "Ligar", aoClicar: async () => { await enviar(`/api/inteligencia/fontes/${f.id}/ligar`); recarregar(); } }]} />
                ) },
              ]}
            />
          </Painel>
          <Painel titulo="Eventos que bateram com um indicador" acao={<Busca valor={busca} aoMudar={setBusca} dica="Indicador, regra ou ativo" />}>
            {/* Sem dizer até onde conferiu, "nada bateu" parece "nada rodou". */}
            {dados.conferencia && (
              <Text size="xs" c="dimmed" mb="sm">
                {numero(dados.conferencia.eventos_30_dias)} eventos dos últimos 30 dias conferidos contra {numero(dados.conferencia.indicadores)} indicadores, até <Data valor={dados.conferencia.ate} />. Eventos antigos são conferidos de novo quando chega indicador novo.
              </Text>
            )}
            <TabelaDeOcorrencias linhas={dados.ocorrencias} vazio={busca ? "Nenhuma ocorrência com essa busca." : dados.conferencia ? "Nenhum evento bateu. Isso é bom: nenhum endereço, domínio ou arquivo visto aqui está nas fontes." : "A primeira conferência ainda não terminou."} aoAbrir={setOcorrencia} aoVerBruto={verBruto} />
          </Painel>
        </Stack>
      )}
      <NovaFonte aberto={nova} aoFechar={() => setNova(false)} aoCriar={recarregar} />
      <ConfirmarDesativar fonte={desativar} aoFechar={() => setDesativar(null)} aoDesativar={recarregar} />
      <GavetaDaFonte fonte={dados?.fontes.find((f) => f.id === fonteAberta) ?? null} aoFechar={() => setFonteAberta(null)} aoAbrirOcorrencia={setOcorrencia} aoVerBruto={verBruto} />
      <GavetaDaOcorrencia ocorrencia={ocorrencia} aoFechar={() => setOcorrencia(null)} aoVerBruto={verBruto} />
      <GavetaDoBruto evento={bruto} aoFechar={() => setBruto(null)} />
    </>
  );
}
