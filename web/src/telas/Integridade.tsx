import { Alert, Button, Drawer, Group, Modal, Select, SimpleGrid, Stack, Switch, Tabs, Text, Textarea, TextInput, Title } from "@mantine/core";
import { IconPlus, IconTerminal2 } from "@tabler/icons-react";
import { useCallback, useState } from "react";

import { detalhe, enviar, useDados, useEu, usePode } from "../api";
import { AcoesDaLinha, BlocoDeComando, Busca, Cabecalho, Carregando, Data, Estado, GavetaDoBruto, Numero, Painel, Tabela } from "../componentes";
import { numero, quando, tamanho } from "../formato";

// ------------------------------------------------------------------ visão geral

const MUDANCAS: Record<string, string> = { added: "Criado", modified: "Alterado", deleted: "Apagado" };
interface VisaoFim {
  caminhos: { id: number; caminho: string; sistema: string; modo: string; estado: string; mensagem: string | null }[];
  ativos: { agente_id: string; nome: string | null; sistema: string | null; estado: string; fim_inicio: string | null; fim_fim: string | null; arquivos: number }[];
  por_dia: { mudanca: string; total: number }[];
}
interface Mudanca { id: number; ocorrido_em: string; ativo: string | null; regra_descricao: string | null; caminho: string | null; mudanca: string | null; dono: string | null }

function VisaoGeral({ visao }: { visao: VisaoFim }) {
  const pode = usePode();
  const [busca, setBusca] = useState("");
  const [bruto, setBruto] = useState<number | null>(null);
  const [mudanca, setMudanca] = useState("");
  const { dados } = useDados<{ arquivos: Mudanca[] }>(`/api/arquivos?${new URLSearchParams({ busca, mudanca })}`);
  const alternar = (m: string) => () => setMudanca((atual) => (atual === m ? "" : m));
  const soma = (m: string) => visao.por_dia.filter((d) => d.mudanca === m).reduce((t, d) => t + Number(d.total), 0);
  return (
    <Stack gap="md">
      <SimpleGrid cols={{ base: 1, sm: 3 }}>
        <Numero rotulo="Criados em 30 dias" valor={numero(soma("added"))} aoClicar={alternar("added")} selecionado={mudanca === "added"} />
        <Numero rotulo="Alterados em 30 dias" valor={numero(soma("modified"))} aoClicar={alternar("modified")} selecionado={mudanca === "modified"} />
        <Numero rotulo="Apagados em 30 dias" valor={numero(soma("deleted"))} aoClicar={alternar("deleted")} selecionado={mudanca === "deleted"} />
      </SimpleGrid>
      <Painel titulo="Alterações recentes" acao={<Busca valor={busca} aoMudar={setBusca} dica="Buscar por arquivo ou servidor" />}>
        {!dados ? <Carregando /> : (
          <Tabela
            linhas={dados.arquivos}
            chave={(a) => a.id}
            vazio="Nenhuma mudança em arquivos monitorados."
            aoClicarLinha={pode("ver_bruto") ? (a) => setBruto(a.id) : undefined}
            colunas={[
              { titulo: "Quando", largura: 150, celula: (a) => <Data valor={a.ocorrido_em} /> },
              { titulo: "Mudança", largura: 90, celula: (a) => MUDANCAS[a.mudanca ?? ""] ?? a.mudanca ?? "-" },
              { titulo: "Arquivo", celula: (a) => <span className="mono">{a.caminho ?? a.regra_descricao ?? "-"}</span> },
              { titulo: "Servidor", celula: (a) => a.ativo ?? "-" },
              { titulo: "Dono", celula: (a) => <span className="mono" style={{ whiteSpace: "nowrap" }}>{a.dono ?? "-"}</span> },
              { titulo: "", largura: 40, celula: (a) => <AcoesDaLinha rotulo="Ações da alteração" itens={pode("ver_bruto") ? [{ texto: "Ver como chegou", aoClicar: () => setBruto(a.id) }] : []} /> },
            ]}
          />
        )}
      </Painel>
      <GavetaDoBruto evento={bruto} aoFechar={() => setBruto(null)} />
    </Stack>
  );
}

// ------------------------------------------------------------------ o que monitorar

const MODOS: Record<string, string> = { agendado: "Nas varreduras", tempo_real: "Em tempo real", quem_alterou: "Em tempo real, com quem alterou" };
const ESTADOS_DE_CAMINHO: Record<string, string> = { pendente: "Aplicando", ativo: "Ativo", recusado: "Recusado" };

function NovoCaminho({ aberto, aoFechar, aoCriar }: { aberto: boolean; aoFechar: () => void; aoCriar: () => void }) {
  const [caminho, setCaminho] = useState("");
  const [sistema, setSistema] = useState("linux");
  const [modo, setModo] = useState("tempo_real");
  const [erro, setErro] = useState<string | null>(null);
  const salvar = async () => {
    const r = await enviar("/api/fim/caminhos", { caminho, sistema, modo });
    if (!r.ok) {
      setErro(await detalhe(r, "Confira o caminho."));
      return;
    }
    setCaminho("");
    setErro(null);
    aoCriar();
    aoFechar();
  };
  return (
    <Modal opened={aberto} onClose={aoFechar} title="Adicionar pasta ou arquivo">
      <Stack gap="sm">
        <TextInput label="Caminho completo" placeholder={sistema === "windows" ? "C:\\Sistemas\\App" : "/var/www"} value={caminho} onChange={(e) => setCaminho(e.currentTarget.value)} error={erro} data-autofocus spellCheck={false} />
        <Group grow>
          <Select label="Sistema" value={sistema} onChange={(v) => setSistema(v ?? "linux")} allowDeselect={false} data={[{ value: "linux", label: "Linux" }, { value: "windows", label: "Windows" }]} />
          <Select label="Como monitorar" value={modo} onChange={(v) => setModo(v ?? "agendado")} allowDeselect={false} data={Object.entries(MODOS).map(([value, label]) => ({ value, label }))}
            description={modo === "quem_alterou" ? "Precisa do serviço de auditoria no servidor." : undefined} />
        </Group>
        <Group justify="flex-end" mt="xs">
          <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
          <Button variant="filled" onClick={salvar} disabled={!caminho.trim()}>Adicionar</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function OQueMonitorar({ visao, recarregar }: { visao: VisaoFim; recarregar: () => void }) {
  const pode = usePode();
  const [novo, setNovo] = useState(false);
  return (
    <Painel
      titulo="Pastas e arquivos adicionais"
      acao={pode("gerir_fontes") && <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setNovo(true)}>Adicionar</Button>}
    >
      <Tabela
        linhas={visao.caminhos}
        chave={(c) => c.id}
        vazio="Só o monitoramento padrão de cada sistema, como /etc e System32."
        colunas={[
          { titulo: "Caminho", celula: (c) => <span className="mono">{c.caminho}</span> },
          { titulo: "Sistema", largura: 90, celula: (c) => (c.sistema === "windows" ? "Windows" : "Linux") },
          { titulo: "Como", celula: (c) => MODOS[c.modo] ?? c.modo },
          { titulo: "Estado", largura: 110, celula: (c) => <Estado tipo={c.estado}>{c.mensagem ?? ESTADOS_DE_CAMINHO[c.estado] ?? c.estado}</Estado> },
          { titulo: "", largura: 40, celula: (c) => <AcoesDaLinha rotulo="Ações do caminho" itens={pode("gerir_fontes") ? [{ texto: "Parar de monitorar", perigo: true, aoClicar: async () => { await enviar(`/api/fim/caminhos/${c.id}/desativar`); recarregar(); } }] : []} /> },
        ]}
      />
      <NovoCaminho aberto={novo} aoFechar={() => setNovo(false)} aoCriar={recarregar} />
    </Painel>
  );
}

// ------------------------------------------------------------------ servidores

interface ArquivoDaBase { caminho: string; tamanho: number | null; modificado_em: string | null; sha256: string | null; dono: string | null }

function ArquivosDoServidor({ ativo, aoFechar }: { ativo: VisaoFim["ativos"][number] | null; aoFechar: () => void }) {
  const [busca, setBusca] = useState("");
  const { dados } = useDados<{ arquivos: ArquivoDaBase[]; total: number }>(ativo ? `/api/fim/ativos/${encodeURIComponent(ativo.agente_id)}/arquivos?${new URLSearchParams({ busca })}` : null);
  return (
    <Drawer opened={ativo !== null} onClose={aoFechar} title={`Arquivos de ${ativo?.nome ?? ativo?.agente_id ?? ""}`} size="60%">
      <Stack gap="sm">
        <Group justify="space-between">
          <Busca valor={busca} aoMudar={setBusca} dica="Parte do caminho" />
          {dados && <Text size="xs" c="dimmed">{numero(dados.total)} arquivos</Text>}
        </Group>
        {!dados ? <Carregando /> : (
          <Tabela
            linhas={dados.arquivos}
            chave={(a) => a.caminho}
            vazio="Nenhum arquivo encontrado."
            colunas={[
              { titulo: "Arquivo", celula: (a) => <span className="mono">{a.caminho}</span> },
              { titulo: "Tamanho", alinhar: "right", largura: 90, celula: (a) => tamanho(a.tamanho) },
              { titulo: "Modificado", largura: 150, celula: (a) => <Data valor={a.modificado_em} /> },
              { titulo: "Dono", largura: 90, celula: (a) => <span className="mono">{a.dono ?? "-"}</span> },
            ]}
          />
        )}
      </Stack>
    </Drawer>
  );
}

function Servidores({ visao }: { visao: VisaoFim }) {
  const pode = usePode();
  const [aberto, setAberto] = useState<VisaoFim["ativos"][number] | null>(null);
  const [pedidos, setPedidos] = useState<Record<string, boolean>>({});
  return (
    <Painel p={0}>
      <Tabela
        linhas={visao.ativos}
        chave={(a) => a.agente_id}
        vazio="Nenhum servidor inscrito ainda."
        aoClicarLinha={setAberto}
        colunas={[
          { titulo: "Servidor", celula: (a) => <Text size="sm" fw={500}>{a.nome ?? a.agente_id}</Text> },
          { titulo: "Sistema", celula: (a) => <Text size="sm" c="dimmed">{a.sistema ?? "-"}</Text> },
          { titulo: "Última varredura", largura: 150, celula: (a) => (pedidos[a.agente_id] ? "Pedida agora" : <Data valor={a.fim_fim ?? a.fim_inicio} />) },
          { titulo: "Arquivos", alinhar: "right", largura: 90, celula: (a) => numero(a.arquivos) },
          { titulo: "", largura: 40, celula: (a) => (
            <AcoesDaLinha rotulo={`Ações de ${a.nome ?? a.agente_id}`} itens={[
              { texto: "Ver arquivos", aoClicar: () => setAberto(a) },
              ...(pode("gerir_fontes") ? [{ texto: "Varrer agora", aoClicar: async () => { const r = await enviar("/api/fim/varreduras", { agente_id: a.agente_id }); if (r.ok) setPedidos((p) => ({ ...p, [a.agente_id]: true })); } }] : []),
            ]} />
          ) },
        ]}
      />
      <ArquivosDoServidor ativo={aberto} aoFechar={() => setAberto(null)} />
    </Painel>
  );
}

// ------------------------------------------------------------------ busca de malware

interface VisaoYara {
  regras: { id: number; nome: string; identificadores: string[]; estado: string; mensagem: string | null }[];
  servidores: { agente_id: string; nome: string | null; sistema: string | null; pronto_em: string | null; erro_em: string | null }[];
  achados: { id: number; ocorrido_em: string; ativo: string | null; regra: string | null; arquivo: string | null; autor: string | null; repositorio: string | null }[];
  comando: string;
  comando_windows: string;
  biblioteca: { versao: string | null; atualizada_em: string | null; erro: string | null; regras: number | null } | null;
  assinatura: { ativa: boolean; automatica: boolean; versao: string | null; excluidas: number; estado: string; mensagem: string | null } | null;
}
interface RegraDaBiblioteca { nome: string; privada: boolean; descricao: string | null; autor: string | null; repositorio: string | null; licenca: string | null; em_uso: boolean }
const ESTADOS_DE_REGRA: Record<string, string> = { pendente: "Aplicando", ativa: "Ativa", recusada: "Recusada", aplicada: "Em uso" };

function RegrasDaBiblioteca({ aberto, aoFechar, aoMudar }: { aberto: boolean; aoFechar: () => void; aoMudar: () => void }) {
  const pode = usePode();
  const [busca, setBusca] = useState("");
  const { dados, recarregar } = useDados<{ regras: RegraDaBiblioteca[]; total: number }>(aberto ? `/api/yara/biblioteca/regras?${new URLSearchParams({ busca })}` : null);
  return (
    <Drawer opened={aberto} onClose={aoFechar} title="Regras da biblioteca" size="70%">
      <Stack gap="sm">
        <Group justify="space-between">
          <Busca valor={busca} aoMudar={setBusca} dica="Nome, descrição, autor ou origem" />
          {dados && <Text size="xs" c="dimmed">{numero(dados.total)} regras</Text>}
        </Group>
        {!dados ? <Carregando /> : (
          <Tabela
            linhas={dados.regras}
            chave={(r) => r.nome}
            vazio="Nenhuma regra encontrada."
            colunas={[
              { titulo: "Regra", celula: (r) => <><span className="mono">{r.nome}</span>{!r.em_uso && <Text size="xs" c="dimmed">Fora de uso</Text>}</> },
              { titulo: "O que procura", celula: (r) => <Text size="xs" lineClamp={2}>{r.descricao ?? "-"}</Text> },
              { titulo: "Autoria", celula: (r) => <Text size="xs">{[r.autor, r.repositorio].filter(Boolean).join(", ") || "-"}</Text> },
              { titulo: "Licença", celula: (r) => <Text size="xs" lineClamp={1} title={r.licenca ?? undefined}>{r.licenca ?? "Veja a origem"}</Text> },
              { titulo: "", largura: 40, celula: (r) => <AcoesDaLinha rotulo={`Ações de ${r.nome}`} itens={pode("gerir_fontes") && !r.privada ? [{ texto: r.em_uso ? "Não usar esta regra" : "Usar de novo", aoClicar: async () => { await enviar(`/api/yara/biblioteca/regras/${encodeURIComponent(r.nome)}/${r.em_uso ? "nao-usar" : "usar"}`); recarregar(); aoMudar(); } }] : []} /> },
            ]}
          />
        )}
      </Stack>
    </Drawer>
  );
}

function NovaRegra({ aberto, aoFechar, aoCriar }: { aberto: boolean; aoFechar: () => void; aoCriar: () => void }) {
  const [nome, setNome] = useState("");
  const [fonte, setFonte] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const salvar = async () => {
    const r = await enviar("/api/yara/regras", { nome, fonte });
    if (!r.ok) {
      setErro(await detalhe(r, "Dê um nome e cole o texto da regra."));
      return;
    }
    setNome("");
    setFonte("");
    setErro(null);
    aoCriar();
    aoFechar();
  };
  return (
    <Modal opened={aberto} onClose={aoFechar} title="Adicionar regra YARA" size="lg">
      <Stack gap="sm">
        <TextInput label="Nome" value={nome} onChange={(e) => setNome(e.currentTarget.value)} data-autofocus maxLength={120} />
        <Textarea label="Regra" value={fonte} onChange={(e) => setFonte(e.currentTarget.value)} autosize minRows={8} maxRows={18} spellCheck={false} styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 12 } }} error={erro} />
        <Group justify="flex-end">
          <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
          <Button variant="filled" onClick={salvar} disabled={!nome.trim() || !fonte.trim()}>Adicionar</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function BuscaDeMalware() {
  const eu = useEu();
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<VisaoYara>("/api/yara");
  const [verRegras, setVerRegras] = useState(false);
  const [novaRegra, setNovaRegra] = useState(false);
  const [preparar, setPreparar] = useState(false);
  const [bruto, setBruto] = useState<number | null>(null);
  const mudar = useCallback(async (novo: { ativa: boolean; automatica: boolean }) => {
    await enviar("/api/yara/biblioteca", novo);
    recarregar();
  }, [recarregar]);

  if (!dados) return <Carregando erro={erro} />;
  const { biblioteca, assinatura } = dados;
  const ativa = Boolean(assinatura?.ativa);
  const automatica = assinatura?.automatica ?? true;
  const emUso = ativa || dados.regras.length > 0;
  const situacao = (s: VisaoYara["servidores"][number]) => {
    if (s.erro_em && (!s.pronto_em || s.erro_em > s.pronto_em)) return <Estado tipo="problema">Com problema</Estado>;
    return s.pronto_em ? <Estado tipo="pronto">Pronto</Estado> : <Estado tipo="outro">Falta preparar</Estado>;
  };

  return (
    <Stack gap="md">
      <Painel>
        <Group justify="space-between" wrap="wrap" gap="md">
          <div>
            <Group gap="xs">
              <Title order={2}>Biblioteca da comunidade</Title>
              {ativa && assinatura && <Estado tipo={assinatura.estado}>{ESTADOS_DE_REGRA[assinatura.estado] ?? assinatura.estado}</Estado>}
            </Group>
            <Text size="sm" c="dimmed" mt={2}>
              {biblioteca?.versao
                ? `${numero(biblioteca.regras)} regras de fontes públicas, versão de ${quando(biblioteca.atualizada_em, eu.fuso)}${assinatura?.excluidas ? `, sem ${assinatura.excluidas} que você tirou` : ""}.`
                : biblioteca?.erro ?? "Ainda sendo baixada."}
            </Text>
          </div>
          <Group gap="lg">
            {pode("gerir_fontes") && biblioteca?.versao && (
              <>
                <Switch label="Usar" checked={ativa} onChange={(e) => mudar({ ativa: e.currentTarget.checked, automatica })} />
                <Switch label="Atualizar sozinha" disabled={!ativa} checked={automatica} onChange={(e) => mudar({ ativa, automatica: e.currentTarget.checked })} />
              </>
            )}
            {biblioteca?.versao && <Button onClick={() => setVerRegras(true)}>Ver regras</Button>}
          </Group>
        </Group>
        {assinatura?.mensagem && <Alert color="red" variant="light" mt="sm" p="xs" fz="sm">{assinatura.mensagem}</Alert>}
        {ativa && !automatica && assinatura?.versao !== biblioteca?.versao && pode("gerir_fontes") && (
          <Alert color="yellow" variant="light" mt="sm" p="xs">
            <Group justify="space-between"><Text size="sm">Há uma versão mais nova.</Text><Button size="xs" onClick={async () => { await enviar("/api/yara/biblioteca/atualizar"); recarregar(); }}>Atualizar agora</Button></Group>
          </Alert>
        )}
      </Painel>

      <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="md">
        <Painel titulo="Suas regras" acao={pode("gerir_fontes") && <Button leftSection={<IconPlus size={14} />} size="xs" onClick={() => setNovaRegra(true)}>Adicionar</Button>}>
          <Tabela
            linhas={dados.regras}
            chave={(r) => r.id}
            vazio="Nenhuma regra própria."
            colunas={[
              { titulo: "Nome", celula: (r) => r.nome },
              { titulo: "Regras", celula: (r) => <span className="mono">{r.identificadores.join(", ")}</span> },
              { titulo: "Estado", largura: 90, celula: (r) => <Estado tipo={r.estado}>{ESTADOS_DE_REGRA[r.estado] ?? r.estado}</Estado> },
              { titulo: "", largura: 40, celula: (r) => <AcoesDaLinha rotulo={`Ações de ${r.nome}`} itens={pode("gerir_fontes") ? [{ texto: "Tirar", perigo: true, aoClicar: async () => { await enviar(`/api/yara/regras/${r.id}/desativar`); recarregar(); } }] : []} /> },
            ]}
          />
        </Painel>
        <Painel titulo="Servidores" acao={emUso && <Button leftSection={<IconTerminal2 size={14} />} size="xs" onClick={() => setPreparar(true)}>Preparar servidor</Button>}>
          <Tabela
            linhas={emUso ? dados.servidores : []}
            chave={(s) => s.agente_id}
            vazio="Ative a biblioteca ou adicione uma regra para preparar os servidores."
            aoClicarLinha={(s) => { if (!s.pronto_em) setPreparar(true); }}
            colunas={[
              { titulo: "Servidor", celula: (s) => s.nome ?? s.agente_id },
              { titulo: "Situação", largura: 120, celula: situacao },
            ]}
          />
        </Painel>
      </SimpleGrid>

      <Painel titulo="Arquivos encontrados">
        <Tabela
          linhas={dados.achados}
          chave={(a) => a.id}
          vazio="Nenhum arquivo bateu com as regras nos últimos 30 dias."
          aoClicarLinha={pode("ver_bruto") ? (a) => setBruto(a.id) : undefined}
          colunas={[
            { titulo: "Quando", largura: 150, celula: (a) => <Data valor={a.ocorrido_em} /> },
            { titulo: "Servidor", celula: (a) => a.ativo ?? "-" },
            { titulo: "Arquivo", celula: (a) => <span className="mono">{a.arquivo ?? "-"}</span> },
            { titulo: "Regra", celula: (a) => <><span className="mono">{a.regra ?? "-"}</span><Text size="xs" c="dimmed">{a.autor ? `${a.autor}${a.repositorio ? `, via ${a.repositorio}` : ""}` : "Regra da organização"}</Text></> },
            { titulo: "", largura: 40, celula: (a) => <AcoesDaLinha rotulo="Ações do achado" itens={pode("ver_bruto") ? [{ texto: "Ver como chegou", aoClicar: () => setBruto(a.id) }] : []} /> },
          ]}
        />
      </Painel>

      <RegrasDaBiblioteca aberto={verRegras} aoFechar={() => setVerRegras(false)} aoMudar={recarregar} />
      <NovaRegra aberto={novaRegra} aoFechar={() => setNovaRegra(false)} aoCriar={recarregar} />
      <GavetaDoBruto evento={bruto} aoFechar={() => setBruto(null)} />
      <Modal opened={preparar} onClose={() => setPreparar(false)} title="Preparar um servidor" size="lg">
        <Stack gap="sm">
          <Text size="sm" c="dimmed">Rode uma vez em cada servidor. Depois as regras chegam sozinhas.</Text>
          <Tabs defaultValue="linux">
            <Tabs.List mb="sm">
              <Tabs.Tab value="linux">Debian e Ubuntu</Tabs.Tab>
              <Tabs.Tab value="windows">Windows</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="linux"><BlocoDeComando texto={dados.comando} /></Tabs.Panel>
            <Tabs.Panel value="windows"><Stack gap="xs"><Text size="xs" c="dimmed">No PowerShell, como administrador.</Text><BlocoDeComando texto={dados.comando_windows} /></Stack></Tabs.Panel>
          </Tabs>
        </Stack>
      </Modal>
    </Stack>
  );
}

// ------------------------------------------------------------------ tela

export function Integridade() {
  const { dados, erro, recarregar } = useDados<VisaoFim>("/api/fim");
  return (
    <>
      <Cabecalho titulo="Integridade" ajuda="Avisa quando um arquivo importante é criado, alterado ou apagado, e procura malware nesses arquivos. O que já estava no disco não é varrido." />
      {!dados ? <Carregando erro={erro} /> : (
        <Tabs defaultValue="geral">
          <Tabs.List mb="md">
            <Tabs.Tab value="geral">Visão geral</Tabs.Tab>
            <Tabs.Tab value="monitorar">O que monitorar</Tabs.Tab>
            <Tabs.Tab value="servidores">Servidores</Tabs.Tab>
            <Tabs.Tab value="malware">Busca de malware</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="geral"><VisaoGeral visao={dados} /></Tabs.Panel>
          <Tabs.Panel value="monitorar"><OQueMonitorar visao={dados} recarregar={recarregar} /></Tabs.Panel>
          <Tabs.Panel value="servidores"><Servidores visao={dados} /></Tabs.Panel>
          <Tabs.Panel value="malware"><BuscaDeMalware /></Tabs.Panel>
        </Tabs>
      )}
    </>
  );
}
