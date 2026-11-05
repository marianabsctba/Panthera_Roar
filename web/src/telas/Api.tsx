import { Accordion, Alert, Badge, Button, Group, Modal, Select, Stack, Text, TextInput } from "@mantine/core";
import { IconDownload, IconPlus } from "@tabler/icons-react";
import { useMemo, useState } from "react";

import { detalhe, enviar, pedir, useDados, usePode } from "../api";
import { AcoesDaLinha, BlocoDeComando, Busca, Cabecalho, Carregando, Data, Estado, Painel, Tabela } from "../componentes";

interface Chave {
  id: number; nome: string; prefixo: string; perfil: string; dono: string; criada_em: string; expira_em: string | null; ultima_vez: string | null;
  revogada_em: string | null; estado: string;
}
interface Parametro { name: string; in: string; required?: boolean; schema?: { type?: string; anyOf?: { type?: string }[] }; description?: string }
interface Operacao { summary?: string; description?: string; parameters?: Parametro[]; requestBody?: { content?: Record<string, { schema?: { $ref?: string } }> }; "x-permissao"?: string; tags?: string[] }
interface Esquema { properties?: Record<string, { type?: string; anyOf?: { type?: string }[]; maxLength?: number; pattern?: string }>; required?: string[] }
interface OpenApi { paths: Record<string, Record<string, Operacao>>; components?: { schemas?: Record<string, Esquema> } }

const PERFIS = [
  { value: "analista_n1", label: "Analista N1", description: "Vê, abre casos e tria. Dado pessoal mascarado." },
  { value: "analista_n2", label: "Analista N2", description: "Como N1, vê dado pessoal e aprova automações." },
  { value: "engenharia", label: "Engenharia de detecção", description: "Regras, fontes, automações e vulnerabilidades." },
  { value: "auditor", label: "Auditoria", description: "Só lê, inclusive a trilha de auditoria." },
];
const NOME_DO_PERFIL = Object.fromEntries(PERFIS.map((p) => [p.value, p.label]));
const VALIDADES = [{ value: "30", label: "30 dias" }, { value: "90", label: "90 dias" }, { value: "365", label: "1 ano" }, { value: "", label: "Sem prazo" }];
const ESTADOS: Record<string, { texto: string; tipo: string }> = { ativa: { texto: "Ativa", tipo: "ativo" }, vencida: { texto: "Vencida", tipo: "outro" }, revogada: { texto: "Revogada", tipo: "outro" } };
const CORES_DO_METODO: Record<string, string> = { get: "blue", post: "green", put: "yellow", patch: "orange", delete: "red" };

function NovaChave({ aoCriar }: { aoCriar: () => void }) {
  const [aberto, setAberto] = useState(false);
  const [nome, setNome] = useState("");
  const [perfil, setPerfil] = useState("analista_n1");
  const [validade, setValidade] = useState("90");
  const [erro, setErro] = useState<string | null>(null);
  const [segredo, setSegredo] = useState<string | null>(null);
  const fechar = () => {
    setAberto(false);
    setSegredo(null);
    setNome("");
  };
  const criar = async () => {
    setErro(null);
    const r = await enviar("/api/chaves", { nome, perfil, dias: validade ? Number(validade) : null });
    if (!r.ok) return setErro(await detalhe(r));
    setSegredo((await r.json()).chave);
    aoCriar();
  };
  return (
    <>
      <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setAberto(true)}>Nova chave</Button>
      <Modal opened={aberto} onClose={fechar} title="Nova chave de API" size="lg">
        {segredo ? (
          <Stack gap="sm">
            <Alert color="yellow" variant="light" p="xs" fz="sm">Copie agora. Esta é a única vez que a chave aparece: nem o administrador consegue ver de novo. Perdeu, revoga e cria outra.</Alert>
            <BlocoDeComando texto={segredo} />
            <Group justify="flex-end"><Button onClick={fechar}>Já copiei</Button></Group>
          </Stack>
        ) : (
          <Stack gap="sm">
            <TextInput label="Nome" description="Para saber depois quem usa, como o sistema que vai chamar a API." value={nome} onChange={(e) => setNome(e.currentTarget.value)} maxLength={80} />
            <Select label="Perfil" description="A chave pode o mesmo que uma pessoa com este perfil. Administração nunca." allowDeselect={false} value={perfil} onChange={(v) => v && setPerfil(v)}
              data={PERFIS.map((p) => ({ value: p.value, label: `${p.label}: ${p.description}` }))} />
            <Select label="Validade" allowDeselect={false} value={validade} onChange={(v) => setValidade(v ?? "")} data={VALIDADES} />
            {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
            <Group justify="flex-end">
              <Button variant="subtle" color="gray" onClick={fechar}>Cancelar</Button>
              <Button variant="filled" disabled={!nome.trim()} onClick={criar}>Criar</Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </>
  );
}

function Chaves() {
  const { dados, erro, recarregar } = useDados<{ chaves: Chave[] }>("/api/chaves");
  const [revogar, setRevogar] = useState<Chave | null>(null);
  const confirmar = async () => {
    if (revogar) await pedir(`/api/chaves/${revogar.id}`, { method: "DELETE" });
    setRevogar(null);
    recarregar();
  };
  return (
    <Painel titulo="Chaves" acao={<NovaChave aoCriar={recarregar} />}>
      {!dados ? <Carregando erro={erro} /> : (
        <Tabela
          linhas={dados.chaves}
          chave={(c) => c.id}
          vazio="Nenhuma chave criada. Sem chave, a API só responde a quem entrou pela tela."
          colunas={[
            { titulo: "Nome", celula: (c) => <Text size="sm" fw={500}>{c.nome}</Text> },
            { titulo: "Começa com", celula: (c) => <span className="mono">roar_{c.prefixo}_…</span> },
            { titulo: "Perfil", celula: (c) => NOME_DO_PERFIL[c.perfil] ?? c.perfil },
            { titulo: "Criada por", celula: (c) => c.dono },
            { titulo: "Último uso", largura: 150, celula: (c) => (c.ultima_vez ? <Data valor={c.ultima_vez} /> : <Text size="sm" c="dimmed">Nunca</Text>) },
            { titulo: "Vale até", largura: 150, celula: (c) => (c.expira_em ? <Data valor={c.expira_em} /> : "Sem prazo") },
            { titulo: "Situação", largura: 100, celula: (c) => <Estado tipo={ESTADOS[c.estado]?.tipo ?? "outro"}>{ESTADOS[c.estado]?.texto ?? c.estado}</Estado> },
            { titulo: "", largura: 40, celula: (c) => <AcoesDaLinha rotulo={`Ações da chave ${c.nome}`} itens={c.estado === "revogada" ? [] : [{ texto: "Revogar", perigo: true, aoClicar: () => setRevogar(c) }]} /> },
          ]}
        />
      )}
      <Modal opened={revogar !== null} onClose={() => setRevogar(null)} title="Revogar a chave?">
        <Stack gap="sm">
          <Text size="sm">{revogar?.nome}: a partir de agora, toda chamada com ela é recusada. Não dá para desfazer.</Text>
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={() => setRevogar(null)}>Cancelar</Button>
            <Button color="red" onClick={confirmar}>Revogar</Button>
          </Group>
        </Stack>
      </Modal>
    </Painel>
  );
}

function tipoDe(s?: { type?: string; anyOf?: { type?: string }[] }) {
  if (!s) return "";
  return s.type ?? (s.anyOf ?? []).map((t) => t.type).filter((t) => t && t !== "null").join(" ou ");
}

function Operacao({ metodo, caminho, op, esquemas }: { metodo: string; caminho: string; op: Operacao; esquemas: Record<string, Esquema> }) {
  const corpo = Object.values(op.requestBody?.content ?? {})[0]?.schema?.$ref?.split("/").pop();
  const esquema = corpo ? esquemas[corpo] : undefined;
  return (
    <Stack gap={6}>
      {op.description && <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{op.description}</Text>}
      <Text size="xs" c="dimmed">Permissão: <span className="mono">{op["x-permissao"]}</span></Text>
      {!!op.parameters?.length && (
        <Stack gap={2}>
          <Text size="xs" fw={600}>Parâmetros</Text>
          {op.parameters.map((p) => (
            <Text key={`${p.in}-${p.name}`} size="xs"><span className="mono">{p.name}</span> <Text span size="xs" c="dimmed">({p.in === "path" ? "no caminho" : "na consulta"}, {tipoDe(p.schema)}{p.required ? ", obrigatório" : ""})</Text></Text>
          ))}
        </Stack>
      )}
      {esquema?.properties && (
        <Stack gap={2}>
          <Text size="xs" fw={600}>Corpo em JSON</Text>
          {Object.entries(esquema.properties).map(([nome, campo]) => (
            <Text key={nome} size="xs"><span className="mono">{nome}</span> <Text span size="xs" c="dimmed">({tipoDe(campo)}{esquema.required?.includes(nome) ? ", obrigatório" : ""}{campo.pattern ? `, ${campo.pattern.replace(/^\^\(|\)\$$/g, "").split("|").join(" | ")}` : ""})</Text></Text>
          ))}
        </Stack>
      )}
      <BlocoDeComando texto={`curl -H "Authorization: Bearer $ROAR_CHAVE"${metodo === "get" ? "" : ` -X ${metodo.toUpperCase()}`}${corpo ? " -H \"Content-Type: application/json\" -d '{...}'" : ""} ${window.location.origin}${caminho}`} />
    </Stack>
  );
}

function Documentacao() {
  const { dados, erro } = useDados<OpenApi>("/api/openapi.json");
  const [busca, setBusca] = useState("");
  const grupos = useMemo(() => {
    const termo = busca.trim().toLowerCase();
    const mapa = new Map<string, { metodo: string; caminho: string; op: Operacao }[]>();
    Object.entries(dados?.paths ?? {}).forEach(([caminho, metodos]) => Object.entries(metodos).forEach(([metodo, op]) => {
      if (termo && !`${caminho} ${op.summary ?? ""} ${op.description ?? ""}`.toLowerCase().includes(termo)) return;
      const grupo = op.tags?.[0] ?? "outros";
      mapa.set(grupo, [...(mapa.get(grupo) ?? []), { metodo, caminho, op }]);
    }));
    return [...mapa.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [dados, busca]);
  const baixar = () => {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([JSON.stringify(dados, null, 2)], { type: "application/json" }));
    link.download = "panthera-roar-openapi.json";
    link.click();
  };
  return (
    <Painel titulo="Documentação" acao={<Group gap="xs"><Busca valor={busca} aoMudar={setBusca} dica="Rota ou assunto" /><Button variant="default" leftSection={<IconDownload size={14} />} disabled={!dados} onClick={baixar}>OpenAPI</Button></Group>}>
      {!dados ? <Carregando erro={erro} /> : (
        <Stack gap="sm">
          <Text size="sm">Toda chamada leva a chave no cabeçalho <span className="mono">Authorization: Bearer roar_…</span>. A chave vale só na organização em que foi criada, pode o mesmo que o perfil dela, e respeita o mascaramento de dado pessoal. As rotas de conta, como senha e autenticador, não aceitam chave.</Text>
          <BlocoDeComando texto={`curl -H "Authorization: Bearer $ROAR_CHAVE" ${window.location.origin}/api/fila`} />
          <Accordion variant="separated" multiple>
            {grupos.map(([grupo, operacoes]) => (
              <Accordion.Item key={grupo} value={grupo}>
                <Accordion.Control><Group gap="xs"><Text size="sm" fw={600}>{grupo}</Text><Badge size="xs" variant="light" color="gray">{operacoes.length}</Badge></Group></Accordion.Control>
                <Accordion.Panel>
                  <Accordion variant="contained" multiple>
                    {operacoes.map(({ metodo, caminho, op }) => (
                      <Accordion.Item key={`${metodo} ${caminho}`} value={`${metodo} ${caminho}`}>
                        <Accordion.Control>
                          <Group gap="xs" wrap="nowrap">
                            <Badge size="sm" radius="sm" w={64} color={CORES_DO_METODO[metodo] ?? "gray"} variant="light">{metodo.toUpperCase()}</Badge>
                            <Text size="sm" className="mono" style={{ overflowWrap: "anywhere" }}>{caminho}</Text>
                          </Group>
                        </Accordion.Control>
                        <Accordion.Panel><Operacao metodo={metodo} caminho={caminho} op={op} esquemas={dados.components?.schemas ?? {}} /></Accordion.Panel>
                      </Accordion.Item>
                    ))}
                  </Accordion>
                </Accordion.Panel>
              </Accordion.Item>
            ))}
          </Accordion>
        </Stack>
      )}
    </Painel>
  );
}

export function Api() {
  const pode = usePode();
  return (
    <>
      <Cabecalho titulo="API" ajuda="Outros sistemas usam o Roar pela API, com uma chave. Aqui estão as chaves da organização e a documentação de cada rota." />
      <Stack gap="md">
        {pode("gerir_usuarios") && <Chaves />}
        <Documentacao />
      </Stack>
    </>
  );
}
