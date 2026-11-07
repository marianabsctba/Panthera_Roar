import { Alert, Anchor, Badge, Button, CopyButton, FileInput, Group, Menu, Modal, Paper, SegmentedControl, Select, Stack, Text, Textarea, TextInput, Title } from "@mantine/core";
import { useEffect, useState } from "react";

import { detalhe, enviar, useDados, useEu, usePode } from "../api";
import { Carregando, Severidade, Vazio } from "../componentes";
import { numero, quando } from "../formato";
import { baixar } from "./Relatorios";

export interface NotaDoCaso { id: number; autor_nome: string; automatica: boolean; texto: string; criado_em: string; tipo: string; situacao: string | null }
export interface EvidenciaDoCaso { id: number; tipo: string; nome: string; tipo_midia: string; descricao: string; tamanho: number; sha256: string; adicionado_por_nome: string; adicionado_em: string }
interface Responsavel { id: string; nome: string }

export const TIPOS_DE_NOTA: Record<string, { texto: string; cor: string }> = {
  nota: { texto: "Nota", cor: "gray" }, fato: { texto: "Fato", cor: "blue" }, hipotese: { texto: "Hipótese", cor: "violet" }, passagem: { texto: "Passagem de plantão", cor: "pink" },
};
const SITUACOES: Record<string, { texto: string; cor: string }> = {
  aberta: { texto: "Aberta", cor: "yellow" }, confirmada: { texto: "Confirmada", cor: "green" }, descartada: { texto: "Descartada", cor: "gray" },
};
const tamanho = (n: number) => (n >= 1048576 ? `${(n / 1048576).toFixed(1).replace(".", ",")} MB` : `${numero(Math.max(1, Math.round(n / 1024)))} KB`);

/** Fatos de um lado, hipóteses do outro: o que foi visto não se mistura com o que se acha. */
export function FatosEHipoteses({ casoId, notas, aoMudar }: { casoId: number; notas: NotaDoCaso[]; aoMudar: () => void }) {
  const pode = usePode();
  const eu = useEu();
  const fatos = notas.filter((n) => n.tipo === "fato");
  const hipoteses = notas.filter((n) => n.tipo === "hipotese");
  const mudar = async (n: NotaDoCaso, situacao: string) => {
    if ((await enviar(`/api/casos/${casoId}/notas/${n.id}/situacao`, { situacao })).ok) aoMudar();
  };
  if (!fatos.length && !hipoteses.length) return null;
  return (
    <Stack gap="sm">
      {fatos.length > 0 && (
        <div>
          <Title order={3} mb="xs">Fatos</Title>
          <Stack gap={6}>
            {fatos.map((n) => (
              <div key={n.id} style={{ borderLeft: "3px solid var(--mantine-color-blue-5)", paddingLeft: 10 }}>
                <Text size="sm" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{n.texto}</Text>
                <Text size="xs" c="dimmed">{n.autor_nome}, {quando(n.criado_em, eu.fuso)}</Text>
              </div>
            ))}
          </Stack>
        </div>
      )}
      {hipoteses.length > 0 && (
        <div>
          <Title order={3} mb="xs">Hipóteses</Title>
          <Stack gap={6}>
            {hipoteses.map((n) => {
              const s = SITUACOES[n.situacao ?? "aberta"];
              return (
                <Group key={n.id} justify="space-between" wrap="nowrap" align="flex-start" style={{ borderLeft: "3px solid var(--mantine-color-violet-5)", paddingLeft: 10 }}>
                  <Stack gap={2} style={{ minWidth: 0 }}>
                    <Text size="sm" td={n.situacao === "descartada" ? "line-through" : undefined} style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{n.texto}</Text>
                    <Text size="xs" c="dimmed">{n.autor_nome}, {quando(n.criado_em, eu.fuso)}</Text>
                  </Stack>
                  {pode("triar") ? (
                    <Menu position="bottom-end" withinPortal>
                      <Menu.Target><Badge component="button" size="sm" radius="sm" variant="light" color={s.cor} tt="none" style={{ cursor: "pointer" }}>{s.texto}</Badge></Menu.Target>
                      <Menu.Dropdown>
                        {Object.entries(SITUACOES).filter(([v]) => v !== n.situacao).map(([v, x]) => (
                          <Menu.Item key={v} onClick={() => mudar(n, v)}>{v === "aberta" ? "Reabrir" : `Marcar como ${x.texto.toLowerCase()}`}</Menu.Item>
                        ))}
                      </Menu.Dropdown>
                    </Menu>
                  ) : <Badge size="sm" radius="sm" variant="light" color={s.cor} tt="none">{s.texto}</Badge>}
                </Group>
              );
            })}
          </Stack>
        </div>
      )}
    </Stack>
  );
}

export function PassarPlantao({ casoId, responsaveis, aoMudar }: { casoId: number; responsaveis: Responsavel[]; aoMudar: () => void }) {
  const [aberto, setAberto] = useState(false);
  const [para, setPara] = useState<string | null>(null);
  const [feito, setFeito] = useState("");
  const [pendente, setPendente] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const passar = async () => {
    setErro(null);
    const r = await enviar(`/api/casos/${casoId}/passagem`, { para, feito, pendente });
    if (!r.ok) return setErro(await detalhe(r));
    setAberto(false); setFeito(""); setPendente(""); setPara(null);
    aoMudar();
  };
  return (
    <>
      <Button size="xs" variant="default" onClick={() => setAberto(true)}>Passar o plantão</Button>
      <Modal opened={aberto} onClose={() => setAberto(false)} title="Passar o caso para o próximo plantão">
        <Stack gap="sm">
          <Select label="Quem assume" placeholder="Escolha" data={responsaveis.map((r) => ({ value: r.id, label: r.nome }))} value={para} onChange={setPara} />
          <Textarea label="O que já foi feito" autosize minRows={2} maxLength={2000} value={feito} onChange={(e) => setFeito(e.currentTarget.value)} />
          <Textarea label="O que falta fazer" autosize minRows={2} maxLength={2000} value={pendente} onChange={(e) => setPendente(e.currentTarget.value)} />
          {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
          <Group justify="flex-end"><Button variant="filled" disabled={!para || (!feito.trim() && !pendente.trim())} onClick={passar}>Passar</Button></Group>
        </Stack>
      </Modal>
    </>
  );
}

function lerEmBase64(arquivo: File): Promise<string> {
  return new Promise((resolver, falhar) => {
    const leitor = new FileReader();
    leitor.onload = () => resolver(String(leitor.result).split(",", 2)[1] ?? "");
    leitor.onerror = () => falhar(leitor.error);
    leitor.readAsDataURL(arquivo);
  });
}

/** Evidências guardadas no caso, com o resumo de cada uma: não se apagam nem se trocam. */
export function EvidenciasDoCaso({ casoId, evidencias, aoMudar, encerrado }: { casoId: number; evidencias: EvidenciaDoCaso[]; aoMudar: () => void; encerrado: boolean }) {
  const pode = usePode();
  const eu = useEu();
  const [gerando, setGerando] = useState(false);
  const [arquivo, setArquivo] = useState<File | null>(null);
  const [descricao, setDescricao] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const triar = pode("triar") && !encerrado;
  const gerar = async () => {
    setErro(null); setGerando(true);
    const r = await enviar(`/api/casos/${casoId}/evidencias/pacote`).finally(() => setGerando(false));
    if (!r.ok) return setErro(await detalhe(r, "Não foi possível gerar o pacote."));
    aoMudar();
  };
  const anexar = async () => {
    if (!arquivo) return;
    setErro(null);
    if (arquivo.size > 10 * 1048576) return setErro("O arquivo precisa ter até 10 MB.");
    const conteudo = await lerEmBase64(arquivo);
    const r = await enviar(`/api/casos/${casoId}/evidencias/arquivo`, { nome: arquivo.name, tipo_midia: arquivo.type || "application/octet-stream", descricao, conteudo });
    if (!r.ok) return setErro(await detalhe(r, "Não foi possível anexar."));
    setArquivo(null); setDescricao("");
    aoMudar();
  };
  return (
    <div>
      <Title order={3} mb="xs">Evidências</Title>
      <Stack gap={6}>
        {!evidencias.length && <Text size="xs" c="dimmed">Nenhuma evidência guardada ainda.</Text>}
        {evidencias.map((e) => (
          <Group key={e.id} justify="space-between" wrap="nowrap" gap="xs" p="xs" style={{ border: "1px solid var(--roar-borda)", borderRadius: 6 }}>
            <Stack gap={2} style={{ minWidth: 0 }}>
              <Group gap={6}>
                <Badge size="sm" radius="sm" variant="light" color={e.tipo === "pacote" ? "pink" : "gray"} tt="none" fw={500}>{e.tipo === "pacote" ? "Pacote de prova" : "Arquivo"}</Badge>
                <Text size="sm" fw={500} style={{ overflowWrap: "anywhere" }}>{e.nome}</Text>
              </Group>
              {e.descricao && <Text size="xs">{e.descricao}</Text>}
              <Text size="xs" c="dimmed">{tamanho(e.tamanho)}, por {e.adicionado_por_nome} em {quando(e.adicionado_em, eu.fuso)}</Text>
              <Text size="xs" c="dimmed" className="mono" style={{ overflowWrap: "anywhere" }}>SHA-256 {e.sha256}</Text>
            </Stack>
            {pode("ver_bruto") && !eu.dados_mascarados && (
              <Button size="xs" variant="default" onClick={() => baixar(`/api/casos/${casoId}/evidencias/${e.id}`, e.nome).catch((x: Error) => setErro(x.message))}>Baixar</Button>
            )}
          </Group>
        ))}
        {triar && (
          <Stack gap={6} mt={4}>
            {pode("ver_bruto") && !eu.dados_mascarados && (
              <Group gap="xs">
                <Button size="xs" loading={gerando} onClick={gerar}>Gerar o pacote de prova dos eventos</Button>
                <Text size="xs" c="dimmed">Os alertas do caso com os selos e o programa que confere, como na tela Prova e evidência.</Text>
              </Group>
            )}
            <Group gap="xs" align="flex-end" wrap="wrap">
              <FileInput size="xs" label="Anexar um arquivo" placeholder="Print, PDF, e-mail exportado" w={240} value={arquivo} onChange={setArquivo} clearable />
              <TextInput size="xs" label="Descrição" style={{ flex: 1, minWidth: 160 }} value={descricao} onChange={(e) => setDescricao(e.currentTarget.value)} maxLength={1000} />
              <Button size="xs" disabled={!arquivo} onClick={anexar}>Anexar</Button>
            </Group>
          </Stack>
        )}
        {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
      </Stack>
    </div>
  );
}

interface CasoDoPlantao { id: number; titulo: string; severidade: string; responsavel_nome: string | null; atrasado?: boolean; hipoteses?: number; ultima_passagem?: string | null; desfecho?: string }
interface Plantao { horas: number; novos: CasoDoPlantao[]; encerrados: CasoDoPlantao[]; abertos: CasoDoPlantao[]; texto: string }

/** O resumo do plantão, para quem chega: o que abriu, o que fechou e o que está pendente, com o texto pronto para colar. */
export function ResumoDoPlantao() {
  const [aberto, setAberto] = useState(false);
  const [horas, setHoras] = useState("12");
  const { dados, erro } = useDados<Plantao>(aberto ? `/api/casos-plantao?horas=${horas}` : null);
  return (
    <>
      <Button size="xs" variant="default" onClick={() => setAberto(true)}>Passagem de plantão</Button>
      <Modal opened={aberto} onClose={() => setAberto(false)} title="Passagem de plantão" size="lg">
        <Stack gap="sm">
          <SegmentedControl size="xs" value={horas} onChange={setHoras} data={[{ value: "8", label: "8 horas" }, { value: "12", label: "12 horas" }, { value: "24", label: "24 horas" }]} />
          {!dados ? <Carregando erro={erro} /> : (
            <>
              <Group gap="lg">
                <Text size="sm"><b>{numero(dados.abertos.length)}</b> em andamento</Text>
                <Text size="sm"><b>{numero(dados.abertos.filter((c) => c.atrasado).length)}</b> atrasados</Text>
                <Text size="sm"><b>{numero(dados.novos.length)}</b> novos</Text>
                <Text size="sm"><b>{numero(dados.encerrados.length)}</b> encerrados</Text>
              </Group>
              {!dados.abertos.length ? <Vazio>Nenhum caso em andamento.</Vazio> : (
                <Stack gap={6}>
                  {dados.abertos.map((c) => (
                    <div key={c.id} style={{ borderLeft: "3px solid var(--roar-borda)", paddingLeft: 10 }}>
                      <Group gap={6}><Text size="sm" fw={500}>#{c.id} {c.titulo}</Text><Severidade valor={c.severidade} />{c.atrasado && <Badge size="xs" color="red" variant="light">Atrasado</Badge>}</Group>
                      <Text size="xs" c="dimmed">Com {c.responsavel_nome ?? "ninguém"}{c.hipoteses ? `, ${c.hipoteses} hipótese(s) aberta(s)` : ""}</Text>
                      {c.ultima_passagem && <Text size="xs" style={{ whiteSpace: "pre-wrap" }}>{c.ultima_passagem}</Text>}
                    </div>
                  ))}
                </Stack>
              )}
              <Group justify="flex-end">
                <CopyButton value={dados.texto}>{({ copied, copy }) => <Button size="xs" variant="filled" onClick={copy}>{copied ? "Copiado" : "Copiar o resumo"}</Button>}</CopyButton>
              </Group>
            </>
          )}
        </Stack>
      </Modal>
    </>
  );
}

export interface ChamadoDoCaso {
  estado: "pedido" | "aberto" | "resolvido" | "falhou";
  numero: string | null;
  endereco: string | null;
  situacao_externa: string | null;
  mensagem: string | null;
  pedido_por_nome: string;
  pedido_em: string;
  conferido_em: string | null;
  tipo: string;
  ferramenta: string;
}
export interface FerramentaDeChamado { id: number; tipo: string; nome: string }

const ESTADOS_DO_CHAMADO: Record<ChamadoDoCaso["estado"], { texto: string; cor: string }> = {
  pedido: { texto: "Abrindo", cor: "yellow" }, aberto: { texto: "Aberto", cor: "blue" }, resolvido: { texto: "Resolvido", cor: "teal" }, falhou: { texto: "Não abriu", cor: "red" },
};

/** O chamado do caso na ferramenta de ITSM (roar_ingestao.chamados): pedir, ver o número e acompanhar o andamento. */
export function ChamadoNoCaso({ casoId, chamado, ferramentas, aoMudar }: { casoId: number; chamado: ChamadoDoCaso | null; ferramentas: FerramentaDeChamado[]; aoMudar: () => void }) {
  const eu = useEu();
  const pode = usePode();
  const [escolhida, setEscolhida] = useState<string | null>(ferramentas.length === 1 ? String(ferramentas[0].id) : null);
  const [falha, setFalha] = useState<string | null>(null);
  // Enquanto o serviço cria o chamado, a tela confere a cada poucos segundos.
  useEffect(() => {
    if (chamado?.estado !== "pedido") return;
    const relogio = window.setInterval(aoMudar, 5000);
    return () => window.clearInterval(relogio);
  }, [chamado?.estado, aoMudar]);
  if (!chamado && !ferramentas.length) return null;
  const pedirChamado = async () => {
    setFalha(null);
    const r = await enviar(`/api/casos/${casoId}/chamado`, { fonte_id: escolhida ? Number(escolhida) : null });
    if (!r.ok) setFalha(await detalhe(r));
    aoMudar();
  };
  const triar = pode("triar");
  return (
    <Paper withBorder p="sm" radius="md">
      <Stack gap={6}>
        <Group justify="space-between" wrap="nowrap">
          <Text size="sm" fw={600}>Chamado</Text>
          {chamado && <Badge color={ESTADOS_DO_CHAMADO[chamado.estado].cor} variant="light" radius="sm">{ESTADOS_DO_CHAMADO[chamado.estado].texto}</Badge>}
        </Group>
        {chamado && chamado.numero && (
          <Text size="sm">
            {chamado.endereco ? <Anchor href={chamado.endereco} target="_blank" rel="noreferrer noopener">{chamado.numero}</Anchor> : chamado.numero} no {chamado.ferramenta}
            {chamado.situacao_externa ? `, ${chamado.situacao_externa.toLowerCase()}` : ""}.
          </Text>
        )}
        {chamado && chamado.estado === "pedido" && <Text size="xs" c="dimmed">O Roar está abrindo o chamado no {chamado.ferramenta}. Leva alguns segundos.</Text>}
        {chamado?.mensagem && <Text size="xs" c={chamado.estado === "falhou" ? "red" : "dimmed"}>{chamado.mensagem}</Text>}
        {chamado && (
          <Text size="xs" c="dimmed">
            Pedido por {chamado.pedido_por_nome} em {quando(chamado.pedido_em, eu.fuso)}.{chamado.conferido_em && chamado.estado === "aberto" ? ` Conferido no ${chamado.ferramenta} em ${quando(chamado.conferido_em, eu.fuso)}.` : ""}
          </Text>
        )}
        {triar && (!chamado || chamado.estado === "falhou") && ferramentas.length > 0 && (
          <Group gap="xs" align="flex-end">
            {ferramentas.length > 1 && (
              <Select size="xs" w={240} label="Ferramenta" placeholder="Escolha" value={escolhida} onChange={setEscolhida} data={ferramentas.map((f) => ({ value: String(f.id), label: f.nome }))} />
            )}
            <Button size="xs" variant="default" disabled={!escolhida} onClick={pedirChamado}>{chamado ? "Tentar de novo" : "Abrir chamado"}</Button>
          </Group>
        )}
        {!chamado && <Text size="xs" c="dimmed">O chamado leva o título, a severidade, o prazo e o número do caso. Os alertas não vão junto.</Text>}
        {falha && <Text size="xs" c="red">{falha}</Text>}
      </Stack>
    </Paper>
  );
}
