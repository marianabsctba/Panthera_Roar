import { ActionIcon, Alert, Anchor, Badge, Box, Button, Drawer, FileInput, Group, Modal, Popover, SimpleGrid, Stack, Switch, Tabs, Text, Title } from "@mantine/core";
import { IconDownload, IconHelp, IconLibrary, IconPlus, IconUpload } from "@tabler/icons-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";

import { detalhe, enviar, ler, pedir, useDados, usePode } from "../api";
import { AcoesDaLinha, Busca, Cabecalho, Carregando, Data, Estado, GavetaDeEventos, GavetaDoBruto, Numero, Painel, Severidade, Tabela, type FiltroDeEventos } from "../componentes";
import { numero, SINAIS } from "../formato";
import { EditorDeRegra, type AberturaDoEditor, type RegraPropria } from "./RegrasEditor";

async function baixar(rota: string, nome: string) {
  const r = await fetch(rota, { credentials: "same-origin" });
  if (!r.ok) return;
  const endereco = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = endereco;
  a.download = nome;
  a.click();
  URL.revokeObjectURL(endereco);
}

function severidadeDoNivel(nivel: number) {
  if (nivel >= 15) return "critica";
  if (nivel >= 12) return "alta";
  if (nivel >= 7) return "media";
  return "baixa";
}

function Etiquetas({ valores, limite = 4 }: { valores: string[] | null; limite?: number }) {
  const lista = valores ?? [];
  if (!lista.length) return <>-</>;
  return (
    <Group gap={4}>
      {lista.slice(0, limite).map((v) => <Badge key={v} variant="default" size="sm" radius="sm" tt="none" fw={400}>{v}</Badge>)}
      {lista.length > limite && <Badge variant="default" size="sm" radius="sm" tt="none" fw={400}>+{lista.length - limite}</Badge>}
    </Group>
  );
}

function Explica({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return (
    <Popover width={320} position="bottom-end" withArrow shadow="md">
      <Popover.Target><ActionIcon variant="subtle" color="gray" size="sm" aria-label={rotulo}><IconHelp size={16} /></ActionIcon></Popover.Target>
      <Popover.Dropdown><Text size="sm">{children}</Text></Popover.Dropdown>
    </Popover>
  );
}

function Fato({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return (
    <div>
      <Text size="xs" c="dimmed">{rotulo}</Text>
      <Text size="sm" component="div">{children}</Text>
    </div>
  );
}

function Codigo({ texto }: { texto: string }) {
  return <Box component="pre" className="mono" m={0} p="sm" style={{ background: "var(--mantine-color-dark-8)", border: "1px solid var(--roar-borda)", borderRadius: 6, whiteSpace: "pre-wrap" }}>{texto}</Box>;
}

// ------------------------------------------------------------------ técnica MITRE

const TATICAS_DE_DEFESA: Record<string, string> = { Model: "Conhecer", Harden: "Fortalecer", Detect: "Detectar", Isolate: "Isolar", Deceive: "Enganar", Evict: "Expulsar", Restore: "Restaurar" };

interface DadosDaTecnica {
  tecnica: { tecnica: string; nome: string };
  match: { regra_id: string; descricao: string | null; nivel: number; disparos: number; ultimo: string | null }[];
  cobertura: { regra_id: string; descricao: string | null; nivel: number }[];
  subtecnicas: { tecnica: string; nome: string }[];
  defesas: { defesa_id: string; defesa_nome: string; tatica_defesa: string | null }[];
}

function GavetaDaTecnica({ tecnica, aoFechar, aoAbrirTecnica, aoAbrirRegra, aoVerEventos }: { tecnica: string | null; aoFechar: () => void; aoAbrirTecnica: (t: string) => void; aoAbrirRegra: (r: string) => void; aoVerEventos: (r: string) => void }) {
  const { dados, erro } = useDados<DadosDaTecnica>(tecnica ? `/api/mitre/tecnicas/${encodeURIComponent(tecnica)}` : null);
  const d = dados?.tecnica.tecnica === tecnica ? dados : null;
  const porTatica = new Map<string, string[]>();
  d?.defesas.forEach((x) => {
    const chave = x.tatica_defesa ?? "Outras";
    porTatica.set(chave, [...(porTatica.get(chave) ?? []), x.defesa_nome]);
  });
  return (
    <Drawer opened={tecnica !== null} onClose={aoFechar} title={d ? `${d.tecnica.tecnica} ${d.tecnica.nome}` : tecnica ?? ""} size="70%" zIndex={300}>
      {!d ? <Carregando erro={erro} /> : (
        <Stack gap="lg">
          <div>
            <Title order={3} mb={4}>Regras que deram match em 30 dias ({d.match.length})</Title>
            <Tabela
              linhas={d.match}
              chave={(m) => m.regra_id}
              vazio="Nenhuma regra disparou para esta técnica no período."
              aoClicarLinha={(m) => aoAbrirRegra(m.regra_id)}
              colunas={[
                { titulo: "Regra", largura: 80, celula: (m) => <span className="mono">{m.regra_id}</span> },
                { titulo: "Severidade", largura: 90, celula: (m) => <Severidade valor={severidadeDoNivel(m.nivel)} /> },
                { titulo: "O que detecta", celula: (m) => m.descricao ?? "-" },
                { titulo: "Disparos", alinhar: "right", largura: 80, celula: (m) => numero(m.disparos) },
                { titulo: "Último", largura: 150, celula: (m) => <Data valor={m.ultimo} /> },
                { titulo: "", largura: 40, celula: (m) => <AcoesDaLinha rotulo="Ações da regra" itens={[{ texto: "Ver eventos", aoClicar: () => aoVerEventos(m.regra_id) }, { texto: "Abrir a regra", aoClicar: () => aoAbrirRegra(m.regra_id) }]} /> },
              ]}
            />
          </div>
          <div>
            <Title order={3} mb={4}>Como se defender, pelo D3FEND ({d.defesas.length})</Title>
            {porTatica.size ? (
              <Stack gap="xs">
                {[...porTatica].map(([t, nomes]) => <Fato key={t} rotulo={TATICAS_DE_DEFESA[t] ?? t}><Etiquetas valores={nomes} limite={60} /></Fato>)}
              </Stack>
            ) : <Text size="sm" c="dimmed">Sem defesas catalogadas para esta técnica.</Text>}
          </div>
          <div>
            <Title order={3} mb={4}>Regras que cobrem e ainda não dispararam ({d.cobertura.length})</Title>
            <Tabela
              linhas={d.cobertura}
              chave={(c) => c.regra_id}
              vazio={d.match.length ? "Todas as regras desta técnica já dispararam." : "Nenhuma regra cobre esta técnica. Aqui existe um ponto cego."}
              aoClicarLinha={(c) => aoAbrirRegra(c.regra_id)}
              colunas={[
                { titulo: "Regra", largura: 80, celula: (c) => <span className="mono">{c.regra_id}</span> },
                { titulo: "Severidade", largura: 90, celula: (c) => <Severidade valor={severidadeDoNivel(c.nivel)} /> },
                { titulo: "O que detecta", celula: (c) => c.descricao ?? "-" },
              ]}
            />
          </div>
          {d.subtecnicas.length > 0 && (
            <div>
              <Title order={3} mb={4}>Subtécnicas ({d.subtecnicas.length})</Title>
              <Group gap="sm">{d.subtecnicas.map((s) => <Anchor key={s.tecnica} component="button" type="button" size="sm" onClick={() => aoAbrirTecnica(s.tecnica)}>{s.tecnica} {s.nome}</Anchor>)}</Group>
            </div>
          )}
        </Stack>
      )}
    </Drawer>
  );
}

// ------------------------------------------------------------------ detalhe da regra

// O que o gerenciador informa sobre as condições de uma regra.
const ROTULOS_CONDICAO: Record<string, string> = {
  if_sid: "Depois da regra", if_group: "Depois do grupo", if_matched_sid: "Se repetir a regra", if_matched_group: "Se repetir o grupo", frequency: "Quantas vezes", timeframe: "Em quantos segundos",
  ignore: "Silêncio depois de disparar (s)", match: "Texto no log", regex: "Padrão no log", decoded_as: "Tipo de log", category: "Categoria", same_source_ip: "Mesma origem", options: "Opções",
  noalert: "Não gera alerta", program_name: "Programa", srcip: "Origem", user: "Usuário", id: "Identificador",
};
const NOMES_DE_NORMAS: Record<string, string> = { pci_dss: "PCI DSS", gdpr: "GDPR", hipaa: "HIPAA", nist_800_53: "NIST 800-53", tsc: "TSC", gpg13: "GPG13" };

function textoDaCondicao(valor: unknown) {
  if (valor === "") return "sim";
  if (valor && typeof valor === "object") return (valor as { pattern?: string }).pattern ?? JSON.stringify(valor);
  return String(valor);
}

interface AjusteDaRegra { id: number; origem: string; estado: string; mensagem: string | null; desligada: boolean; aplicada_em: string | null }
interface DadosDaRegra {
  regra: { regra_id: string; nivel: number; descricao: string | null; grupos: string[] | null; mitre: string[] | null; arquivo: string | null; ativa: boolean; normas: Record<string, string[]> | null; detalhes: Record<string, unknown> | null };
  tecnicas: { tecnica: string; nome: string }[];
  disparos: { total: number; ultimo: string | null; ativos: number };
  recentes: { id: number; ocorrido_em: string; severidade: string; ativo: string | null; ip_origem: string | null; usuario: string | null }[];
  xml: string | null;
  ajuste: AjusteDaRegra | null;
}

function textoDoAjuste(ativa: boolean, ajuste: AjusteDaRegra | null) {
  if (!ajuste) return ativa ? "Ativa" : "Desligada";
  if (ajuste.estado === "pendente") return ajuste.desligada ? "Desativando..." : "Aplicando sua versão...";
  if (ajuste.estado === "recusada") return "Última versão recusada";
  return ajuste.desligada ? "Desativada por você" : "Editada por você";
}

function GavetaDaRegra({ regraId, aoFechar, aoEditar, aoUsarComoBase, aoMudar }: { regraId: string | null; aoFechar: () => void; aoEditar: (regraId: string, xml: string) => void; aoUsarComoBase: (xml: string) => void; aoMudar: () => void }) {
  const pode = usePode();
  const [tecnica, setTecnica] = useState<string | null>(null);
  const [eventos, setEventos] = useState<FiltroDeEventos | null>(null);
  const [bruto, setBruto] = useState<number | null>(null);
  const [erroDeAcao, setErroDeAcao] = useState<string | null>(null);
  const [aberta, setAberta] = useState<string | null>(regraId);
  // Dentro da gaveta dá para saltar para outra regra, pelas técnicas: a regra da lista é só o ponto de partida.
  useEffect(() => { setAberta(regraId); setTecnica(null); setErroDeAcao(null); }, [regraId]);
  const { dados, erro, recarregar } = useDados<DadosDaRegra>(aberta ? `/api/regras/${encodeURIComponent(aberta)}` : null);
  const d = dados?.regra.regra_id === aberta ? dados : null;

  const ajustar = async (acao: "desligar" | "restaurar") => {
    if (!aberta) return;
    const r = await enviar(`/api/regras/${encodeURIComponent(aberta)}/${acao}`);
    if (!r.ok) {
      setErroDeAcao(await detalhe(r));
      return;
    }
    setErroDeAcao(null);
    recarregar();
    aoMudar();
  };
  const verEventos = (id: string) => setEventos({ rotulo: `Eventos da regra ${id}`, consulta: { regra: id, dias: "30" } });
  const gerir = pode("gerir_regras");
  const editada = d?.ajuste && !d.ajuste.desligada ? d.ajuste : null;
  const normas = Object.entries(d?.regra.normas ?? {});
  const condicoes = Object.entries(d?.regra.detalhes ?? {});

  return (
    <>
      <Drawer opened={regraId !== null} onClose={aoFechar} title={d ? `Regra ${d.regra.regra_id}` : "Regra"} size="70%">
        {!d ? <Carregando erro={erro} /> : (
          <Stack gap="md">
            <Group justify="space-between" gap="sm" wrap="wrap">
              <Group gap="sm"><Title order={2}>{d.regra.descricao ?? "Sem descrição"}</Title><Severidade valor={severidadeDoNivel(d.regra.nivel)} /></Group>
              {d.xml && (
                <Group gap="xs">
                  <Explica rotulo="O que acontece ao editar">O arquivo original nunca é alterado. Sua versão vale no lugar dele, e restaurar volta ao original. Desativada, a regra para de alertar, mas as que dependem dela continuam funcionando.</Explica>
                  {d.regra.arquivo && <Button leftSection={<IconDownload size={14} />} onClick={() => baixar(`/api/regras/arquivos/${encodeURIComponent(d.regra.arquivo ?? "")}`, d.regra.arquivo ?? "")}>Baixar arquivo</Button>}
                  {gerir && <Button onClick={() => aoUsarComoBase(d.xml ?? "")}>Usar como base</Button>}
                  {gerir && d.ajuste && <Button onClick={() => ajustar("restaurar")}>Restaurar a original</Button>}
                  {gerir && !d.ajuste?.desligada && <Button onClick={() => ajustar("desligar")}>Desativar</Button>}
                  {gerir && <Button variant="filled" onClick={() => aoEditar(d.regra.regra_id, editada ? editada.origem : d.xml ?? "")}>Editar</Button>}
                </Group>
              )}
            </Group>
            {erroDeAcao && <Alert color="red" variant="light" p="xs">{erroDeAcao}</Alert>}
            {d.ajuste?.estado === "recusada" && <Alert color="red" variant="light" p="xs">{`A última versão foi recusada: ${d.ajuste.mensagem ?? "sem detalhes"}`}</Alert>}

            <SimpleGrid cols={{ base: 2, md: 3 }} spacing="sm">
              <Numero rotulo="Disparos em 30 dias" valor={numero(d.disparos.total)} aoClicar={() => verEventos(d.regra.regra_id)} />
              <Numero rotulo="Ativos" valor={numero(d.disparos.ativos)} aoClicar={() => verEventos(d.regra.regra_id)} />
              <Numero rotulo="Estado" valor={<Text span size="sm">{textoDoAjuste(d.regra.ativa, d.ajuste)}</Text>} />
            </SimpleGrid>
            <Group gap="xl">
              <Fato rotulo="Último disparo"><Data valor={d.disparos.ultimo} /></Fato>
              <Fato rotulo="Arquivo"><span className="mono">{d.regra.arquivo ?? "-"}</span></Fato>
            </Group>

            <div>
              <Title order={3} mb={4}>Quando dispara</Title>
              {condicoes.length ? (
                <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xs">
                  {condicoes.map(([k, v]) => <Fato key={k} rotulo={ROTULOS_CONDICAO[k] ?? k}><span className="mono">{textoDaCondicao(v)}</span></Fato>)}
                </SimpleGrid>
              ) : <Text size="sm" c="dimmed">As condições desta regra não estão disponíveis.</Text>}
            </div>

            {d.tecnicas.length > 0 && (
              <div>
                <Title order={3} mb={4}>Técnicas MITRE</Title>
                <Group gap="sm">{d.tecnicas.map((t) => <Anchor key={t.tecnica} component="button" type="button" size="sm" onClick={() => setTecnica(t.tecnica)}>{t.tecnica} {t.nome}</Anchor>)}</Group>
              </div>
            )}
            {normas.length > 0 && (
              <div>
                <Title order={3} mb={4}>Normas</Title>
                <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xs">{normas.map(([k, v]) => <Fato key={k} rotulo={NOMES_DE_NORMAS[k] ?? k}>{v.join(", ")}</Fato>)}</SimpleGrid>
              </div>
            )}
            {(d.regra.grupos ?? []).length > 0 && <div><Title order={3} mb={4}>Grupos</Title><Etiquetas valores={d.regra.grupos} limite={30} /></div>}

            {editada && <div><Title order={3} mb={4}>Sua versão, em uso</Title><Codigo texto={editada.origem} /></div>}
            <div>
              <Title order={3} mb={4}>Regra original</Title>
              {d.xml ? <Codigo texto={d.xml} /> : (
                <Text size="sm" c="dimmed">{d.regra.arquivo ? "O texto desta regra aparece aqui depois da próxima sincronização, e então dá para editar uma cópia." : "Esta regra não veio de um arquivo do catálogo, então não há texto para abrir."}</Text>
              )}
            </div>

            <div>
              <Title order={3} mb={4}>Disparos recentes</Title>
              <Tabela
                linhas={d.recentes}
                chave={(e) => e.id}
                vazio="Esta regra ainda não disparou."
                aoClicarLinha={pode("ver_bruto") ? (e) => setBruto(e.id) : undefined}
                colunas={[
                  { titulo: "Quando", largura: 150, celula: (e) => <Data valor={e.ocorrido_em} /> },
                  { titulo: "Ativo", celula: (e) => e.ativo ?? "-" },
                  { titulo: "Usuário", celula: (e) => <span className="mono">{e.usuario ?? "-"}</span> },
                  { titulo: "Origem", celula: (e) => <span className="mono">{e.ip_origem ?? "-"}</span> },
                  { titulo: "", largura: 40, celula: (e) => <AcoesDaLinha rotulo="Ações do evento" itens={pode("ver_bruto") ? [{ texto: "Ver como chegou", aoClicar: () => setBruto(e.id) }] : []} /> },
                ]}
              />
            </div>
          </Stack>
        )}
      </Drawer>
      <GavetaDaTecnica
        tecnica={tecnica}
        aoFechar={() => setTecnica(null)}
        aoAbrirTecnica={setTecnica}
        aoAbrirRegra={(r) => { setTecnica(null); setAberta(r); }}
        aoVerEventos={(r) => { setTecnica(null); verEventos(r); }}
      />
      <GavetaDeEventos filtro={eventos} aoFechar={() => setEventos(null)} />
      <GavetaDoBruto evento={bruto} aoFechar={() => setBruto(null)} />
    </>
  );
}

// ------------------------------------------------------------------ catálogo

interface RegraDoCatalogo { regra_id: string; nivel: number; descricao: string | null; grupos: string[] | null; mitre: string[] | null; arquivo: string | null; ativa: boolean; ajuste: string | null; disparos: number; ultimo: string | null }
interface RespostaDoCatalogo { regras: RegraDoCatalogo[]; total_filtrado: number; catalogo: number; atualizado_em: string | null; comportamento: { tipo: string; peso: number }[] }

function Catalogo({ versao, aoAbrir }: { versao: number; aoAbrir: (id: string) => void }) {
  const [busca, setBusca] = useState("");
  const [soDisparadas, setSoDisparadas] = useState(false);
  const [regras, setRegras] = useState<RegraDoCatalogo[] | null>(null);
  const [resumo, setResumo] = useState<RespostaDoCatalogo | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const consulta = new URLSearchParams({ busca, so_disparadas: String(soDisparadas) }).toString();
  useEffect(() => {
    let valendo = true;
    ler<RespostaDoCatalogo>(`/api/regras?${consulta}`)
      .then((d) => { if (valendo) { setRegras(d.regras); setResumo(d); setErro(null); } })
      .catch((e: Error) => { if (valendo) setErro(e.message); });
    return () => { valendo = false; };
  }, [consulta, versao]);
  const mais = async () => {
    const d = await ler<RespostaDoCatalogo>(`/api/regras?${consulta}&deslocamento=${regras?.length ?? 0}`);
    setRegras((r) => [...(r ?? []), ...d.regras]);
    setResumo(d);
  };
  return (
    <Painel
      acao={(
        <Group justify="space-between" w="100%" gap="sm" wrap="wrap">
          <Group gap="md">
            <Busca valor={busca} aoMudar={setBusca} dica="Número, descrição, grupo ou técnica" />
            <Switch label="Só as que dispararam em 30 dias" checked={soDisparadas} onChange={(e) => setSoDisparadas(e.currentTarget.checked)} />
          </Group>
          {resumo && <Text size="xs" c="dimmed">{resumo.catalogo ? `${numero(resumo.catalogo)} regras no catálogo` : "O catálogo de regras ainda não foi carregado."}{resumo.atualizado_em && <>, atualizado em <Data valor={resumo.atualizado_em} /></>}</Text>}
        </Group>
      )}
    >
      {!regras ? <Carregando erro={erro} /> : (
        <Stack gap="sm">
          <Tabela
            linhas={regras}
            chave={(x) => x.regra_id}
            vazio={resumo?.catalogo ? "Nenhuma regra encontrada." : "Nada para mostrar ainda."}
            aoClicarLinha={(x) => aoAbrir(x.regra_id)}
            colunas={[
              { titulo: "Regra", largura: 80, celula: (x) => <span className="mono">{x.regra_id}</span> },
              { titulo: "Severidade", largura: 90, celula: (x) => <Severidade valor={severidadeDoNivel(x.nivel)} /> },
              { titulo: "O que detecta", celula: (x) => <>{x.descricao ?? "-"}{x.ajuste && <> <Estado tipo="outro">{x.ajuste === "desligada" ? "Desativada" : "Editada"}</Estado></>}</> },
              { titulo: "Grupos", celula: (x) => <Etiquetas valores={x.grupos} limite={3} /> },
              { titulo: "MITRE", celula: (x) => <Etiquetas valores={x.mitre} limite={3} /> },
              { titulo: "Disparos", alinhar: "right", largura: 80, celula: (x) => numero(x.disparos) },
            ]}
          />
          {resumo && regras.length < resumo.total_filtrado && <Group justify="center"><Button onClick={mais}>Carregar mais</Button></Group>}
        </Stack>
      )}
    </Painel>
  );
}

// ------------------------------------------------------------------ regras criadas aqui

const ROTULOS_DE_FORMATO: Record<string, string> = { sigma: "Sigma", guiada: "Guiada", xml: "XML", biblioteca: "Biblioteca" };
const ESTADOS_DA_REGRA: Record<string, string> = { pendente: "Aguardando aplicação", ativa: "Ativa", recusada: "Recusada", desativada: "Desativada" };

function RegrasProprias({ versao, aoEditar }: { versao: number; aoEditar: (r: RegraPropria) => void }) {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<{ regras: RegraPropria[] }>(`/api/regras/proprias?v=${versao}`);
  const [aberta, setAberta] = useState<RegraPropria | null>(null);
  const [erroDeAcao, setErroDeAcao] = useState<string | null>(null);
  const gerir = pode("gerir_regras");
  const desativavel = (r: RegraPropria) => r.estado === "ativa" || r.estado === "pendente";
  const desativar = async (r: RegraPropria) => {
    const resposta = await enviar(`/api/regras/proprias/${r.id}/desativar`);
    if (!resposta.ok) setErroDeAcao(await detalhe(resposta));
    else setErroDeAcao(null);
    setAberta(null);
    recarregar();
  };
  if (!dados) return <Carregando erro={erro} />;
  return (
    <Stack gap="sm">
      {erroDeAcao && <Alert color="red" variant="light" p="xs">{erroDeAcao}</Alert>}
      <Painel p={0}>
        <Tabela
          linhas={dados.regras}
          chave={(r) => r.id}
          vazio="Nenhuma regra criada ainda."
          aoClicarLinha={setAberta}
          colunas={[
            { titulo: "Regra", celula: (r) => <Text size="sm" fw={500}>{r.titulo}</Text> },
            { titulo: "Estado", celula: (r) => <Estado tipo={r.estado}>{ESTADOS_DA_REGRA[r.estado] ?? r.estado}</Estado> },
            { titulo: "Formato", celula: (r) => ROTULOS_DE_FORMATO[r.formato] ?? r.formato },
            { titulo: "Criada em", largura: 150, celula: (r) => <Data valor={r.criada_em} /> },
            { titulo: "Observação", celula: (r) => <Text size="xs" c="dimmed" lineClamp={2}>{r.mensagem ?? "-"}</Text> },
            { titulo: "", largura: 40, celula: (r) => (
              <AcoesDaLinha rotulo={`Ações de ${r.titulo}`} itens={gerir ? [
                { texto: "Abrir e editar", aoClicar: () => aoEditar(r) },
                ...(desativavel(r) ? [{ texto: "Desativar", perigo: true, aoClicar: () => desativar(r) }] : []),
              ] : []} />
            ) },
          ]}
        />
      </Painel>
      <Drawer opened={aberta !== null} onClose={() => setAberta(null)} title={aberta?.titulo ?? ""}>
        {aberta && (
          <Stack gap="md">
            {gerir && (
              <Group justify="flex-end" gap="xs">
                {desativavel(aberta) && <Button onClick={() => desativar(aberta)}>Desativar</Button>}
                <Button variant="filled" onClick={() => { setAberta(null); aoEditar(aberta); }}>Editar</Button>
              </Group>
            )}
            <SimpleGrid cols={{ base: 2, sm: 3 }} spacing="sm">
              <Fato rotulo="Estado"><Estado tipo={aberta.estado}>{ESTADOS_DA_REGRA[aberta.estado] ?? aberta.estado}</Estado></Fato>
              <Fato rotulo="Formato">{ROTULOS_DE_FORMATO[aberta.formato] ?? aberta.formato}</Fato>
              <Fato rotulo="Criada em"><Data valor={aberta.criada_em} /></Fato>
              <Fato rotulo="Aplicada em"><Data valor={aberta.aplicada_em} /></Fato>
            </SimpleGrid>
            {aberta.mensagem && <Alert color={aberta.estado === "recusada" ? "red" : "gray"} variant="light" p="xs">{aberta.mensagem}</Alert>}
            <div><Title order={3} mb={4}>Como foi escrita</Title><Codigo texto={aberta.origem} /></div>
          </Stack>
        )}
      </Drawer>
    </Stack>
  );
}

// ------------------------------------------------------------------ comportamento

const DESCRICAO_COMPORTAMENTO: Record<string, string> = {
  sucesso_apos_falhas: "Acesso depois de 5 falhas ou mais do mesmo endereço, no mesmo ativo, em 10 minutos.",
  viagem_impossivel: "Mais de 500 km a mais de 1.000 km/h entre dois acessos.",
  primeiro_privilegio: "Primeira vez que a pessoa executa como outro usuário naquele ativo.",
  pico_de_falhas: "Falhas de acesso em uma hora muito acima do histórico.",
  primeiro_host: "Ativo que a pessoa nunca tinha usado.",
  horario_incomum: "Acesso em hora muito rara para a pessoa, no fuso da organização.",
  primeiro_ip: "Endereço que a pessoa nunca tinha usado.",
  host_raro_no_cliente: "Ativo usado por menos de 5% da organização.",
  ioc_tocado: "Evento com um IP que está nas fontes de inteligência da organização.",
  grupo_administrativo: "Alguém entrou num grupo que manda na máquina ou no domínio, como Administrators, Domain Admins, sudo ou wheel.",
  arquivo_sensivel: "Mudança em arquivo que guarda contas, privilégios ou inicialização, como /etc/shadow, sudoers, authorized_keys e cron.",
  conta_criada: "Conta criada por quem não costuma criar contas naquele ativo. Sem saber quem criou, soma para o ativo.",
  pessoa_em_risco: "Pessoa com risco acima do limite de alerta entrou no ativo. Soma para o ativo.",
  ativo_em_risco: "Entrada num ativo com risco acima do limite de alerta. Soma para a pessoa. Risco repassado não se repassa de novo.",
};

interface SilencioDoUeba { id: number; tipo: string; motivo: string; criado_por_nome: string | null; criado_em: string; expira_em: string | null; entidade: string | null }

function SilenciosDoUeba() {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<{ silencios: SilencioDoUeba[] }>("/api/silencios");
  if (!dados) return <Carregando erro={erro} />;
  const remover = async (s: SilencioDoUeba) => {
    if ((await pedir(`/api/silencios/${s.id}`, { method: "DELETE" })).ok) recarregar();
  };
  return (
    <Painel titulo="Sinais silenciados" acao={<Explica rotulo="Como silenciar">Abra o risco da pessoa na Fila e use "Silenciar um sinal". O sinal deixa de somar para ela até o prazo acabar.</Explica>}>
      <Tabela
        linhas={dados.silencios}
        chave={(s) => s.id}
        vazio="Nenhum sinal silenciado: todos somam para todos."
        colunas={[
          { titulo: "Sinal", celula: (s) => <Text size="sm" fw={500}>{SINAIS[s.tipo] ?? s.tipo}</Text> },
          { titulo: "Para quem", celula: (s) => s.entidade ?? "Todos" },
          { titulo: "Por quê", celula: (s) => <Text size="sm" c="dimmed">{s.motivo}</Text> },
          { titulo: "Quem", celula: (s) => s.criado_por_nome ?? "-" },
          { titulo: "Até", largura: 150, celula: (s) => (s.expira_em ? <Data valor={s.expira_em} /> : "Sem prazo") },
          { titulo: "", largura: 40, celula: (s) => <AcoesDaLinha rotulo="Ações do silêncio" itens={pode("gerir_regras") ? [{ texto: "Tirar o silêncio", perigo: true, aoClicar: () => remover(s) }] : []} /> },
        ]}
      />
    </Painel>
  );
}

function Comportamento() {
  const { dados, erro } = useDados<RespostaDoCatalogo>("/api/regras?so_disparadas=true");
  const [filtro, setFiltro] = useState<FiltroDeEventos | null>(null);
  if (!dados) return <Carregando erro={erro} />;
  return (
    <Stack gap="md">
      <Painel titulo="Regras de comportamento" acao={<Explica rotulo="Como os pontos funcionam">Somam pontos no risco de cada pessoa. O alerta abre em 60 pontos, e os pontos caem pela metade a cada 24 horas.</Explica>}>
        <Tabela
          linhas={dados.comportamento}
          chave={(r) => r.tipo}
          vazio="Nenhuma regra de comportamento."
          aoClicarLinha={(r) => setFiltro({ rotulo: `Eventos com o sinal: ${SINAIS[r.tipo] ?? r.tipo}`, consulta: { sinal: r.tipo, dias: "30" } })}
          colunas={[
            { titulo: "Sinal", celula: (r) => <Text size="sm" fw={500}>{SINAIS[r.tipo] ?? r.tipo}</Text> },
            { titulo: "Quando soma", celula: (r) => <Text size="sm" c="dimmed">{DESCRICAO_COMPORTAMENTO[r.tipo] ?? "-"}</Text> },
            { titulo: "Pontos", alinhar: "right", largura: 70, celula: (r) => `+${Math.round(r.peso)}` },
          ]}
        />
        <GavetaDeEventos filtro={filtro} aoFechar={() => setFiltro(null)} />
      </Painel>
      <SilenciosDoUeba />
    </Stack>
  );
}

// ------------------------------------------------------------------ importar

function Importar({ aberto, aoFechar, aoImportar }: { aberto: boolean; aoFechar: () => void; aoImportar: () => void }) {
  const [arquivo, setArquivo] = useState<File | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [relatorio, setRelatorio] = useState<{ criadas: string[]; recusadas: { titulo: string; motivo: string }[] } | null>(null);
  const fechar = () => {
    setArquivo(null);
    setErro(null);
    setRelatorio(null);
    aoFechar();
  };
  const importar = async () => {
    if (!arquivo) return;
    setErro(null);
    const r = await enviar("/api/regras/importar", { formato: arquivo.name.toLowerCase().endsWith(".xml") ? "xml" : "sigma", conteudo: await arquivo.text() });
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível importar este arquivo."));
      return;
    }
    setRelatorio(await r.json());
    aoImportar();
  };
  return (
    <Modal opened={aberto} onClose={fechar} title="Importar regras" size="lg">
      <Stack gap="sm">
        <FileInput label="Arquivo" description="Sigma (.yml), que pode ter várias regras separadas por ---, ou XML de regras." placeholder="Escolher arquivo" accept=".yml,.yaml,.xml" value={arquivo} onChange={setArquivo} error={erro} clearable />
        <Group justify="flex-end">
          <Button variant="subtle" color="gray" onClick={fechar}>Cancelar</Button>
          <Button variant="filled" disabled={!arquivo} onClick={importar}>Importar</Button>
        </Group>
        {relatorio && (
          <Stack gap="xs">
            <Title order={3}>{relatorio.criadas.length} importadas, {relatorio.recusadas.length} recusadas</Title>
            {relatorio.recusadas.length > 0 && (
              <Tabela linhas={relatorio.recusadas} chave={(x) => `${x.titulo}-${x.motivo}`} vazio="" colunas={[{ titulo: "Regra", celula: (x) => x.titulo }, { titulo: "Por que não entrou", celula: (x) => x.motivo }]} />
            )}
          </Stack>
        )}
      </Stack>
    </Modal>
  );
}

// ------------------------------------------------------------------ biblioteca

interface RegraDaBiblioteca { id: string; titulo: string; descricao: string | null; autor: string | null; nivel: string | null; origem: string | null; tecnicas: string[] | null; endereco: string | null; convertivel: boolean; motivo: string | null }
interface RespostaDaBiblioteca { regras: RegraDaBiblioteca[]; total_filtrado: number; total: number; convertiveis: number }
const RESPOSTA_DE_ATIVAR: Record<number, string> = { 201: "Ativada", 409: "Já ativa" };

function Biblioteca({ aberta, aoFechar, aoAtivar }: { aberta: boolean; aoFechar: () => void; aoAtivar: () => void }) {
  const pode = usePode();
  const [busca, setBusca] = useState("");
  const [soUsaveis, setSoUsaveis] = useState(true);
  const [regras, setRegras] = useState<RegraDaBiblioteca[] | null>(null);
  const [resumo, setResumo] = useState<RespostaDaBiblioteca | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [aberto, setAberto] = useState<RegraDaBiblioteca | null>(null);
  const [resultados, setResultados] = useState<Record<string, string>>({});
  const consulta = new URLSearchParams({ busca, so_convertiveis: String(soUsaveis) }).toString();
  useEffect(() => {
    if (!aberta) return;
    let valendo = true;
    ler<RespostaDaBiblioteca>(`/api/regras/biblioteca?${consulta}`)
      .then((d) => { if (valendo) { setRegras(d.regras); setResumo(d); setErro(null); } })
      .catch((e: Error) => { if (valendo) setErro(e.message); });
    return () => { valendo = false; };
  }, [aberta, consulta]);
  const mais = async () => {
    const d = await ler<RespostaDaBiblioteca>(`/api/regras/biblioteca?${consulta}&deslocamento=${regras?.length ?? 0}`);
    setRegras((r) => [...(r ?? []), ...d.regras]);
    setResumo(d);
  };
  const ativar = useCallback(async (r: RegraDaBiblioteca) => {
    const resposta = await enviar(`/api/regras/biblioteca/${encodeURIComponent(r.id)}/ativar`);
    setResultados((atual) => ({ ...atual, [r.id]: RESPOSTA_DE_ATIVAR[resposta.status] ?? "Não ativou" }));
    aoAtivar();
  }, [aoAtivar]);
  const podeAtivar = (r: RegraDaBiblioteca) => pode("gerir_regras") && r.convertivel && !resultados[r.id];
  // O endereço vem da biblioteca, de fora: só vira link se for mesmo um endereço web.
  const endereco = aberto?.endereco && /^https?:\/\//i.test(aberto.endereco) ? aberto.endereco : null;

  return (
    <>
      <Drawer opened={aberta} onClose={aoFechar} title="Biblioteca de regras" size="75%">
        <Stack gap="sm">
          <Group justify="space-between" gap="sm" wrap="wrap">
            <Group gap="md">
              <Busca valor={busca} aoMudar={setBusca} dica="Título, autor ou técnica MITRE" />
              <Switch label="Só as que podem ser usadas" checked={soUsaveis} onChange={(e) => setSoUsaveis(e.currentTarget.checked)} />
            </Group>
            {resumo && <Text size="xs" c="dimmed">{numero(resumo.total)} regras, {numero(resumo.convertiveis)} podem ser usadas aqui.</Text>}
          </Group>
          {!regras ? <Carregando erro={erro} /> : (
            <Tabela
              linhas={regras}
              chave={(x) => x.id}
              vazio="Nenhuma regra encontrada."
              aoClicarLinha={setAberto}
              colunas={[
                { titulo: "Regra", celula: (x) => <><Text size="sm" fw={500}>{x.titulo}</Text>{x.descricao && <Text size="xs" c="dimmed" lineClamp={1}>{x.descricao}</Text>}</> },
                { titulo: "Autoria", celula: (x) => x.autor ?? "-" },
                { titulo: "Onde olha", celula: (x) => x.origem ?? "-" },
                { titulo: "MITRE", celula: (x) => <Etiquetas valores={x.tecnicas} limite={3} /> },
                { titulo: "Situação", celula: (x) => (resultados[x.id] ? <Estado tipo="ativa">{resultados[x.id]}</Estado> : x.convertivel ? "-" : <Text size="xs" c="dimmed" lineClamp={2}>{x.motivo ?? "Não pode ser usada"}</Text>) },
                { titulo: "", largura: 40, celula: (x) => <AcoesDaLinha rotulo={`Ações de ${x.titulo}`} itens={podeAtivar(x) ? [{ texto: "Ativar", aoClicar: () => ativar(x) }] : []} /> },
              ]}
            />
          )}
          {regras && resumo && regras.length < resumo.total_filtrado && <Group justify="center"><Button onClick={mais}>Carregar mais</Button></Group>}
          <Text size="xs" c="dimmed">Regras da comunidade SigmaHQ, sob a Detection Rule License 1.1. A autoria aparece aqui e nos alertas.</Text>
        </Stack>
      </Drawer>
      <Drawer opened={aberto !== null} onClose={() => setAberto(null)} title={aberto?.titulo ?? ""} size="lg" zIndex={300}>
        {aberto && (
          <Stack gap="md">
            {podeAtivar(aberto) && <Group justify="flex-end"><Button variant="filled" onClick={() => ativar(aberto)}>Ativar</Button></Group>}
            {resultados[aberto.id] && <Estado tipo="ativa">{resultados[aberto.id]}</Estado>}
            {!aberto.convertivel && <Alert color="yellow" variant="light" p="xs">{aberto.motivo ?? "Não pode ser usada"}</Alert>}
            {aberto.descricao && <Text size="sm">{aberto.descricao}</Text>}
            <SimpleGrid cols={2} spacing="sm">
              <Fato rotulo="Autoria">{aberto.autor ?? "-"}</Fato>
              <Fato rotulo="Onde olha">{aberto.origem ?? "-"}</Fato>
            </SimpleGrid>
            <Fato rotulo="MITRE"><Etiquetas valores={aberto.tecnicas} limite={30} /></Fato>
            {endereco && <Anchor href={endereco} target="_blank" rel="noreferrer" size="sm">Ver a regra na origem</Anchor>}
          </Stack>
        )}
      </Drawer>
    </>
  );
}

// ------------------------------------------------------------------ tela

export function Regras() {
  const pode = usePode();
  const [aba, setAba] = useState("catalogo");
  const [versao, setVersao] = useState(0);
  const [regra, setRegra] = useState<string | null>(null);
  const [editor, setEditor] = useState<AberturaDoEditor | null>(null);
  const [importar, setImportar] = useState(false);
  const [biblioteca, setBiblioteca] = useState(false);
  const atualizar = useCallback(() => setVersao((v) => v + 1), []);
  return (
    <>
      <Cabecalho titulo="Regras" ajuda="O que gera alerta: o catálogo, as regras criadas pela sua equipe e os sinais de comportamento. O arquivo original do catálogo nunca é alterado.">
        <Button leftSection={<IconDownload size={14} />} onClick={() => baixar("/api/regras/exportar", "regras-roar.json")}>Exportar</Button>
        {pode("gerir_regras") && <Button leftSection={<IconUpload size={14} />} onClick={() => setImportar(true)}>Importar</Button>}
        <Button leftSection={<IconLibrary size={14} />} onClick={() => setBiblioteca(true)}>Biblioteca</Button>
        {pode("gerir_regras") && <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setEditor({ tipo: "nova" })}>Nova regra</Button>}
      </Cabecalho>
      <Tabs value={aba} onChange={(v) => setAba(v ?? "catalogo")}>
        <Tabs.List mb="md">
          <Tabs.Tab value="catalogo">Catálogo</Tabs.Tab>
          <Tabs.Tab value="proprias">Criadas aqui</Tabs.Tab>
          <Tabs.Tab value="comportamento">Comportamento</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="catalogo"><Catalogo versao={versao} aoAbrir={setRegra} /></Tabs.Panel>
        <Tabs.Panel value="proprias"><RegrasProprias versao={versao} aoEditar={(r) => setEditor({ tipo: "propria", regra: r })} /></Tabs.Panel>
        <Tabs.Panel value="comportamento"><Comportamento /></Tabs.Panel>
      </Tabs>

      <GavetaDaRegra
        regraId={regra}
        aoFechar={() => setRegra(null)}
        aoEditar={(regraId, xml) => { setRegra(null); setEditor({ tipo: "catalogo", regraId, xml }); }}
        aoUsarComoBase={(xml) => { setRegra(null); setEditor({ tipo: "base", xml }); }}
        aoMudar={atualizar}
      />
      <EditorDeRegra abertura={editor} aoFechar={() => setEditor(null)} aoSalvar={() => { if (editor?.tipo !== "catalogo") setAba("proprias"); atualizar(); }} />
      <Importar aberto={importar} aoFechar={() => setImportar(false)} aoImportar={atualizar} />
      <Biblioteca aberta={biblioteca} aoFechar={() => setBiblioteca(false)} aoAtivar={atualizar} />
    </>
  );
}
