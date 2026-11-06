import { AreaChart } from "@mantine/charts";
import { Alert, Anchor, Badge, Button, Checkbox, Drawer, Group, Modal, NumberInput, Progress, SimpleGrid, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconPlus, IconRadar } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { detalhe, enviar, useDados, usePode } from "../api";
import { AcoesDaLinha, Carregando, Data, Estado, Painel, Tabela } from "../componentes";
import { numero } from "../formato";
import { chamar, Fato, GavetaDaCve, GavetaDeAchados, porcentoDeEpss, Prioridade, type PedidoDeAchados } from "./VulnerabilidadesAchados";

interface Dominio {
  id: number; dominio: string; autorizado_por_nome: string; autorizado_em: string; ativo: boolean;
  descobrir_a_cada_horas: number; conferir_a_cada_horas: number; proxima_descoberta: string | null; ultima_descoberta: string | null; ultimo_erro: string | null;
  nomes: number; conferidos: number; na_fila: number; conferindo_agora: string | null; proxima_conferencia: string | null;
}
interface Pacote { nome?: string; versao: string; distribuicao: string; ecossistemas?: string[]; confirmado?: boolean; corrigidas?: number }
interface Servico {
  porta: number; nome: string; versao: string | null; resposta: string; distribuicao: boolean; falhas: number;
  tipo?: "servico" | "app" | "painel" | "borda"; pacote?: Pacote | null; exploradas_do_produto?: number;
}

/** O que aparece ao lado do serviço na tabela de nomes. */
function resumoDoServico(s: Servico) {
  const nome = s.versao ? `${s.nome} ${s.versao}` : s.nome;
  if (s.tipo === "borda") return `${nome}, ${s.exploradas_do_produto ? `${numero(s.exploradas_do_produto)} falhas já exploradas no produto` : "versão não aparece"}`;
  if (!s.versao) return `${nome}, versão não aparece`;
  if (s.pacote?.confirmado) return s.falhas ? `${nome}, ${numero(s.falhas)} CVE(s) no pacote instalado` : `${nome}, pacote em dia`;
  if (!s.falhas) return `${nome}, sem CVE conhecida`;
  return `${nome}, ${numero(s.falhas)} CVE(s)${s.distribuicao ? " a confirmar" : ""}`;
}

const SITUACAO: Record<string, { texto: string; cor?: string }> = {
  confirmada: { texto: "Pega o pacote instalado", cor: "red" },
  pela_versao: { texto: "Pega a versão", cor: "red" },
  explorada_no_produto: { texto: "Explorada no produto: confira a versão", cor: "orange" },
  a_confirmar: { texto: "A confirmar no servidor", cor: "yellow" },
  corrigida_na_distribuicao: { texto: "Corrigida pela distribuição", cor: "green" },
};
interface EmailDoDominio { spf: string | null; dmarc: string | null; dkim: string[]; problemas: number }

/** SPF, DKIM e DMARC do domínio, numa linha cada: verde quando barra e-mail falso, vermelho quando não. */
function EmailDoDominio({ email }: { email: EmailDoDominio | null | undefined }) {
  if (!email) return <Text size="sm" c="dimmed">Ainda não conferido. Sai junto com o nome do próprio domínio.</Text>;
  const barra = email.dmarc === "reject" || email.dmarc === "quarantine";
  return (
    <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
      <Fato rotulo="SPF (quem pode mandar)">{email.spf ? <Text span size="sm" className="mono" lineClamp={2} title={email.spf}>{email.spf}</Text> : <Text span c="red">Não tem</Text>}</Fato>
      <Fato rotulo="DMARC (o que barra e-mail falso)">
        <Text span c={barra ? "green" : "red"}>{email.dmarc ? `p=${email.dmarc}${barra ? "" : ", não barra"}` : "Não tem"}</Text>
      </Fato>
      <Fato rotulo="DKIM (assinatura)">{email.dkim.length ? `seletor ${email.dkim.join(", ")}` : <Text span c="dimmed">Não achado nos seletores comuns</Text>}</Fato>
    </SimpleGrid>
  );
}

interface Nome {
  id: number; dominio_id: number; nome: string; ips: string[]; origem: string; interno: boolean; sumiu: boolean; portas: number[]; servicos: Servico[];
  tls_vence: string | null; tls_emissor: string | null; tls_problema: string | null; conferido_em: string | null; proxima_conferencia: string;
  conferindo: boolean; abertos: number; ativo_id: number | null; email: EmailDoDominio | null; cname: string | null;
}

const ORIGEM: Record<string, string> = { dominio: "O próprio domínio", certificados: "Registro público de certificados", dns: "Nome comum que respondeu no DNS" };
const PROBLEMA_DO_CERTIFICADO: Record<string, string> = { vencido: "Vencido", nome: "Não é para este nome", nao_confiavel: "Autoridade não reconhecida", sem_tls: "Não respondeu com HTTPS" };

function Andamento({ d }: { d: Dominio }) {
  if (!d.ativo) return <Estado tipo="desativado">Pausado</Estado>;
  if (!d.ultima_descoberta) return <Text size="sm" c="dimmed">Procurando os nomes</Text>;
  const parte = d.nomes ? Math.round((d.conferidos / d.nomes) * 100) : 0;
  return (
    <Stack gap={2}>
      <Progress value={parte} size="sm" aria-label={`${parte}% dos nomes conferidos`} />
      <Text size="xs" c="dimmed">{numero(d.conferidos)} de {numero(d.nomes)} conferidos{d.na_fila ? `, ${numero(d.na_fila)} na fila` : ""}</Text>
    </Stack>
  );
}

function SituacaoDoNome({ n }: { n: Nome }) {
  if (n.sumiu) return <Estado tipo="desativado">Saiu do DNS</Estado>;
  if (!n.ips.length && n.abertos) return <Estado tipo="problema">Apelido pendurado</Estado>;
  if (!n.ips.length) return <Estado tipo="desativado">Só apelido, sem endereço</Estado>;
  if (n.conferindo) return <Estado tipo="pendente">Conferindo agora</Estado>;
  if (n.interno) return <Estado tipo="desativado">Aponta para a rede interna</Estado>;
  if (!n.conferido_em) return <Estado tipo="pendente">Na fila</Estado>;
  return n.abertos ? <Estado tipo="problema">{numero(n.abertos)} achado(s)</Estado> : <Estado tipo="pronto">Sem achados</Estado>;
}

interface CveDoServico { cve: string; titulo: string | null; cvss: number | null; epss: number | null; kev_desde: string | null; kev_ransomware: boolean; prioridade: string; situacao: string }

/** As CVEs da versão que o serviço anunciou, cruzadas com a base na hora. Cada uma abre o detalhe da base. */
function GavetaDoServico({ alvo, aoFechar }: { alvo: { host: number; indice: number } | null; aoFechar: () => void }) {
  const { dados, erro } = useDados<{ nome: string; servico: Servico; cves: CveDoServico[] }>(alvo ? `/api/vuln/superficie/nomes/${alvo.host}/servicos/${alvo.indice}` : null);
  const [cve, setCve] = useState<string | null>(null);
  const s = dados?.servico;
  const valem = dados?.cves.filter((c) => c.situacao !== "corrigida_na_distribuicao") ?? [];
  const exploradas = valem.filter((c) => c.kev_desde).length;
  const corrigidas = (dados?.cves.length ?? 0) - valem.length;
  return (
    <Drawer opened={alvo !== null} onClose={aoFechar} title={s ? `${s.versao ? `${s.nome} ${s.versao}` : s.nome} em ${dados?.nome}` : ""} size="xl" zIndex={300}>
      {!dados || !s ? <Carregando erro={erro} /> : (
        <Stack gap="md">
          <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="sm">
            <Fato rotulo="Porta">{s.porta}</Fato>
            <Fato rotulo={s.pacote?.confirmado ? "CVEs no pacote" : s.tipo === "borda" || !s.versao ? "Exploradas no produto" : "CVEs da versão"}>{numero(valem.length)}</Fato>
            <Fato rotulo="Já exploradas">{exploradas ? <Text span c="red" fw={600}>{numero(exploradas)}</Text> : "Nenhuma"}</Fato>
            <Fato rotulo="Resposta do serviço"><Text span size="sm" className="mono">{s.resposta}</Text></Fato>
          </SimpleGrid>
          {s.pacote?.confirmado ? (
            <Alert color="blue" variant="light" p="xs">
              O serviço anuncia o pacote {s.pacote.versao} ({s.pacote.ecossistemas?.join(", ")}). A lista foi conferida com a distribuição:
              {corrigidas ? ` ${numero(corrigidas)} CVE(s) da versão já foram corrigidas no pacote e aparecem no fim, em verde.` : " todas as CVEs da lista ainda pegam o pacote instalado."}
            </Alert>
          ) : s.distribuicao ? (
            <Alert color="yellow" variant="light" p="xs">
              A resposta é de uma distribuição Linux, que corrige as falhas sem trocar o número da versão, e o serviço não mostra o pacote instalado
              (ou a distribuição não respondeu). Confira o pacote no servidor para saber quais ainda valem.
            </Alert>
          ) : s.tipo === "borda" || !s.versao ? (
            <Alert color="orange" variant="light" p="xs">
              {s.nome} não mostra a versão sem login. A lista traz as falhas deste produto que já foram exploradas por atacantes: confira a versão no próprio
              equipamento e veja se ela está entre as afetadas.
            </Alert>
          ) : null}
          <Tabela
            linhas={dados.cves}
            chave={(c) => c.cve}
            vazio={s.pacote?.confirmado ? "Nenhuma CVE pega o pacote instalado." : "Nenhuma CVE da base pega esta versão."}
            aoClicarLinha={(c) => setCve(c.cve)}
            colunas={[
              { titulo: "CVE", largura: 150, celula: (c) => <Text size="sm" className="mono" style={{ whiteSpace: "nowrap" }}>{c.cve}</Text> },
              { titulo: "Situação", largura: 150, celula: (c) => <Text size="sm" c={SITUACAO[c.situacao]?.cor}>{SITUACAO[c.situacao]?.texto ?? c.situacao}</Text> },
              { titulo: "Prioridade", largura: 120, celula: (c) => <Prioridade valor={c.prioridade} /> },
              { titulo: "CVSS", largura: 70, celula: (c) => c.cvss ?? "-" },
              { titulo: "Chance de exploração", largura: 110, celula: (c) => porcentoDeEpss(c.epss) },
              { titulo: "Explorada", largura: 110, celula: (c) => c.kev_desde ? <Badge color="red" variant="light" size="sm" tt="none">{c.kev_ransomware ? "Sim, ransomware" : "Sim"}</Badge> : <Text size="sm" c="dimmed">Não</Text> },
              { titulo: "Título", celula: (c) => <Text size="sm" lineClamp={2}>{c.titulo ?? "-"}</Text> },
            ]}
          />
        </Stack>
      )}
      <GavetaDaCve cve={cve} aoFechar={() => setCve(null)} />
    </Drawer>
  );
}

interface Mudanca { id: number; dominio_id: number; nome: string; tipo: string; detalhe: string; em: string }
interface Nota { pontos: number; letra: string; por_severidade: Record<string, number>; historico: { dia: string; pontos: number; letra: string }[]; dominios: Record<string, { pontos: number; letra: string }> }

const COR_DA_LETRA: Record<string, string> = { A: "green.7", B: "lime.7", C: "yellow.6", D: "orange.6", F: "red.7" };
const MUDANCA: Record<string, string> = {
  nome_novo: "Nome novo", nome_sumiu: "Nome saiu", porta_abriu: "Porta abriu", porta_fechou: "Porta fechou",
  certificado_trocou: "Certificado trocou", servico_mudou: "Serviço mudou", cname_mudou: "Apelido mudou",
};

function Letra({ letra, tamanho = 28 }: { letra: string; tamanho?: number }) {
  return <Text span fw={800} fz={tamanho} lh={1} c={COR_DA_LETRA[letra] ?? "red.7"}>{letra}</Text>;
}

/** A nota da superfície e a evolução dela, dia a dia. */
function CartaoDaNota({ nota }: { nota: Nota }) {
  const s = nota.por_severidade;
  return (
    <Painel titulo="Nota da superfície externa">
      <Group align="flex-start" gap="xl" wrap="wrap">
        <Stack gap={4} miw={180}>
          <Group gap="xs" align="baseline"><Letra letra={nota.letra} tamanho={56} /><Text c="dimmed">{nota.pontos} de 100</Text></Group>
          <Text size="sm">{numero(s.critica)} crítica(s), {numero(s.alta)} alta(s), {numero(s.media)} média(s), {numero(s.baixa)} baixa(s) abertas</Text>
          <Text size="xs" c="dimmed">Parte de 100 e perde 25 por crítica, 10 por alta, 4 por média e 1 por baixa. A a partir de 90, B de 80, C de 70, D de 60.</Text>
        </Stack>
        <div style={{ flex: 1, minWidth: 260 }}>
          {nota.historico.length > 1 ? (
            <AreaChart h={140} data={nota.historico.map((h) => ({ ...h, dia: `${h.dia.slice(8, 10)}/${h.dia.slice(5, 7)}` }))} dataKey="dia" yAxisProps={{ domain: [0, 100] }}
              series={[{ name: "pontos", label: "Pontos", color: "pink.6" }]} curveType="monotone" withDots={false} gridAxis="y" />
          ) : <Text size="sm" c="dimmed">A evolução aparece a partir do segundo dia.</Text>}
        </div>
      </Group>
    </Painel>
  );
}

function NovoDominio({ aberto, aoFechar, aoCriar }: { aberto: boolean; aoFechar: () => void; aoCriar: () => void }) {
  const [dominio, setDominio] = useState("");
  const [autorizado, setAutorizado] = useState(false);
  const [descobrir, setDescobrir] = useState<number | string>(24);
  const [conferir, setConferir] = useState<number | string>(6);
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => { if (aberto) { setDominio(""); setAutorizado(false); setErro(null); } }, [aberto]);
  const salvar = async () => {
    const r = await enviar("/api/vuln/superficie", { dominio, autorizado, descobrir_a_cada_horas: Number(descobrir), conferir_a_cada_horas: Number(conferir) });
    if (!r.ok) return setErro(await detalhe(r, "Não foi possível cadastrar o domínio."));
    aoFechar();
    aoCriar();
  };
  return (
    <Modal opened={aberto} onClose={aoFechar} title="Novo domínio">
      <Stack gap="sm">
        <TextInput label="Domínio" placeholder="empresa.com.br" value={dominio} onChange={(e) => setDominio(e.currentTarget.value)} data-autofocus />
        <SimpleGrid cols={2} spacing="sm">
          <NumberInput label="Procurar nomes novos a cada (horas)" min={6} max={720} value={descobrir} onChange={setDescobrir} />
          <NumberInput label="Conferir cada nome a cada (horas)" min={1} max={168} value={conferir} onChange={setConferir} />
        </SimpleGrid>
        <Checkbox checked={autorizado} onChange={(e) => setAutorizado(e.currentTarget.checked)}
          label="Declaro que a organização é dona deste domínio ou tem autorização por escrito para conferi-lo. Fica registrado com o meu nome." />
        {erro && <Alert color="red" variant="light" p="xs">{erro}</Alert>}
        <Group justify="flex-end">
          <Button onClick={aoFechar}>Cancelar</Button>
          <Button variant="filled" onClick={salvar} disabled={!dominio.trim() || !autorizado}>Cadastrar</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

export function Superficie() {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<{ dominios: Dominio[]; hosts: Nome[]; mudancas: Mudanca[]; nota: Nota | null }>("/api/vuln/superficie");
  const [novo, setNovo] = useState(false);
  const [aberto, setAberto] = useState<number | null>(null);
  const [aviso, setAviso] = useState<{ ok: boolean; texto: string } | null>(null);
  const [pedido, setPedido] = useState<PedidoDeAchados | null>(null);
  const [servico, setServico] = useState<{ host: number; indice: number } | null>(null);
  // O serviço trabalha aos poucos: a tela acompanha sozinha o andamento da fila.
  useEffect(() => {
    const t = setInterval(recarregar, 15000);
    return () => clearInterval(t);
  }, [recarregar]);

  if (!dados) return <Carregando erro={erro} />;
  const gerir = pode("gerir_vulnerabilidades");
  const dominio = dados.dominios.find((d) => d.id === aberto) ?? null;
  const nomes = dominio ? dados.hosts.filter((h) => h.dominio_id === dominio.id) : [];

  const agora = async (d: Dominio) => {
    const r = await enviar(`/api/vuln/superficie/${d.id}/agora`);
    setAviso(r.ok ? { ok: true, texto: `${d.dominio} foi para a frente da fila. Os nomes são conferidos um por vez.` } : { ok: false, texto: await detalhe(r) });
    recarregar();
  };
  const mudar = async (d: Dominio, ativo: boolean) => {
    const r = await chamar(`/api/vuln/superficie/${d.id}`, "PUT", { ativo, descobrir_a_cada_horas: d.descobrir_a_cada_horas, conferir_a_cada_horas: d.conferir_a_cada_horas });
    if (!r.ok) setAviso({ ok: false, texto: await detalhe(r) });
    recarregar();
  };
  const tirar = async (d: Dominio) => {
    const r = await chamar(`/api/vuln/superficie/${d.id}`, "DELETE");
    if (!r.ok) setAviso({ ok: false, texto: await detalhe(r) });
    setAberto(null);
    recarregar();
  };
  const acoes = (d: Dominio) => gerir ? [
    { texto: "Conferir agora", aoClicar: () => agora(d) },
    { texto: d.ativo ? "Pausar" : "Retomar", aoClicar: () => mudar(d, !d.ativo) },
    { texto: "Tirar domínio", perigo: true, aoClicar: () => tirar(d) },
  ] : [];

  return (
    <Stack gap="md">
      {aviso && <Alert color={aviso.ok ? "green" : "red"} variant="light" p="xs" withCloseButton onClose={() => setAviso(null)}>{aviso.texto}</Alert>}
      {dados.nota && <CartaoDaNota nota={dados.nota} />}
      <Painel titulo="Superfície externa" acao={gerir && <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setNovo(true)}>Novo domínio</Button>}>
        <Text size="sm" c="dimmed" mb="sm">
          O que os domínios da organização deixam à vista na internet. Os nomes são conferidos um por vez, sem parar e sem pesar: portas perigosas abertas, certificado e HTTPS.
        </Text>
        <Tabela
          linhas={dados.dominios}
          chave={(d) => d.id}
          vazio="Nenhum domínio cadastrado."
          aoClicarLinha={(d) => setAberto(d.id)}
          colunas={[
            { titulo: "Domínio", celula: (d) => <Text size="sm" fw={500}>{d.dominio}</Text> },
            { titulo: "Nota", largura: 70, celula: (d) => <Letra letra={dados.nota?.dominios[String(d.id)]?.letra ?? "A"} tamanho={18} /> },
            { titulo: "Andamento", largura: 240, celula: (d) => <Andamento d={d} /> },
            { titulo: "Agora", celula: (d) => d.conferindo_agora ? <Text size="sm" className="mono">{d.conferindo_agora}</Text> : <Text size="sm" c="dimmed">Aguardando a hora</Text> },
            { titulo: "Última procura de nomes", largura: 170, celula: (d) => <Data valor={d.ultima_descoberta} /> },
            { titulo: "", largura: 40, celula: (d) => <AcoesDaLinha rotulo={`Ações de ${d.dominio}`} itens={acoes(d)} /> },
          ]}
        />
      </Painel>

      <NovoDominio aberto={novo} aoFechar={() => setNovo(false)} aoCriar={recarregar} />
      <Drawer opened={dominio !== null} onClose={() => setAberto(null)} title={dominio?.dominio ?? ""} size="70%">
        {dominio && (
          <Stack gap="md">
            {gerir && (
              <Group justify="flex-end" gap="xs">
                <Button onClick={() => mudar(dominio, !dominio.ativo)}>{dominio.ativo ? "Pausar" : "Retomar"}</Button>
                <Button variant="filled" leftSection={<IconRadar size={14} />} onClick={() => agora(dominio)}>Conferir agora</Button>
              </Group>
            )}
            {dominio.ultimo_erro && <Alert color="yellow" variant="light" p="xs">{dominio.ultimo_erro}</Alert>}
            <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="sm">
              <Fato rotulo="Andamento"><Andamento d={dominio} /></Fato>
              <Fato rotulo="Procura nomes novos">a cada {dominio.descobrir_a_cada_horas} h</Fato>
              <Fato rotulo="Confere cada nome">a cada {dominio.conferir_a_cada_horas} h</Fato>
              <Fato rotulo="Autorizado por">{dominio.autorizado_por_nome}, <Data valor={dominio.autorizado_em} /></Fato>
            </SimpleGrid>
            <div>
              <Title order={3} mb={4}>E-mail do domínio</Title>
              <EmailDoDominio email={nomes.find((n) => n.origem === "dominio")?.email} />
            </div>
            <div>
              <Title order={3} mb={4}>O que mudou</Title>
              <Tabela
                linhas={dados.mudancas.filter((m) => m.dominio_id === dominio.id).slice(0, 50)}
                chave={(m) => m.id}
                vazio="Nada mudou desde a primeira conferência."
                colunas={[
                  { titulo: "Quando", largura: 150, celula: (m) => <Data valor={m.em} /> },
                  { titulo: "Nome", celula: (m) => <Text size="sm" className="mono">{m.nome}</Text> },
                  { titulo: "Mudança", largura: 150, celula: (m) => <Text size="sm" c={m.tipo === "porta_abriu" || m.tipo === "nome_novo" ? "orange" : undefined}>{MUDANCA[m.tipo] ?? m.tipo}</Text> },
                  { titulo: "Detalhe", celula: (m) => <Text size="sm">{m.detalhe}</Text> },
                ]}
              />
            </div>
            <div>
              <Title order={3} mb={4}>Nomes encontrados</Title>
              <Tabela
                linhas={nomes}
                chave={(n) => n.id}
                vazio={dominio.ultima_descoberta ? "Nenhum nome respondeu no DNS." : "Ainda procurando os nomes deste domínio."}
                aoClicarLinha={(n) => { if (n.ativo_id) setPedido({ titulo: `Achados de ${n.nome}`, consulta: `ativo=${n.ativo_id}&estado=`, filtro: () => true }); }}
                colunas={[
                  { titulo: "Nome", celula: (n) => (
                    <Stack gap={0}>
                      <Text size="sm" className="mono" title={ORIGEM[n.origem]}>{n.nome}</Text>
                      {n.cname && <Text size="xs" c="dimmed" className="mono" title="Apelido (CNAME): para onde o nome aponta">→ {n.cname}</Text>}
                    </Stack>
                  ) },
                  { titulo: "Endereços", celula: (n) => <Text size="sm" className="mono" lineClamp={1} title={n.ips.join(", ")}>{n.ips.join(", ")}</Text> },
                  { titulo: "Portas abertas", celula: (n) => n.portas.length ? <Text size="sm" className="mono">{n.portas.join(", ")}</Text> : <Text size="sm" c="dimmed">Nenhuma</Text> },
                  { titulo: "Serviços", celula: (n) => n.servicos.length ? (
                    <Stack gap={0}>{n.servicos.map((s, i) => (
                      // O clique no serviço abre as CVEs dele, não os achados do nome.
                      <Anchor key={`${s.porta}${s.nome}`} component="button" type="button" size="sm" ta="left" c={s.falhas && (!s.distribuicao || s.pacote?.confirmado) ? "red" : s.tipo === "borda" || s.tipo === "painel" ? "orange" : undefined} title={s.resposta}
                        onClick={(e: React.MouseEvent) => { e.stopPropagation(); setServico({ host: n.id, indice: i }); }}>
                        {resumoDoServico(s)}
                      </Anchor>
                    ))}</Stack>
                  ) : <Text size="sm" c="dimmed">Não informam</Text> },
                  { titulo: "Certificado", celula: (n) => n.tls_problema ? <Text size="sm" c="red">{PROBLEMA_DO_CERTIFICADO[n.tls_problema] ?? n.tls_problema}</Text>
                    : n.tls_vence ? <Text size="sm">Vence <Data valor={n.tls_vence} /></Text> : <Text size="sm" c="dimmed">Sem HTTPS</Text> },
                  { titulo: "Situação", celula: (n) => <SituacaoDoNome n={n} /> },
                  { titulo: "Conferido", largura: 150, celula: (n) => <Data valor={n.conferido_em} /> },
                ]}
              />
            </div>
          </Stack>
        )}
      </Drawer>
      <GavetaDeAchados pedido={pedido} aoFechar={() => setPedido(null)} />
      <GavetaDoServico alvo={servico} aoFechar={() => setServico(null)} />
    </Stack>
  );
}
