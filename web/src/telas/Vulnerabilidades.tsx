import { Alert, Box, Button, Checkbox, Drawer, Group, Modal, NumberInput, PasswordInput, Select, SimpleGrid, Stack, Tabs, Text, TextInput, Title, Tooltip } from "@mantine/core";
import { IconPlus, IconRadar } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { detalhe, enviar, useDados, useEu, usePode } from "../api";
import { AcoesDaLinha, BarrasMetalicas, Busca, Cabecalho, Carregando, Data, Estado, METAL_ROSA, Numero, Painel, Tabela } from "../componentes";
import { numero, quando } from "../formato";
import { SEVERIDADES } from "../tema";
import {
  Achados, chamar, dataComAno, Explica, explicaDaPrioridade, Fato, GavetaDaCve, GavetaDeAchados, GavetaDoAchado, ORDEM_DE_PRIORIDADE, porcentoDeEpss, Prioridade, TabelaDeAchados, textoDaPrioridade, useAchadosCompletos,
  type Achado, type FiltroDeAchados, type PedidoDeAchados,
} from "./VulnerabilidadesAchados";

// ------------------------------------------------------------------ panorama

interface Indicadores {
  abertos: Record<string, number>; exposicao: number | string; ativos_expostos: number; urgentes: number; descobertos: number; corrigidos: number; aceitos: number; dias_para_corrigir: number | null;
  evolucao: { dia: string; abertos: number }[]; ultima_varredura: string | null; periodo: number; pontos: Record<string, number>;
}

function Panorama({ aoVerAchados, aoVerAtivos }: { aoVerAchados: (f: FiltroDeAchados) => void; aoVerAtivos: () => void }) {
  const eu = useEu();
  const { dados: d, erro } = useDados<Indicadores>("/api/vuln/indicadores");
  const [pedido, setPedido] = useState<PedidoDeAchados | null>(null);
  const [verDados, setVerDados] = useState(false);
  if (!d) return <Carregando erro={erro} />;

  const limite = Date.now() - d.periodo * 86400000;
  const noPeriodo = (v: string | null) => v !== null && new Date(v).getTime() >= limite;
  const verCorrigidos = () => setPedido({ titulo: `Corrigidos em ${d.periodo} dias`, consulta: "estado=corrigido", filtro: (a) => noPeriodo(a.corrigido_em) });
  const dias = d.evolucao.map((e) => ({ dia: new Date(e.dia).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit", timeZone: eu.fuso }), abertos: Number(e.abertos), completo: new Date(e.dia).toLocaleDateString("pt-BR", { timeZone: eu.fuso }) }));
  const p = d.pontos;

  return (
    <Stack gap="md">
      <SimpleGrid cols={{ base: 2, sm: 3, lg: 5 }} spacing="md">
        <Numero rotulo="Críticos abertos" valor={numero(d.abertos.critica)} destaque={d.abertos.critica > 0 ? SEVERIDADES.critica.cor : undefined} aoClicar={() => aoVerAchados({ severidade: "critica", estado: "aberto" })} />
        <Numero rotulo="Altos abertos" valor={numero(d.abertos.alta)} aoClicar={() => aoVerAchados({ severidade: "alta", estado: "aberto" })} />
        <Numero rotulo="Médios abertos" valor={numero(d.abertos.media)} aoClicar={() => aoVerAchados({ severidade: "media", estado: "aberto" })} />
        <Numero rotulo="Baixos abertos" valor={numero(d.abertos.baixa)} aoClicar={() => aoVerAchados({ severidade: "baixa", estado: "aberto" })} />
        <Numero rotulo="Com exploração confirmada" valor={numero(d.urgentes)} destaque={d.urgentes > 0 ? SEVERIDADES.critica.cor : undefined} aoClicar={() => setPedido({ titulo: "Com exploração confirmada", consulta: "estado=aberto", filtro: (a) => a.prioridade === "agora" })} />
        <Numero rotulo="Exposição" valor={numero(d.exposicao)} detalhe={`${numero(d.ativos_expostos)} ativos`} aoClicar={aoVerAtivos} />
        <Numero rotulo={`Descobertos em ${d.periodo} dias`} valor={numero(d.descobertos)} aoClicar={() => setPedido({ titulo: `Descobertos em ${d.periodo} dias`, consulta: "estado=", filtro: (a) => noPeriodo(a.primeira_vez) })} />
        <Numero rotulo={`Corrigidos em ${d.periodo} dias`} valor={numero(d.corrigidos)} aoClicar={verCorrigidos} />
        <Numero rotulo="Dias para corrigir, em média" valor={d.dias_para_corrigir === null ? "-" : numero(d.dias_para_corrigir)} aoClicar={verCorrigidos} />
        <Numero rotulo="Riscos aceitos ou falsos" valor={numero(d.aceitos)} aoClicar={() => setPedido({ titulo: "Riscos aceitos e falsos positivos", consulta: "estado=", filtro: (a) => a.estado === "aceito" || a.estado === "falso_positivo" })} />
      </SimpleGrid>

      <Painel
        titulo="Achados abertos por dia"
        acao={(
          <Group gap="xs" wrap="nowrap">
            <Text size="xs" c="dimmed">{d.ultima_varredura ? `Última varredura em ${quando(d.ultima_varredura, eu.fuso)}` : "Nenhuma varredura concluída ainda"}</Text>
            <Explica rotulo="Como a exposição é calculada">{`Cada achado aberto vale crítica ${p.critica}, alta ${p.alta}, média ${p.media} ou baixa ${p.baixa} pontos, multiplicados pelo peso do ativo.`}</Explica>
            <Button onClick={() => setVerDados(true)}>Ver dados</Button>
          </Group>
        )}
      >
        <BarrasMetalicas altura={200} dados={dias} chave="dia" series={[{ nome: "abertos", rotulo: "Abertos", metal: METAL_ROSA }]} />
      </Painel>

      <GavetaDeAchados pedido={pedido} aoFechar={() => setPedido(null)} />
      <Modal opened={verDados} onClose={() => setVerDados(false)} title="Achados abertos por dia">
        <Tabela
          linhas={dias.filter((x) => x.abertos)}
          chave={(x) => x.completo}
          vazio="Nenhum achado aberto no período."
          colunas={[{ titulo: "Dia", celula: (x) => x.completo }, { titulo: "Abertos", alinhar: "right", celula: (x) => numero(x.abertos) }]}
        />
      </Modal>
    </Stack>
  );
}

// ------------------------------------------------------------------ ativos

interface AtivoVuln { id: number; host: string; nome: string | null; sistema: string | null; peso: number; monitorado: boolean; primeira_vez: string; ultima_varredura: string | null; abertos: number; graves: number; corrigidos: number; exposicao: number | string }
const PESOS = [1, 2, 3, 4, 5].map((p) => ({ value: String(p), label: `Peso ${p}` }));

function GavetaDoAtivo({ ativo, aoFechar, aoMudar }: { ativo: AtivoVuln | null; aoFechar: () => void; aoMudar: () => void }) {
  const pode = usePode();
  const [vendo, setVendo] = useState<"abertos" | "graves" | "corrigidos">("abertos");
  const [achado, setAchado] = useState<{ id: number; focar: boolean } | null>(null);
  const [versao, setVersao] = useState(0);
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => { setVendo("abertos"); setErro(null); }, [ativo?.id]);
  const consulta = ativo ? `ativo=${ativo.id}&estado=${vendo === "corrigidos" ? "corrigido" : "aberto"}` : null;
  const { achados, cortado, erro: erroDaLista } = useAchadosCompletos(consulta, versao);
  const graves = (a: Achado) => a.severidade === "critica" || a.severidade === "alta";
  const linhas = achados && (vendo === "graves" ? achados.filter(graves) : achados);
  const mudarPeso = async (v: string | null) => {
    if (!ativo || !v) return;
    const r = await chamar(`/api/vuln/ativos/${ativo.id}`, "PUT", { peso: Number(v) });
    if (r.ok) aoMudar();
    else setErro(await detalhe(r));
  };
  return (
    <>
      <Drawer opened={ativo !== null} onClose={aoFechar} title={ativo?.nome ?? ativo?.host ?? ""} size="70%">
        {ativo && (
          <Stack gap="md">
            <Group justify="space-between" align="flex-end">
              <Group gap="xl">
                <Fato rotulo="Endereço"><span className="mono">{ativo.host}</span></Fato>
                <Fato rotulo="Sistema">{ativo.sistema ?? "-"}</Fato>
                <Fato rotulo="Última varredura"><Data valor={ativo.ultima_varredura} /></Fato>
              </Group>
              {pode("gerir_vulnerabilidades")
                ? <Select w={120} label="Peso no negócio" allowDeselect={false} value={String(ativo.peso)} data={PESOS} onChange={mudarPeso} error={erro} />
                : <Fato rotulo="Peso no negócio">{ativo.peso}</Fato>}
            </Group>
            <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="sm">
              <Numero rotulo="Abertos" valor={numero(ativo.abertos)} aoClicar={() => setVendo("abertos")} selecionado={vendo === "abertos"} />
              <Numero rotulo="Graves" valor={numero(ativo.graves)} aoClicar={() => setVendo("graves")} selecionado={vendo === "graves"} />
              <Numero rotulo="Corrigidos" valor={numero(ativo.corrigidos)} aoClicar={() => setVendo("corrigidos")} selecionado={vendo === "corrigidos"} />
              <Numero rotulo="Exposição" valor={numero(ativo.exposicao)} />
            </SimpleGrid>
            {!linhas ? <Carregando erro={erroDaLista} /> : <TabelaDeAchados achados={linhas} vazio="Nenhum achado aqui." aoAbrir={(id, focar = false) => setAchado({ id, focar })} />}
            {cortado && <Text size="xs" c="dimmed">Mostrando só o que coube na leitura: pode haver mais.</Text>}
          </Stack>
        )}
      </Drawer>
      <GavetaDoAchado id={achado?.id ?? null} focar={achado?.focar} aoFechar={() => setAchado(null)} aoMudar={() => { setVersao((v) => v + 1); aoMudar(); }} />
    </>
  );
}

function Ativos() {
  const { dados, erro, recarregar } = useDados<{ ativos: AtivoVuln[] }>("/api/vuln/ativos");
  const [aberto, setAberto] = useState<number | null>(null);
  if (!dados) return <Carregando erro={erro} />;
  return (
    <Painel titulo="Ativos" acao={<Explica rotulo="O que é o peso">O peso diz o quanto o ativo importa para o negócio e multiplica a exposição. Os ativos aparecem quando uma varredura os alcança.</Explica>}>
      <Tabela
        linhas={dados.ativos}
        chave={(t) => t.id}
        vazio="Nenhum ativo varrido ainda."
        aoClicarLinha={(t) => setAberto(t.id)}
        colunas={[
          { titulo: "Ativo", celula: (t) => <Text size="sm" fw={500}>{t.nome ?? t.host}</Text> },
          { titulo: "Endereço", celula: (t) => <span className="mono">{t.host}</span> },
          { titulo: "Peso", alinhar: "right", largura: 60, celula: (t) => t.peso },
          { titulo: "Abertos", alinhar: "right", largura: 70, celula: (t) => numero(t.abertos) },
          { titulo: "Graves", alinhar: "right", largura: 70, celula: (t) => numero(t.graves) },
          { titulo: "Corrigidos", alinhar: "right", largura: 80, celula: (t) => numero(t.corrigidos) },
          { titulo: "Exposição", alinhar: "right", largura: 80, celula: (t) => numero(t.exposicao) },
          { titulo: "Última varredura", largura: 150, celula: (t) => <Data valor={t.ultima_varredura} /> },
          { titulo: "", largura: 40, celula: (t) => <AcoesDaLinha rotulo="Ações do ativo" itens={[{ texto: "Ver achados e mudar o peso", aoClicar: () => setAberto(t.id) }]} /> },
        ]}
      />
      <GavetaDoAtivo ativo={dados.ativos.find((t) => t.id === aberto) ?? null} aoFechar={() => setAberto(null)} aoMudar={recarregar} />
    </Painel>
  );
}

// ------------------------------------------------------------------ varreduras

interface Modelo { id: number; nome: string; ferramenta: string; intrusiva: boolean; todas_portas: boolean }
interface Alvo { id: number; nome: string; hosts: string[]; modelo_id: number; modelo: string; intrusiva: boolean; credencial_tipo: string | null; credencial_usuario: string | null; com_credencial: boolean; a_cada_dias: number; proxima_em: string | null }
interface Varredura { id: number; alvo: string; modelo: string; estado: string; agendada: boolean; pedida_em: string; iniciada_em: string | null; terminada_em: string | null; autenticada: boolean | null; hosts_respondendo: number | null; novos: number | null; corrigidos: number | null; mensagem: string | null }

const ROTULO_VARREDURA: Record<string, string> = { pendente: "Na fila", em_andamento: "Em andamento", concluida: "Concluída", falhou: "Falhou" };
const TIPO_DA_VARREDURA: Record<string, string> = { pendente: "pendente", em_andamento: "pendente", concluida: "pronto", falhou: "problema" };
const ROTULO_FERRAMENTA: Record<string, string> = { rede: "Rede e servidores", web: "Aplicação web", conteiner: "Contêiner", nuvem: "Nuvem" };
const EXEMPLOS_DE_ALVO: Record<string, string> = { rede: "10.0.0.5, 10.0.1.0/24", web: "https://app.exemplo.test", conteiner: "nginx:1.27", nuvem: "aws, azure ou gcp" };
const textoDaCredencial = (a: Alvo) => (a.com_credencial ? `${(a.credencial_tipo ?? "").toUpperCase()}: ${a.credencial_usuario ?? ""}` : "Sem credencial");
const textoDaRepeticao = (a: Alvo) => (a.a_cada_dias ? `A cada ${a.a_cada_dias} dias` : "Sob demanda");

function NovoAlvo({ aberto, modelos, aoFechar, aoCriar }: { aberto: boolean; modelos: Modelo[]; aoFechar: () => void; aoCriar: () => void }) {
  const [nome, setNome] = useState("");
  const [modelo, setModelo] = useState<string | null>(null);
  const [dias, setDias] = useState<number | string>(30);
  const [hosts, setHosts] = useState("");
  const [tipo, setTipo] = useState("nenhuma");
  const [usuario, setUsuario] = useState("");
  const [senha, setSenha] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const escolhido = modelos.find((m) => String(m.id) === modelo) ?? modelos[0];
  const fechar = () => {
    // A credencial digitada não fica guardada no formulário ao fechar a janela.
    setSenha("");
    setErro(null);
    aoFechar();
  };
  const salvar = async () => {
    const r = await enviar("/api/vuln/alvos", {
      nome: nome.trim(), hosts: hosts.split(/[\s,]+/).filter(Boolean), modelo_id: escolhido?.id, a_cada_dias: Number(dias || 0),
      ...(tipo === "nenhuma" ? {} : { credencial_tipo: tipo, credencial_usuario: usuario.trim() || null, credencial_senha: senha || null }),
    });
    setSenha("");
    if (!r.ok) {
      setErro(await detalhe(r, "Confira o nome, o modelo e os endereços."));
      return;
    }
    setNome("");
    setHosts("");
    setTipo("nenhuma");
    setUsuario("");
    setErro(null);
    aoCriar();
    aoFechar();
  };
  return (
    <Modal opened={aberto} onClose={fechar} title="Novo alvo" size="lg">
      <Stack gap="sm">
        <Alert color="yellow" variant="light" p="xs">Só varra o que você tem autorização para testar. Varredura intrusiva pode derrubar serviço frágil: combine a janela antes.</Alert>
        <Group grow align="flex-start">
          <TextInput label="Nome" value={nome} onChange={(e) => setNome(e.currentTarget.value)} maxLength={120} data-autofocus />
          <Select label="Modelo" allowDeselect={false} value={escolhido ? String(escolhido.id) : null} onChange={setModelo} data={modelos.map((m) => ({ value: String(m.id), label: m.nome }))} />
          <NumberInput label="Repetir a cada (dias)" description="0 só sob demanda" min={0} max={365} value={dias} onChange={setDias} />
        </Group>
        <TextInput label="Alvos" description="Separados por vírgula ou espaço" placeholder={EXEMPLOS_DE_ALVO[escolhido?.ferramenta ?? "rede"]} value={hosts} onChange={(e) => setHosts(e.currentTarget.value)} spellCheck={false} />
        <Group grow align="flex-start">
          <Select label="Credencial" allowDeselect={false} value={tipo} onChange={(v) => setTipo(v ?? "nenhuma")} data={[{ value: "nenhuma", label: "Sem credencial" }, { value: "ssh", label: "SSH (Linux, equipamentos)" }, { value: "smb", label: "SMB (Windows)" }, { value: "snmp", label: "SNMP (rede)" }]} />
          <TextInput label="Usuário" disabled={tipo === "nenhuma"} value={usuario} onChange={(e) => setUsuario(e.currentTarget.value)} maxLength={120} autoComplete="off" />
          <PasswordInput label="Senha" disabled={tipo === "nenhuma"} value={senha} onChange={(e) => setSenha(e.currentTarget.value)} autoComplete="new-password" />
        </Group>
        {tipo !== "nenhuma" && <Text size="xs" c="dimmed">A senha fica cifrada e não volta para a tela. Crie uma conta só para varredura, com o menor privilégio possível.</Text>}
        {erro && <Alert color="red" variant="light" p="xs">{erro}</Alert>}
        <Group justify="flex-end">
          <Button variant="subtle" color="gray" onClick={fechar}>Cancelar</Button>
          <Button variant="filled" onClick={salvar} disabled={!nome.trim() || !hosts.trim() || !escolhido}>Criar</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function GavetaDaVarredura({ varredura, aoFechar }: { varredura: Varredura | null; aoFechar: () => void }) {
  const v = varredura;
  return (
    <Drawer opened={v !== null} onClose={aoFechar} title={v ? `Varredura de ${v.alvo}` : ""} size="lg" zIndex={300}>
      {v && (
        <Stack gap="md">
          <Group gap="sm"><Estado tipo={TIPO_DA_VARREDURA[v.estado] ?? "outro"}>{ROTULO_VARREDURA[v.estado] ?? v.estado}</Estado><Text size="sm" c="dimmed">{v.agendada ? "Pela agenda" : "A pedido"}</Text></Group>
          {v.mensagem && <Alert color={v.estado === "falhou" ? "red" : "gray"} variant="light" p="xs">{v.mensagem}</Alert>}
          <SimpleGrid cols={2} spacing="sm">
            <Fato rotulo="Alvo">{v.alvo}</Fato>
            <Fato rotulo="Modelo">{v.modelo}</Fato>
            <Fato rotulo="Pedida em"><Data valor={v.pedida_em} /></Fato>
            <Fato rotulo="Começou em"><Data valor={v.iniciada_em} /></Fato>
            <Fato rotulo="Terminou em"><Data valor={v.terminada_em} /></Fato>
            <Fato rotulo="Com credencial">{v.autenticada === null ? "-" : v.autenticada ? "Sim" : "Não"}</Fato>
            <Fato rotulo="Hosts respondendo">{numero(v.hosts_respondendo)}</Fato>
            <Fato rotulo="Achados novos">{numero(v.novos)}</Fato>
            <Fato rotulo="Achados corrigidos">{numero(v.corrigidos)}</Fato>
          </SimpleGrid>
        </Stack>
      )}
    </Drawer>
  );
}

function TabelaDeVarreduras({ linhas, aoAbrir }: { linhas: Varredura[]; aoAbrir: (v: Varredura) => void }) {
  return (
    <Tabela
      linhas={linhas}
      chave={(v) => v.id}
      vazio="Nenhuma varredura ainda."
      aoClicarLinha={aoAbrir}
      colunas={[
        { titulo: "Alvo", celula: (v) => v.alvo },
        { titulo: "Modelo", celula: (v) => v.modelo },
        { titulo: "Situação", celula: (v) => <><Estado tipo={TIPO_DA_VARREDURA[v.estado] ?? "outro"}>{ROTULO_VARREDURA[v.estado] ?? v.estado}</Estado>{v.mensagem && <Text size="xs" c="dimmed" lineClamp={1} title={v.mensagem}>{v.mensagem}</Text>}</> },
        { titulo: "Origem", largura: 80, celula: (v) => (v.agendada ? "Agenda" : "Pedido") },
        { titulo: "Pedida em", largura: 150, celula: (v) => <Data valor={v.pedida_em} /> },
        { titulo: "Terminou em", largura: 150, celula: (v) => <Data valor={v.terminada_em} /> },
        { titulo: "Hosts", alinhar: "right", largura: 60, celula: (v) => numero(v.hosts_respondendo) },
        { titulo: "Com credencial", largura: 100, celula: (v) => (v.autenticada === null ? "-" : v.autenticada ? "Sim" : "Não") },
        { titulo: "Novos", alinhar: "right", largura: 60, celula: (v) => numero(v.novos) },
        { titulo: "Corrigidos", alinhar: "right", largura: 80, celula: (v) => numero(v.corrigidos) },
      ]}
    />
  );
}

function Alvos({ alvoInicial, aoVerVarreduras }: { alvoInicial: number | null; aoVerVarreduras: () => void }) {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<{ alvos: Alvo[] }>("/api/vuln/alvos");
  const { dados: dadosModelos } = useDados<{ modelos: Modelo[] }>("/api/vuln/modelos");
  const [aberto, setAberto] = useState<number | null>(alvoInicial);
  const [novo, setNovo] = useState(false);
  const [confirmando, setConfirmando] = useState<Alvo | null>(null);
  const [resposta, setResposta] = useState<{ ok: boolean; texto: string } | null>(null);
  const [varredura, setVarredura] = useState<Varredura | null>(null);
  const { dados: dadosVarreduras, recarregar: recarregarVarreduras } = useDados<{ varreduras: Varredura[] }>(aberto === null ? null : "/api/vuln/varreduras");

  const pedir = async (a: Alvo) => {
    setConfirmando(null);
    const r = await enviar("/api/vuln/varreduras", { alvo_id: a.id });
    setResposta(r.ok ? { ok: true, texto: `Varredura de ${a.nome} pedida.` } : { ok: false, texto: await detalhe(r, "Não foi possível pedir a varredura.") });
    recarregarVarreduras();
  };
  const varrer = (a: Alvo) => {
    if (a.intrusiva) setConfirmando(a);
    else pedir(a);
  };
  const desativar = async (a: Alvo) => {
    const r = await chamar(`/api/vuln/alvos/${a.id}`, "DELETE");
    if (!r.ok) setResposta({ ok: false, texto: await detalhe(r) });
    setAberto(null);
    recarregar();
  };

  if (!dados) return <Carregando erro={erro} />;
  const modelos = dadosModelos?.modelos ?? [];
  const alvo = dados.alvos.find((a) => a.id === aberto) ?? null;
  const gerir = pode("gerir_vulnerabilidades");
  const historico = alvo ? (dadosVarreduras?.varreduras ?? []).filter((v) => v.alvo === alvo.nome) : [];
  const aviso = resposta && (
    <Alert color={resposta.ok ? "green" : "red"} variant="light" p="xs" withCloseButton onClose={() => setResposta(null)}>
      <Group justify="space-between" gap="sm"><Text size="sm">{resposta.texto}</Text>{resposta.ok && <Button onClick={aoVerVarreduras}>Ver varreduras</Button>}</Group>
    </Alert>
  );

  return (
    <Stack gap="md">
      {aberto === null && aviso}
      <Painel titulo="Alvos" acao={gerir && <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setNovo(true)} disabled={!modelos.length} title={modelos.length ? undefined : "Crie um modelo para poder cadastrar alvos."}>Novo alvo</Button>}>
        <Tabela
          linhas={dados.alvos}
          chave={(a) => a.id}
          vazio="Nenhum alvo cadastrado."
          aoClicarLinha={(a) => setAberto(a.id)}
          colunas={[
            { titulo: "Alvo", celula: (a) => <Text size="sm" fw={500}>{a.nome}</Text> },
            { titulo: "Endereços", celula: (a) => <Text className="mono" lineClamp={1} title={a.hosts.join(", ")}>{a.hosts.join(", ")}</Text> },
            { titulo: "Modelo", celula: (a) => a.modelo },
            { titulo: "Credencial", celula: (a) => textoDaCredencial(a) },
            { titulo: "Repetição", celula: (a) => textoDaRepeticao(a) },
            { titulo: "Próxima", largura: 150, celula: (a) => <Data valor={a.proxima_em} /> },
            { titulo: "", largura: 40, celula: (a) => (
              <AcoesDaLinha rotulo={`Ações de ${a.nome}`} itens={gerir ? [{ texto: "Varrer agora", aoClicar: () => varrer(a) }, { texto: "Desativar", perigo: true, aoClicar: () => desativar(a) }] : []} />
            ) },
          ]}
        />
      </Painel>

      <NovoAlvo aberto={novo} modelos={modelos} aoFechar={() => setNovo(false)} aoCriar={recarregar} />
      <Drawer opened={alvo !== null} onClose={() => { setAberto(null); setResposta(null); }} title={alvo?.nome ?? ""} size="70%">
        {alvo && (
          <Stack gap="md">
            {gerir && (
              <Group justify="flex-end" gap="xs">
                <Button onClick={() => desativar(alvo)}>Desativar</Button>
                <Button variant="filled" leftSection={<IconRadar size={14} />} onClick={() => varrer(alvo)}>Varrer agora</Button>
              </Group>
            )}
            {aviso}
            <SimpleGrid cols={{ base: 2, sm: 3 }} spacing="sm">
              <Fato rotulo="Modelo">{alvo.modelo}{alvo.intrusiva ? ", intrusivo" : ""}</Fato>
              <Fato rotulo="Credencial">{textoDaCredencial(alvo)}</Fato>
              <Fato rotulo="Repetição">{textoDaRepeticao(alvo)}</Fato>
              <Fato rotulo="Próxima"><Data valor={alvo.proxima_em} /></Fato>
            </SimpleGrid>
            <Fato rotulo="Endereços"><span className="mono">{alvo.hosts.join(", ")}</span></Fato>
            <div>
              <Title order={3} mb={4}>Varreduras deste alvo</Title>
              <TabelaDeVarreduras linhas={historico} aoAbrir={setVarredura} />
            </div>
          </Stack>
        )}
      </Drawer>
      <GavetaDaVarredura varredura={varredura} aoFechar={() => setVarredura(null)} />
      <Modal opened={confirmando !== null} onClose={() => setConfirmando(null)} title="Varredura intrusiva" zIndex={400}>
        <Stack gap="sm">
          <Text size="sm">A varredura de {confirmando?.nome} é intrusiva e pode afetar os serviços. Continuar?</Text>
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={() => setConfirmando(null)}>Cancelar</Button>
            <Button variant="filled" onClick={() => { if (confirmando) pedir(confirmando); }}>Varrer agora</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}

function NovoModelo({ aberto, aoFechar, aoCriar }: { aberto: boolean; aoFechar: () => void; aoCriar: () => void }) {
  const [nome, setNome] = useState("");
  const [ferramenta, setFerramenta] = useState("rede");
  const [intrusiva, setIntrusiva] = useState(false);
  const [portas, setPortas] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const salvar = async () => {
    const r = await enviar("/api/vuln/modelos", { nome: nome.trim(), ferramenta, intrusiva, todas_portas: portas });
    if (!r.ok) {
      setErro(await detalhe(r, "Confira o nome do modelo."));
      return;
    }
    setNome("");
    setIntrusiva(false);
    setPortas(false);
    setErro(null);
    aoCriar();
    aoFechar();
  };
  return (
    <Modal opened={aberto} onClose={aoFechar} title="Novo modelo">
      <Stack gap="sm">
        <TextInput label="Nome" value={nome} onChange={(e) => setNome(e.currentTarget.value)} maxLength={120} error={erro} data-autofocus />
        <Select label="Tipo" allowDeselect={false} value={ferramenta} onChange={(v) => setFerramenta(v ?? "rede")} data={Object.entries(ROTULO_FERRAMENTA).map(([value, label]) => ({ value, label }))} />
        <Checkbox label="Intrusiva: tenta explorar a falha" checked={intrusiva} onChange={(e) => setIntrusiva(e.currentTarget.checked)} />
        <Checkbox label="Todas as portas, não só as comuns" checked={portas} onChange={(e) => setPortas(e.currentTarget.checked)} />
        <Group justify="flex-end">
          <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
          <Button variant="filled" onClick={salvar} disabled={!nome.trim()}>Criar</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function Modelos({ aoAbrirAlvo }: { aoAbrirAlvo: (id: number) => void }) {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<{ modelos: Modelo[] }>("/api/vuln/modelos");
  const { dados: dadosAlvos } = useDados<{ alvos: Alvo[] }>("/api/vuln/alvos");
  const [novo, setNovo] = useState(false);
  const [aberto, setAberto] = useState<Modelo | null>(null);
  if (!dados) return <Carregando erro={erro} />;
  const modoDe = (m: Modelo) => (m.intrusiva ? "Intrusiva" : "Não intrusiva");
  const portasDe = (m: Modelo) => (m.todas_portas ? "Todas" : "Comuns");
  return (
    <Painel titulo="Modelos" acao={pode("gerir_vulnerabilidades") && <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setNovo(true)}>Novo modelo</Button>}>
      <Tabela
        linhas={dados.modelos}
        chave={(m) => m.id}
        vazio="Crie um modelo para poder cadastrar alvos."
        aoClicarLinha={setAberto}
        colunas={[
          { titulo: "Modelo", celula: (m) => <Text size="sm" fw={500}>{m.nome}</Text> },
          { titulo: "Tipo", celula: (m) => ROTULO_FERRAMENTA[m.ferramenta] ?? m.ferramenta },
          { titulo: "Modo", celula: modoDe },
          { titulo: "Portas", celula: portasDe },
          { titulo: "Alvos", alinhar: "right", largura: 60, celula: (m) => numero((dadosAlvos?.alvos ?? []).filter((a) => a.modelo_id === m.id).length) },
        ]}
      />
      <NovoModelo aberto={novo} aoFechar={() => setNovo(false)} aoCriar={recarregar} />
      <Drawer opened={aberto !== null} onClose={() => setAberto(null)} title={aberto?.nome ?? ""} size="lg">
        {aberto && (
          <Stack gap="md">
            <SimpleGrid cols={3} spacing="sm">
              <Fato rotulo="Tipo">{ROTULO_FERRAMENTA[aberto.ferramenta] ?? aberto.ferramenta}</Fato>
              <Fato rotulo="Modo">{modoDe(aberto)}</Fato>
              <Fato rotulo="Portas">{portasDe(aberto)}</Fato>
            </SimpleGrid>
            <div>
              <Title order={3} mb={4}>Alvos que usam este modelo</Title>
              <Tabela
                linhas={(dadosAlvos?.alvos ?? []).filter((a) => a.modelo_id === aberto.id)}
                chave={(a) => a.id}
                vazio="Nenhum alvo usa este modelo."
                aoClicarLinha={(a) => aoAbrirAlvo(a.id)}
                colunas={[{ titulo: "Alvo", celula: (a) => a.nome }, { titulo: "Repetição", celula: textoDaRepeticao }, { titulo: "Próxima", largura: 150, celula: (a) => <Data valor={a.proxima_em} /> }]}
              />
            </div>
          </Stack>
        )}
      </Drawer>
    </Painel>
  );
}

function Varreduras() {
  const { dados, erro } = useDados<{ varreduras: Varredura[] }>("/api/vuln/varreduras");
  const [aberta, setAberta] = useState<Varredura | null>(null);
  if (!dados) return <Carregando erro={erro} />;
  return (
    <Painel p={0}>
      <TabelaDeVarreduras linhas={dados.varreduras} aoAbrir={setAberta} />
      <GavetaDaVarredura varredura={aberta} aoFechar={() => setAberta(null)} />
    </Painel>
  );
}

// ------------------------------------------------------------------ base de CVEs

interface Cve { cve: string; titulo: string | null; produto: string | null; cvss: number | null; epss: number | null; kev_desde: string | null; prioridade: string }
interface RespostaDeCves {
  cves: Cve[]; contagem: { prioridade: string; total: number }[];
  carga: { total: number; epss_data: string | null; carregada_em: string; falha: string | null; falha_em: string | null; velha: boolean } | null;
}

function BaseDeCves() {
  const eu = useEu();
  const [busca, setBusca] = useState("");
  const [prioridade, setPrioridade] = useState("todas");
  const [aberta, setAberta] = useState<string | null>(null);
  const [contagem, setContagem] = useState<RespostaDeCves["contagem"]>([]);
  const { dados, erro } = useDados<RespostaDeCves>(`/api/cves?${new URLSearchParams({ busca, prioridade: prioridade === "todas" ? "" : prioridade })}`);
  // A API só conta quando não há filtro: os números ficam, senão sumiriam ao clicar em um deles.
  useEffect(() => { if (dados?.contagem.length) setContagem(dados.contagem); }, [dados]);
  const carga = dados?.carga;
  return (
    <Stack gap="md">
      {carga?.velha && <Alert color="yellow" variant="light" p="xs">A base está com mais de 3 dias: uma CVE nova ou recém-explorada pode não aparecer aqui.</Alert>}
      {carga?.falha && <Alert color="red" variant="light" p="xs">{`A última atualização falhou em ${quando(carga.falha_em, eu.fuso)}: ${carga.falha} Continua valendo a base anterior.`}</Alert>}
      {contagem.length > 0 && (
        <SimpleGrid cols={{ base: 2, sm: 3, lg: 5 }} spacing="md">
          {ORDEM_DE_PRIORIDADE.map((p) => (
            <Tooltip key={p} label={explicaDaPrioridade(p)} multiline w={260}>
              <Box>
                <Numero
                  rotulo={textoDaPrioridade(p)}
                  valor={numero(contagem.find((c) => c.prioridade === p)?.total ?? 0)}
                  selecionado={prioridade === p}
                  aoClicar={() => setPrioridade((atual) => (atual === p ? "todas" : p))}
                />
              </Box>
            </Tooltip>
          ))}
        </SimpleGrid>
      )}
      <Painel
        titulo="CVEs"
        acao={(
          <Group gap="xs" wrap="wrap" justify="flex-end">
            <Busca valor={busca} aoMudar={setBusca} dica="CVE-2021-44228, ou uma palavra" />
            <Select w={190} aria-label="Prioridade" allowDeselect={false} value={prioridade} onChange={(v) => setPrioridade(v ?? "todas")} data={[{ value: "todas", label: "Todas as prioridades" }, { value: "agora", label: "Agora: exploração confirmada" }, { value: "alta", label: "Alta" }, { value: "media", label: "Média" }, { value: "baixa", label: "Baixa" }, { value: "sem_dados", label: "Sem nota" }]} />
          </Group>
        )}
      >
        {!dados ? <Carregando erro={erro} /> : (
          <Tabela
            linhas={dados.cves}
            chave={(c) => c.cve}
            vazio="Nenhuma CVE encontrada."
            aoClicarLinha={(c) => setAberta(c.cve)}
            colunas={[
              { titulo: "CVE", largura: 150, celula: (c) => <span className="mono" style={{ whiteSpace: "nowrap" }}>{c.cve}</span> },
              { titulo: "Prioridade", largura: 90, celula: (c) => <Prioridade valor={c.prioridade} /> },
              { titulo: "O que é", celula: (c) => c.titulo ?? c.produto ?? "-" },
              { titulo: "CVSS", alinhar: "right", largura: 60, celula: (c) => c.cvss ?? "-" },
              { titulo: "EPSS", alinhar: "right", largura: 70, celula: (c) => porcentoDeEpss(c.epss) },
              { titulo: "Explorada desde", largura: 110, celula: (c) => (c.kev_desde ? dataComAno(c.kev_desde) : "-") },
            ]}
          />
        )}
      </Painel>
      <Text size="xs" c="dimmed">
        {carga ? `${numero(carga.total)} registros, carregados em ${quando(carga.carregada_em, eu.fuso)}.${carga.epss_data ? ` EPSS de ${dataComAno(carga.epss_data)}.` : ""} ` : "A base de CVEs ainda não foi carregada. "}
        Dados do registro CVE, da NVD, do catálogo KEV da CISA e do EPSS, atualizados por eles. Este produto usa dados da API da NVD, mas não é endossado nem certificado pela NVD.
      </Text>
      <GavetaDaCve cve={aberta} aoFechar={() => setAberta(null)} />
    </Stack>
  );
}

// ------------------------------------------------------------------ tela

export function Vulnerabilidades() {
  const [aba, setAba] = useState("panorama");
  const [filtro, setFiltro] = useState<FiltroDeAchados>({ severidade: "todas", estado: "aberto" });
  const [alvoInicial, setAlvoInicial] = useState<number | null>(null);
  return (
    <>
      <Cabecalho titulo="Vulnerabilidades" ajuda="O que as varreduras encontraram, por ordem de risco. Abra um achado para ver como corrigir e para informar a correção: quem confirma é a varredura seguinte." />
      <Tabs value={aba} onChange={(v) => { setAba(v ?? "panorama"); setAlvoInicial(null); }}>
        <Tabs.List mb="md">
          <Tabs.Tab value="panorama">Panorama</Tabs.Tab>
          <Tabs.Tab value="achados">Achados</Tabs.Tab>
          <Tabs.Tab value="ativos">Ativos</Tabs.Tab>
          <Tabs.Tab value="alvos">Alvos</Tabs.Tab>
          <Tabs.Tab value="modelos">Modelos</Tabs.Tab>
          <Tabs.Tab value="varreduras">Varreduras</Tabs.Tab>
          <Tabs.Tab value="base">Base de CVEs</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="panorama"><Panorama aoVerAchados={(f) => { setFiltro(f); setAba("achados"); }} aoVerAtivos={() => setAba("ativos")} /></Tabs.Panel>
        <Tabs.Panel value="achados"><Achados filtro={filtro} aoMudarFiltro={setFiltro} /></Tabs.Panel>
        <Tabs.Panel value="ativos"><Ativos /></Tabs.Panel>
        <Tabs.Panel value="alvos"><Alvos alvoInicial={alvoInicial} aoVerVarreduras={() => setAba("varreduras")} /></Tabs.Panel>
        <Tabs.Panel value="modelos"><Modelos aoAbrirAlvo={(id) => { setAlvoInicial(id); setAba("alvos"); }} /></Tabs.Panel>
        <Tabs.Panel value="varreduras"><Varreduras /></Tabs.Panel>
        <Tabs.Panel value="base"><BaseDeCves /></Tabs.Panel>
      </Tabs>
    </>
  );
}
