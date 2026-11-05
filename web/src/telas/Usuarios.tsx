import { Alert, Box, Button, Checkbox, CopyButton, Drawer, Group, Modal, Select, SimpleGrid, Stack, Switch, Tabs, Text, TextInput } from "@mantine/core";
import { IconCheck, IconCopy, IconPlus } from "@tabler/icons-react";
import { useMemo, useState, type FormEvent, type ReactNode } from "react";

import { detalhe, enviar, useDados } from "../api";
import { AcoesDaLinha, Busca, Cabecalho, Carregando, Data, Estado, Numero, Painel, Tabela } from "../componentes";
import { numero } from "../formato";

interface Usuario { id: string; email: string; nome: string; perfil: string; ativo: boolean; criado_em: string | null; mfa_ativo: boolean }

const NOMES_DE_PERFIL: Record<string, string> = { administrador: "Administração", engenharia: "Engenharia de detecção", analista_n2: "Analista N2", analista_n1: "Analista N1", auditor: "Auditoria" };
const OPCOES_DE_PERFIL = Object.entries(NOMES_DE_PERFIL).map(([value, label]) => ({ value, label }));

const O_QUE_CADA_UM_FAZ: [string, string][] = [
  ["Ver painéis, fila, eventos, regras e fontes", "ver"], ["Ver log e alerta brutos", "ver_bruto"], ["Ver dados pessoais sem máscara", "ver_dado_pessoal"], ["Encerrar risco dizendo o que era", "triar"], ["Decidir aprovações da automação", "aprovar"],
  ["Criar e mudar regras", "gerir_regras"], ["Criar e mudar playbooks", "gerir_playbooks"], ["Criar e mudar fontes de dados", "gerir_fontes"],
  ["Ver o comando de instalação de agente", "instalar_agente"], ["Gerir usuários", "gerir_usuarios"], ["Ver a trilha de auditoria e os avisos", "ver_auditoria"], ["Gerir varreduras, pesos e aceite de risco", "gerir_vulnerabilidades"],
];
const PERMISSOES_POR_PERFIL: Record<string, string[]> = {
  administrador: ["ver", "ver_bruto", "ver_dado_pessoal", "triar", "aprovar", "gerir_regras", "gerir_playbooks", "gerir_fontes", "instalar_agente", "gerir_usuarios", "ver_auditoria", "gerir_vulnerabilidades"],
  engenharia: ["ver", "ver_bruto", "gerir_regras", "gerir_playbooks", "gerir_fontes", "instalar_agente", "gerir_vulnerabilidades"],
  analista_n2: ["ver", "ver_bruto", "ver_dado_pessoal", "triar", "aprovar"],
  analista_n1: ["ver", "ver_bruto", "triar"],
  auditor: ["ver", "ver_auditoria"],
};

const CATEGORIAS_DE_DADO: [string, string, string][] = [
  ["usuario", "Nome de usuário", "Vira um apelido, como usuario-3f9a2c: o mesmo usuário tem sempre o mesmo apelido."],
  ["ip", "Endereço IP", "Ficam só os dois primeiros números, como 203.0.x.x."],
  ["email", "E-mail", "Fica a primeira letra e o domínio, como m***@exemplo.com."],
  ["cpf", "CPF", "Só os números válidos, achados em qualquer texto do log."],
  ["cnpj", "CNPJ", "Só os números válidos, achados em qualquer texto do log."],
  ["cartao", "Cartão de pagamento", "Ficam os quatro últimos dígitos."],
  ["telefone", "Telefone", "Números no formato brasileiro, como (41) 99876-5432."],
];

function DadosPessoais() {
  const { dados, recarregar } = useDados<{ ofuscar: string[] }>("/api/eu");
  const [erro, setErro] = useState<string | null>(null);
  if (!dados) return <Carregando />;
  const marcadas = new Set(dados.ofuscar);
  const mudar = async (categoria: string, ligar: boolean) => {
    setErro(null);
    const categorias = CATEGORIAS_DE_DADO.map(([c]) => c).filter((c) => (c === categoria ? ligar : marcadas.has(c)));
    const r = await colocar("/api/organizacao/ofuscacao", { categorias });
    if (!r.ok) setErro(await detalhe(r, "Não foi possível mudar."));
    recarregar();
  };
  return (
    <Painel titulo="Dados pessoais mascarados">
      <Stack gap="sm">
        <Text size="sm">
          Para quem não tem o perfil {NOMES_DE_PERFIL.administrador} ou {NOMES_DE_PERFIL.analista_n2}, o que estiver marcado aparece mascarado em eventos, logs, fila, riscos e relatórios.
          O log guardado não muda, então a prova de integridade continua valendo. Quem vê mascarado não gera pacote de evidência, porque o pacote leva o log original.
        </Text>
        <Erro texto={erro} />
        {CATEGORIAS_DE_DADO.map(([c, rotulo, explicacao]) => (
          <Checkbox key={c} label={rotulo} description={explicacao} checked={marcadas.has(c)} onChange={(e) => mudar(c, e.currentTarget.checked)} />
        ))}
      </Stack>
    </Painel>
  );
}

// api.ts só sabe enviar POST, e estas rotas são PUT.
async function colocar(rota: string, corpo: unknown) {
  const r = await fetch(rota, { method: "PUT", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo) });
  if (r.status === 401) window.location.assign("/");
  return r;
}

function Fato({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return (
    <Group justify="space-between" gap="lg" wrap="nowrap" align="flex-start">
      <Text size="sm" c="dimmed" style={{ whiteSpace: "nowrap" }}>{rotulo}</Text>
      <Text span size="sm" ta="right" style={{ overflowWrap: "anywhere" }}>{children}</Text>
    </Group>
  );
}

function Erro({ texto }: { texto: string | null }) {
  return texto ? <Alert color="red" variant="light" p="xs" fz="sm">{texto}</Alert> : null;
}

function NovoUsuario({ aoFechar, aoCriar }: { aoFechar: () => void; aoCriar: (nome: string, senha: string) => void }) {
  const [nome, setNome] = useState("");
  const [email, setEmail] = useState("");
  const [perfil, setPerfil] = useState("analista_n1");
  const [erro, setErro] = useState<string | null>(null);
  const salvar = async (e: FormEvent) => {
    e.preventDefault();
    setErro(null);
    const r = await enviar("/api/usuarios", { nome: nome.trim(), email: email.trim(), perfil });
    if (!r.ok) {
      setErro(await detalhe(r, "Confira o nome e o e-mail."));
      return;
    }
    const { senha_temporaria: senha } = await r.json() as { senha_temporaria: string };
    aoCriar(nome.trim(), senha);
  };
  return (
    <form onSubmit={salvar} noValidate autoComplete="off">
      <Stack gap="sm">
        <TextInput label="Nome" maxLength={120} value={nome} onChange={(e) => setNome(e.currentTarget.value)} data-autofocus />
        <TextInput label="E-mail" type="email" maxLength={254} value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
        <Select label="Perfil" allowDeselect={false} value={perfil} onChange={(v) => setPerfil(v ?? "analista_n1")} data={OPCOES_DE_PERFIL} />
        <Erro texto={erro} />
        <Group justify="flex-end" mt="xs">
          <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
          <Button variant="filled" type="submit" disabled={!nome.trim() || !email.trim()}>Criar</Button>
        </Group>
      </Stack>
    </form>
  );
}

/** A senha só existe nesta janela: não dá para voltar e ver de novo, então fechar é sempre um clique de propósito. */
function SenhaTemporaria({ senha, aoFechar }: { senha: { texto: string; valor: string } | null; aoFechar: () => void }) {
  return (
    <Modal opened={senha !== null} onClose={aoFechar} title="Senha temporária" closeOnClickOutside={false} closeOnEscape={false}>
      {senha && (
        <Stack gap="sm">
          <Text size="sm">{senha.texto}</Text>
          <Box component="pre" className="mono" m={0} p="sm" style={{ background: "var(--mantine-color-dark-8)", border: "1px solid var(--roar-borda)", borderRadius: 6, whiteSpace: "pre-wrap" }}>{senha.valor}</Box>
          <Group justify="flex-end">
            <CopyButton value={senha.valor}>
              {({ copied, copy }) => <Button leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy}>{copied ? "Copiado" : "Copiar"}</Button>}
            </CopyButton>
            <Button variant="filled" onClick={aoFechar}>Já guardei</Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}

function SituacaoDoUsuario({ ativo }: { ativo: boolean }) {
  return <Estado tipo={ativo ? "ativo" : "outro"}>{ativo ? "Ativo" : "Desativado"}</Estado>;
}

function Autenticador({ ligado }: { ligado: boolean }) {
  return <Estado tipo={ligado ? "ativo" : "pendente"}>{ligado ? "Ligado" : "Desligado"}</Estado>;
}

function TabelaDePerfis() {
  const perfis = Object.keys(NOMES_DE_PERFIL);
  return (
    <Painel p={0}>
      <Tabela
        linhas={O_QUE_CADA_UM_FAZ}
        chave={([, chave]) => chave}
        vazio=""
        colunas={[
          { titulo: "Permissão", celula: ([texto]) => texto },
          ...perfis.map((p) => ({
            titulo: NOMES_DE_PERFIL[p],
            celula: ([, chave]: [string, string]) => (PERMISSOES_POR_PERFIL[p].includes(chave)
              ? <Group gap={4} wrap="nowrap"><IconCheck size={14} color="var(--mantine-color-rosa-3)" /><Text span size="sm">Sim</Text></Group>
              : <Text span size="sm" c="dimmed">-</Text>),
          })),
        ]}
      />
    </Painel>
  );
}

interface Confirmacao { titulo: string; texto: string; rotulo: string; acao: () => Promise<void> }

export function Usuarios() {
  const { dados, erro: erroAoLer, recarregar } = useDados<{ usuarios: Usuario[]; eu: string }>("/api/usuarios");
  // O Eu da aplicação não traz a política: ela só interessa nesta tela.
  const { dados: minhaConta, recarregar: recarregarConta } = useDados<{ mfa_obrigatorio: boolean }>("/api/eu");
  const [busca, setBusca] = useState("");
  const [filtro, setFiltro] = useState<"ativos" | "desativados" | "sem_autenticador" | null>(null);
  const [novo, setNovo] = useState(false);
  const [idAberto, setIdAberto] = useState<string | null>(null);
  const [senha, setSenha] = useState<{ texto: string; valor: string } | null>(null);
  const [confirmar, setConfirmar] = useState<Confirmacao | null>(null);
  const [erro, setErro] = useState<string | null>(null);

  const usuarios = useMemo(() => dados?.usuarios ?? [], [dados]);
  const linhas = useMemo(() => {
    const termo = busca.trim().toLowerCase();
    return usuarios.filter((u) => {
      if (filtro === "ativos" && !u.ativo) return false;
      if (filtro === "desativados" && u.ativo) return false;
      if (filtro === "sem_autenticador" && (!u.ativo || u.mfa_ativo)) return false;
      return !termo || u.nome.toLowerCase().includes(termo) || u.email.toLowerCase().includes(termo);
    });
  }, [usuarios, busca, filtro]);
  const aberto = usuarios.find((u) => u.id === idAberto) ?? null;
  const alternar = (f: NonNullable<typeof filtro>) => () => setFiltro((a) => (a === f ? null : f));

  const alterar = async (u: Usuario, mudanca: Partial<Pick<Usuario, "perfil" | "ativo">>) => {
    setErro(null);
    const r = await colocar(`/api/usuarios/${u.id}`, { perfil: u.perfil, ativo: u.ativo, ...mudanca });
    if (!r.ok) setErro(await detalhe(r, "Não foi possível alterar."));
    recarregar();
  };
  const pedirDesativar = (u: Usuario) => {
    if (!u.ativo) {
      alterar(u, { ativo: true });
      return;
    }
    setConfirmar({ titulo: `Desativar ${u.nome}?`, texto: "As sessões abertas dessa pessoa são encerradas na hora.", rotulo: "Desativar", acao: () => alterar(u, { ativo: false }) });
  };
  const pedirNovaSenha = (u: Usuario) => setConfirmar({
    titulo: `Redefinir a senha de ${u.nome}?`, texto: "A senha atual deixa de valer, e no próximo acesso a pessoa precisa trocar a temporária.", rotulo: "Redefinir",
    acao: async () => {
      setErro(null);
      const r = await enviar(`/api/usuarios/${u.id}/nova-senha`);
      if (!r.ok) {
        setErro(await detalhe(r, "Não foi possível redefinir."));
        return;
      }
      const { senha_temporaria: valor } = await r.json() as { senha_temporaria: string };
      setSenha({ texto: `Senha temporária de ${u.nome}. Ela não aparece de novo.`, valor });
    },
  });
  const pedirRemoverMfa = (u: Usuario) => setConfirmar({
    titulo: `Remover o autenticador de ${u.nome}?`, texto: "As sessões abertas dessa pessoa serão encerradas.", rotulo: "Remover",
    acao: async () => {
      setErro(null);
      const r = await enviar(`/api/usuarios/${u.id}/mfa/remover`);
      if (!r.ok) setErro(await detalhe(r, "Não foi possível remover."));
      recarregar();
    },
  });
  const mudarPolitica = async (obrigatorio: boolean) => {
    setErro(null);
    const r = await colocar("/api/organizacao/mfa", { obrigatorio });
    if (!r.ok) setErro(await detalhe(r, "Não foi possível mudar."));
    recarregarConta();
  };
  const executar = async () => {
    const c = confirmar;
    setConfirmar(null);
    await c?.acao();
  };
  const podeRemoverMfa = (u: Usuario) => u.mfa_ativo && u.id !== dados?.eu;

  return (
    <>
      <Cabecalho titulo="Usuários" ajuda="Quem entra na console e o que cada pessoa pode fazer. Mudar o perfil ou desativar encerra as sessões abertas daquela pessoa na hora.">
        <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setNovo(true)}>Novo usuário</Button>
      </Cabecalho>
      {!dados ? <Carregando erro={erroAoLer} /> : (
        <Tabs defaultValue="pessoas">
          <Tabs.List mb="md">
            <Tabs.Tab value="pessoas">Pessoas</Tabs.Tab>
            <Tabs.Tab value="perfis">O que cada perfil pode fazer</Tabs.Tab>
            <Tabs.Tab value="dados">Dados pessoais</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="pessoas">
            <Stack gap="md">
              <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
                <Numero rotulo="Ativos" valor={numero(usuarios.filter((u) => u.ativo).length)} aoClicar={alternar("ativos")} selecionado={filtro === "ativos"} />
                <Numero rotulo="Desativados" valor={numero(usuarios.filter((u) => !u.ativo).length)} aoClicar={alternar("desativados")} selecionado={filtro === "desativados"} />
                <Numero rotulo="Ativos sem autenticador" valor={numero(usuarios.filter((u) => u.ativo && !u.mfa_ativo).length)} aoClicar={alternar("sem_autenticador")} selecionado={filtro === "sem_autenticador"} />
              </SimpleGrid>
              {erro && !aberto && <Erro texto={erro} />}
              <Painel
                titulo="Pessoas"
                acao={(
                  <Group gap="lg" wrap="wrap" justify="flex-end">
                    <Switch size="xs" label="Exigir o autenticador de todos" checked={Boolean(minhaConta?.mfa_obrigatorio)} disabled={!minhaConta} onChange={(e) => mudarPolitica(e.currentTarget.checked)} />
                    <Busca valor={busca} aoMudar={setBusca} dica="Nome ou e-mail" />
                  </Group>
                )}
              >
                <Tabela
                  linhas={linhas}
                  chave={(u) => u.id}
                  vazio="Nenhuma pessoa com esse filtro."
                  aoClicarLinha={(u) => { setErro(null); setIdAberto(u.id); }}
                  colunas={[
                    { titulo: "Nome", celula: (u) => <Text size="sm" fw={500}>{u.id === dados.eu ? `${u.nome} (você)` : u.nome}</Text> },
                    { titulo: "E-mail", celula: (u) => <span className="mono">{u.email}</span> },
                    { titulo: "Perfil", celula: (u) => NOMES_DE_PERFIL[u.perfil] ?? u.perfil },
                    { titulo: "Situação", largura: 110, celula: (u) => <SituacaoDoUsuario ativo={u.ativo} /> },
                    { titulo: "Autenticador", largura: 110, celula: (u) => <Autenticador ligado={u.mfa_ativo} /> },
                    { titulo: "", largura: 40, celula: (u) => (
                      <AcoesDaLinha rotulo={`Ações de ${u.nome}`} itens={[
                        { texto: "Mudar perfil", aoClicar: () => { setErro(null); setIdAberto(u.id); } },
                        { texto: "Redefinir senha", aoClicar: () => pedirNovaSenha(u) },
                        ...(podeRemoverMfa(u) ? [{ texto: "Remover autenticador", perigo: true, aoClicar: () => pedirRemoverMfa(u) }] : []),
                        { texto: u.ativo ? "Desativar" : "Reativar", perigo: u.ativo, aoClicar: () => pedirDesativar(u) },
                      ]} />
                    ) },
                  ]}
                />
              </Painel>
            </Stack>
          </Tabs.Panel>
          <Tabs.Panel value="perfis"><TabelaDePerfis /></Tabs.Panel>
          <Tabs.Panel value="dados"><DadosPessoais /></Tabs.Panel>
        </Tabs>
      )}

      <Drawer opened={aberto !== null} onClose={() => setIdAberto(null)} closeOnEscape={!confirmar && !senha} title={aberto ? (aberto.id === dados?.eu ? `${aberto.nome} (você)` : aberto.nome) : ""} size="md">
        {aberto && (
          <Stack gap="md">
            <Erro texto={erro} />
            <Select label="Perfil" description="Mudar encerra as sessões abertas." allowDeselect={false} value={aberto.perfil} data={OPCOES_DE_PERFIL} onChange={(v) => { if (v && v !== aberto.perfil) alterar(aberto, { perfil: v }); }} />
            <Stack gap={8}>
              <Fato rotulo="E-mail"><span className="mono">{aberto.email}</span></Fato>
              <Fato rotulo="Situação"><SituacaoDoUsuario ativo={aberto.ativo} /></Fato>
              <Fato rotulo="Autenticador"><Autenticador ligado={aberto.mfa_ativo} /></Fato>
              <Fato rotulo="Criado em"><Data valor={aberto.criado_em} /></Fato>
            </Stack>
            <Group gap="xs">
              <Button onClick={() => pedirNovaSenha(aberto)}>Redefinir senha</Button>
              {podeRemoverMfa(aberto) && <Button onClick={() => pedirRemoverMfa(aberto)}>Remover autenticador</Button>}
              <Button onClick={() => pedirDesativar(aberto)}>{aberto.ativo ? "Desativar" : "Reativar"}</Button>
            </Group>
          </Stack>
        )}
      </Drawer>

      <Modal opened={novo} onClose={() => setNovo(false)} title="Novo usuário">
        <NovoUsuario
          aoFechar={() => setNovo(false)}
          aoCriar={(nome, valor) => {
            setNovo(false);
            setSenha({ texto: `Senha temporária de ${nome}. Ela não aparece de novo, e no primeiro acesso precisa ser trocada.`, valor });
            recarregar();
          }}
        />
      </Modal>

      <Modal opened={confirmar !== null} onClose={() => setConfirmar(null)} title={confirmar?.titulo ?? ""}>
        <Stack gap="sm">
          <Text size="sm">{confirmar?.texto}</Text>
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={() => setConfirmar(null)}>Cancelar</Button>
            <Button variant="filled" onClick={executar}>{confirmar?.rotulo}</Button>
          </Group>
        </Stack>
      </Modal>

      <SenhaTemporaria senha={senha} aoFechar={() => setSenha(null)} />
    </>
  );
}
