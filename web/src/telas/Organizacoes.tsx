import { Alert, Button, Group, Modal, SimpleGrid, Stack, Text, TextInput } from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { useEffect, useState, type FormEvent } from "react";

import { detalhe, enviar, useDados, useEu } from "../api";
import { trocarDeOrganizacao } from "../trocarDeOrganizacao";
import { AcoesDaLinha, BlocoDeComando, Cabecalho, Carregando, Data, Estado, Numero, Painel, Tabela } from "../componentes";
import { numero } from "../formato";

interface Organizacao { id: string; nome: string; criado_em: string; usuarios: number; ativos: number; eventos_24h: number; ultimo_evento: string | null; removivel: boolean }
interface Pedido { id: number; acao: string; nome: string; email: string | null; estado: string; mensagem: string | null; criado_em: string }
interface Visao { organizacoes: Organizacao[]; pedidos: Pedido[] }

const ESTADOS: Record<string, string> = { pendente: "Na fila", em_andamento: "Em andamento", pronto: "Pronto", falhou: "Falhou" };
const TIPOS: Record<string, string> = { pendente: "pendente", em_andamento: "pendente", pronto: "ativa", falhou: "recusada" };

function NovaOrganizacao({ aberta, aoFechar, aoCriar }: { aberta: boolean; aoFechar: () => void; aoCriar: () => void }) {
  const [nome, setNome] = useState("");
  const [email, setEmail] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const [senha, setSenha] = useState<string | null>(null);

  const fechar = () => {
    setNome("");
    setEmail("");
    setErro(null);
    setSenha(null);
    aoFechar();
  };

  const criar = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const r = await enviar("/api/organizacoes", { nome, email });
    if (!r.ok) {
      setErro(await detalhe(r, "Confira o nome e o e-mail."));
      return;
    }
    setErro(null);
    setSenha((await r.json()).senha_temporaria);
    aoCriar();
  };

  // A senha só aparece esta vez: nada de fechar por engano clicando fora.
  return (
    <Modal opened={aberta} onClose={fechar} title="Nova organização" closeOnClickOutside={!senha} closeOnEscape={!senha}>
      {senha ? (
        <Stack gap="sm">
          <Text size="sm">Pedido registrado. A organização fica pronta em alguns minutos. Passe esta senha temporária a {email}: ela não aparece de novo, e será trocada no primeiro acesso.</Text>
          <BlocoDeComando texto={senha} />
          <Group justify="flex-end"><Button variant="filled" onClick={fechar}>Já guardei</Button></Group>
        </Stack>
      ) : (
        <form onSubmit={criar} noValidate>
          <Stack gap="sm">
            <TextInput label="Nome da organização" value={nome} onChange={(e) => setNome(e.currentTarget.value)} maxLength={120} data-autofocus />
            <TextInput label="E-mail de quem vai administrar" type="email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} maxLength={254} />
            <Text size="xs" c="dimmed">Cada organização tem o próprio gerenciador, que ocupa cerca de 1 GB de memória.</Text>
            {erro && <Alert color="red" variant="light" p="xs"><Text size="sm">{erro}</Text></Alert>}
            <Group justify="flex-end">
              <Button variant="subtle" color="gray" onClick={fechar}>Cancelar</Button>
              <Button type="submit" variant="filled" disabled={!nome.trim() || !email.trim()}>Criar</Button>
            </Group>
          </Stack>
        </form>
      )}
    </Modal>
  );
}

function RemoverOrganizacao({ org, aoFechar, aoRemover }: { org: Organizacao | null; aoFechar: () => void; aoRemover: () => void }) {
  const [confirmacao, setConfirmacao] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => { setConfirmacao(""); setErro(null); }, [org]);
  const remover = async () => {
    const r = await enviar(`/api/organizacoes/${org!.id}/remover`, { confirmacao });
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível pedir a remoção."));
      return;
    }
    aoRemover();
    aoFechar();
  };
  return (
    <Modal opened={org !== null} onClose={aoFechar} title={`Remover ${org?.nome ?? ""}`}>
      <Stack gap="sm">
        <Alert color="red" variant="light" p="xs"><Text size="sm">Apaga eventos, regras, pessoas e o gerenciador desta organização. Não tem volta. Os selos de integridade ficam, porque são prova.</Text></Alert>
        <TextInput label={`Digite ${org?.nome ?? ""} para confirmar`} value={confirmacao} onChange={(e) => setConfirmacao(e.currentTarget.value)} data-autofocus error={erro} />
        <Group justify="flex-end">
          <Button variant="subtle" color="gray" onClick={aoFechar}>Cancelar</Button>
          <Button color="red" variant="filled" disabled={confirmacao !== org?.nome} onClick={remover}>Remover</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

export function Organizacoes() {
  const eu = useEu();
  const entrar = (o: Organizacao) => trocarDeOrganizacao(`/api/organizacoes/${o.id}/entrar`);
  const { dados, erro, recarregar } = useDados<Visao>("/api/organizacoes");
  const [nova, setNova] = useState(false);
  const [remover, setRemover] = useState<Organizacao | null>(null);

  const emAndamento = dados?.pedidos.some((p) => p.estado === "pendente" || p.estado === "em_andamento");
  useEffect(() => {
    if (!emAndamento) return;
    const t = setInterval(recarregar, 10000);
    return () => clearInterval(t);
  }, [emAndamento, recarregar]);

  return (
    <>
      <Cabecalho titulo="Organizações" ajuda="As empresas atendidas por esta instalação. Os dados de cada uma ficam isolados das outras.">
        <Button variant="filled" leftSection={<IconPlus size={14} />} onClick={() => setNova(true)}>Nova organização</Button>
      </Cabecalho>
      {!dados ? <Carregando erro={erro} /> : (
        <Stack gap="md">
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <Numero rotulo="Organizações" valor={numero(dados.organizacoes.length)} />
            <Numero rotulo="Ativos no total" valor={numero(dados.organizacoes.reduce((t, o) => t + Number(o.ativos), 0))} />
            <Numero rotulo="Eventos em 24 horas" valor={numero(dados.organizacoes.reduce((t, o) => t + Number(o.eventos_24h), 0))} />
          </SimpleGrid>
          <Painel p={0}>
            <Tabela
              linhas={dados.organizacoes}
              chave={(o) => o.id}
              vazio="Nenhuma organização."
              aoClicarLinha={(o) => { if (o.id !== eu.cliente_id) entrar(o); }}
              colunas={[
                { titulo: "Organização", celula: (o) => <Group gap="xs" wrap="nowrap"><Text size="sm" fw={500}>{o.nome}</Text>{o.id === eu.cliente_id && <Estado tipo="ativo">Você está aqui</Estado>}</Group> },
                { titulo: "Pessoas", alinhar: "right", largura: 80, celula: (o) => numero(o.usuarios) },
                { titulo: "Ativos", alinhar: "right", largura: 80, celula: (o) => numero(o.ativos) },
                { titulo: "Eventos em 24 h", alinhar: "right", largura: 120, celula: (o) => numero(o.eventos_24h) },
                { titulo: "Último evento", largura: 150, celula: (o) => <Data valor={o.ultimo_evento} /> },
                { titulo: "Criada em", largura: 150, celula: (o) => <Data valor={o.criado_em} /> },
                { titulo: "", largura: 40, celula: (o) => <AcoesDaLinha rotulo={`Ações de ${o.nome}`} itens={[
                  ...(o.id === eu.cliente_id ? [] : [{ texto: "Entrar", aoClicar: () => entrar(o) }]),
                  ...(o.removivel ? [{ texto: "Remover", perigo: true, aoClicar: () => setRemover(o) }] : []),
                ]} /> },
              ]}
            />
          </Painel>
          {dados.pedidos.length > 0 && (
            <Painel titulo="Pedidos recentes">
              <Tabela
                linhas={dados.pedidos}
                chave={(p) => p.id}
                vazio=""
                colunas={[
                  { titulo: "Pedido", celula: (p) => `${p.acao === "criar" ? "Criar" : "Remover"} ${p.nome}` },
                  { titulo: "Quando", largura: 150, celula: (p) => <Data valor={p.criado_em} /> },
                  { titulo: "Situação", celula: (p) => <Group gap="xs"><Estado tipo={TIPOS[p.estado] ?? "outro"}>{ESTADOS[p.estado] ?? p.estado}</Estado>{p.mensagem && <Text size="xs" c="dimmed">{p.mensagem}</Text>}</Group> },
                ]}
              />
            </Painel>
          )}
        </Stack>
      )}
      <NovaOrganizacao aberta={nova} aoFechar={() => setNova(false)} aoCriar={recarregar} />
      <RemoverOrganizacao org={remover} aoFechar={() => setRemover(null)} aoRemover={recarregar} />
    </>
  );
}
