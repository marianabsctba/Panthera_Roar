import { Button, Code, CopyButton, Drawer, Group, Modal, Select, Stack, Text, Textarea, TextInput, Title } from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";

import { detalhe, enviar, pedir, useDados, usePode } from "../api";
import { AcoesDaLinha, Busca, Carregando, Data, Painel, Tabela } from "../componentes";
import { numero } from "../formato";

interface Lista { id: number; nome: string; titulo: string; descricao: string; tipo: string; criada_em: string; alterada_em: string; itens: number }
interface Item { valor: string; nota: string; adicionado_em: string }
interface ListaAberta extends Omit<Lista, "itens"> { itens: Item[]; regra: string; campo: string }

const DICAS: Record<string, string> = {
  ip: "Um endereço por linha. Redes /8, /16 e /24 também valem, como 10.20.0.0/16.",
  usuario: "Um usuário por linha, do jeito que aparece nos eventos.",
  dominio: "Um domínio por linha, como exemplo.com.br.",
  hash: "Um hash por linha: MD5, SHA-1 ou SHA-256.",
  texto: "Um valor por linha.",
};

/** "nome-da-lista" a partir do título, sem acento: é o nome do arquivo no gerenciador. */
const nomeDoTitulo = (titulo: string) => titulo.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63);

/** O prefixo que o gerenciador compara, 10.20., aparece como a rede que a pessoa digitou, 10.20.0.0/16. */
const comoRede = (valor: string) => {
  if (!/^(\d{1,3}\.){1,3}$/.test(valor)) return valor;
  const partes = valor.slice(0, -1).split(".");
  return `${[...partes, ...Array(4 - partes.length).fill("0")].join(".")}/${partes.length * 8}`;
};

/** Cada linha é um item; o que vem depois de ponto e vírgula é a nota. */
function lerItens(texto: string) {
  return texto.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
    const [valor, ...nota] = l.split(";");
    return { valor: valor.trim(), nota: nota.join(";").trim() };
  });
}

function NovaLista({ aberta, tipos, aoFechar, aoCriar }: { aberta: boolean; tipos: Record<string, string>; aoFechar: () => void; aoCriar: (id: number) => void }) {
  const [titulo, setTitulo] = useState("");
  const [nome, setNome] = useState("");
  const [nomeMexido, setNomeMexido] = useState(false);
  const [tipo, setTipo] = useState("ip");
  const [descricao, setDescricao] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => { if (aberta) { setTitulo(""); setNome(""); setNomeMexido(false); setTipo("ip"); setDescricao(""); setErro(null); } }, [aberta]);
  const criar = async () => {
    const r = await enviar("/api/listas", { titulo, nome: nomeMexido ? nome : nomeDoTitulo(titulo), tipo, descricao });
    if (r.ok) aoCriar((await r.json()).id);
    else setErro(await detalhe(r));
  };
  return (
    <Modal opened={aberta} onClose={aoFechar} title="Nova lista de observação">
      <Stack gap="sm">
        <TextInput label="Título" placeholder="IPs bloqueados no firewall" value={titulo} onChange={(e) => setTitulo(e.currentTarget.value)} data-autofocus />
        <TextInput label="Nome na regra" description="Vai no caminho que a regra consulta. Não muda depois." classNames={{ input: "mono" }}
          value={nomeMexido ? nome : nomeDoTitulo(titulo)} onChange={(e) => { setNomeMexido(true); setNome(e.currentTarget.value); }} />
        <Select label="O que a lista guarda" allowDeselect={false} value={tipo} onChange={(v) => setTipo(v ?? "ip")} data={Object.entries(tipos).map(([value, label]) => ({ value, label }))} />
        <Textarea label="Para que serve" autosize minRows={2} value={descricao} onChange={(e) => setDescricao(e.currentTarget.value)} />
        {erro && <Text size="sm" c="red">{erro}</Text>}
        <Group justify="flex-end"><Button variant="filled" onClick={criar} disabled={!titulo.trim()}>Criar</Button></Group>
      </Stack>
    </Modal>
  );
}

function GavetaDaLista({ id, aoFechar, aoMudar, aoCriarRegra }: { id: number | null; aoFechar: () => void; aoMudar: () => void; aoCriarRegra: (xml: string) => void }) {
  const pode = usePode();
  const { dados: l, erro, recarregar } = useDados<ListaAberta>(id === null ? null : `/api/listas/${id}`);
  const [colados, setColados] = useState("");
  const [busca, setBusca] = useState("");
  const [aviso, setAviso] = useState<{ ok: boolean; texto: string } | null>(null);
  const [apagando, setApagando] = useState(false);
  useEffect(() => { setColados(""); setBusca(""); setAviso(null); }, [id]);
  const itens = useMemo(() => {
    const termo = busca.trim().toLowerCase();
    return (l?.itens ?? []).filter((i) => !termo || i.valor.toLowerCase().includes(termo) || i.nota.toLowerCase().includes(termo));
  }, [l, busca]);
  const mudou = () => { recarregar(); aoMudar(); };
  const acrescentar = async () => {
    const novos = lerItens(colados);
    const r = await enviar(`/api/listas/${id}/itens`, { itens: novos });
    if (r.ok) { setColados(""); setAviso({ ok: true, texto: `${numero((await r.json()).gravados)} itens gravados. Chegam ao gerenciador em alguns minutos.` }); mudou(); }
    else setAviso({ ok: false, texto: await detalhe(r) });
  };
  const tirar = async (valor: string) => {
    const r = await enviar(`/api/listas/${id}/itens/remover`, { valores: [valor] });
    if (r.ok) mudou();
    else setAviso({ ok: false, texto: await detalhe(r) });
  };
  const apagar = async () => {
    const r = await pedir(`/api/listas/${id}`, { method: "DELETE" });
    setApagando(false);
    if (r.ok) { aoMudar(); aoFechar(); }
    else setAviso({ ok: false, texto: await detalhe(r) });
  };
  return (
    <Drawer opened={id !== null} onClose={aoFechar} title={l?.titulo ?? ""} size="70%">
      {!l ? <Carregando erro={erro} /> : (
        <Stack gap="md">
          {l.descricao && <Text size="sm">{l.descricao}</Text>}
          <Text size="xs" c="dimmed">Arquivo no gerenciador: <span className="mono">etc/lists/roar/{l.nome}</span></Text>

          {pode("gerir_regras") && (
            <Stack gap={8}>
              <Title order={2}>Acrescentar itens</Title>
              <Textarea autosize minRows={3} maxRows={10} classNames={{ input: "mono" }} placeholder={DICAS[l.tipo]} value={colados} onChange={(e) => setColados(e.currentTarget.value)}
                description={`${DICAS[l.tipo]} Para pôr uma nota, escreva depois de ponto e vírgula: 203.0.113.9; scanner conhecido.`} />
              <Group gap="sm">
                <Button variant="filled" onClick={acrescentar} disabled={!colados.trim()}>Acrescentar {colados.trim() ? numero(lerItens(colados).length) : ""}</Button>
                {aviso && <Text size="sm" c={aviso.ok ? "dimmed" : "red"}>{aviso.texto}</Text>}
              </Group>
            </Stack>
          )}

          <Painel titulo={`Itens (${numero(l.itens.length)})`} acao={<Busca valor={busca} aoMudar={setBusca} dica="Valor ou nota" />}>
            <Tabela
              linhas={itens.slice(0, 500)}
              chave={(i) => i.valor}
              vazio={l.itens.length ? "Nenhum item com essa busca." : "A lista ainda está vazia."}
              colunas={[
                { titulo: "Valor", celula: (i) => <span className="mono">{l.tipo === "ip" ? comoRede(i.valor) : i.valor}</span> },
                { titulo: "Nota", celula: (i) => <Text size="sm" c="dimmed">{i.nota || "-"}</Text> },
                { titulo: "Desde", largura: 150, celula: (i) => <Data valor={i.adicionado_em} /> },
                ...(pode("gerir_regras") ? [{ titulo: "", largura: 40, celula: (i: Item) => <AcoesDaLinha rotulo={`Ações de ${i.valor}`} itens={[{ texto: "Tirar da lista", aoClicar: () => tirar(i.valor) }]} /> }] : []),
              ]}
            />
            {itens.length > 500 && <Text size="xs" c="dimmed" mt="xs">Mostrando 500 de {numero(itens.length)}. Use a busca para achar um item.</Text>}
          </Painel>

          <Stack gap={8}>
            <Title order={2}>Usar numa regra</Title>
            <Text size="sm">A regra consulta a lista pelo caminho do arquivo. Este exemplo alerta quando o campo <span className="mono">{l.campo}</span> do evento está na lista. Troque o campo se precisar.</Text>
            <Code block>{l.regra}</Code>
            <Group gap="sm">
              {pode("gerir_regras") && <Button variant="filled" onClick={() => aoCriarRegra(l.regra)}>Criar regra com esta lista</Button>}
              <CopyButton value={l.regra}>{({ copied, copy }) => <Button onClick={copy}>{copied ? "Copiado" : "Copiar"}</Button>}</CopyButton>
            </Group>
          </Stack>

          {pode("gerir_regras") && <Group><Button color="red" variant="subtle" onClick={() => setApagando(true)}>Apagar a lista</Button></Group>}
          <Modal opened={apagando} onClose={() => setApagando(false)} title="Apagar a lista?">
            <Stack gap="sm">
              <Text size="sm">A lista {l.titulo} e os {numero(l.itens.length)} itens dela saem. Regra que ainda consulta a lista para de achar qualquer item.</Text>
              <Group justify="flex-end"><Button onClick={() => setApagando(false)}>Cancelar</Button><Button color="red" variant="filled" onClick={apagar}>Apagar</Button></Group>
            </Stack>
          </Modal>
        </Stack>
      )}
    </Drawer>
  );
}

export function Listas({ aoCriarRegra }: { aoCriarRegra: (xml: string) => void }) {
  const pode = usePode();
  const { dados, erro, recarregar } = useDados<{ listas: Lista[]; tipos: Record<string, string>; limite: number }>("/api/listas");
  const [nova, setNova] = useState(false);
  const [aberta, setAberta] = useState<number | null>(null);
  if (!dados) return <Carregando erro={erro} />;
  return (
    <>
      <Painel titulo="Listas de observação" acao={pode("gerir_regras") && <Button leftSection={<IconPlus size={14} />} onClick={() => setNova(true)}>Nova lista</Button>}>
        <Text size="sm" c="dimmed" mb="sm">Endereços, usuários, domínios ou hashes que as regras consultam. Mudou a lista, ela chega ao gerenciador em alguns minutos, sem mexer na regra.</Text>
        <Tabela
          linhas={dados.listas}
          chave={(l) => l.id}
          vazio="Nenhuma lista ainda."
          aoClicarLinha={(l) => setAberta(l.id)}
          colunas={[
            { titulo: "Lista", celula: (l) => <><Text size="sm" fw={500}>{l.titulo}</Text><Text size="xs" c="dimmed" className="mono">{l.nome}</Text></> },
            { titulo: "Guarda", celula: (l) => <Text size="sm" c="dimmed">{dados.tipos[l.tipo] ?? l.tipo}</Text> },
            { titulo: "Itens", alinhar: "right", largura: 90, celula: (l) => numero(l.itens) },
            { titulo: "Alterada em", largura: 150, celula: (l) => <Data valor={l.alterada_em} /> },
          ]}
        />
      </Painel>
      <NovaLista aberta={nova} tipos={dados.tipos} aoFechar={() => setNova(false)} aoCriar={(id) => { setNova(false); recarregar(); setAberta(id); }} />
      <GavetaDaLista id={aberta} aoFechar={() => setAberta(null)} aoMudar={recarregar} aoCriarRegra={(xml) => { setAberta(null); aoCriarRegra(xml); }} />
    </>
  );
}
