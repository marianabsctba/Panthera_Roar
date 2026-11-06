import { Alert, Button, Checkbox, Group, PasswordInput, SegmentedControl, Select, SimpleGrid, Stack, Switch, Text, Textarea, TextInput } from "@mantine/core";
import { useEffect, useState } from "react";

import { detalhe, enviar, pedir, useDados } from "../api";
import { Carregando, Data, Painel } from "../componentes";

interface Config {
  servidor: string; porta: number; seguranca: string; usuario: string; remetente: string; destinatarios: string[]; tipos: string[]; ativo: boolean;
  ultimo_envio: string | null; ultimo_erro: string | null; teste_resultado: string | null; teste_em: string | null;
}
interface Visao { config: Config | null; tem_senha: boolean; tipos: Record<string, string> }

const PORTAS = [{ value: "587", label: "587 (o mais comum)" }, { value: "465", label: "465" }, { value: "25", label: "25" }, { value: "2525", label: "2525" }];

/** Os avisos do sino também por e-mail, pelo servidor de e-mail da própria organização. */
export function AvisosPorEmail() {
  const { dados, erro: erroAoLer, recarregar } = useDados<Visao>("/api/organizacao/email");
  const [servidor, setServidor] = useState("");
  const [porta, setPorta] = useState("587");
  const [seguranca, setSeguranca] = useState("starttls");
  const [usuario, setUsuario] = useState("");
  const [senha, setSenha] = useState("");
  const [remetente, setRemetente] = useState("");
  const [destinatarios, setDestinatarios] = useState("");
  const [todos, setTodos] = useState(true);
  const [tipos, setTipos] = useState<string[]>([]);
  const [ativo, setAtivo] = useState(true);
  const [erro, setErro] = useState<string | null>(null);
  const [aviso, setAviso] = useState<string | null>(null);
  const [ocupado, setOcupado] = useState<"salvando" | "testando" | null>(null);
  useEffect(() => {
    const c = dados?.config;
    if (!c) return;
    setServidor(c.servidor); setPorta(String(c.porta)); setSeguranca(c.seguranca); setUsuario(c.usuario); setRemetente(c.remetente);
    setDestinatarios(c.destinatarios.join(", ")); setTodos(!c.tipos.length); setTipos(c.tipos); setAtivo(c.ativo);
  }, [dados]);
  if (!dados) return <Carregando erro={erroAoLer} />;

  const salvar = async () => {
    setErro(null); setAviso(null); setOcupado("salvando");
    const r = await pedir("/api/organizacao/email", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ servidor: servidor.trim(), porta: Number(porta), seguranca, usuario, senha: senha ? senha : null, remetente,
        destinatarios: destinatarios.split(/[\s,;]+/).filter(Boolean), tipos: todos ? [] : tipos, ativo }),
    }).finally(() => setOcupado(null));
    if (!r.ok) return setErro(await detalhe(r, "Não foi possível salvar."));
    setSenha("");
    setAviso("Salvo. Clique em Mandar um e-mail de teste para conferir.");
    recarregar();
  };
  const testar = async () => {
    setErro(null); setAviso(null); setOcupado("testando");
    const r = await enviar("/api/organizacao/email/teste").finally(() => setOcupado(null));
    if (!r.ok) return setErro(await detalhe(r, "O e-mail de teste não saiu."));
    setAviso(`E-mail de teste mandado para ${destinatarios}. Confira a caixa de entrada e o spam.`);
    recarregar();
  };
  const remover = async () => {
    await pedir("/api/organizacao/email", { method: "DELETE" });
    setServidor(""); setUsuario(""); setRemetente(""); setDestinatarios("");
    recarregar();
  };
  const c = dados.config;
  return (
    <Painel titulo="Avisos por e-mail">
      <Stack gap="sm" maw={680}>
        <Text size="sm">Os avisos do sino também chegam por e-mail, pelo servidor de e-mail da sua organização. Os avisos novos são juntados num e-mail só, a cada poucos segundos: um ataque com mil alertas não vira mil e-mails.</Text>
        {c?.ultimo_erro && <Alert color="red" variant="light" p="xs" fz="sm">O último envio falhou: {c.ultimo_erro} Os avisos esperam e vão no próximo envio que der certo.</Alert>}
        {c?.ultimo_envio && !c.ultimo_erro && <Text size="xs" c="dimmed">Último e-mail mandado em <Data valor={c.ultimo_envio} />.</Text>}
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
          <TextInput label="Servidor de e-mail" placeholder="smtp.office365.com" value={servidor} onChange={(e) => setServidor(e.currentTarget.value)} spellCheck={false} />
          <Select label="Porta" allowDeselect={false} value={porta} onChange={(v) => { setPorta(v ?? "587"); setSeguranca(v === "465" ? "ssl" : "starttls"); }} data={PORTAS} />
        </SimpleGrid>
        <SegmentedControl value={seguranca} onChange={setSeguranca} data={[{ value: "starttls", label: "STARTTLS (porta 587)" }, { value: "ssl", label: "SSL direto (porta 465)" }]} />
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
          <TextInput label="Usuário" description="Em branco se o servidor não pede." value={usuario} onChange={(e) => setUsuario(e.currentTarget.value)} spellCheck={false} />
          <PasswordInput label="Senha" description={dados.tem_senha ? "Guardada e cifrada. Deixe em branco para manter." : "Fica cifrada: ninguém vê de novo."} value={senha} onChange={(e) => setSenha(e.currentTarget.value)} />
        </SimpleGrid>
        <TextInput label="Remetente" placeholder="roar@empresa.com.br" value={remetente} onChange={(e) => setRemetente(e.currentTarget.value)} spellCheck={false} />
        <Textarea label="Para quem mandar" description="E-mails separados por vírgula. Até 20." autosize minRows={2} value={destinatarios} onChange={(e) => setDestinatarios(e.currentTarget.value)} spellCheck={false} />
        <Switch label="Todos os avisos do sino" checked={todos} onChange={(e) => setTodos(e.currentTarget.checked)} />
        {!todos && (
          <Checkbox.Group value={tipos} onChange={setTipos} label="Só estes avisos">
            <Stack gap={6} mt={6}>{Object.entries(dados.tipos).map(([valor, rotulo]) => <Checkbox key={valor} value={valor} label={rotulo} />)}</Stack>
          </Checkbox.Group>
        )}
        <Switch label="Ligado" checked={ativo} onChange={(e) => setAtivo(e.currentTarget.checked)} />
        {erro && <Alert color="red" variant="light" p="xs" fz="sm">{erro}</Alert>}
        {aviso && <Alert color="green" variant="light" p="xs" fz="sm">{aviso}</Alert>}
        <Group justify="space-between">
          {c ? <Button variant="subtle" color="red" onClick={remover}>Parar os avisos por e-mail</Button> : <span />}
          <Group gap="sm">
            {c && <Button loading={ocupado === "testando"} disabled={ocupado !== null} onClick={testar}>Mandar um e-mail de teste</Button>}
            <Button variant="filled" loading={ocupado === "salvando"} disabled={ocupado !== null || !servidor.trim() || !remetente.trim() || !destinatarios.trim() || (!todos && !tipos.length)} onClick={salvar}>Salvar</Button>
          </Group>
        </Group>
      </Stack>
    </Painel>
  );
}
