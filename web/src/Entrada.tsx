import { Alert, Anchor, Button, Card, Center, Divider, Image, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { useState, type FormEvent, type ReactNode } from "react";

import { detalhe, enviar } from "./api";
import { passkeyDisponivel, usarPasskey } from "./passkey";

/** O login único volta para a tela com o motivo da falha no endereço: mostra uma vez e limpa. */
function erroDoSso() {
  const motivo = new URLSearchParams(window.location.search).get("sso");
  if (motivo) window.history.replaceState(null, "", window.location.pathname);
  return motivo;
}

function Moldura({ children, aoEnviar }: { children: ReactNode; aoEnviar: (e: FormEvent<HTMLFormElement>) => void }) {
  return (
    <Center h="100%" p="md" style={{ background: "radial-gradient(circle at 50% 0%, #2a0a1d 0%, var(--mantine-color-dark-8) 55%)" }}>
      <Card w={360} p="xl">
        <form onSubmit={aoEnviar} noValidate>
          <Stack gap="md">
            <Stack gap={6} align="center">
              <Image src="/estatico/pantera.webp" alt="" w={64} h={64} radius="md" />
              <Title order={1}>Panthera Roar</Title>
            </Stack>
            {children}
            <div className="assinatura assinatura-centro">Powered by<b>Mariana BS</b></div>
          </Stack>
        </form>
      </Card>
    </Center>
  );
}

function Erro({ texto }: { texto: string | null }) {
  return texto ? <Alert color="red" variant="light" p="xs"><Text size="sm">{texto}</Text></Alert> : null;
}

/** Depois da senha, a sessão só vale de verdade com o segundo fator: quem decide é a API, pelo /api/eu. */
export function Entrada({ aoEntrar, pedirCodigo }: { aoEntrar: () => void; pedirCodigo: boolean }) {
  const [email, setEmail] = useState("");
  const [senha, setSenha] = useState("");
  const [codigo, setCodigo] = useState("");
  const [erro, setErro] = useState<string | null>(erroDoSso);
  const [voltou, setVoltou] = useState(false);
  const [enviando, setEnviando] = useState(false);

  const entrar = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setErro(null);
    setEnviando(true);
    const r = await enviar("/api/entrar", { email, senha }).finally(() => setEnviando(false));
    setSenha("");
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível entrar."));
      return;
    }
    setVoltou(false);
    aoEntrar();
  };

  const confirmar = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setErro(null);
    setEnviando(true);
    const r = await enviar("/api/mfa/verificar", { codigo }).finally(() => setEnviando(false));
    setCodigo("");
    if (r.status === 429) {
      setErro(await detalhe(r, "Muitas tentativas."));
      setVoltou(true);
      return;
    }
    if (!r.ok) {
      setErro(await detalhe(r, "Código incorreto."));
      return;
    }
    aoEntrar();
  };

  const entrarComPasskey = async () => {
    setErro(null);
    setEnviando(true);
    try {
      const inicio = await enviar("/api/passkeys/entrar/inicio");
      if (!inicio.ok) return setErro(await detalhe(inicio, "Não foi possível entrar."));
      const { pedido, opcoes } = await inicio.json();
      const credencial = await usarPasskey(opcoes);
      const r = await enviar("/api/passkeys/entrar/fim", { pedido, credencial });
      if (!r.ok) return setErro(await detalhe(r, "Passkey não reconhecida."));
      setVoltou(false);
      aoEntrar();
    } catch {
      setErro("A passkey não foi usada. Tente de novo, ou entre com a senha.");
    } finally {
      setEnviando(false);
    }
  };

  const entrarComSso = async () => {
    setErro(null);
    if (!email.trim()) return setErro("Digite o seu e-mail para achar o login único da sua organização.");
    setEnviando(true);
    const r = await fetch(`/api/sso/inicio?${new URLSearchParams({ email: email.trim() })}`, { credentials: "same-origin" }).finally(() => setEnviando(false));
    if (!r.ok) return setErro(await detalhe(r, "Não foi possível iniciar o login único."));
    window.location.assign((await r.json()).url);
  };

  const voltar = async () => {
    await enviar("/api/sair");
    setErro(null);
    setVoltou(true);
  };

  if (pedirCodigo && !voltou) {
    return (
      <Moldura aoEnviar={confirmar}>
        <TextInput label="Código do autenticador ou de recuperação" autoComplete="one-time-code" value={codigo} onChange={(e) => setCodigo(e.currentTarget.value)} autoFocus />
        <Erro texto={erro} />
        <Button type="submit" variant="filled" loading={enviando} disabled={!codigo.trim()} fullWidth>Confirmar</Button>
        <Anchor component="button" type="button" size="xs" c="dimmed" ta="center" onClick={voltar}>Voltar</Anchor>
      </Moldura>
    );
  }
  return (
    <Moldura aoEnviar={entrar}>
      <TextInput label="E-mail" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.currentTarget.value)} autoFocus />
      <PasswordInput label="Senha" autoComplete="current-password" value={senha} onChange={(e) => setSenha(e.currentTarget.value)} />
      <Erro texto={erro} />
      <Button type="submit" variant="filled" loading={enviando} disabled={!email.trim() || !senha} fullWidth>Entrar</Button>
      <Divider label="ou" labelPosition="center" />
      {passkeyDisponivel() && <Button variant="default" onClick={entrarComPasskey} disabled={enviando} fullWidth>Entrar com passkey</Button>}
      <Button variant="default" onClick={entrarComSso} disabled={enviando} fullWidth>Entrar com login único (SSO)</Button>
    </Moldura>
  );
}
