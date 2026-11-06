import { Alert, Anchor, Button, Card, Center, Divider, Image, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { useState, type FormEvent, type ReactNode } from "react";

import { detalhe, enviar } from "./api";
import { passkeyDisponivel, usarPasskey } from "./passkey";
import { caminho, consulta, trocar } from "./rota";

export function LogoDoGoogle({ tamanho = 18 }: { tamanho?: number }) {
  return (
    <svg width={tamanho} height={tamanho} viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#FFC107" d="M43.6 20.1H42V20H24v8h11.3c-1.6 4.7-6.1 8-11.3 8-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 8 3l5.7-5.7C34 6.1 29.3 4 24 4 13 4 4 13 4 24s9 20 20 20 20-9 20-20c0-1.3-.1-2.6-.4-3.9z" />
      <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 8 3l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
      <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z" />
      <path fill="#1976D2" d="M43.6 20.1H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.6-.4-3.9z" />
    </svg>
  );
}

export function LogoDaMicrosoft({ tamanho = 18 }: { tamanho?: number }) {
  return (
    <svg width={tamanho} height={tamanho} viewBox="0 0 21 21" aria-hidden="true">
      <rect x="1" y="1" width="9" height="9" fill="#F25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7FBA00" />
      <rect x="1" y="11" width="9" height="9" fill="#00A4EF" />
      <rect x="11" y="11" width="9" height="9" fill="#FFB900" />
    </svg>
  );
}

/** O login único volta para a tela com o motivo da falha no endereço: mostra uma vez e limpa. */
function erroDoSso() {
  const motivo = new URLSearchParams(consulta()).get("sso");
  if (motivo) trocar(caminho());
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

  const entrarComSso = async (provedor: string) => {
    setErro(null);
    if (!email.trim()) return setErro("Digite o seu e-mail primeiro: é por ele que o Roar acha a sua organização.");
    setEnviando(true);
    const r = await fetch(`/api/sso/inicio?${new URLSearchParams({ email: email.trim(), provedor })}`, { credentials: "same-origin" }).finally(() => setEnviando(false));
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
      <Button variant="default" leftSection={<LogoDoGoogle />} onClick={() => entrarComSso("google")} disabled={enviando} fullWidth>Entrar com Google</Button>
      <Button variant="default" leftSection={<LogoDaMicrosoft />} onClick={() => entrarComSso("microsoft")} disabled={enviando} fullWidth>Entrar com Microsoft</Button>
      <Anchor component="button" type="button" size="xs" c="dimmed" ta="center" onClick={() => entrarComSso("")} disabled={enviando}>Outro login único (SSO)</Anchor>
    </Moldura>
  );
}
