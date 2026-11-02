import { Alert, Button, Center, CopyButton, Group, Image, Modal, PasswordInput, Stack, Text, TextInput } from "@mantine/core";
import { useEffect, useState, type FormEvent } from "react";

import { detalhe, enviar, type Eu } from "./api";
import { BlocoDeComando } from "./componentes";

function Erro({ texto }: { texto: string | null }) {
  return texto ? <Alert color="red" variant="light" p="xs"><Text size="sm">{texto}</Text></Alert> : null;
}

/** Senha temporária não sai daqui sem ser trocada: a API também recusa todo o resto até lá. */
export function TrocaDeSenha({ aberta, obrigatoria, aoFechar, aoTrocar }: { aberta: boolean; obrigatoria: boolean; aoFechar: () => void; aoTrocar: () => void }) {
  const [atual, setAtual] = useState("");
  const [nova, setNova] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const trocar = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const r = await enviar("/api/minha-senha", { atual, nova });
    setAtual("");
    setNova("");
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível trocar."));
      return;
    }
    setErro(null);
    aoTrocar();
  };
  return (
    <Modal opened={aberta} onClose={aoFechar} title="Trocar senha" withCloseButton={!obrigatoria} closeOnEscape={!obrigatoria} closeOnClickOutside={!obrigatoria}>
      <form onSubmit={trocar} noValidate>
        <Stack gap="sm">
          {obrigatoria && <Text size="sm" c="dimmed">Sua senha é temporária. Crie a sua para continuar.</Text>}
          <PasswordInput label="Senha atual" autoComplete="current-password" value={atual} onChange={(e) => setAtual(e.currentTarget.value)} data-autofocus />
          <PasswordInput label="Nova senha" description="Pelo menos 12 caracteres" autoComplete="new-password" value={nova} onChange={(e) => setNova(e.currentTarget.value)} />
          <Erro texto={erro} />
          <Group justify="flex-end"><Button type="submit" variant="filled" disabled={!atual || !nova}>Trocar</Button></Group>
        </Stack>
      </form>
    </Modal>
  );
}

type Etapa = "inicio" | "leitura" | "recuperacao" | "ligado";

export function Autenticador({ aberto, eu, aoFechar, aoMudar }: { aberto: boolean; eu: Eu; aoFechar: () => void; aoMudar: () => void }) {
  const forcado = eu.mfa_obrigatorio && !eu.mfa_ativo;
  const [etapa, setEtapa] = useState<Etapa>("inicio");
  const [senha, setSenha] = useState("");
  const [codigo, setCodigo] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const [qr, setQr] = useState("");
  const [segredo, setSegredo] = useState("");
  const [codigos, setCodigos] = useState<string[]>([]);

  useEffect(() => {
    if (!aberto) return;
    setEtapa(eu.mfa_ativo ? "ligado" : "inicio");
    setSenha("");
    setCodigo("");
    setErro(null);
  }, [aberto, eu.mfa_ativo]);

  const iniciar = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const r = await enviar("/api/mfa/iniciar", { senha });
    setSenha("");
    if (!r.ok) {
      setErro(await detalhe(r, "Não foi possível começar."));
      return;
    }
    const d = await r.json();
    // Como imagem: o desenho vem da nossa API e nunca entra no documento como código.
    setQr(`data:image/svg+xml;charset=utf-8,${encodeURIComponent(d.qr)}`);
    setSegredo(d.segredo);
    setErro(null);
    setEtapa("leitura");
  };

  const confirmar = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const r = await enviar("/api/mfa/confirmar", { codigo });
    setCodigo("");
    if (!r.ok) {
      setErro(await detalhe(r, "Código incorreto."));
      return;
    }
    setCodigos((await r.json()).codigos_de_recuperacao);
    setQr("");
    setSegredo("");
    setErro(null);
    setEtapa("recuperacao");
  };

  const mudar = async (rota: string) => {
    const r = await enviar(rota, { senha, codigo });
    setSenha("");
    setCodigo("");
    if (!r.ok) {
      setErro(await detalhe(r, "A senha ou o código não confere."));
      return null;
    }
    setErro(null);
    return r;
  };

  // Os códigos só aparecem uma vez: nada de fechar por engano antes de guardar.
  const travado = etapa === "recuperacao" || forcado;
  return (
    <Modal opened={aberto} onClose={aoFechar} title="Autenticador" withCloseButton={!travado} closeOnEscape={!travado} closeOnClickOutside={!travado}>
      <Stack gap="sm">
        {forcado && etapa !== "recuperacao" && <Text size="sm" c="dimmed">Sua organização exige o autenticador. Configure-o para continuar.</Text>}
        {etapa === "inicio" && (
          <form onSubmit={iniciar} noValidate>
            <Stack gap="sm">
              <PasswordInput label="Confirme sua senha" autoComplete="current-password" value={senha} onChange={(e) => setSenha(e.currentTarget.value)} data-autofocus />
              <Erro texto={erro} />
              <Group justify="flex-end"><Button type="submit" variant="filled" disabled={!senha}>Continuar</Button></Group>
            </Stack>
          </form>
        )}
        {etapa === "leitura" && (
          <form onSubmit={confirmar} noValidate>
            <Stack gap="sm">
              <Text size="sm">Leia no aplicativo autenticador.</Text>
              <Center p="sm" style={{ background: "#fff", borderRadius: 8 }}><Image src={qr} alt="Código para ler no aplicativo" w={180} h={180} /></Center>
              <Text size="xs" c="dimmed">Ou digite a chave no aplicativo:</Text>
              <BlocoDeComando texto={segredo} />
              <TextInput label="Código de 6 dígitos" autoComplete="one-time-code" value={codigo} onChange={(e) => setCodigo(e.currentTarget.value)} data-autofocus />
              <Erro texto={erro} />
              <Group justify="flex-end"><Button type="submit" variant="filled" disabled={!codigo.trim()}>Ligar</Button></Group>
            </Stack>
          </form>
        )}
        {etapa === "recuperacao" && (
          <>
            <Text size="sm">Guarde estes códigos num lugar seguro. Cada um entra uma vez, e eles não aparecem de novo.</Text>
            <BlocoDeComando texto={codigos.join("\n")} />
            <Group justify="flex-end">
              <CopyButton value={codigos.join("\n")}>{({ copied, copy }) => <Button onClick={copy}>{copied ? "Copiado" : "Copiar"}</Button>}</CopyButton>
              <Button variant="filled" onClick={() => { setCodigos([]); aoMudar(); aoFechar(); }}>Já guardei</Button>
            </Group>
          </>
        )}
        {etapa === "ligado" && (
          <Stack gap="sm">
            <Text size="sm" c="dimmed">Ligado, com {eu.mfa_codigos_restantes} {eu.mfa_codigos_restantes === 1 ? "código" : "códigos"} de recuperação. Para mudar, confirme a senha e o código do aplicativo.</Text>
            <PasswordInput label="Senha" autoComplete="current-password" value={senha} onChange={(e) => setSenha(e.currentTarget.value)} data-autofocus />
            <TextInput label="Código do aplicativo" autoComplete="one-time-code" value={codigo} onChange={(e) => setCodigo(e.currentTarget.value)} />
            <Erro texto={erro} />
            <Group justify="flex-end">
              {!eu.mfa_obrigatorio && <Button variant="subtle" color="red" disabled={!senha || !codigo} onClick={async () => { if (await mudar("/api/mfa/desligar")) { aoMudar(); aoFechar(); } }}>Desligar</Button>}
              <Button disabled={!senha || !codigo} onClick={async () => { const r = await mudar("/api/mfa/novos-codigos"); if (r) { setCodigos((await r.json()).codigos_de_recuperacao); setEtapa("recuperacao"); } }}>Novos códigos</Button>
            </Group>
          </Stack>
        )}
      </Stack>
    </Modal>
  );
}
