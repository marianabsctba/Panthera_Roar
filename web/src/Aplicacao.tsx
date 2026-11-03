import { ActionIcon, Alert, AppShell, Avatar, Box, Burger, Button, Center, Group, Indicator, Loader, Menu, ScrollArea, Text, UnstyledButton } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconAlertTriangle, IconBell, IconBuildingSkyscraper, IconCheck, IconDatabaseCog, IconDeviceMobile, IconKey, IconBug, IconChartHistogram, IconChevronDown, IconClipboardCheck, IconDatabase, IconFileCertificate, IconFileText, IconFingerprint, IconHelpCircle,
  IconListSearch, IconLogout, IconPlugConnected, IconRobot, IconServer2, IconShieldCheck, IconShieldHalf, IconTargetArrow, IconTopologyStar3, IconUsers,
} from "@tabler/icons-react";
import { Component, useEffect, useState, type ComponentType, type ReactNode } from "react";

import { ContextoEu, enviar, ler, type Eu } from "./api";
import { Autenticador, TrocaDeSenha } from "./Conta";
import { Entrada } from "./Entrada";
import { trocarDeOrganizacao } from "./trocarDeOrganizacao";
import { Ajuda } from "./telas/Ajuda";
import { Armazenamento } from "./telas/Armazenamento";
import { Ataques } from "./telas/Ataques";
import { Ativos } from "./telas/Ativos";
import { Auditoria } from "./telas/Auditoria";
import { Automacao } from "./telas/Automacao";
import { Eventos } from "./telas/Eventos";
import { Fila } from "./telas/Fila";
import { Fontes } from "./telas/Fontes";
import { Inteligencia } from "./telas/Inteligencia";
import { Integridade } from "./telas/Integridade";
import { Logs } from "./telas/Logs";
import { Normas } from "./telas/Normas";
import { Organizacoes } from "./telas/Organizacoes";
import { Panorama } from "./telas/Panorama";
import { Prova } from "./telas/Prova";
import { Regras } from "./telas/Regras";
import { Relatorios } from "./telas/Relatorios";
import { Usuarios } from "./telas/Usuarios";
import { Vulnerabilidades } from "./telas/Vulnerabilidades";


interface Item { id: string; rotulo: string; icone: ComponentType<{ size?: number; stroke?: number }>; modulo?: string; permissao?: string; soPlataforma?: boolean; tela: ComponentType }

const GRUPOS: { titulo: string; itens: Item[] }[] = [
  { titulo: "Monitorar", itens: [
    { id: "panorama", rotulo: "Panorama", icone: IconChartHistogram, modulo: "siem", tela: Panorama },
    { id: "fila", rotulo: "Fila", icone: IconAlertTriangle, modulo: "siem", tela: Fila },
    { id: "eventos", rotulo: "Eventos", icone: IconListSearch, modulo: "siem", tela: Eventos },
    { id: "logs", rotulo: "Logs brutos", icone: IconFileText, modulo: "siem", tela: Logs },
  ] },
  { titulo: "Investigar", itens: [
    { id: "ataques", rotulo: "Ataque e defesa", icone: IconTargetArrow, modulo: "siem", tela: Ataques },
    { id: "inteligencia", rotulo: "Inteligência", icone: IconTopologyStar3, modulo: "siem", tela: Inteligencia },
    { id: "prova", rotulo: "Prova e evidência", icone: IconFingerprint, modulo: "siem", tela: Prova },
  ] },
  { titulo: "Proteger", itens: [
    { id: "vulnerabilidades", rotulo: "Vulnerabilidades", icone: IconBug, modulo: "vulnerabilidades", tela: Vulnerabilidades },
    { id: "arquivos", rotulo: "Integridade", icone: IconShieldCheck, modulo: "siem", tela: Integridade },
    { id: "regras", rotulo: "Regras", icone: IconShieldHalf, modulo: "siem", tela: Regras },
    { id: "automacao", rotulo: "Automação", icone: IconRobot, modulo: "siem", tela: Automacao },
  ] },
  { titulo: "Ambiente", itens: [
    { id: "ativos", rotulo: "Ativos", icone: IconServer2, modulo: "siem", tela: Ativos },
    { id: "fontes", rotulo: "Fontes de dados", icone: IconPlugConnected, modulo: "siem", tela: Fontes },
  ] },
  { titulo: "Conformidade", itens: [
    { id: "normas", rotulo: "Normas", icone: IconClipboardCheck, modulo: "siem", tela: Normas },
    { id: "relatorios", rotulo: "Relatórios", icone: IconFileCertificate, modulo: "siem", tela: Relatorios },
    { id: "auditoria", rotulo: "Auditoria", icone: IconDatabase, permissao: "ver_auditoria", tela: Auditoria },
  ] },
  { titulo: "Administrar", itens: [
    { id: "organizacoes", rotulo: "Organizações", icone: IconBuildingSkyscraper, soPlataforma: true, tela: Organizacoes },
    { id: "usuarios", rotulo: "Usuários", icone: IconUsers, permissao: "gerir_usuarios", tela: Usuarios },
    { id: "armazenamento", rotulo: "Armazenamento", icone: IconDatabaseCog, modulo: "siem", permissao: "gerir_usuarios", tela: Armazenamento },
    { id: "ajuda", rotulo: "Ajuda", icone: IconHelpCircle, tela: Ajuda },
  ] },
];

const TELAS = GRUPOS.flatMap((g) => g.itens);
/** Um erro em uma tela não pode derrubar o menu nem as outras telas. */
class ProtecaoDaTela extends Component<{ children: ReactNode; chave: string }, { erro: boolean }> {
  state = { erro: false };

  static getDerivedStateFromError() {
    return { erro: true };
  }

  componentDidUpdate(anterior: { chave: string }) {
    if (anterior.chave !== this.props.chave && this.state.erro) this.setState({ erro: false });
  }

  render() {
    if (!this.state.erro) return this.props.children;
    return <Alert color="red" variant="light" title="Esta tela encontrou um erro">Recarregue a página. Se continuar, as outras telas seguem funcionando.</Alert>;
  }
}

function SeletorDeOrganizacao({ eu }: { eu: Eu }) {
  const [lista, setLista] = useState<{ id: string; nome: string }[] | null>(null);
  return (
    <Menu position="bottom-start" shadow="md" onOpen={() => { ler<{ organizacoes: { id: string; nome: string }[] }>("/api/organizacoes").then((d) => setLista(d.organizacoes)).catch(() => {}); }}>
      <Menu.Target>
        <UnstyledButton aria-label="Trocar de organização">
          <Group gap={4} wrap="nowrap">
            <Text size="sm" truncate maw={220}>{eu.cliente}</Text>
            <IconChevronDown size={14} />
          </Group>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown mah={360} style={{ overflowY: "auto" }}>
        <Menu.Label>Organizações</Menu.Label>
        {!lista && <Menu.Item fz="sm" disabled>Carregando</Menu.Item>}
        {lista?.map((o) => (
          <Menu.Item key={o.id} fz="sm" rightSection={o.id === eu.cliente_id ? <IconCheck size={14} /> : undefined} onClick={() => { if (o.id !== eu.cliente_id) trocarDeOrganizacao(`/api/organizacoes/${o.id}/entrar`); }}>{o.nome}</Menu.Item>
        ))}
      </Menu.Dropdown>
    </Menu>
  );
}

const vistaDaUrl = () => window.location.pathname.split("/")[1] || "panorama";

export function Aplicacao() {
  const [eu, setEu] = useState<Eu | null>(null);
  const [fase, setFase] = useState<"carregando" | "entrada" | "codigo" | "dentro">("carregando");
  const [verSenha, setVerSenha] = useState(false);
  const [verMfa, setVerMfa] = useState(false);
  const [avisos, setAvisos] = useState(0);
  const [violada, setViolada] = useState(false);
  const [vista, setVista] = useState(vistaDaUrl);
  const [aberto, { toggle, close }] = useDisclosure();

  const abrir = () => ler<Eu>("/api/eu").then((d) => {
    setEu(d);
    setFase(d.mfa_pendente ? "codigo" : "dentro");
    if (!d.mfa_pendente && d.modulos.includes("siem")) {
      ler<{ verificacao?: { estado?: string } | null }>("/api/integridade").then((p) => setViolada(p.verificacao?.estado === "violada")).catch(() => {});
    }
    if (!d.mfa_pendente && d.permissoes.includes("ver_auditoria")) {
      ler<{ avisos: { contagem: number }[] }>("/api/notificacoes").then((n) => setAvisos(n.avisos.reduce((t, a) => t + a.contagem, 0))).catch(() => {});
    }
  }).catch(() => {});

  useEffect(() => {
    const semSessao = () => { setEu(null); setFase("entrada"); };
    const voltar = () => setVista(vistaDaUrl());
    window.addEventListener("roar:sem-sessao", semSessao);
    window.addEventListener("popstate", voltar);
    abrir();
    return () => {
      window.removeEventListener("roar:sem-sessao", semSessao);
      window.removeEventListener("popstate", voltar);
    };
  }, []);

  if (fase === "entrada" || fase === "codigo") return <Entrada aoEntrar={abrir} pedirCodigo={fase === "codigo"} />;
  if (!eu) return <Center h="100%"><Loader color="gray" size="sm" /></Center>;

  const visivel = (i: Item) => (!i.modulo || eu.modulos.includes(i.modulo)) && (!i.permissao || eu.permissoes.includes(i.permissao)) && (!i.soPlataforma || eu.plataforma);
  const atual = TELAS.find((i) => i.id === vista && visivel(i)) ?? TELAS.find(visivel);
  const Tela = atual?.tela;

  const ir = (i: Item) => {
    window.history.pushState(null, "", `/${i.id}`);
    setVista(i.id);
    close();
  };

  const sair = async () => {
    await enviar("/api/sair");
    setEu(null);
    setFase("entrada");
  };

  return (
    <ContextoEu.Provider value={eu}>
      <AppShell header={{ height: 48 }} navbar={{ width: 224, breakpoint: "sm", collapsed: { mobile: !aberto } }} padding="lg">
        <AppShell.Header className="barra-metal">
          <Group h="100%" px="md" justify="space-between" wrap="nowrap">
            <Group gap="sm" wrap="nowrap">
              <Burger opened={aberto} onClick={toggle} hiddenFrom="sm" size="sm" aria-label="Abrir o menu" />
              <Avatar src="/estatico/pantera.webp" size={24} radius="sm" alt="" />
              <Text fw={600} size="sm">Panthera Roar</Text>
              {eu.plataforma ? <SeletorDeOrganizacao eu={eu} /> : <Text size="sm" visibleFrom="sm" style={{ opacity: 0.85 }}>{eu.cliente}</Text>}
            </Group>
            <Group gap="sm" wrap="nowrap">
            {eu.permissoes.includes("ver_auditoria") && (
              <Indicator disabled={!avisos} label={avisos > 99 ? "99+" : avisos} size={16} color="red">
                <ActionIcon variant="subtle" color="gray" c="white" aria-label={`${avisos} avisos`} onClick={() => ir(TELAS.find((i) => i.id === "auditoria")!)}><IconBell size={18} /></ActionIcon>
              </Indicator>
            )}
            <Menu position="bottom-end" shadow="md">
              <Menu.Target>
                <UnstyledButton aria-label="Menu da conta">
                  <Group gap={6} wrap="nowrap">
                    <Avatar size={24} radius="xl" color="dark" variant="filled" name={eu.nome} />
                    <Text size="sm" visibleFrom="sm">{eu.nome}</Text>
                    <IconChevronDown size={14} />
                  </Group>
                </UnstyledButton>
              </Menu.Target>
              <Menu.Dropdown>
                <Menu.Item fz="sm" leftSection={<IconKey size={14} />} onClick={() => setVerSenha(true)}>Trocar senha</Menu.Item>
                <Menu.Item fz="sm" leftSection={<IconDeviceMobile size={14} />} onClick={() => setVerMfa(true)}>Autenticador</Menu.Item>
                <Menu.Divider />
                <Menu.Item fz="sm" leftSection={<IconLogout size={14} />} onClick={sair}>Sair</Menu.Item>
              </Menu.Dropdown>
            </Menu>
            </Group>
          </Group>
        </AppShell.Header>

        <AppShell.Navbar style={{ background: "var(--mantine-color-dark-7)", borderColor: "var(--roar-borda)" }}>
          <ScrollArea h="100%" px={8} pb={8} component="nav" aria-label="Seções">
            {GRUPOS.map((g) => {
              const itens = g.itens.filter(visivel);
              if (!itens.length) return null;
              return (
                <Box key={g.titulo}>
                  <div className="menu-grupo">{g.titulo}</div>
                  {itens.map((i) => {
                    const Icone = i.icone;
                    return (
                      <button key={i.id} type="button" className="menu-item" aria-current={atual?.id === i.id ? "page" : undefined} onClick={() => ir(i)}>
                        <Icone size={16} stroke={1.6} />
                        <span>{i.rotulo}</span>
                      </button>
                    );
                  })}
                </Box>
              );
            })}
          </ScrollArea>
        </AppShell.Navbar>

        <TrocaDeSenha aberta={verSenha || eu.trocar_senha} obrigatoria={eu.trocar_senha} aoFechar={() => setVerSenha(false)} aoTrocar={() => { setVerSenha(false); abrir(); }} />
        <Autenticador aberto={verMfa || (!eu.trocar_senha && eu.mfa_obrigatorio && !eu.mfa_ativo)} eu={eu} aoFechar={() => setVerMfa(false)} aoMudar={abrir} />
        <AppShell.Main style={{ background: "var(--mantine-color-dark-8)" }}>
          <Box maw={1400} mx="auto">
            {eu.em_outra_organizacao && (
              <Alert color="pink" variant="light" mb="md" p="xs">
                <Group justify="space-between" gap="sm">
                  <Text size="sm">Você está atuando em <b>{eu.cliente}</b>. O que fizer aqui fica na auditoria desta organização.</Text>
                  <Button size="xs" variant="default" onClick={() => trocarDeOrganizacao("/api/organizacoes/voltar")}>Voltar para {eu.cliente_proprio}</Button>
                </Group>
              </Alert>
            )}
            {violada && <Alert color="red" variant="filled" mb="md" p="xs" title="">A conferência dos selos encontrou registros alterados. Veja em Prova e evidência.</Alert>}
            {eu.trocar_senha || (eu.mfa_obrigatorio && !eu.mfa_ativo) || !Tela ? null : <ProtecaoDaTela chave={atual!.id}><Tela /></ProtecaoDaTela>}
          </Box>
        </AppShell.Main>
      </AppShell>
    </ContextoEu.Provider>
  );
}
