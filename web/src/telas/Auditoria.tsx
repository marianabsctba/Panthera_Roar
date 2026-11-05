import { Alert, Badge, Button, Drawer, Group, Select, Stack, Text } from "@mantine/core";
import { IconDownload } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { detalhe, enviar, ler, useDados, usePode } from "../api";
import { AcoesDaLinha, Cabecalho, Carregando, Data, GavetaDeEventos, Painel, Tabela, type FiltroDeEventos } from "../componentes";
import { numero } from "../formato";
import { Fatos } from "./Ataques";
import { salvarArquivo } from "./Prova";

const NOMES_DA_TRILHA: Record<string, string> = {
  logon: "Entrou", logoff: "Saiu", login_recusado: "Senha recusada", mfa_recusado: "Código do autenticador recusado", entrar_com_mfa: "Entrou com autenticador",
  entrar_com_codigo_de_recuperacao: "Entrou com código de recuperação", criar_usuario: "Criou usuário", alterar_usuario: "Alterou perfil ou situação de usuário", redefinir_senha: "Gerou senha temporária",
  trocar_senha: "Trocou a própria senha", ligar_mfa: "Ligou o autenticador", desligar_mfa: "Desligou o autenticador", remover_mfa_de_usuario: "Removeu o autenticador de outra pessoa",
  definir_mfa_obrigatorio: "Mudou a exigência do autenticador", definir_ofuscacao: "Mudou os dados pessoais mascarados", decidir_risco: "Encerrou um risco", definir_criticidade: "Mudou a criticidade de um ativo", silenciar_sinal: "Silenciou um sinal do UEBA", remover_silencio: "Tirou o silêncio de um sinal", gerar_codigos_de_recuperacao: "Gerou novos códigos de recuperação", incluir_ativo: "Ativo incluído", excluir_ativo: "Ativo excluído",
  indicador_encontrado: "Evento bateu com um indicador de ameaça", criar_fonte_de_inteligencia: "Criou fonte de inteligência", desativar_fonte_de_inteligencia: "Desativou fonte de inteligência",
  buscar_logs: "Buscou nos logs", ver_bruto: "Viu alerta bruto", gerar_relatorio: "Gerou relatório", gerar_evidencia: "Gerou pacote de evidência", exportar_auditoria: "Exportou a trilha",
  criar_fonte: "Criou fonte de dados", desativar_fonte: "Desativou fonte de dados", criar_regra: "Criou regra", editar_regra: "Editou regra", desativar_regra: "Desativou regra",
  importar_regras: "Importou regras", exportar_regras: "Exportou regras", criar_playbook: "Criou playbook", alterar_playbook: "Alterou playbook",
  criar_regra_yara: "Criou regra YARA", desativar_regra_yara: "Tirou regra YARA", mudar_biblioteca_yara: "Mudou o uso da biblioteca YARA", atualizar_biblioteca_yara: "Atualizou a biblioteca YARA", tirar_regra_yara: "Tirou regra da biblioteca YARA", usar_regra_yara: "Voltou a usar regra da biblioteca YARA",
  entrar_na_organizacao: "Administração da instalação entrou nesta organização", sair_da_organizacao: "Administração da instalação saiu desta organização", entrar_em_outra_organizacao: "Entrou em outra organização", voltar_para_a_organizacao: "Voltou para a própria organização",
  pedir_organizacao: "Pediu uma organização nova", definir_armazenamento: "Mudou o armazenamento", gerar_evidencia_de_periodo: "Gerou pacote para perícia", recuperar_copia_fria: "Pediu dias de volta da cópia fria", devolver_copia_fria: "Devolveu dias recuperados", remover_organizacao: "Pediu a remoção de uma organização", ver_instalacao_de_agente: "Viu o comando de instalação de agente", criar_caminho_fim: "Incluiu caminho na integridade", desativar_caminho_fim: "Tirou caminho da integridade", pedir_varredura_fim: "Pediu varredura de integridade",
};
export const nomeDaAcao = (acao: string) => NOMES_DA_TRILHA[acao] ?? acao.replaceAll("_", " ");
/** Avisa o sino da barra de cima que os avisos mudaram, para o número não ficar velho. */
export const AVISOS_MUDARAM = "roar:avisos-mudaram";

const SEGUNDOS_ENTRE_AVISOS = 15;
const PERIODOS = [{ value: "1", label: "Último dia" }, { value: "7", label: "7 dias" }, { value: "30", label: "30 dias" }, { value: "180", label: "180 dias" }];

interface LinhaDaTrilha { id: number; em: string; usuario_id: string | null; acao: string; alvo: string | null; origem: string | null; pessoa: string | null }
interface Trilha { linhas: LinhaDaTrilha[]; acoes: string[]; pessoas: { id: string; nome: string }[]; proximo: number | null }
interface Aviso { id: number; tipo: string; alvo: string | null; origem: string | null; contagem: number; criada_em: string; atualizada_em: string }

const nomeDaPessoa = (l: LinhaDaTrilha) => l.pessoa ?? (l.usuario_id ? "Pessoa removida" : "Sistema");

function GavetaDaLinha({ linha: l, aoFechar, aoFiltrarAcao, aoFiltrarPessoa, aoVerOrigem }: { linha: LinhaDaTrilha | null; aoFechar: () => void; aoFiltrarAcao: (acao: string) => void; aoFiltrarPessoa: (pessoa: string) => void; aoVerOrigem?: (origem: string) => void }) {
  return (
    <Drawer opened={l !== null} onClose={aoFechar} title={l ? nomeDaAcao(l.acao) : ""} size="lg">
      {l && (
        <Stack gap="md">
          <Fatos itens={[
            ["Quando", <Data valor={l.em} />],
            ["Ação", <span className="mono">{l.acao}</span>],
            ["Pessoa", nomeDaPessoa(l)],
            ["Alvo", <span className="mono">{l.alvo ?? "-"}</span>],
            ["Origem", <span className="mono">{l.origem ?? "-"}</span>],
          ]} />
          <Group gap="xs">
            <Button onClick={() => aoFiltrarAcao(l.acao)}>Só esta ação</Button>
            {l.usuario_id && <Button onClick={() => aoFiltrarPessoa(l.usuario_id as string)}>Só esta pessoa</Button>}
            {l.origem && aoVerOrigem && <Button onClick={() => aoVerOrigem(l.origem as string)}>Eventos desta origem</Button>}
          </Group>
        </Stack>
      )}
    </Drawer>
  );
}

function GavetaDoAviso({ aviso: a, naTrilha, aoFechar, aoVerNaTrilha, aoVerOrigem }: { aviso: Aviso | null; naTrilha: boolean; aoFechar: () => void; aoVerNaTrilha: (acao: string) => void; aoVerOrigem?: (origem: string) => void }) {
  return (
    <Drawer opened={a !== null} onClose={aoFechar} title={a ? nomeDaAcao(a.tipo) : ""}>
      {a && (
        <Stack gap="md">
          <Fatos itens={[
            ["Conta", <span className="mono">{a.alvo ?? "-"}</span>],
            ["Tentativas", numero(a.contagem)],
            ["Origem", <span className="mono">{a.origem ?? "-"}</span>],
            ["Primeira vez", <Data valor={a.criada_em} />],
            ["Última vez", <Data valor={a.atualizada_em} />],
          ]} />
          <Group gap="xs">
            {naTrilha && <Button onClick={() => aoVerNaTrilha(a.tipo)}>Ver na trilha</Button>}
            {a.origem && aoVerOrigem && <Button onClick={() => aoVerOrigem(a.origem as string)}>Eventos desta origem</Button>}
          </Group>
        </Stack>
      )}
    </Drawer>
  );
}

function Avisos({ acoes, aoVerNaTrilha, aoVerOrigem }: { acoes: string[]; aoVerNaTrilha: (acao: string) => void; aoVerOrigem?: (origem: string) => void }) {
  const { dados, erro, recarregar } = useDados<{ avisos: Aviso[] }>("/api/notificacoes");
  const [aberto, setAberto] = useState<Aviso | null>(null);
  useEffect(() => {
    const relogio = setInterval(recarregar, SEGUNDOS_ENTRE_AVISOS * 1000);
    return () => clearInterval(relogio);
  }, [recarregar]);
  const avisos = dados?.avisos ?? [];
  const total = avisos.reduce((t, a) => t + Number(a.contagem), 0);
  return (
    <Painel
      titulo="Avisos"
      acao={avisos.length > 0 && (
        <Group gap="xs" wrap="nowrap">
          <Badge variant="light" size="sm" radius="sm" color="yellow" tt="none" fw={500} className="numero">{numero(total)}</Badge>
          <Button onClick={async () => { await enviar("/api/notificacoes/lidas"); recarregar(); window.dispatchEvent(new Event(AVISOS_MUDARAM)); }}>Marcar como lidos</Button>
        </Group>
      )}
    >
      {!dados ? <Carregando erro={erro} /> : (
        <Tabela
          linhas={avisos}
          chave={(a) => a.id}
          vazio="Nenhum aviso novo."
          aoClicarLinha={setAberto}
          colunas={[
            { titulo: "Última vez", largura: 140, celula: (a) => <Data valor={a.atualizada_em} /> },
            { titulo: "O que houve", celula: (a) => nomeDaAcao(a.tipo) },
            { titulo: "Conta", celula: (a) => <span className="mono">{a.alvo ?? "-"}</span> },
            { titulo: "Tentativas", alinhar: "right", largura: 90, celula: (a) => numero(a.contagem) },
            { titulo: "Origem", celula: (a) => <span className="mono">{a.origem ?? "-"}</span> },
          ]}
        />
      )}
      <GavetaDoAviso aviso={aberto} naTrilha={aberto !== null && acoes.includes(aberto.tipo)} aoFechar={() => setAberto(null)} aoVerNaTrilha={(acao) => { setAberto(null); aoVerNaTrilha(acao); }} aoVerOrigem={aoVerOrigem} />
    </Painel>
  );
}

export function Auditoria() {
  const pode = usePode();
  const [dias, setDias] = useState("30");
  const [acao, setAcao] = useState<string | null>(null);
  const [pessoa, setPessoa] = useState<string | null>(null);
  const [aberta, setAberta] = useState<LinhaDaTrilha | null>(null);
  const [filtroDeEventos, setFiltroDeEventos] = useState<FiltroDeEventos | null>(null);
  const [erroDeExportar, setErroDeExportar] = useState<string | null>(null);
  const [exportando, setExportando] = useState(false);
  const [carregandoMais, setCarregandoMais] = useState(false);
  // As páginas seguintes valem só para a consulta que as pediu: mudar um filtro as descarta.
  const [seguintes, setSeguintes] = useState<{ rota: string; linhas: LinhaDaTrilha[]; proximo: number | null } | null>(null);

  const filtros = new URLSearchParams({ dias });
  if (acao) filtros.set("acao", acao);
  if (pessoa) filtros.set("pessoa", pessoa);
  const rota = `/api/auditoria?${filtros}`;
  const { dados, erro } = useDados<Trilha>(rota);
  const mais = seguintes?.rota === rota ? seguintes : null;
  const linhas = [...(dados?.linhas ?? []), ...(mais?.linhas ?? [])];
  const proximo = mais ? mais.proximo : dados?.proximo ?? null;

  const carregarMais = async () => {
    if (proximo === null) return;
    setCarregandoMais(true);
    try {
      const d = await ler<Trilha>(`${rota}&antes_de=${proximo}`);
      setSeguintes({ rota, linhas: [...(mais?.linhas ?? []), ...d.linhas], proximo: d.proximo });
    } finally {
      setCarregandoMais(false);
    }
  };

  const exportar = async () => {
    setErroDeExportar(null);
    setExportando(true);
    try {
      const r = await fetch(`/api/auditoria/exportar?${filtros}`, { credentials: "same-origin" });
      if (r.status === 401) {
        window.location.assign("/");
        return;
      }
      if (!r.ok) {
        setErroDeExportar(await detalhe(r, "Não foi possível exportar a trilha."));
        return;
      }
      salvarArquivo(await r.blob(), "auditoria-roar.csv");
    } catch {
      setErroDeExportar("Não foi possível exportar a trilha.");
    } finally {
      setExportando(false);
    }
  };

  const filtrarAcao = (a: string) => { setAberta(null); setAcao(a); };
  const filtrarPessoa = (p: string) => { setAberta(null); setPessoa(p); };
  const verOrigem = pode("ver") ? (origem: string) => setFiltroDeEventos({ rotulo: `Eventos vindos de ${origem}`, consulta: { origem, dias: "90" } }) : undefined;

  return (
    <>
      <Cabecalho titulo="Auditoria" ajuda="Quem entrou, saiu e errou a senha, quem mudou o quê, e quais ativos entraram e saíram. A trilha não pode ser alterada pela tela." />
      <Stack gap="md">
        <Avisos acoes={dados?.acoes ?? []} aoVerNaTrilha={filtrarAcao} aoVerOrigem={verOrigem} />
        <Painel titulo="Trilha" acao={<Button leftSection={<IconDownload size={14} />} loading={exportando} onClick={exportar}>Exportar em CSV</Button>}>
          <Stack gap="sm">
            <Group gap="xs">
              <Select w={130} aria-label="Período" value={dias} onChange={(v) => setDias(v ?? "30")} allowDeselect={false} data={PERIODOS} />
              <Select w={280} aria-label="Ação" placeholder="Todas as ações" clearable searchable value={acao} onChange={setAcao} data={(dados?.acoes ?? []).map((a) => ({ value: a, label: nomeDaAcao(a) }))} />
              <Select w={220} aria-label="Pessoa" placeholder="Todas as pessoas" clearable searchable value={pessoa} onChange={setPessoa} data={(dados?.pessoas ?? []).map((p) => ({ value: p.id, label: p.nome }))} />
            </Group>
            {erroDeExportar && <Alert color="red" variant="light" p="xs" fz="sm" role="alert">{erroDeExportar}</Alert>}
            {!dados ? <Carregando erro={erro} /> : (
              <>
                <Tabela
                  linhas={linhas}
                  chave={(l) => l.id}
                  vazio="Nada registrado neste filtro."
                  aoClicarLinha={setAberta}
                  colunas={[
                    { titulo: "Quando", largura: 140, celula: (l) => <Data valor={l.em} /> },
                    { titulo: "Ação", celula: (l) => nomeDaAcao(l.acao) },
                    { titulo: "Pessoa", celula: nomeDaPessoa },
                    { titulo: "Alvo", celula: (l) => <Text span className="mono" lineClamp={2} title={l.alvo ?? undefined}>{l.alvo ?? "-"}</Text> },
                    { titulo: "Origem", celula: (l) => <span className="mono">{l.origem ?? "-"}</span> },
                    { titulo: "", largura: 40, celula: (l) => (
                      <AcoesDaLinha rotulo="Ações do registro" itens={[
                        { texto: "Só esta ação", aoClicar: () => filtrarAcao(l.acao) },
                        ...(l.usuario_id ? [{ texto: "Só esta pessoa", aoClicar: () => filtrarPessoa(l.usuario_id as string) }] : []),
                        ...(l.origem && verOrigem ? [{ texto: "Eventos desta origem", aoClicar: () => verOrigem(l.origem as string) }] : []),
                      ]} />
                    ) },
                  ]}
                />
                {proximo !== null && <Group justify="center"><Button loading={carregandoMais} onClick={carregarMais}>Carregar mais</Button></Group>}
              </>
            )}
          </Stack>
        </Painel>
      </Stack>
      <GavetaDaLinha linha={aberta} aoFechar={() => setAberta(null)} aoFiltrarAcao={filtrarAcao} aoFiltrarPessoa={filtrarPessoa} aoVerOrigem={verOrigem} />
      <GavetaDeEventos filtro={filtroDeEventos} aoFechar={() => setFiltroDeEventos(null)} />
    </>
  );
}
