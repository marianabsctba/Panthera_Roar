import { Alert, Box, Button, Card, Flex, List, Stack, Text, Title } from "@mantine/core";
import { useMediaQuery } from "@mantine/hooks";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { useEu } from "../api";
import { Busca, Cabecalho, Carregando, Painel } from "../componentes";
import { caminho, ir, trocar } from "../rota";

type Bloco =
  | string
  | { h: string }
  | { aviso: string }
  | { artigo: string; texto: string }
  | { lista: string[] }
  | { passos: string[] }
  | { chaves: [string, string][] };
interface Artigo { id: string; titulo: string; vista?: string; blocos: Bloco[] }
interface Grupo { grupo: string; artigos: Artigo[] }

const SO_SIEM = ["panorama", "fila", "casos", "eventos", "logs", "ataques", "fontes", "ativos", "arquivos", "inteligencia", "prova", "normas", "regras", "relatorios", "automacao"];
// O menu mora em Aplicacao.tsx e não é exportado: aqui fica só o que decide quem vê cada tela.
const ACESSO: Record<string, { modulo?: string; permissao?: string }> = {
  ...Object.fromEntries(SO_SIEM.map((v) => [v, { modulo: "siem" }])),
  vulnerabilidades: { modulo: "vulnerabilidades" },
  usuarios: { permissao: "gerir_usuarios" },
  auditoria: { permissao: "ver_auditoria" },
  integracao: {},
};

const semAcento = (t: string) => t.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase();

function textoDoBloco(b: Bloco) {
  if (typeof b === "string") return b;
  if ("h" in b) return b.h;
  if ("aviso" in b) return b.aviso;
  if ("artigo" in b) return b.texto;
  if ("lista" in b) return b.lista.join(" ");
  if ("passos" in b) return b.passos.join(" ");
  return b.chaves.flat().join(" ");
}

function MontarBloco({ bloco, aoAbrirArtigo }: { bloco: Bloco; aoAbrirArtigo: (id: string) => void }): ReactNode {
  if (typeof bloco === "string") return <Text size="sm" lh={1.6}>{bloco}</Text>;
  if ("h" in bloco) return <Title order={3} mt="xs">{bloco.h}</Title>;
  if ("aviso" in bloco) return <Alert color="rosa" variant="light" p="xs" fz="sm">{bloco.aviso}</Alert>;
  if ("artigo" in bloco) return <Box><Button size="xs" onClick={() => aoAbrirArtigo(bloco.artigo)}>{bloco.texto}</Button></Box>;
  if ("lista" in bloco || "passos" in bloco) {
    const itens = "lista" in bloco ? bloco.lista : bloco.passos;
    return <List type={"passos" in bloco ? "ordered" : "unordered"} size="sm" spacing={6} pl="xs">{itens.map((t) => <List.Item key={t}>{t}</List.Item>)}</List>;
  }
  return (
    <Box component="dl" m={0} style={{ display: "grid", gridTemplateColumns: "minmax(120px, auto) 1fr", gap: "6px 16px" }}>
      {bloco.chaves.map(([k, v]) => [
        <Text key={`${k}-k`} component="dt" size="sm" fw={600}>{k}</Text>,
        <Text key={`${k}-v`} component="dd" size="sm" c="dimmed" m={0}>{v}</Text>,
      ])}
    </Box>
  );
}

const artigoDaUrl = () => caminho().split("/")[2] || "primeiros-passos";

export function Ajuda() {
  const eu = useEu();
  const [ajuda, setAjuda] = useState<Grupo[] | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [busca, setBusca] = useState("");
  const [artigoAberto, setArtigoAberto] = useState(artigoDaUrl);
  const refArtigo = useRef<HTMLDivElement>(null);
  const largo = useMediaQuery("(min-width: 62em)");

  useEffect(() => {
    // O texto continua em um só lugar, coberto pelos testes dele. Em variável, para o empacotador não tentar incluir o arquivo.
    // Na demonstração, o arquivo mora ao lado da página, e o import resolve a partir do script: precisa do endereço inteiro.
    const rota = import.meta.env.MODE === "demo" ? new URL("estatico/ajuda.js", document.baseURI).href : "/estatico/ajuda.js";
    import(/* @vite-ignore */ rota)
      .then((m: { AJUDA: Grupo[] }) => setAjuda(m.AJUDA))
      .catch(() => setErro("Não foi possível carregar a ajuda."));
  }, []);

  const visivel = (vista: string) => {
    const a = ACESSO[vista];
    return Boolean(a) && (!a.modulo || eu.modulos.includes(a.modulo)) && (!a.permissao || eu.permissoes.includes(a.permissao));
  };

  const grupos = useMemo(() => {
    const termo = semAcento(busca.trim());
    // Artigo de módulo que não está instalado só confundiria.
    const instalado = (a: Artigo) => {
      const modulo = a.vista ? ACESSO[a.vista]?.modulo : undefined;
      return !modulo || eu.modulos.includes(modulo);
    };
    return (ajuda ?? [])
      .map((g) => ({ ...g, artigos: g.artigos.filter((a) => instalado(a) && semAcento(`${a.titulo} ${a.blocos.map(textoDoBloco).join(" ")}`).includes(termo)) }))
      .filter((g) => g.artigos.length);
  }, [ajuda, busca, eu.modulos]);

  const todos = (ajuda ?? []).flatMap((g) => g.artigos);
  const artigo = todos.find((a) => a.id === artigoAberto) ?? todos[0];

  const abrir = (id: string) => {
    setArtigoAberto(id);
    trocar(`/ajuda/${id}`);
    // Em tela estreita o artigo fica abaixo do índice: sem isto, o clique parece não fazer nada.
    refArtigo.current?.scrollIntoView({ block: "start" });
  };
  const irParaTela = (vista: string) => {
    ir(`/${vista}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  };

  return (
    <>
      <Cabecalho titulo="Ajuda" ajuda="Como usar cada tela da console. Busque por uma palavra ou escolha um artigo." />
      {!ajuda ? <Carregando erro={erro} /> : (
        <Flex gap="md" direction={{ base: "column", md: "row" }} align="flex-start">
          <Card p="sm" w={{ base: "100%", md: 306 }} style={{ flex: "none", ...(largo ? { position: "sticky", top: 64, maxHeight: "calc(100vh - 88px)", overflowY: "auto" } : {}) }}>
            <Busca valor={busca} aoMudar={setBusca} dica="Buscar na ajuda" />
            <nav aria-label="Artigos da ajuda">
              {grupos.map((g) => (
                <div key={g.grupo}>
                  <div className="menu-grupo">{g.grupo}</div>
                  {g.artigos.map((a) => (
                    <button key={a.id} type="button" className="menu-item" aria-current={a.id === artigo?.id ? "page" : undefined} onClick={() => abrir(a.id)} style={{ height: "auto", minHeight: 32, paddingBlock: 6 }}>
                      <span>{a.titulo}</span>
                    </button>
                  ))}
                </div>
              ))}
              {!grupos.length && <Text size="sm" c="dimmed" mt="sm">Nada encontrado.</Text>}
            </nav>
          </Card>
          <Box ref={refArtigo} style={{ flex: 1, minWidth: 0, width: "100%", scrollMarginTop: 64 }}>
            {artigo && (
              <Painel>
                <Stack gap="sm" maw={760}>
                  <Title order={2}>{artigo.titulo}</Title>
                  {artigo.blocos.map((b, i) => <MontarBloco key={i} bloco={b} aoAbrirArtigo={abrir} />)}
                  {/* Quem não tem acesso à tela ainda pode ler o artigo, só não recebe o atalho. */}
                  {artigo.vista && visivel(artigo.vista) && <Box mt="xs"><Button variant="filled" onClick={() => irParaTela(artigo.vista!)}>Abrir esta tela</Button></Box>}
                </Stack>
              </Painel>
            )}
          </Box>
        </Flex>
      )}
    </>
  );
}
