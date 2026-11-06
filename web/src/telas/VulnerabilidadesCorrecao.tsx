import { Button, Group, NumberInput, SimpleGrid, Stack, Text } from "@mantine/core";
import { useEffect, useState } from "react";

import { detalhe, useDados, usePode } from "../api";
import { Carregando, Numero, Painel, Tabela } from "../componentes";
import { numero } from "../formato";
import { SEVERIDADES } from "../tema";
import { chamar, DIA, Explica, GavetaDeAchados, Prazo, SeveridadeDoAchado, venceu, type Achado, type PedidoDeAchados } from "./VulnerabilidadesAchados";

type Prazos = Record<"critica" | "alta" | "media" | "baixa" | "explorada", number>;
interface Grupo { correcao: string; pacote: boolean; falhas: number; ativos: number; exploradas: number; vencidas: number; vence_primeiro: string | null; pior: string }
interface DadosDeCorrecao {
  prazos: Prazos; padrao: Prazos; periodo: number; vencidos: number; vencem_em_7_dias: number; com_prazo: number; no_prazo: number | null;
  corrigidos: Record<string, { total: number; no_prazo: number; dias_para_corrigir: number | null }>;
  faixas: { de: number; ate: number | null }[];
  idade: ({ severidade: string; total: number; mais_velho: number } & Record<string, number | string>)[];
  primeiro: Grupo[];
}

const ROTULOS: Record<keyof Prazos, string> = { critica: "Crítica", alta: "Alta", media: "Média", baixa: "Baixa", explorada: "Já explorada" };
const ORDEM = ["critica", "alta", "media", "baixa", "informativa"];

function EditorDePrazos({ atuais, padrao, aoSalvar }: { atuais: Prazos; padrao: Prazos; aoSalvar: () => void }) {
  const pode = usePode();
  const [valores, setValores] = useState<Prazos>(atuais);
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => setValores(atuais), [atuais]);
  const mudou = (Object.keys(ROTULOS) as (keyof Prazos)[]).some((k) => valores[k] !== atuais[k]);
  const salvar = async () => {
    setSalvando(true);
    setErro(null);
    const r = await chamar("/api/vuln/prazos", "PUT", valores);
    setSalvando(false);
    if (r.ok) aoSalvar();
    else setErro(await detalhe(r));
  };
  return (
    <Painel titulo="Prazos para corrigir" acao={<Explica rotulo="Como o prazo conta">Conta de quando a falha foi vista pela primeira vez. Falha já explorada por atacantes usa o prazo de exploradas quando ele é menor. Informativa não tem prazo.</Explica>}>
      <Stack gap="sm">
        <SimpleGrid cols={{ base: 2, sm: 5 }} spacing="sm">
          {(Object.keys(ROTULOS) as (keyof Prazos)[]).map((k) => (
            <NumberInput key={k} label={ROTULOS[k]} suffix=" dias" min={1} max={730} allowDecimal={false} disabled={!pode("gerir_vulnerabilidades")}
              value={valores[k]} onChange={(v) => setValores((atual) => ({ ...atual, [k]: Number(v) || 1 }))} />
          ))}
        </SimpleGrid>
        {pode("gerir_vulnerabilidades") && (
          <Group gap="sm">
            <Button onClick={salvar} loading={salvando} disabled={!mudou}>Salvar prazos</Button>
            <Button variant="subtle" onClick={() => setValores(padrao)}>Voltar ao padrão</Button>
            {erro && <Text size="sm" c="red">{erro}</Text>}
          </Group>
        )}
      </Stack>
    </Painel>
  );
}

export function Correcao() {
  const { dados: d, erro, recarregar } = useDados<DadosDeCorrecao>("/api/vuln/correcao");
  const [pedido, setPedido] = useState<PedidoDeAchados | null>(null);
  if (!d) return <Carregando erro={erro} />;

  const corrigidos = Object.values(d.corrigidos).reduce((t, c) => t + c.total, 0);
  const idade = [...d.idade].sort((x, y) => ORDEM.indexOf(x.severidade) - ORDEM.indexOf(y.severidade));
  const faixa = (f: { de: number; ate: number | null }) => (f.ate === null ? `Mais de ${f.de - 1} dias` : `${f.de} a ${f.ate} dias`);
  const naFaixa = (f: { de: number; ate: number | null }) => (a: Achado) => {
    const dias = Math.floor((Date.now() - new Date(a.primeira_vez).getTime()) / DIA);
    return dias >= f.de && (f.ate === null || dias <= f.ate);
  };

  return (
    <Stack gap="md">
      <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
        <Numero rotulo="Vencidos" valor={numero(d.vencidos)} detalhe={`de ${numero(d.com_prazo)} com prazo`} destaque={d.vencidos > 0 ? SEVERIDADES.critica.cor : undefined}
          aoClicar={() => setPedido({ titulo: "Achados vencidos", consulta: "estado=aberto", filtro: venceu })} />
        <Numero rotulo="Vencem em 7 dias" valor={numero(d.vencem_em_7_dias)}
          aoClicar={() => setPedido({ titulo: "Achados que vencem em 7 dias", consulta: "estado=aberto", filtro: (a) => !venceu(a) && a.vence_em !== null && new Date(a.vence_em).getTime() < Date.now() + 7 * DIA })} />
        <Numero rotulo={`Corrigidos no prazo em ${d.periodo} dias`} valor={d.no_prazo === null ? "-" : `${d.no_prazo}%`} detalhe={`${numero(corrigidos)} corrigidos`} />
        <Numero rotulo="Abertos com prazo" valor={numero(d.com_prazo)} aoClicar={() => setPedido({ titulo: "Achados abertos com prazo", consulta: "estado=aberto", filtro: (a) => a.vence_em !== null })} />
      </SimpleGrid>

      <Painel titulo="O que corrigir primeiro" acao={<Explica rotulo="Como esta lista é montada">As falhas abertas juntadas por pacote ou correção, começando pelas exploradas por atacantes e pelas vencidas. Clique numa linha para ver as falhas.</Explica>}>
        <Tabela
          linhas={d.primeiro}
          chave={(g) => `${g.pacote}|${g.correcao}`}
          vazio="Nenhuma falha aberta."
          aoClicarLinha={(g) => setPedido({ titulo: g.pacote ? `Pacote ${g.correcao}` : g.correcao, consulta: `estado=aberto&busca=${encodeURIComponent(g.correcao)}`, filtro: () => true })}
          colunas={[
            { titulo: "Pior", largura: 100, celula: (g) => <SeveridadeDoAchado valor={g.pior} /> },
            { titulo: "Correção", celula: (g) => (g.pacote ? <Text size="sm">Atualizar o pacote <span className="mono">{g.correcao}</span></Text> : <Text size="sm">{g.correcao}</Text>) },
            { titulo: "Falhas", alinhar: "right", largura: 70, celula: (g) => numero(g.falhas) },
            { titulo: "Ativos", alinhar: "right", largura: 70, celula: (g) => numero(g.ativos) },
            { titulo: "Exploradas", alinhar: "right", largura: 90, celula: (g) => (g.exploradas ? <Text span size="sm" c="red" fw={500}>{numero(g.exploradas)}</Text> : "-") },
            { titulo: "Prazo", largura: 150, celula: (g) => <Prazo vence_em={g.vence_primeiro} /> },
          ]}
        />
      </Painel>

      <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="md">
        <Painel titulo="Idade dos abertos">
          <Tabela
            linhas={idade}
            chave={(l) => l.severidade}
            vazio="Nenhuma falha aberta."
            colunas={[
              { titulo: "Severidade", largura: 100, celula: (l) => <SeveridadeDoAchado valor={l.severidade} /> },
              ...d.faixas.map((f) => ({
                titulo: faixa(f), alinhar: "right" as const, celula: (l: (typeof idade)[number]) => {
                  const n = Number(l[String(f.de)]);
                  return n ? <Text span size="sm" className="clicavel" style={{ cursor: "pointer" }}
                    onClick={() => setPedido({ titulo: `${SEVERIDADES[l.severidade as keyof typeof SEVERIDADES]?.texto ?? "Informativa"}, ${faixa(f).toLowerCase()}`, consulta: `estado=aberto&severidade=${l.severidade}`, filtro: naFaixa(f) })}>{numero(n)}</Text> : "-";
                },
              })),
              { titulo: "Mais velho", alinhar: "right", celula: (l) => `${numero(l.mais_velho)} dias` },
            ]}
          />
        </Painel>
        <Painel titulo={`Tempo para corrigir em ${d.periodo} dias`}>
          <Tabela
            linhas={ORDEM.filter((s) => d.corrigidos[s])}
            chave={(s) => s}
            vazio="Nada corrigido no período."
            colunas={[
              { titulo: "Severidade", largura: 100, celula: (s) => <SeveridadeDoAchado valor={s} /> },
              { titulo: "Corrigidos", alinhar: "right", celula: (s) => numero(d.corrigidos[s].total) },
              { titulo: "No prazo", alinhar: "right", celula: (s) => (s === "informativa" ? "-" : `${Math.round((100 * d.corrigidos[s].no_prazo) / d.corrigidos[s].total)}%`) },
              { titulo: "Dias, em média", alinhar: "right", celula: (s) => (d.corrigidos[s].dias_para_corrigir === null ? "-" : numero(d.corrigidos[s].dias_para_corrigir!)) },
            ]}
          />
        </Painel>
      </SimpleGrid>

      <EditorDePrazos atuais={d.prazos} padrao={d.padrao} aoSalvar={recarregar} />
      <GavetaDeAchados pedido={pedido} aoFechar={() => setPedido(null)} />
    </Stack>
  );
}
