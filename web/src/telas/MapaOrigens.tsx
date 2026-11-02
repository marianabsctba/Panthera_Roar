import { ScrollArea, SegmentedControl, Stack, Text } from "@mantine/core";
import { useEffect, useMemo, useState, type MouseEvent } from "react";

import { Vazio } from "../componentes";
import { codigoDoPais, nomeDaCidade, nomeDoPais, numero } from "../formato";

export interface Pais { pais: string; total: number; graves: number }
export interface Cidade { cidade: string; regiao: string | null; pais: string; total: number; graves: number; lat: number | null; lon: number | null }
interface Desenho { largura: number; altura: number; escala: number; yNorte: number; paises: { c: string; d: string }[]; pontos: { c: string; x: number; y: number }[] }

// Sul, norte, oeste, leste. Na visão do mundo, as cidades de um país caem umas sobre as outras.
const REGIOES: Record<string, [number, number, number, number] | null> = {
  Mundo: null, Brasil: [-34, 6, -75, -34], "América do Norte": [14, 60, -130, -60], "América do Sul": [-56, 13, -82, -34], Europa: [35, 62, -11, 35], "África": [-35, 37, -18, 52], "Ásia": [-10, 55, 60, 148],
};

// A mesma projeção do desenho (Natural Earth): com ela, o ponto cai no lugar certo do país.
function projetar(d: Desenho, lat: number, lon: number): [number, number] {
  const f = (lat * Math.PI) / 180;
  const l = (lon * Math.PI) / 180;
  const f2 = f * f;
  const f4 = f2 * f2;
  const x = l * (0.8707 - 0.131979 * f2 + f4 * (-0.013791 + f4 * (0.003971 * f2 - 0.001529 * f4)));
  const y = f * (1.007226 + f2 * (0.015085 + f4 * (-0.044475 + 0.028874 * f2 - 0.005916 * f4)));
  return [d.largura / 2 + x * d.escala, (d.yNorte - y) * d.escala];
}

function caixa(d: Desenho, limites: [number, number, number, number] | null) {
  if (!limites) return [0, 0, d.largura, d.altura];
  const [sul, norte, oeste, leste] = limites;
  const cantos = [projetar(d, sul, oeste), projetar(d, sul, leste), projetar(d, norte, oeste), projetar(d, norte, leste)];
  const xs = cantos.map((c) => c[0]);
  const ys = cantos.map((c) => c[1]);
  let w = Math.max(...xs) - Math.min(...xs);
  let h = Math.max(...ys) - Math.min(...ys);
  const cx = Math.min(...xs) + w / 2;
  const cy = Math.min(...ys) + h / 2;
  // Mantém a proporção do mapa, para a região não sair espremida.
  if (w / h < d.largura / d.altura) w = (h * d.largura) / d.altura;
  else h = (w * d.altura) / d.largura;
  return [cx - w / 2, cy - h / 2, w, h];
}

export function MapaOrigens({ paises, cidades, semCidade, aoEscolher }: {
  paises: Pais[]; cidades: Cidade[]; semCidade: number; aoEscolher: (f: { pais: string; cidade?: string; rotulo: string }) => void;
}) {
  const [desenho, setDesenho] = useState<Desenho | null>(null);
  const [regiao, setRegiao] = useState("Mundo");
  const [dica, setDica] = useState<{ x: number; y: number; texto: string } | null>(null);

  useEffect(() => {
    fetch("/estatico/mapa-paises.json").then((r) => r.json()).then(setDesenho).catch(() => {});
  }, []);

  const porCodigo = useMemo(() => new Map(paises.map((p) => [codigoDoPais(p.pais), p]).filter(([c]) => c) as [string, Pais][]), [paises]);
  const maior = Math.max(1, ...paises.map((p) => p.total));
  const maiorCidade = Math.max(1, ...cidades.map((c) => c.total));

  if (!desenho) return <Vazio>Carregando o mapa...</Vazio>;
  const vb = caixa(desenho, REGIOES[regiao]);
  const aproximacao = vb[2] / desenho.largura;

  const mostrar = (texto: string) => (e: MouseEvent<SVGElement>) => {
    const r = e.currentTarget.ownerSVGElement!.getBoundingClientRect();
    setDica({ x: e.clientX - r.left, y: e.clientY - r.top, texto });
  };

  const forma = (c: string, conteudo: (props: object) => React.ReactNode, chave: string) => {
    const dado = porCodigo.get(c);
    if (!dado) return conteudo({ key: chave, className: "mapa-pais" });
    return conteudo({
      key: chave,
      className: "mapa-pais mapa-com-dado",
      style: { fillOpacity: 0.18 + 0.42 * Math.sqrt(dado.total / maior) },
      onMouseMove: mostrar(`${nomeDoPais(dado.pais)}: ${numero(dado.total)} alertas`),
      onMouseLeave: () => setDica(null),
      onClick: () => aoEscolher({ pais: dado.pais, rotulo: nomeDoPais(dado.pais) }),
    });
  };

  const pontos = cidades
    .filter((c) => Number.isFinite(c.lat) && Number.isFinite(c.lon) && Math.abs(c.lat!) <= 90 && Math.abs(c.lon!) <= 180)
    // As grandes primeiro: assim as pequenas ficam por cima e continuam clicáveis.
    .sort((a, b) => b.total - a.total);

  return (
    <Stack gap="xs">
      <ScrollArea type="never">
        <SegmentedControl size="xs" value={regiao} onChange={setRegiao} data={Object.keys(REGIOES)} aria-label="Aproximar o mapa" />
      </ScrollArea>
      <div className="mapa">
        <svg viewBox={vb.join(" ")} role="img" aria-label="Mapa com os países e as cidades de origem dos alertas. Os números estão na tabela.">
          <defs>
            <radialGradient id="metal-ponto" cx="35%" cy="30%" r="75%">
              <stop offset="0%" stopColor="#ffe3f4" />
              <stop offset="45%" stopColor="#ff6cc6" />
              <stop offset="100%" stopColor="#a81a78" />
            </radialGradient>
          </defs>
          {desenho.paises.map(({ c, d }, i) => forma(c, (p) => <path {...p} d={d} />, `p${i}`))}
          {desenho.pontos.filter(({ c }) => porCodigo.has(c)).map(({ c, x, y }, i) => forma(c, (p) => <circle {...p} cx={x} cy={y} r={4 * aproximacao} />, `q${i}`))}
          {pontos.map((c) => {
            const [x, y] = projetar(desenho, c.lat!, c.lon!);
            return (
              <circle
                key={`${c.pais}-${c.cidade}-${c.regiao}`}
                className="mapa-cidade"
                cx={x}
                cy={y}
                r={(2.5 + 7.5 * Math.sqrt(c.total / maiorCidade)) * aproximacao}
                onMouseMove={mostrar(`${nomeDaCidade(c)}: ${numero(c.total)} alertas`)}
                onMouseLeave={() => setDica(null)}
                onClick={() => aoEscolher({ pais: c.pais, cidade: c.cidade, rotulo: nomeDaCidade(c) })}
              />
            );
          })}
        </svg>
        {dica && <div className="mapa-dica" style={{ left: dica.x, top: dica.y }}>{dica.texto}</div>}
      </div>
      <Text size="xs" c="dimmed">Local provável do endereço de origem. {semCidade > 0 && `${numero(semCidade)} alertas só têm o país.`}</Text>
    </Stack>
  );
}
