import { Button } from "@mantine/core";
import { useSyncExternalStore } from "react";

import { useEu } from "./api";

/** O pacote de evidência em montagem. Vive fora das telas: a pessoa junta itens enquanto navega. */
interface Estado { fonte: string | null; itens: Map<string, string>; versao: number }

const estado: Estado = { fonte: null, itens: new Map(), versao: 0 };
const ouvintes = new Set<() => void>();

function avisar() {
  estado.versao += 1;
  ouvintes.forEach((o) => o());
}

export const cesta = {
  /** Um pacote só leva itens de uma fonte. Devolve false quando este item é de outra. */
  alternar(fonte: string, id: string, resumo: string) {
    if (estado.itens.has(id)) estado.itens.delete(id);
    else if (estado.itens.size && estado.fonte !== fonte) return false;
    else {
      estado.fonte = fonte;
      estado.itens.set(id, resumo);
    }
    avisar();
    return true;
  },
  tirar(id: string) {
    estado.itens.delete(id);
    avisar();
  },
  esvaziar() {
    estado.itens.clear();
    estado.fonte = null;
    avisar();
  },
};

export function useCesta() {
  useSyncExternalStore((o) => { ouvintes.add(o); return () => ouvintes.delete(o); }, () => estado.versao);
  return { fonte: estado.fonte, itens: [...estado.itens.entries()].map(([id, resumo]) => ({ id, resumo })), tem: (id: string) => estado.itens.has(id) };
}

export function BotaoDaCesta({ fonte, id, resumo }: { fonte: string; id: string; resumo: string }) {
  const c = useCesta();
  const eu = useEu();
  const outraFonte = c.itens.length > 0 && c.fonte !== fonte && !c.tem(id);
  // A evidência leva o log original: quem vê mascarado não pode tirá-lo do sistema.
  if (eu.dados_mascarados) return null;
  return (
    <Button size="xs" disabled={outraFonte} title={outraFonte ? `O pacote já tem ${c.fonte}: gere ou esvazie antes` : undefined} onClick={() => cesta.alternar(fonte, id, resumo)}>
      {c.tem(id) ? "Tirar da evidência" : "Incluir na evidência"}
    </Button>
  );
}
