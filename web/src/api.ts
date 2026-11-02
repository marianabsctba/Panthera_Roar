import { createContext, useCallback, useContext, useEffect, useState } from "react";

export interface Eu {
  nome: string;
  cliente: string;
  fuso?: string;
  perfil: string;
  permissoes: string[];
  modulos: string[];
  mfa_pendente: boolean;
  mfa_ativo: boolean;
  mfa_obrigatorio: boolean;
  mfa_codigos_restantes: number;
  trocar_senha: boolean;
}

export const ContextoEu = createContext<Eu | null>(null);
export const useEu = () => useContext(ContextoEu)!;

export function usePode() {
  const eu = useEu();
  // Esconder é só conforto: quem decide é a API, em cada rota.
  return (permissao: string) => eu.permissoes.includes(permissao);
}

async function pedir(rota: string, opcoes?: RequestInit) {
  const r = await fetch(rota, { credentials: "same-origin", ...opcoes });
  if (r.status === 401 && rota !== "/api/entrar" && rota !== "/api/mfa/verificar") {
    window.dispatchEvent(new Event("roar:sem-sessao"));
    throw new Error("sem sessão");
  }
  return r;
}

export async function ler<T>(rota: string): Promise<T> {
  const r = await pedir(rota);
  if (!r.ok) throw new Error(await detalhe(r));
  return r.json();
}

export async function enviar(rota: string, corpo?: unknown) {
  return pedir(rota, {
    method: "POST",
    ...(corpo === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo) }),
  });
}

export async function detalhe(r: Response, padrao = "Não foi possível concluir. Tente de novo.") {
  const corpo = await r.json().catch(() => ({}));
  return typeof corpo.detail === "string" ? corpo.detail : padrao;
}

export function useDados<T>(rota: string | null) {
  const [dados, setDados] = useState<T | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [carregando, setCarregando] = useState(rota !== null);
  const [versao, setVersao] = useState(0);
  const recarregar = useCallback(() => setVersao((v) => v + 1), []);
  useEffect(() => {
    if (rota === null) return;
    let valendo = true;
    setCarregando(true);
    ler<T>(rota)
      .then((d) => { if (valendo) { setDados(d); setErro(null); } })
      .catch((e: Error) => { if (valendo) setErro(e.message); })
      .finally(() => { if (valendo) setCarregando(false); });
    return () => { valendo = false; };
  }, [rota, versao]);
  return { dados, erro, carregando, recarregar };
}
