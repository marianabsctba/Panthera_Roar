import { enviar } from "./api";
import { recomecar } from "./rota";

/** A tela inteira recarrega ao trocar: nada do que estava aberto pode continuar à vista na outra organização. */
export async function trocarDeOrganizacao(rota: string) {
  const r = await enviar(rota);
  if (r.ok) recomecar("/panorama");
}
