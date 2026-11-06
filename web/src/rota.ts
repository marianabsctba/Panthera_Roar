// Onde a console está. Na instalação, a tela fica no caminho (/vulnerabilidades). Na demonstração estática
// (npm run demo), fica depois do # (#/vulnerabilidades), porque ela pode morar numa subpasta qualquer do site.
const NO_HASH = import.meta.env.MODE === "demo";

export function caminho() {
  return NO_HASH ? (window.location.hash.slice(1).split("?")[0] || "/") : window.location.pathname;
}

/** A consulta (o que vem depois do ?), sem o ?. */
export function consulta() {
  return NO_HASH ? (window.location.hash.split("?")[1] ?? "") : window.location.search.slice(1);
}

export function ir(destino: string) {
  window.history.pushState(null, "", NO_HASH ? `#${destino}` : destino);
}

export function trocar(destino: string) {
  window.history.replaceState(null, "", NO_HASH ? `#${destino}` : destino);
}

/** Volta ao começo carregando tudo de novo, como depois de perder a sessão. */
export function recomecar(destino = "/") {
  if (!NO_HASH) {
    window.location.assign(destino);
    return;
  }
  window.location.hash = destino;
  window.location.reload();
}
