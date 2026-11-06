// Demonstração estática (npm run demo): a console de verdade, com as respostas da API gravadas da organização
// Demonstração (infra/demo/gravar_respostas.py). Nada sai do navegador: o fetch responde com o que foi gravado, e o
// que mudaria algo responde como se tivesse dado certo, sem gravar nada.

interface Gravacao {
  rotas: string[];
  respostas: Record<string, unknown>;
}

const NAO_TEM = { detail: "Esta parte não vem na demonstração." };

/** O mesmo texto que o gravador usa como chave do corpo: o json.dumps do Python, com as chaves em ordem. */
function comoNoPython(valor: unknown): string {
  if (valor === null || valor === undefined) return "null";
  if (Array.isArray(valor)) return `[${valor.map(comoNoPython).join(", ")}]`;
  if (typeof valor === "object") {
    const o = valor as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}: ${comoNoPython(o[k])}`).join(", ")}}`;
  }
  return JSON.stringify(valor);
}

function resposta(corpo: unknown, status = 200) {
  return new Response(status === 204 ? null : JSON.stringify(corpo), { status, headers: { "Content-Type": "application/json" } });
}

export async function ligarDemonstracao() {
  const dados: Gravacao = await (await fetch(new URL("dados-demo.json", document.baseURI))).json();
  // Primeira resposta gravada de cada caminho, sem a consulta: a tela pede com outros filtros e recebe a mesma lista.
  const porCaminho = new Map<string, unknown>();
  for (const [chave, valor] of Object.entries(dados.respostas)) {
    const [metodo, url] = chave.split(" ");
    const curta = `${metodo} ${url.split("?")[0]}`;
    if (!porCaminho.has(curta)) porCaminho.set(curta, valor);
  }
  // Detalhe que não foi gravado (outro id) recebe um que foi, do mesmo tipo de rota.
  const modelos = dados.rotas.filter((r) => r.includes("{")).map((r) => new RegExp(`^${r.replace(/\{[^}]+\}/g, "[^/]+")}$`));
  const porModelo = (metodo: string, caminho: string) => {
    const modelo = modelos.find((m) => m.test(caminho));
    if (!modelo) return undefined;
    const achada = Object.entries(dados.respostas).find(([chave]) => {
      const [m, url] = chave.split(" ");
      return m === metodo && modelo.test(url.split("?")[0]);
    });
    return achada?.[1];
  };

  const original = window.fetch.bind(window);
  window.fetch = async (entrada: RequestInfo | URL, opcoes?: RequestInit) => {
    const url = new URL(typeof entrada === "string" ? entrada : entrada instanceof URL ? entrada.href : entrada.url, document.baseURI);
    const inicio = url.pathname.indexOf("/api/");
    if (inicio < 0) return original(entrada, opcoes);
    const caminho = url.pathname.slice(inicio);
    const metodo = (opcoes?.method ?? "GET").toUpperCase();
    if (metodo !== "GET") {
      if (caminho === "/api/buscas/bloco" && typeof opcoes?.body === "string") {
        const gravada = dados.respostas[`POST ${caminho} ${comoNoPython(JSON.parse(opcoes.body))}`];
        return gravada === undefined ? resposta(NAO_TEM, 422) : resposta(gravada);
      }
      if (caminho === "/api/sair") return resposta(null, 204);
      window.dispatchEvent(new CustomEvent("roar:demonstracao", { detail: "Na demonstração nada é gravado." }));
      return resposta({}, 200);
    }
    const gravada = dados.respostas[`GET ${caminho}${url.search}`] ?? porCaminho.get(`GET ${caminho}`) ?? porModelo("GET", caminho);
    if (gravada === undefined) {
      // Para quem regrava a demonstração saber o que faltou (infra/demo/LEIAME.md).
      console.warn("demonstração sem resposta gravada:", `${caminho}${url.search}`);
      return resposta(NAO_TEM, 404);
    }
    return resposta(gravada);
  };

  // Um aviso discreto, sempre à vista: os dados são fictícios.
  const aviso = document.createElement("div");
  aviso.textContent = "Demonstração com dados fictícios";
  aviso.setAttribute("role", "note");
  Object.assign(aviso.style, {
    position: "fixed", right: "12px", bottom: "12px", zIndex: "1000", padding: "6px 10px", borderRadius: "6px", fontSize: "12px",
    background: "rgba(194, 24, 91, 0.92)", color: "#fff", pointerEvents: "none", fontFamily: "inherit",
  });
  document.body.appendChild(aviso);
}
