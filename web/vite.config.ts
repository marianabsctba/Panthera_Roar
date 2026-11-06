import { cpSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

const ESTATICO = resolve(__dirname, "../api/roar_api/estatico");

// A demonstração estática (npm run demo) mora numa subpasta qualquer, como a do GitHub Pages: os caminhos /estatico/
// viram relativos à página, a fonte vai embutida no CSS, e os arquivos de /estatico vão junto.
function demonstracao(): Plugin {
  const fonte = `url("data:font/woff2;base64,${readFileSync(resolve(ESTATICO, "fontes/MrDeHaviland-Regular.woff2")).toString("base64")}")`;
  return {
    name: "roar-demonstracao",
    transform(codigo, id) {
      if (!/\.(tsx?|css)$/.test(id) || !codigo.includes("/estatico/")) return null;
      return codigo
        .replace('url("/estatico/fontes/MrDeHaviland-Regular.woff2")', fonte)
        .replaceAll('"/estatico/', '"./estatico/')
        .replaceAll("`/estatico/", "`./estatico/");
    },
    transformIndexHtml: (html) => html.replaceAll('"/estatico/', '"./estatico/'),
    closeBundle() {
      for (const item of ["ajuda.js", "mapa-paises.json", "pantera.webp", "logos", "fontes"]) {
        cpSync(resolve(ESTATICO, item), resolve(__dirname, "../demo/estatico", item), { recursive: true });
      }
    },
  };
}

// O resultado vai para a pasta que a API já serve: o servidor de produção não precisa de Node.
export default defineConfig(({ mode }) => mode === "demo"
  ? {
      plugins: [react(), demonstracao()],
      base: "./",
      // web/demo traz as respostas gravadas (dados-demo.json), copiadas para a raiz da demonstração.
      publicDir: "demo",
      build: { outDir: "../demo", emptyOutDir: true, chunkSizeWarningLimit: 1500 },
    }
  : {
      plugins: [react()],
      base: "/estatico/console/",
      build: { outDir: "../api/roar_api/estatico/console", emptyOutDir: true, chunkSizeWarningLimit: 1500 },
      server: { proxy: { "/api": "http://localhost:8600", "/estatico/mapa-paises.json": "http://localhost:8600", "/estatico/fontes": "http://localhost:8600", "/estatico/pantera.webp": "http://localhost:8600" } },
    });
