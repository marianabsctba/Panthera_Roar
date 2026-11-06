import "@fontsource-variable/inter";
import "@mantine/core/styles.css";
import "@mantine/charts/styles.css";
import "./estilo.css";

import { MantineProvider } from "@mantine/core";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { Aplicacao } from "./Aplicacao";
import { tema } from "./tema";

// A política de segurança só aceita a tag de estilo do Mantine com a chave desta resposta.
const chave = document.querySelector<HTMLMetaElement>('meta[name="roar-chave-de-estilo"]')?.content ?? "";
// A trava de rolagem de modais e gavetas cria a própria tag de estilo e procura a chave nesta variável.
(globalThis as { __webpack_nonce__?: string }).__webpack_nonce__ = chave;

// Sem animações as gavetas abrem na hora: é o que permite testar a tela sem ninguém olhando.
// Vale só para este carregamento: esse modo também tira as camadas flutuantes, e não pode ficar grudado no navegador de ninguém.
const semAnimacao = new URLSearchParams(window.location.search).has("sem-animacao");

const montar = () => createRoot(document.getElementById("raiz")!).render(
  <StrictMode>
    <MantineProvider theme={tema} defaultColorScheme="dark" forceColorScheme="dark" getStyleNonce={() => chave} env={semAnimacao ? "test" : "default"}>
      <Aplicacao />
    </MantineProvider>
  </StrictMode>,
);

// Na demonstração estática (npm run demo), as respostas da API vêm gravadas: liga isso antes de desenhar a primeira tela.
if (import.meta.env.MODE === "demo") {
  import("./demo").then((d) => d.ligarDemonstracao()).then(montar);
} else {
  montar();
}
