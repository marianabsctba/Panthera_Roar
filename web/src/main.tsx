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

// Sem animações as gavetas abrem na hora: é o que permite testar a tela sem ninguém olhando.
let semAnimacao = false;
try {
  semAnimacao = localStorage.getItem("roar-sem-animacao") === "1";
} catch {
  // Sem acesso ao armazenamento, a tela segue normal.
}

createRoot(document.getElementById("raiz")!).render(
  <StrictMode>
    <MantineProvider theme={tema} defaultColorScheme="dark" forceColorScheme="dark" getStyleNonce={() => chave} env={semAnimacao ? "test" : "default"}>
      <Aplicacao />
    </MantineProvider>
  </StrictMode>,
);
