import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// O resultado vai para a pasta que a API já serve: o servidor de produção não precisa de Node.
export default defineConfig({
  plugins: [react()],
  base: "/estatico/console/",
  build: { outDir: "../api/roar_api/estatico/console", emptyOutDir: true, chunkSizeWarningLimit: 1500 },
  server: { proxy: { "/api": "http://localhost:8600", "/estatico/mapa-paises.json": "http://localhost:8600" } },
});
