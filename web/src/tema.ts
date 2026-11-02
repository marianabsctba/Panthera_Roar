import { Button, Card, createTheme, Drawer, Input, Modal, Table, Tabs, Tooltip, type MantineColorsTuple } from "@mantine/core";

// O rosa é a marca: aparece na ação principal e no que está selecionado, nunca em severidade.
const rosa: MantineColorsTuple = ["#fff0f9", "#ffd6ef", "#ffadde", "#ff80cc", "#ff57bb", "#ff33ae", "#ff1fa8", "#d6138a", "#ad0d6f", "#850954"];
const escuro: MantineColorsTuple = ["#ececee", "#c6c6cb", "#9b9ba3", "#6f6f77", "#34343a", "#26262b", "#1a1a1e", "#111114", "#0c0c0e", "#08080a"];

export const SEVERIDADES = {
  critica: { texto: "Crítica", cor: "#ff5a52" },
  alta: { texto: "Alta", cor: "#ff9f43" },
  media: { texto: "Média", cor: "#ffd24d" },
  baixa: { texto: "Baixa", cor: "#6db3f2" },
} as const;

export const tema = createTheme({
  primaryColor: "rosa",
  primaryShade: 7,
  colors: { rosa, dark: escuro },
  fontFamily: "'Inter Variable', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
  fontFamilyMonospace: "ui-monospace, 'Cascadia Code', Menlo, Consolas, monospace",
  defaultRadius: "md",
  radius: { xs: "4px", sm: "6px", md: "8px", lg: "10px", xl: "12px" },
  fontSizes: { xs: "12px", sm: "13px", md: "14px", lg: "16px", xl: "20px" },
  headings: { fontWeight: "600", sizes: { h1: { fontSize: "20px", lineHeight: "28px" }, h2: { fontSize: "15px", lineHeight: "22px" }, h3: { fontSize: "13px", lineHeight: "20px" } } },
  components: {
    Button: Button.extend({ defaultProps: { size: "sm", variant: "default" } }),
    Input: Input.extend({ defaultProps: { size: "sm" } }),
    Card: Card.extend({ defaultProps: { withBorder: true, padding: "md", radius: "md" } }),
    Table: Table.extend({ defaultProps: { verticalSpacing: 8, horizontalSpacing: "sm", highlightOnHover: true, fz: "sm" } }),
    Tabs: Tabs.extend({ defaultProps: { keepMounted: false } }),
    Tooltip: Tooltip.extend({ defaultProps: { withArrow: true, openDelay: 200, fz: "xs" } }),
    Modal: Modal.extend({ defaultProps: { centered: true, radius: "md", overlayProps: { backgroundOpacity: 0.6 } } }),
    Drawer: Drawer.extend({ defaultProps: { position: "right", size: "xl", overlayProps: { backgroundOpacity: 0.5 } } }),
  },
});
