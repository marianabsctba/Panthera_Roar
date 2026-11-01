// Tudo o que vem de alerta pode ter sido escrito por um atacante. Por isso a tela só monta
// elementos com textContent, nunca com innerHTML.

const SEVERIDADE = {
  critica: { texto: "Crítica", icone: "▲" },
  alta: { texto: "Alta", icone: "◆" },
  media: { texto: "Média", icone: "●" },
  baixa: { texto: "Baixa", icone: "○" },
};

const SINAIS = {
  sucesso_apos_falhas: {
    titulo: "Acesso depois de várias falhas",
    texto: (d) => `${d.falhas ?? "Várias"} tentativas falharam antes do acesso, vindas de ${d.ip ?? "um mesmo IP"}.`,
  },
  viagem_impossivel: {
    titulo: "Viagem impossível",
    texto: (d) => `${d.km ?? "?"} km em ${d.horas ?? "?"} h desde o acesso anterior${d.ip ? `, agora de ${d.ip}` : ""}.`,
  },
  primeiro_privilegio: {
    titulo: "Primeiro uso deste privilégio",
    texto: (d) => `Executou como ${d.como ?? "outro usuário"} em ${d.host ?? "um ativo"} pela primeira vez.`,
  },
  pico_de_falhas: {
    titulo: "Pico de falhas de acesso",
    texto: (d) => `${d.falhas_na_hora ?? "Muitas"} falhas em uma hora; o normal é ${d.mediana_historica ?? 0}.`,
  },
  primeiro_host: {
    titulo: "Ativo nunca usado",
    texto: (d) => `Primeiro acesso a ${d.host ?? "este ativo"}${d.ip ? `, vindo de ${d.ip}` : ""}.`,
  },
  horario_incomum: {
    titulo: "Horário fora do padrão",
    texto: (d) => `Acesso às ${String(d.hora_local ?? "?").padStart(2, "0")}h, hora local, em ${d.host ?? "um ativo"}.`,
  },
  primeiro_ip: {
    titulo: "Endereço nunca usado",
    texto: (d) => `Primeiro acesso vindo de ${d.ip ?? "um novo endereço"}.`,
  },
  host_raro_no_cliente: {
    titulo: "Ativo incomum na organização",
    texto: (d) => `Quase ninguém na organização acessa ${d.host ?? "este ativo"}.`,
  },
};

const NOMES_DE_NORMAS = { pci_dss: "PCI DSS", gdpr: "GDPR", hipaa: "HIPAA", nist_800_53: "NIST 800-53", tsc: "TSC", gpg13: "GPG13" };

const TATICAS_DE_DEFESA = {
  Model: "Conhecer", Harden: "Fortalecer", Detect: "Detectar", Isolate: "Isolar",
  Deceive: "Enganar", Evict: "Expulsar", Restore: "Restaurar",
};

const DESCRICAO_COMPORTAMENTO = {
  sucesso_apos_falhas: "Acesso depois de 5 falhas ou mais do mesmo endereço, no mesmo ativo, em 10 minutos.",
  viagem_impossivel: "Mais de 500 km a mais de 1.000 km/h entre dois acessos.",
  primeiro_privilegio: "Primeira vez que a pessoa executa como outro usuário naquele ativo.",
  pico_de_falhas: "Falhas de acesso em uma hora muito acima do histórico.",
  primeiro_host: "Ativo que a pessoa nunca tinha usado.",
  horario_incomum: "Acesso em hora muito rara para a pessoa, no fuso da organização.",
  primeiro_ip: "Endereço que a pessoa nunca tinha usado.",
  host_raro_no_cliente: "Ativo usado por menos de 5% da organização.",
};

const $ = (id) => document.getElementById(id);
const estado = { aba: "riscos", fila: { riscos: [], grupos: [] }, selecionado: null, fuso: undefined, dias: 30, panorama: null, eventos: [], regras: [], logs: [], proximoLog: null, norma: "gdpr", matriz: null, modoRegra: "guiada", biblioteca: [], filtrosLog: [], colunasLog: [] };

function el(tag, classe, texto) {
  const e = document.createElement(tag);
  if (classe) e.className = classe;
  if (texto !== undefined && texto !== null) e.textContent = texto;
  return e;
}

function selo(severidade) {
  const s = SEVERIDADE[severidade] ?? SEVERIDADE.baixa;
  return el("span", `selo selo-${severidade in SEVERIDADE ? severidade : "baixa"}`, `${s.icone} ${s.texto}`);
}

function quando(valor) {
  if (!valor) return "-";
  return new Date(valor).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: estado.fuso });
}

function tituloDoSinal(tipo) {
  return SINAIS[tipo]?.titulo ?? tipo;
}

async function pedir(rota, opcoes) {
  const r = await fetch(rota, { credentials: "same-origin", ...opcoes });
  if (r.status === 401 && rota !== "/api/entrar") {
    mostrarEntrada();
    throw new Error("sem sessão");
  }
  return r;
}

function mostrarEntrada() {
  $("painel").hidden = true;
  $("entrada").hidden = false;
  $("email").focus();
}

async function entrar(evento) {
  evento.preventDefault();
  const erro = $("erro-entrada");
  erro.hidden = true;
  const r = await pedir("/api/entrar", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: $("email").value, senha: $("senha").value }),
  });
  $("senha").value = "";
  if (!r.ok) {
    const corpo = await r.json().catch(() => ({}));
    erro.textContent = typeof corpo.detail === "string" ? corpo.detail : "Não foi possível entrar.";
    erro.hidden = false;
    return;
  }
  await abrirPainel();
}

async function abrirPainel() {
  const r = await pedir("/api/eu");
  const eu = await r.json();
  estado.fuso = eu.fuso;
  $("cliente").textContent = eu.cliente;
  $("usuario").textContent = eu.nome;
  $("entrada").hidden = true;
  $("painel").hidden = false;
  await Promise.all([carregarFila(), carregarPanorama()]);
}

async function carregarFila() {
  const r = await pedir("/api/fila");
  estado.fila = await r.json();
  const { riscos, grupos } = estado.fila;
  $("n-criticos").textContent = riscos.filter((a) => a.severidade === "critica").length;
  $("n-altos").textContent = riscos.filter((a) => a.severidade === "alta").length;
  $("n-grupos").textContent = grupos.length;
  $("n-eventos").textContent = grupos.reduce((t, g) => t + g.total, 0).toLocaleString("pt-BR");
  desenharLista();
  if (!estado.selecionado) desenharDetalheVazio();
}

function itemDeRisco(a) {
  const botao = el("button", "item");
  botao.type = "button";
  const topo = el("div", "item-topo");
  topo.append(el("span", "item-titulo", a.entidade), selo(a.severidade));
  const sinais = (a.sinais ?? []).map(tituloDoSinal).join(" · ");
  botao.append(topo, el("span", "item-linha", sinais),
    el("span", "item-linha", `Risco ${Math.round(a.risco_maximo)} · ${quando(a.quando)}`));
  botao.addEventListener("click", () => selecionar("riscos", a.id));
  return botao;
}

function itemDeGrupo(g) {
  const botao = el("button", "item");
  botao.type = "button";
  const topo = el("div", "item-topo");
  topo.append(el("span", "item-titulo", g.descricao ?? "Alerta"), selo(g.severidade));
  const origem = g.ip_origem ? `de ${g.ip_origem}` : "sem origem";
  const vezes = g.total === 1 ? "1 evento" : `${g.total.toLocaleString("pt-BR")} eventos`;
  botao.append(topo, el("span", "item-linha", `${g.ativo ?? g.agente_id} · ${origem}`),
    el("span", "item-linha", `${vezes} · ${quando(g.quando)}`));
  botao.addEventListener("click", () => selecionar("grupos", g.id));
  return botao;
}

function desenharLista() {
  const lista = $("lista");
  lista.replaceChildren();
  document.querySelectorAll(".abas button").forEach((b) => {
    b.setAttribute("aria-selected", String(b.dataset.aba === estado.aba));
  });
  const itens = estado.fila[estado.aba];
  if (!itens.length) {
    lista.append(el("li", "vazio", estado.aba === "riscos" ? "Nenhum risco aberto." : "Nenhum alerta."));
    return;
  }
  for (const item of itens) {
    const li = el("li");
    const botao = estado.aba === "riscos" ? itemDeRisco(item) : itemDeGrupo(item);
    const atual = estado.selecionado?.aba === estado.aba && estado.selecionado?.id === item.id;
    if (atual) botao.setAttribute("aria-current", "true");
    li.append(botao);
    lista.append(li);
  }
}

function desenharDetalheVazio() {
  $("detalhe").replaceChildren(el("div", "detalhe-vazio", "Selecione um item da fila para ver as evidências."));
}

function fato(rotulo, valor) {
  const d = el("div", "fato");
  d.append(el("span", null, rotulo), el("b", null, valor ?? "-"));
  return d;
}

function desenharRisco({ alerta, sinais }) {
  const cab = el("h2");
  cab.append(el("span", null, alerta.entidade), selo(alerta.severidade));
  const tipo = alerta.entidade_tipo === "ativo" ? "Ativo" : "Usuário";

  const medidor = el("div", "medidor");
  const rotulos = el("div", "medidor-rotulos");
  rotulos.append(el("span", null, `Risco atual ${Math.round(alerta.risco_atual)}`),
    el("span", null, `Máximo ${Math.round(alerta.risco_maximo)}`));
  const barra = el("div", "medidor-barra");
  const preenchido = el("span");
  preenchido.style.width = `${Math.min(100, alerta.risco_atual)}%`;
  barra.append(preenchido);
  medidor.append(rotulos, barra);

  const linha = el("ol", "linha-do-tempo");
  for (const s of sinais) {
    const descricao = SINAIS[s.tipo];
    const li = el("li", "sinal");
    li.append(el("span", "sinal-titulo", tituloDoSinal(s.tipo)), el("span", "sinal-peso", `+${Math.round(s.peso)}`),
      el("span", "sinal-texto", descricao ? descricao.texto(s.detalhes ?? {}) : (s.regra_descricao ?? "")),
      el("span", "sinal-quando", `${quando(s.ocorrido_em)} · ${s.regra_descricao ?? "evento"}`), botaoBruto(s.evento_id));
    linha.append(li);
  }
  $("detalhe").replaceChildren(cab, el("p", "subtitulo", `${tipo} · aberto em ${quando(alerta.aberto_em)}`),
    medidor, botaoAutomatizar(() => rascunhoDeRisco(alerta)), el("h3", null, "Por que este alerta existe"), linha);
}

function desenharGrupo({ grupo, eventos }) {
  const titulo = eventos[0]?.regra_descricao ?? "Alerta";
  const cab = el("h2");
  cab.append(el("span", null, titulo), selo(grupo.severidade));
  const fatos = el("div", "fatos");
  fatos.append(fato("Eventos", grupo.total.toLocaleString("pt-BR")), fato("Origem", grupo.ip_origem ?? "Sem origem"),
    fato("Ativo", eventos[0]?.ativo ?? grupo.agente_id), fato("Primeiro", quando(grupo.primeira_em)),
    fato("Último", quando(grupo.ultima_em)));

  const tabela = el("table");
  const cabecalho = el("tr");
  ["Quando", "Severidade", "Evento", "Usuário", "Origem", ""].forEach((c) => cabecalho.append(el("th", null, c)));
  const thead = el("thead");
  thead.append(cabecalho);
  const tbody = el("tbody");
  for (const e of eventos) {
    const tr = el("tr");
    const sev = el("td");
    sev.append(selo(e.severidade));
    tr.append(el("td", null, quando(e.ocorrido_em)), sev, el("td", null, e.regra_descricao ?? e.regra_id),
      el("td", "mono", e.usuario ?? "-"), el("td", "mono ip", e.ip_origem ?? "-"), celula(botaoBruto(e.id)));
    tbody.append(tr);
  }
  tabela.append(thead, tbody);
  const rolagem = el("div", "tabela-rolagem");
  rolagem.append(tabela);
  $("detalhe").replaceChildren(cab, fatos, botaoAutomatizar(() => rascunhoDeGrupo(grupo, eventos)), el("h3", null, "Eventos recentes"), rolagem);
}

async function selecionar(aba, id) {
  estado.selecionado = { aba, id };
  desenharLista();
  const r = await pedir(`/api/${aba}/${id}`);
  if (!r.ok) {
    $("detalhe").replaceChildren(el("div", "detalhe-vazio", "Este item não está mais disponível."));
    return;
  }
  const dados = await r.json();
  if (aba === "riscos") desenharRisco(dados);
  else desenharGrupo(dados);
}

// ------------------------------------------------------------------ panorama

const FAIXAS = ["baixa", "media", "alta", "critica"];
const NS = "http://www.w3.org/2000/svg";

function svg(tag, atributos = {}, texto) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(atributos)) e.setAttribute(k, v);
  if (texto !== undefined) e.textContent = texto;
  return e;
}

function mostrarDica(alvo, titulo, linhas) {
  const dica = $("dica");
  const cab = el("b", null, titulo);
  dica.replaceChildren(cab, ...linhas.map(([rotulo, valor]) => {
    const d = el("div");
    d.append(el("span", null, rotulo), el("span", null, valor));
    return d;
  }));
  dica.hidden = false;
  const a = alvo.getBoundingClientRect();
  const m = dica.getBoundingClientRect();
  dica.style.left = `${Math.max(8, Math.min(innerWidth - m.width - 8, a.left + a.width / 2 - m.width / 2))}px`;
  dica.style.top = `${a.top - m.height - 8 > 0 ? a.top - m.height - 8 : a.bottom + 8}px`;
}

function esconderDica() {
  $("dica").hidden = true;
}

function comDica(alvo, titulo, linhas) {
  const abrir = () => mostrarDica(alvo, titulo, linhas);
  alvo.addEventListener("mouseenter", abrir);
  alvo.addEventListener("focus", abrir);
  alvo.addEventListener("mouseleave", esconderDica);
  alvo.addEventListener("blur", esconderDica);
}

function marcaLimpa(maximo) {
  // A grade tem 4 divisões: o passo precisa ser um número redondo, e inteiro em escala pequena.
  const minimo = maximo / 4;
  const ordem = 10 ** Math.floor(Math.log10(Math.max(minimo, 1)));
  const passos = ordem === 1 ? [1, 2, 3, 5, 10] : [1, 1.5, 2, 2.5, 3, 5, 7.5, 10];
  return passos.find((p) => p * ordem >= minimo) * ordem * 4;
}

function dataCurta(dia) {
  const [, mes, d] = dia.split("-");
  return `${d}/${mes}`;
}

function desenharColunas(dias) {
  const area = $("grafico-dias");
  const largura = area.clientWidth;
  if (!largura) return;
  const altura = area.clientHeight;
  const m = { topo: 8, dir: 4, base: 22, esq: 34 };
  const totais = dias.map((d) => FAIXAS.reduce((t, f) => t + d[f], 0));
  const teto = marcaLimpa(Math.max(...totais, 1));
  const planoA = altura - m.topo - m.base;
  const planoL = largura - m.esq - m.dir;
  const y = (v) => m.topo + planoA - (v / teto) * planoA;
  const grafico = svg("svg", { viewBox: `0 0 ${largura} ${altura}`, role: "img", "aria-label": "Alertas por dia, por severidade" });

  for (let i = 0; i <= 4; i += 1) {
    const v = (teto / 4) * i;
    grafico.append(svg("line", { class: "grade", x1: m.esq, x2: largura - m.dir, y1: y(v), y2: y(v) }));
    grafico.append(svg("text", { x: m.esq - 6, y: y(v) + 4, "text-anchor": "end" }, Math.round(v).toLocaleString("pt-BR")));
  }

  const faixa = planoL / dias.length;
  const coluna = Math.min(24, Math.max(2, faixa - 2));
  const salto = Math.ceil(44 / faixa);
  dias.forEach((d, i) => {
    const x = m.esq + faixa * i + (faixa - coluna) / 2;
    const g = svg("g", { class: "coluna", tabindex: "0", role: "img", "aria-label": `${dataCurta(d.dia)}: ${totais[i]} alertas` });
    g.append(svg("rect", { class: "coluna-foco", x: m.esq + faixa * i, y: m.topo, width: faixa, height: planoA }));
    let base = 0;
    const visiveis = FAIXAS.filter((f) => d[f] > 0);
    visiveis.forEach((f, ordem) => {
      const topo = y(base + d[f]);
      const fundo = y(base) - (base > 0 ? 2 : 0);
      const h = Math.max(1, fundo - topo);
      const raio = ordem === visiveis.length - 1 ? Math.min(4, h, coluna / 2) : 0;
      // Só a ponta da coluna é arredondada; a base fica reta sobre o eixo.
      g.append(svg("path", {
        class: `seg-${f}`,
        d: `M${x},${topo + h}V${topo + raio}Q${x},${topo} ${x + raio},${topo}H${x + coluna - raio}Q${x + coluna},${topo} ${x + coluna},${topo + raio}V${topo + h}Z`,
      }));
      base += d[f];
    });
    comDica(g, dataCurta(d.dia), [...FAIXAS].reverse().map((f) => [SEVERIDADE[f].texto, d[f].toLocaleString("pt-BR")]));
    grafico.append(g);
    if ((dias.length - 1 - i) % salto === 0) {
      // O rótulo da ponta alinha pela direita, para não ser cortado na borda do gráfico.
      const ultimo = i === dias.length - 1;
      grafico.append(svg("text", {
        x: ultimo ? largura - m.dir : x + coluna / 2,
        y: altura - 6,
        "text-anchor": ultimo ? "end" : "middle",
      }, dataCurta(d.dia)));
    }
  });
  area.replaceChildren(grafico);
}

function desenharBarras(destino, itens, vazio) {
  const alvo = $(destino);
  if (!itens.length) {
    alvo.replaceChildren(el("p", "sem-dados", vazio));
    return;
  }
  const maximo = Math.max(...itens.map((i) => i.valor), 1);
  const lista = el("div", "barras");
  for (const item of itens) {
    const linha = el("div", "barra");
    linha.tabIndex = 0;
    const trilho = el("div", "barra-trilho");
    const marca = el("span", "barra-marca");
    // O número fica fora da barra, então ela nunca ocupa o trilho inteiro.
    marca.style.width = `calc(${(item.valor / maximo) * 100}% - ${(item.valor / maximo) * 44}px)`;
    trilho.append(marca, el("span", "barra-valor", item.valor.toLocaleString("pt-BR")));
    linha.append(el("span", "barra-rotulo", item.rotulo), trilho);
    comDica(linha, item.rotulo, [[item.medida, item.valor.toLocaleString("pt-BR")]]);
    lista.append(linha);
  }
  alvo.replaceChildren(lista);
}

function desenharTabelaDias(dias) {
  const tabela = el("table");
  const cab = el("tr");
  ["Dia", ...FAIXAS.map((f) => SEVERIDADE[f].texto)].forEach((c) => cab.append(el("th", null, c)));
  const thead = el("thead");
  thead.append(cab);
  const tbody = el("tbody");
  for (const d of [...dias].reverse()) {
    const tr = el("tr");
    tr.append(el("td", null, dataCurta(d.dia)), ...FAIXAS.map((f) => el("td", null, d[f].toLocaleString("pt-BR"))));
    tbody.append(tr);
  }
  tabela.append(thead, tbody);
  $("tabela-dias").replaceChildren(tabela);
}

function desenharLegenda() {
  $("legenda-dias").replaceChildren(...[...FAIXAS].reverse().map((f) => {
    const item = el("span");
    item.append(el("i", `cor-${f}`), `${SEVERIDADE[f].icone} ${SEVERIDADE[f].texto}`);
    return item;
  }));
}

async function carregarPanorama() {
  const r = await pedir(`/api/panorama?dias=${estado.dias}`);
  const p = await r.json();
  estado.panorama = p;
  desenharColunas(p.por_dia);
  desenharTabelaDias(p.por_dia);
  desenharBarras("grafico-riscos", p.riscos.map((x) => ({ rotulo: x.entidade, valor: Math.round(x.risco), medida: "Risco" })),
    "Ninguém com risco no momento.");
  desenharBarras("grafico-sinais", p.sinais.map((x) => ({ rotulo: tituloDoSinal(x.tipo), valor: x.total, medida: "Sinais" })),
    "Nenhum sinal no período.");
  desenharBarras("grafico-origens", p.origens.map((x) => ({ rotulo: x.origem, valor: x.total, medida: "Eventos" })),
    "Nenhuma origem no período.");
}

// ------------------------------------------------------------------ bruto

function botaoBruto(evento) {
  const b = el("button", "botao-discreto botao-tabela", "Ver bruto");
  b.type = "button";
  b.addEventListener("click", () => abrirBruto(evento));
  return b;
}

async function abrirBruto(evento) {
  const r = await pedir(`/api/eventos/${evento}/bruto`);
  if (!r.ok) return;
  const dados = await r.json();
  $("meta-bruto").textContent = `Recebido em ${quando(dados.recebido_em)} · identificador ${dados.origem_id}`
    + (dados.bruto?.roar_truncado ? " · conteúdo grande: guardamos só o resumo e o hash" : "");
  $("conteudo-bruto").textContent = JSON.stringify(dados.bruto, null, 2);
  $("janela-bruto").showModal();
}

// ------------------------------------------------------------------ eventos

function montarTabela(colunas, linhas) {
  const tabela = el("table");
  const cab = el("tr");
  colunas.forEach(([rotulo, classe]) => cab.append(el("th", classe, rotulo)));
  const thead = el("thead");
  thead.append(cab);
  const tbody = el("tbody");
  linhas.forEach((celulas) => {
    const tr = el("tr");
    tr.append(...celulas);
    tbody.append(tr);
  });
  tabela.append(thead, tbody);
  return tabela;
}

function celula(conteudo, classe) {
  const td = el("td", classe);
  td.append(conteudo);
  return td;
}

function linhaDeEvento(e) {
  return [el("td", null, quando(e.ocorrido_em)), celula(selo(e.severidade)),
    el("td", null, e.regra_descricao ?? e.regra_id), el("td", null, e.ativo ?? "-"),
    el("td", "mono", e.usuario ?? "-"), el("td", "mono ip", e.ip_origem ?? "-"), celula(botaoBruto(e.id))];
}

const COLUNAS_EVENTOS = [["Quando"], ["Severidade"], ["Evento"], ["Ativo"], ["Usuário"], ["Origem"], [""]];

async function carregarEventos(continuar = false) {
  const consulta = new URLSearchParams({
    busca: $("busca-eventos").value,
    severidade: $("severidade-eventos").value,
    dias: $("dias-eventos").value,
  });
  if (continuar && estado.eventos.length) consulta.set("antes_de", estado.eventos.at(-1).id);
  const r = await pedir(`/api/eventos?${consulta}`);
  const dados = await r.json();
  estado.eventos = continuar ? [...estado.eventos, ...dados.eventos] : dados.eventos;
  const destino = $("tabela-eventos");
  if (!estado.eventos.length) destino.replaceChildren(el("p", "vazio", "Nenhum evento encontrado."));
  else destino.replaceChildren(montarTabela(COLUNAS_EVENTOS, estado.eventos.map(linhaDeEvento)));
  $("mais-eventos").hidden = !dados.ha_mais;
}

// ------------------------------------------------------------------ logs brutos

const ROTULOS_DE_CAMPO = {
  timestamp: "Quando", "agent.name": "Ativo", location: "Fonte", "decoder.name": "Tipo de log", "data.srcip": "Origem",
  "data.srcuser": "Usuário", "data.dstuser": "Usuário de destino", "data.protocol": "Protocolo",
  "predecoder.program_name": "Programa", full_log: "Log",
};
const COLUNAS_PADRAO = ["timestamp", "agent.name", "decoder.name", "data.srcip", "data.srcuser", "full_log"];

function rotuloDoCampo(campo) {
  return ROTULOS_DE_CAMPO[campo] ?? campo;
}

// Transforma o documento em pares "campo.subcampo": valor, que é o que a tabela e os filtros usam.
function achatar(objeto, prefixo = "", saida = {}) {
  for (const [chave, valor] of Object.entries(objeto ?? {})) {
    const nome = prefixo ? `${prefixo}.${chave}` : chave;
    if (valor && typeof valor === "object" && !Array.isArray(valor)) achatar(valor, nome, saida);
    else saida[nome] = Array.isArray(valor) ? valor.join(", ") : valor;
  }
  return saida;
}

function colunasSalvas() {
  try {
    const salvas = JSON.parse(localStorage.getItem("roar-colunas-logs"));
    if (Array.isArray(salvas) && salvas.length && salvas.every((c) => typeof c === "string")) return salvas;
  } catch { /* preferência é só conveniência */ }
  return COLUNAS_PADRAO;
}

estado.colunasLog = colunasSalvas();

function guardarColunas() {
  try { localStorage.setItem("roar-colunas-logs", JSON.stringify(estado.colunasLog)); } catch { /* idem */ }
}

function alternarFiltro(campo, valor, negar = false) {
  const existente = estado.filtrosLog.findIndex((f) => f.campo === campo && f.valor === valor);
  if (existente >= 0) estado.filtrosLog.splice(existente, 1);
  estado.filtrosLog.push({ campo, valor, negar });
  carregarLogs();
}

function desenharFiltrosLog() {
  $("filtros-logs").replaceChildren(...estado.filtrosLog.map((f, i) => {
    const b = el("button", `filtro-ativo ${f.negar ? "filtro-negado" : ""}`, `${f.negar ? "não " : ""}${rotuloDoCampo(f.campo)}: ${f.valor} ✕`);
    b.type = "button";
    b.title = "Remover filtro";
    b.addEventListener("click", () => {
      estado.filtrosLog.splice(i, 1);
      carregarLogs();
    });
    return b;
  }));
}

function desenharLinhaDoTempo(pontos) {
  const area = $("linha-do-tempo");
  if (!pontos.length) {
    area.replaceChildren();
    return;
  }
  const largura = area.clientWidth || 600;
  const altura = area.clientHeight || 56;
  const maximo = Math.max(...pontos.map((p) => p.total), 1);
  const faixa = largura / pontos.length;
  const grafico = svg("svg", { viewBox: `0 0 ${largura} ${altura}` });
  pontos.forEach((p, i) => {
    const h = p.total ? Math.max(2, (p.total / maximo) * (altura - 4)) : 0;
    const g = svg("g", { tabindex: "0" });
    g.append(svg("rect", { class: "faixa-tempo", x: faixa * i, y: 0, width: faixa, height: altura }));
    if (h) {
      g.append(svg("rect", { class: "barra-tempo", x: faixa * i + 1, y: altura - h, width: Math.max(1, Math.min(24, faixa - 2)), height: h, rx: 1 }));
    }
    comDica(g, new Date(p.quando).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: estado.fuso }),
      [["Logs", p.total.toLocaleString("pt-BR")]]);
    grafico.append(g);
  });
  area.replaceChildren(grafico);
}

function desenharCamposLog(campos) {
  const blocos = Object.entries(campos).filter(([, valores]) => valores.length).map(([campo, valores]) => {
    const bloco = el("div", "campo-log");
    bloco.append(el("h3", null, rotuloDoCampo(campo)));
    valores.forEach((v) => {
      const linha = el("div", "valor-campo");
      const nome = el("button", "nome", String(v.valor));
      nome.type = "button";
      nome.title = `Filtrar por ${v.valor}`;
      nome.addEventListener("click", () => alternarFiltro(campo, v.valor));
      const excluir = el("button", "excluir-valor", "−");
      excluir.type = "button";
      excluir.title = `Excluir ${v.valor}`;
      excluir.setAttribute("aria-label", `Excluir ${v.valor}`);
      excluir.addEventListener("click", () => alternarFiltro(campo, v.valor, true));
      linha.append(nome, el("span", null, v.total.toLocaleString("pt-BR")), excluir);
      bloco.append(linha);
    });
    return bloco;
  });
  $("campos-logs").replaceChildren(...(blocos.length ? blocos : [el("p", "texto-secao", "Sem campos para mostrar.")]));
}

function celulaDeCampo(item, campo) {
  const valor = achatar(item.bruto)[campo];
  if (campo === "timestamp") return el("td", "curto", quando(valor));
  if (campo === "full_log") return el("td", "log-texto", valor ?? "-");
  return el("td", "curto mono", valor ?? "-");
}

function desenharTabelaLogs() {
  const destino = $("tabela-logs");
  if (!estado.logs.length) {
    destino.replaceChildren(el("p", "vazio", "Nenhum log encontrado."));
    return;
  }
  const colunas = estado.colunasDaConsulta ?? estado.colunasLog;
  const tabela = montarTabela(colunas.map((c) => [rotuloDoCampo(c)]), estado.logs.map((item) => colunas.map((c) => celulaDeCampo(item, c))));
  tabela.classList.add("tabela-logs");
  tabela.querySelectorAll("tbody tr").forEach((tr, i) => {
    tr.tabIndex = 0;
    tr.addEventListener("click", () => abrirLog(estado.logs[i]));
    tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter") abrirLog(estado.logs[i]); });
  });
  destino.replaceChildren(tabela);
}

// Resultado de "contar por": uma barra por valor, e clicar filtra por ele.
function desenharContagem(dados) {
  const { campo, linhas } = dados.contagem;
  const total = Number(dados.total ?? 0).toLocaleString("pt-BR");
  $("total-logs").textContent = campo ? `${total} logs, em ${linhas.length} valores de ${rotuloDoCampo(campo)}.` : `${total} logs.`;
  $("linha-do-tempo").replaceChildren();
  $("campos-logs").hidden = true;
  $("mais-logs").hidden = true;
  const destino = $("tabela-logs");
  if (!campo) {
    destino.replaceChildren();
    return;
  }
  if (!linhas.length) {
    destino.replaceChildren(el("p", "vazio", "Nenhum valor encontrado para este campo."));
    return;
  }
  const maximo = Math.max(...linhas.map((l) => l.total), 1);
  const lista = el("div", "barras");
  linhas.forEach((l) => {
    const linha = el("button", "barra");
    linha.type = "button";
    linha.title = `Filtrar por ${l.valor}`;
    linha.style.cursor = "pointer";
    const trilho = el("div", "barra-trilho");
    const marca = el("span", "barra-marca");
    marca.style.width = `calc(${(l.total / maximo) * 100}% - ${(l.total / maximo) * 60}px)`;
    trilho.append(marca, el("span", "barra-valor", l.total.toLocaleString("pt-BR")));
    linha.append(el("span", "barra-rotulo", String(l.valor)), trilho);
    linha.addEventListener("click", () => {
      $("busca-logs").value = $("busca-logs").value.split("|")[0].trim();
      alternarFiltro(campo, l.valor);
    });
    lista.append(linha);
  });
  destino.replaceChildren(lista);
}

function abrirLog(item) {
  const campos = achatar(item.bruto);
  const corpo = [];
  corpo.push(el("p", "texto-secao", `${quando(item.bruto.timestamp)} · identificador ${item.id}`));
  const tabela = el("table", "campos-do-log");
  const tbody = el("tbody");
  Object.keys(campos).sort().forEach((campo) => {
    const tr = el("tr");
    const acoes = el("td");
    const fechar = () => $("janela-log").close();
    const filtrar = el("button", "botao-discreto botao-tabela", "Filtrar");
    filtrar.type = "button";
    filtrar.addEventListener("click", () => { fechar(); alternarFiltro(campo, campos[campo]); });
    const excluir = el("button", "botao-discreto botao-tabela", "Excluir");
    excluir.type = "button";
    excluir.addEventListener("click", () => { fechar(); alternarFiltro(campo, campos[campo], true); });
    const coluna = el("button", "botao-discreto botao-tabela", estado.colunasLog.includes(campo) ? "Tirar coluna" : "Coluna");
    coluna.type = "button";
    coluna.addEventListener("click", () => { alternarColuna(campo); coluna.textContent = estado.colunasLog.includes(campo) ? "Tirar coluna" : "Coluna"; });
    if (campo !== "full_log" && campo !== "timestamp") acoes.append(filtrar, excluir);
    acoes.append(coluna);
    tr.append(el("td", null, campo), el("td", null, String(campos[campo])), acoes);
    tbody.append(tr);
  });
  tabela.append(tbody);
  corpo.push(tabela, el("h3", null, "Documento original"), el("pre", "bruto", JSON.stringify(item.bruto, null, 2)));
  $("conteudo-log").replaceChildren(...corpo);
  $("janela-log").showModal();
}

function alternarColuna(campo) {
  estado.colunasLog = estado.colunasLog.includes(campo) ? estado.colunasLog.filter((c) => c !== campo) : [...estado.colunasLog, campo];
  if (!estado.colunasLog.length) estado.colunasLog = [...COLUNAS_PADRAO];
  guardarColunas();
  desenharTabelaLogs();
}

function abrirColunas() {
  const disponiveis = new Set([...COLUNAS_PADRAO, ...estado.colunasLog]);
  estado.logs.forEach((item) => Object.keys(achatar(item.bruto)).forEach((c) => disponiveis.add(c)));
  $("lista-colunas").replaceChildren(...[...disponiveis].sort().map((campo) => {
    const rotulo = el("label");
    const caixa = el("input");
    caixa.type = "checkbox";
    caixa.checked = estado.colunasLog.includes(campo);
    caixa.addEventListener("change", () => alternarColuna(campo));
    rotulo.append(caixa, campo);
    return rotulo;
  }));
  $("janela-colunas").showModal();
}

async function carregarLogs(continuar = false) {
  const consulta = new URLSearchParams({
    busca: $("busca-logs").value,
    dias: $("dias-logs").value,
    filtros: JSON.stringify(estado.filtrosLog),
  });
  if (continuar && estado.proximoLog) consulta.set("depois_de", estado.proximoLog);
  desenharFiltrosLog();
  $("erro-consulta").hidden = true;
  const r = await pedir(`/api/logs?${consulta}`);
  if (!r.ok) {
    const corpo = await r.json().catch(() => ({}));
    if (r.status === 422 && typeof corpo.detail === "string") {
      // Erro de escrita na consulta: mantém o resultado anterior na tela para a pessoa corrigir.
      $("erro-consulta").textContent = corpo.detail;
      $("erro-consulta").hidden = false;
    } else {
      $("tabela-logs").replaceChildren(el("p", "vazio", "Não foi possível consultar os logs agora."));
    }
    return;
  }
  const dados = await r.json();
  estado.logs = continuar ? [...estado.logs, ...dados.logs] : dados.logs;
  estado.proximoLog = dados.proximo;
  estado.colunasDaConsulta = dados.colunas?.length ? dados.colunas : null;
  if (dados.contagem) {
    desenharContagem(dados);
    return;
  }
  $("campos-logs").hidden = false;
  if (!continuar) {
    const total = Number(dados.total ?? 0).toLocaleString("pt-BR");
    $("total-logs").textContent = `${dados.total_exato === false ? "Mais de " : ""}${total} logs, inclusive os que não viraram alerta. Clique numa linha para ver os campos. Cada busca fica registrada.`;
    desenharLinhaDoTempo(dados.linha_do_tempo ?? []);
    desenharCamposLog(dados.campos ?? {});
  }
  desenharTabelaLogs();
  $("mais-logs").hidden = !dados.proximo;
}

$("form-logs").addEventListener("submit", (ev) => { ev.preventDefault(); carregarLogs(); });
$("mais-logs").addEventListener("click", () => carregarLogs(true));
$("abrir-colunas").addEventListener("click", abrirColunas);
$("fechar-colunas").addEventListener("click", () => $("janela-colunas").close());
$("fechar-log").addEventListener("click", () => $("janela-log").close());

// ------------------------------------------------------------------ ataque e defesa

function estadoDaTecnica(t) {
  if (t.observados >= 50) return "estado-3";
  if (t.observados >= 10) return "estado-2";
  if (t.observados > 0) return "estado-1";
  return t.regras > 0 ? "estado-coberta" : "";
}

function desenharMatriz() {
  const { taticas, tecnicas } = estado.matriz;
  const so = $("so-observadas").checked;
  $("matriz-ataques").replaceChildren(...taticas.map((tatica) => {
    const coluna = el("div", "coluna-tatica");
    const daTatica = tecnicas.filter((t) => t.taticas.includes(tatica.tatica) && (!so || t.observados > 0));
    const titulo = el("h3", null, tatica.nome);
    titulo.append(el("small", null, `${daTatica.length} técnicas`));
    coluna.append(titulo);
    for (const t of daTatica) {
      const botao = el("button", `celula-tecnica ${estadoDaTecnica(t)}`);
      botao.type = "button";
      botao.append(el("b", null, t.tecnica), t.nome);
      comDica(botao, `${t.tecnica} ${t.nome}`, [["Eventos", Number(t.observados).toLocaleString("pt-BR")],
        ["Regras", Number(t.regras).toLocaleString("pt-BR")], ["Defesas", Number(t.defesas).toLocaleString("pt-BR")]]);
      botao.addEventListener("click", () => abrirTecnica(t.tecnica));
      coluna.append(botao);
    }
    return coluna;
  }));
}

async function carregarAtaques() {
  const r = await pedir("/api/mitre/matriz");
  estado.matriz = await r.json();
  const { tecnicas, versao } = estado.matriz;
  const observadas = tecnicas.filter((t) => t.observados > 0).length;
  const cobertas = tecnicas.filter((t) => t.regras > 0).length;
  $("resumo-ataques").textContent = tecnicas.length
    ? `${observadas} técnicas observadas em 30 dias · ${cobertas} de ${tecnicas.length} com regra de detecção. Clique numa técnica para ver as regras e as defesas.`
    : "A matriz ainda não foi carregada.";
  $("credito-attack").textContent = versao
    ? `MITRE ATT&CK® v${versao} e MITRE D3FEND. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.`
    : "";
  desenharMatriz();
}

function verEventosDaRegra(regra) {
  $("janela-tecnica").close();
  $("busca-eventos").value = regra;
  $("severidade-eventos").value = "";
  trocarVista("eventos");
  carregarEventos();
}

async function abrirTecnica(tecnica) {
  esconderDica();
  const r = await pedir(`/api/mitre/tecnicas/${encodeURIComponent(tecnica)}`);
  if (!r.ok) return;
  const d = await r.json();
  $("titulo-tecnica").textContent = `${d.tecnica.tecnica} ${d.tecnica.nome}`;
  const corpo = [];

  corpo.push(el("h3", null, `Regras que deram match em 30 dias (${d.match.length})`));
  if (d.match.length) {
    corpo.push(montarTabela([["Regra"], ["Severidade"], ["O que detecta"], ["Disparos", "numero-celula"], ["Último"], [""]], d.match.map((m) => {
      const botao = el("button", "botao-discreto botao-tabela", "Ver eventos");
      botao.type = "button";
      botao.addEventListener("click", () => verEventosDaRegra(m.regra_id));
      return [el("td", "mono", m.regra_id), celula(selo(severidadeDoNivel(m.nivel))), el("td", null, m.descricao ?? "-"),
        el("td", "numero-celula", Number(m.disparos).toLocaleString("pt-BR")), el("td", null, quando(m.ultimo)), celula(botao)];
    })));
  } else {
    corpo.push(el("p", "texto-secao", "Nenhuma regra disparou para esta técnica no período."));
  }

  corpo.push(el("h3", null, `Como se defender, pelo D3FEND (${d.defesas.length})`));
  if (d.defesas.length) {
    const blocos = el("div", "defesas");
    const porTatica = new Map();
    d.defesas.forEach((x) => {
      const chave = x.tatica_defesa ?? "Outras";
      porTatica.set(chave, [...(porTatica.get(chave) ?? []), x.defesa_nome]);
    });
    porTatica.forEach((nomes, tatica) => blocos.append(el("h4", null, TATICAS_DE_DEFESA[tatica] ?? tatica), etiquetas(nomes, 60)));
    corpo.push(blocos);
  } else {
    corpo.push(el("p", "texto-secao", "Sem defesas catalogadas para esta técnica."));
  }

  corpo.push(el("h3", null, `Regras que cobrem e ainda não dispararam (${d.cobertura.length})`));
  if (d.cobertura.length) {
    corpo.push(montarTabela([["Regra"], ["Severidade"], ["O que detecta"]], d.cobertura.map((c) => [
      el("td", "mono", c.regra_id), celula(selo(severidadeDoNivel(c.nivel))), el("td", null, c.descricao ?? "-")])));
  } else if (!d.match.length) {
    corpo.push(el("p", "texto-secao", "Nenhuma regra cobre esta técnica. Aqui existe um ponto cego."));
  } else {
    corpo.push(el("p", "texto-secao", "Todas as regras desta técnica já dispararam."));
  }

  if (d.subtecnicas.length) {
    corpo.push(el("h3", null, `Subtécnicas (${d.subtecnicas.length})`));
    const lista = el("div");
    d.subtecnicas.forEach((s) => {
      const b = el("button", "botao-discreto botao-tabela", `${s.tecnica} ${s.nome}`);
      b.type = "button";
      b.style.margin = "0 4px 4px 0";
      b.addEventListener("click", () => abrirTecnica(s.tecnica));
      lista.append(b);
    });
    corpo.push(lista);
  }
  $("conteudo-tecnica").replaceChildren(...corpo);
  if (!$("janela-tecnica").open) $("janela-tecnica").showModal();
}

$("so-observadas").addEventListener("change", desenharMatriz);
$("fechar-tecnica").addEventListener("click", () => $("janela-tecnica").close());
$("legenda-ataques").replaceChildren(...[["amostra-3", "Muitos eventos"], ["amostra-2", "Vários eventos"], ["amostra-1", "Poucos eventos"],
  ["amostra-coberta", "Tem regra, sem eventos"], ["amostra-sem", "Sem regra"]].map(([classe, rotulo]) => {
  const item = el("span");
  item.append(el("i", classe), rotulo);
  return item;
}));

// ------------------------------------------------------------------ ativos

const ESTADOS = { active: "Ativo", disconnected: "Desconectado", pending: "Pendente", never_connected: "Nunca conectou" };

function celulaDeNota(a) {
  if (a.sca_nota === null) return el("td", null, "-");
  const td = el("td");
  const nota = el("span", "nota");
  const barra = el("span", "nota-barra");
  const fill = el("span");
  fill.style.width = `${Math.min(100, a.sca_nota)}%`;
  barra.append(fill);
  nota.append(barra, `${a.sca_nota}%`);
  td.append(nota);
  td.title = `${a.sca_politica ?? ""}: ${a.sca_aprovados ?? 0} aprovados, ${a.sca_reprovados ?? 0} reprovados`;
  return td;
}

async function carregarAtivos() {
  const r = await pedir("/api/ativos");
  const { ativos } = await r.json();
  const ativosOk = ativos.filter((a) => a.estado === "active").length;
  $("resumo-ativos").textContent = `${ativos.length} ativos · ${ativosOk} conectados`;
  const destino = $("tabela-ativos");
  if (!ativos.length) {
    destino.replaceChildren(el("p", "vazio", "Nenhum ativo inscrito ainda."));
    return;
  }
  destino.replaceChildren(montarTabela(
    [["Ativo"], ["Estado"], ["Sistema"], ["Endereço"], ["Configuração segura"], ["Alertas em 7 dias", "numero-celula"], ["Última conexão"]],
    ativos.map((a) => [el("td", null, a.nome ?? a.agente_id), el("td", null, ESTADOS[a.estado] ?? a.estado ?? "-"),
      el("td", null, a.sistema ?? "-"), el("td", "mono ip", a.ip ?? "-"), celulaDeNota(a),
      el("td", "numero-celula", Number(a.alertas_7_dias).toLocaleString("pt-BR")), el("td", null, quando(a.ultima_conexao))]),
  ));
}

// ------------------------------------------------------------------ arquivos

const MUDANCAS = { added: "Criado", modified: "Alterado", deleted: "Apagado" };

async function carregarArquivos() {
  const r = await pedir(`/api/arquivos?${new URLSearchParams({ busca: $("busca-arquivos").value })}`);
  const { arquivos } = await r.json();
  const destino = $("tabela-arquivos");
  if (!arquivos.length) {
    destino.replaceChildren(el("p", "vazio", "Nenhuma mudança em arquivos monitorados."));
    return;
  }
  destino.replaceChildren(montarTabela([["Quando"], ["Mudança"], ["Arquivo"], ["Ativo"], ["Dono"], [""]], arquivos.map((a) => [
    el("td", null, quando(a.ocorrido_em)), el("td", null, MUDANCAS[a.mudanca] ?? a.mudanca ?? "-"),
    el("td", "mono", a.caminho ?? a.regra_descricao ?? "-"), el("td", null, a.ativo ?? "-"), el("td", "mono", a.dono ?? "-"),
    celula(botaoBruto(a.id))])));
}

// ------------------------------------------------------------------ normas

async function carregarNormas(norma = estado.norma) {
  estado.norma = norma;
  const r = await pedir(`/api/normas?norma=${encodeURIComponent(norma)}`);
  const dados = await r.json();
  const escolha = $("escolha-norma");
  escolha.replaceChildren(...Object.entries(dados.normas).map(([chave, rotulo]) => {
    const b = el("button", null, rotulo);
    b.type = "button";
    b.setAttribute("aria-pressed", String(chave === norma));
    b.addEventListener("click", () => carregarNormas(chave));
    return b;
  }));
  $("resumo-norma").textContent = `${dados.controles.length} controles com alertas em 30 dias · ${dados.regras_da_norma.toLocaleString("pt-BR")} regras cobrem esta norma`;
  const destino = $("tabela-normas");
  if (!dados.controles.length) {
    destino.replaceChildren(el("p", "vazio", "Nenhum alerta ligado a esta norma no período."));
    return;
  }
  destino.replaceChildren(montarTabela(
    [["Controle"], ["Maior severidade"], ["Alertas", "numero-celula"], ["Ativos", "numero-celula"], ["Último"]],
    dados.controles.map((c) => [el("td", "mono", c.controle), celula(selo(severidadeDoNivel(c.nivel))),
      el("td", "numero-celula", Number(c.total).toLocaleString("pt-BR")), el("td", "numero-celula", c.ativos), el("td", null, quando(c.ultimo))]),
  ));
}

$("form-arquivos").addEventListener("submit", (ev) => { ev.preventDefault(); carregarArquivos(); });

// ------------------------------------------------------------------ regras

function severidadeDoNivel(nivel) {
  if (nivel >= 15) return "critica";
  if (nivel >= 12) return "alta";
  if (nivel >= 7) return "media";
  return "baixa";
}

function etiquetas(valores, limite = 4) {
  const span = el("span");
  (valores ?? []).slice(0, limite).forEach((v) => span.append(el("span", "etiqueta", v)));
  if ((valores ?? []).length > limite) span.append(el("span", "etiqueta", `+${valores.length - limite}`));
  return span;
}

const COLUNAS_REGRAS = [["Regra"], ["Severidade"], ["O que detecta"], ["Grupos"], ["MITRE"], ["Disparos", "numero-celula"]];

function desenharComportamento(regras) {
  $("regras-comportamento").replaceChildren(...regras.map((r) => {
    const cartao = el("div", "cartao-regra");
    const topo = el("div");
    topo.append(el("span", null, tituloDoSinal(r.tipo)), el("b", null, `+${Math.round(r.peso)}`));
    cartao.append(topo, el("p", null, DESCRICAO_COMPORTAMENTO[r.tipo] ?? ""));
    return cartao;
  }));
}

async function carregarRegras(continuar = false) {
  const consulta = new URLSearchParams({
    busca: $("busca-regras").value,
    so_disparadas: $("so-disparadas").checked,
    deslocamento: continuar ? estado.regras.length : 0,
  });
  const r = await pedir(`/api/regras?${consulta}`);
  const dados = await r.json();
  estado.regras = continuar ? [...estado.regras, ...dados.regras] : dados.regras;
  desenharComportamento(dados.comportamento);
  $("resumo-regras").textContent = dados.catalogo
    ? `${dados.catalogo.toLocaleString("pt-BR")} regras no catálogo · atualizado em ${quando(dados.atualizado_em)}`
    : "O catálogo de regras ainda não foi carregado.";
  const destino = $("tabela-regras");
  if (!estado.regras.length) {
    destino.replaceChildren(el("p", "vazio", dados.catalogo ? "Nenhuma regra encontrada." : "Nada para mostrar ainda."));
  } else {
    destino.replaceChildren(montarTabela(COLUNAS_REGRAS, estado.regras.map((x) => {
      const abrir = el("button", "botao-discreto botao-tabela", x.regra_id);
      abrir.type = "button";
      abrir.setAttribute("aria-label", `Abrir a regra ${x.regra_id}`);
      abrir.addEventListener("click", () => abrirRegra(x.regra_id));
      return [celula(abrir), celula(selo(severidadeDoNivel(x.nivel))), el("td", null, x.descricao ?? "-"),
        celula(etiquetas(x.grupos)), celula(etiquetas(x.mitre)),
        el("td", "numero-celula", Number(x.disparos).toLocaleString("pt-BR"))];
    })));
  }
  $("mais-regras").hidden = estado.regras.length >= dados.total_filtrado;
  carregarRegrasProprias();
}

// O que o gerenciador informa sobre as condições de uma regra.
const ROTULOS_CONDICAO = {
  if_sid: "Depois da regra", if_group: "Depois do grupo", if_matched_sid: "Se repetir a regra", if_matched_group: "Se repetir o grupo",
  frequency: "Quantas vezes", timeframe: "Em quantos segundos", ignore: "Silêncio depois de disparar (s)", match: "Texto no log",
  regex: "Padrão no log", decoded_as: "Tipo de log", category: "Categoria", same_source_ip: "Mesma origem", options: "Opções",
  noalert: "Não gera alerta", program_name: "Programa", srcip: "Origem", user: "Usuário", id: "Identificador",
};

function textoDaCondicao(valor) {
  if (valor === "") return "sim";
  if (valor && typeof valor === "object") return valor.pattern ?? JSON.stringify(valor);
  return String(valor);
}

function listaDeChaves(pares) {
  const lista = el("dl", "chaves");
  pares.forEach(([rotulo, valor]) => lista.append(el("dt", null, rotulo), el("dd", null, valor)));
  return lista;
}

async function abrirRegra(regraId) {
  esconderDica();
  const r = await pedir(`/api/regras/${encodeURIComponent(regraId)}`);
  if (!r.ok) return;
  const { regra, tecnicas, disparos, recentes, xml } = await r.json();
  $("titulo-tecnica").textContent = `Regra ${regra.regra_id}`;
  const corpo = [];
  const cab = el("h2");
  cab.append(el("span", null, regra.descricao ?? "Sem descrição"), selo(severidadeDoNivel(regra.nivel)));
  corpo.push(cab);
  const fatos = el("div", "fatos");
  fatos.append(fato("Disparos em 30 dias", Number(disparos.total).toLocaleString("pt-BR")), fato("Ativos", disparos.ativos),
    fato("Último disparo", quando(disparos.ultimo)), fato("Estado", regra.ativa ? "Ativa" : "Desligada"), fato("Arquivo", regra.arquivo ?? "-"));
  corpo.push(fatos);

  const condicoes = Object.entries(regra.detalhes ?? {});
  corpo.push(el("h3", null, "Quando dispara"));
  corpo.push(condicoes.length
    ? listaDeChaves(condicoes.map(([k, v]) => [ROTULOS_CONDICAO[k] ?? k, textoDaCondicao(v)]))
    : el("p", "texto-secao", "As condições desta regra não estão disponíveis."));

  if (tecnicas.length) {
    corpo.push(el("h3", null, "Técnicas MITRE"));
    const lista = el("div");
    tecnicas.forEach((t) => {
      const b = el("button", "botao-discreto botao-tabela", `${t.tecnica} ${t.nome}`);
      b.type = "button";
      b.style.margin = "0 4px 4px 0";
      b.addEventListener("click", () => abrirTecnica(t.tecnica));
      lista.append(b);
    });
    corpo.push(lista);
  }
  const normas = Object.entries(regra.normas ?? {});
  if (normas.length) {
    corpo.push(el("h3", null, "Normas"));
    corpo.push(listaDeChaves(normas.map(([k, v]) => [NOMES_DE_NORMAS[k] ?? k, v.join(", ")])));
  }
  if ((regra.grupos ?? []).length) {
    corpo.push(el("h3", null, "Grupos"), etiquetas(regra.grupos, 30));
  }
  if (xml) {
    corpo.push(el("h3", null, "Regra original"), el("pre", "bruto", xml));
    const acoes = el("div", "acoes-regra");
    const copiar = el("button", "botao-primario", "Copiar e personalizar");
    copiar.type = "button";
    copiar.addEventListener("click", () => personalizarRegra(xml));
    const exportar = el("button", "botao-discreto", `Baixar ${regra.arquivo}`);
    exportar.type = "button";
    exportar.addEventListener("click", () => baixar(`/api/regras/arquivos/${encodeURIComponent(regra.arquivo)}`, regra.arquivo));
    acoes.append(exportar, copiar);
    corpo.push(acoes);
  }
  corpo.push(el("h3", null, "Disparos recentes"));
  if (recentes.length) {
    corpo.push(montarTabela([["Quando"], ["Ativo"], ["Usuário"], ["Origem"], [""]], recentes.map((e) => [
      el("td", null, quando(e.ocorrido_em)), el("td", null, e.ativo ?? "-"), el("td", "mono", e.usuario ?? "-"),
      el("td", "mono ip", e.ip_origem ?? "-"), celula(botaoBruto(e.id))])));
  } else {
    corpo.push(el("p", "texto-secao", "Esta regra ainda não disparou."));
  }
  $("conteudo-tecnica").replaceChildren(...corpo);
  if (!$("janela-tecnica").open) $("janela-tecnica").showModal();
}

// ------------------------------------------------------------------ nova regra

const CAMPOS_DA_ORIGEM = {
  windows_processo: [["Image", "Programa"], ["CommandLine", "Linha de comando"], ["ParentImage", "Programa pai"],
    ["ParentCommandLine", "Linha de comando do pai"], ["User", "Usuário"], ["OriginalFileName", "Nome original do arquivo"], ["CurrentDirectory", "Pasta atual"]],
  windows_seguranca: [["EventID", "Número do evento"], ["TargetUserName", "Conta afetada"], ["SubjectUserName", "Conta que agiu"],
    ["IpAddress", "Endereço"], ["LogonType", "Tipo de logon"], ["WorkstationName", "Estação"], ["ServiceName", "Serviço"]],
};
const OPERADORES_DA_TELA = [["contem", "contém"], ["igual", "é igual a"], ["comeca", "começa com"], ["termina", "termina com"]];

function opcoes(select, pares) {
  select.replaceChildren(...pares.map(([valor, rotulo]) => {
    const o = el("option", null, rotulo);
    o.value = valor;
    return o;
  }));
  return select;
}

function novaCondicao() {
  const origem = $("regra-origem").value;
  const linha = el("div", `condicao ${origem === "linux_syslog" ? "condicao-linux" : ""}`);
  if (origem !== "linux_syslog") {
    linha.append(opcoes(el("select", "condicao-campo"), CAMPOS_DA_ORIGEM[origem]), opcoes(el("select", "condicao-operador"), OPERADORES_DA_TELA));
  }
  const valor = el("input", "condicao-valor");
  valor.placeholder = origem === "linux_syslog" ? "Texto que aparece no log" : "Valor";
  valor.maxLength = 500;
  const remover = el("button", "botao-discreto botao-tabela", "Remover");
  remover.type = "button";
  remover.addEventListener("click", () => linha.remove());
  linha.append(valor, remover);
  $("regra-condicoes").append(linha);
}

function reiniciarCondicoes() {
  $("regra-condicoes").replaceChildren();
  novaCondicao();
}

function dadosDaRegra() {
  if (estado.modoRegra === "sigma") return { formato: "sigma", sigma: $("regra-sigma").value };
  if (estado.modoRegra === "xml") return { formato: "xml", xml: $("regra-xml").value };
  const tecnica = $("regra-tecnica").value.trim().toUpperCase();
  return {
    formato: "guiada",
    titulo: $("regra-titulo").value,
    origem: $("regra-origem").value,
    nivel: $("regra-nivel").value,
    tecnicas: tecnica ? [tecnica] : [],
    condicoes: [...document.querySelectorAll("#regra-condicoes .condicao")].map((c) => ({
      campo: c.querySelector(".condicao-campo")?.value,
      operador: c.querySelector(".condicao-operador")?.value,
      valor: c.querySelector(".condicao-valor").value,
    })),
  };
}

async function enviarRegra(rota) {
  const erro = $("erro-regra");
  erro.hidden = true;
  const r = await pedir(rota, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(dadosDaRegra()),
  });
  const corpo = await r.json().catch(() => ({}));
  if (!r.ok) {
    erro.textContent = typeof corpo.detail === "string" ? corpo.detail : "Confira os campos da regra.";
    erro.hidden = false;
    $("previa-saida").hidden = true;
    return null;
  }
  return corpo;
}

const ROTULOS_DE_FORMATO = { sigma: "Sigma", guiada: "Guiada", xml: "XML", biblioteca: "Biblioteca" };
const ESTADOS_DA_REGRA = { pendente: "Aguardando aplicação", ativa: "Ativa", recusada: "Recusada", desativada: "Desativada" };

async function carregarRegrasProprias() {
  const r = await pedir("/api/regras/proprias");
  const { regras } = await r.json();
  const destino = $("tabela-proprias");
  if (!regras.length) {
    destino.replaceChildren(el("p", "texto-secao", "Nenhuma regra criada ainda."));
    return;
  }
  destino.replaceChildren(montarTabela([["Regra"], ["Estado"], ["Formato"], ["Criada em"], ["Observação"], [""]], regras.map((x) => {
    const acao = el("td");
    if (x.estado === "ativa" || x.estado === "pendente") {
      const b = el("button", "botao-discreto botao-tabela", "Desativar");
      b.type = "button";
      b.addEventListener("click", async () => {
        await pedir(`/api/regras/proprias/${x.id}/desativar`, { method: "POST" });
        carregarRegrasProprias();
      });
      acao.append(b);
    }
    return [el("td", null, x.titulo), el("td", null, ESTADOS_DA_REGRA[x.estado] ?? x.estado),
      el("td", null, ROTULOS_DE_FORMATO[x.formato] ?? x.formato), el("td", null, quando(x.criada_em)), el("td", null, x.mensagem ?? "-"), acao];
  })));
}

function escolherModo(modo) {
  estado.modoRegra = modo;
  document.querySelectorAll("#janela-regra [data-modo]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.modo === modo)));
  $("campos-guiada").hidden = modo !== "guiada";
  $("campos-sigma").hidden = modo !== "sigma";
  $("campos-xml").hidden = modo !== "xml";
}

// Copia uma regra do catálogo para o editor, para personalizar sem mexer na original.
function personalizarRegra(xml) {
  $("janela-tecnica").close();
  $("form-regra").reset();
  $("erro-regra").hidden = true;
  $("previa-saida").hidden = true;
  reiniciarCondicoes();
  escolherModo("xml");
  $("regra-xml").value = `<group name="personalizadas,">\n  ${xml}\n</group>`;
  $("janela-regra").showModal();
}

// ------------------------------------------------------------------ importar e exportar

async function baixar(rota, nome) {
  const r = await pedir(rota);
  if (!r.ok) return;
  const endereco = URL.createObjectURL(await r.blob());
  const a = el("a");
  a.href = endereco;
  a.download = nome;
  a.click();
  URL.revokeObjectURL(endereco);
}

$("exportar-regras").addEventListener("click", () => baixar("/api/regras/exportar", "regras-roar.json"));
$("abrir-importar").addEventListener("click", () => {
  $("form-importar").reset();
  $("erro-importar").hidden = true;
  $("relatorio-importar").replaceChildren();
  $("janela-importar").showModal();
});
$("fechar-importar").addEventListener("click", () => $("janela-importar").close());
$("form-importar").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const arquivo = $("arquivo-importar").files[0];
  if (!arquivo) return;
  const formato = arquivo.name.toLowerCase().endsWith(".xml") ? "xml" : "sigma";
  const r = await pedir("/api/regras/importar", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ formato, conteudo: await arquivo.text() }),
  });
  const corpo = await r.json().catch(() => ({}));
  if (!r.ok) {
    $("erro-importar").textContent = typeof corpo.detail === "string" ? corpo.detail : "Não foi possível importar este arquivo.";
    $("erro-importar").hidden = false;
    return;
  }
  const relatorio = [el("h3", null, `${corpo.criadas.length} importadas, ${corpo.recusadas.length} recusadas`)];
  if (corpo.recusadas.length) {
    relatorio.push(montarTabela([["Regra"], ["Por que não entrou"]],
      corpo.recusadas.map((x) => [el("td", null, x.titulo), el("td", null, x.motivo)])));
  }
  $("relatorio-importar").replaceChildren(...relatorio);
  carregarRegrasProprias();
});

// ------------------------------------------------------------------ biblioteca

async function carregarBiblioteca(continuar = false) {
  const consulta = new URLSearchParams({
    busca: $("busca-biblioteca").value,
    so_convertiveis: $("so-convertiveis").checked,
    deslocamento: continuar ? estado.biblioteca.length : 0,
  });
  const r = await pedir(`/api/regras/biblioteca?${consulta}`);
  const dados = await r.json();
  estado.biblioteca = continuar ? [...estado.biblioteca, ...dados.regras] : dados.regras;
  $("resumo-biblioteca").textContent = `${Number(dados.total).toLocaleString("pt-BR")} regras na biblioteca, ${Number(dados.convertiveis).toLocaleString("pt-BR")} podem ser usadas aqui.`;
  const destino = $("tabela-biblioteca");
  if (!estado.biblioteca.length) {
    destino.replaceChildren(el("p", "vazio", "Nenhuma regra encontrada."));
  } else {
    destino.replaceChildren(montarTabela([["Regra"], ["Autoria"], ["Onde olha"], ["MITRE"], [""]], estado.biblioteca.map((x) => {
      const acao = el("td");
      if (x.convertivel) {
        const b = el("button", "botao-discreto botao-tabela", "Ativar");
        b.type = "button";
        b.addEventListener("click", async () => {
          const resposta = await pedir(`/api/regras/biblioteca/${encodeURIComponent(x.id)}/ativar`, { method: "POST" });
          b.textContent = resposta.status === 201 ? "Ativada" : resposta.status === 409 ? "Já ativa" : "Não ativou";
          b.disabled = true;
          carregarRegrasProprias();
        });
        acao.append(b);
      } else {
        acao.textContent = x.motivo ?? "Não pode ser usada";
      }
      const nome = el("td");
      nome.append(el("b", null, x.titulo));
      if (x.descricao) nome.append(el("div", "texto-secao", x.descricao.slice(0, 160)));
      return [nome, el("td", null, x.autor ?? "-"), el("td", null, x.origem ?? "-"), celula(etiquetas(x.tecnicas, 3)), acao];
    })));
  }
  $("mais-biblioteca").hidden = estado.biblioteca.length >= dados.total_filtrado;
}

$("abrir-biblioteca").addEventListener("click", () => {
  $("janela-biblioteca").showModal();
  carregarBiblioteca();
});
$("fechar-biblioteca").addEventListener("click", () => $("janela-biblioteca").close());
$("form-biblioteca").addEventListener("submit", (ev) => { ev.preventDefault(); carregarBiblioteca(); });
$("so-convertiveis").addEventListener("change", () => carregarBiblioteca());
$("mais-biblioteca").addEventListener("click", () => carregarBiblioteca(true));

document.querySelectorAll("#janela-regra [data-modo]").forEach((b) => b.addEventListener("click", () => escolherModo(b.dataset.modo)));
$("regra-origem").addEventListener("change", reiniciarCondicoes);
$("mais-condicao").addEventListener("click", novaCondicao);
$("fechar-regra").addEventListener("click", () => $("janela-regra").close());
$("nova-regra").addEventListener("click", () => {
  $("form-regra").reset();
  $("erro-regra").hidden = true;
  $("previa-saida").hidden = true;
  escolherModo("guiada");
  reiniciarCondicoes();
  $("janela-regra").showModal();
});
$("previa-regra").addEventListener("click", async () => {
  const corpo = await enviarRegra("/api/regras/converter");
  if (!corpo) return;
  $("previa-titulo").textContent = `Como a regra fica (${corpo.regras_geradas} ${corpo.regras_geradas === 1 ? "regra gerada" : "regras geradas"})`;
  $("previa-xml").textContent = corpo.xml;
  $("previa-saida").hidden = false;
});
$("form-regra").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (await enviarRegra("/api/regras/proprias")) {
    $("janela-regra").close();
    carregarRegrasProprias();
  }
});

$("form-eventos").addEventListener("submit", (ev) => { ev.preventDefault(); carregarEventos(); });
$("mais-eventos").addEventListener("click", () => carregarEventos(true));
$("form-regras").addEventListener("submit", (ev) => { ev.preventDefault(); carregarRegras(); });
$("so-disparadas").addEventListener("change", () => carregarRegras());
$("mais-regras").addEventListener("click", () => carregarRegras(true));
$("fechar-bruto").addEventListener("click", () => $("janela-bruto").close());
$("copiar-bruto").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("conteudo-bruto").textContent);
  $("copiar-bruto").textContent = "Copiado";
  setTimeout(() => { $("copiar-bruto").textContent = "Copiar"; }, 1500);
});

// ------------------------------------------------------------------ automação

const NOMES_DE_ACAO = { bloquear_ip: "Bloquear o endereço", webhook: "Avisar um endereço web", registrar: "Registrar uma nota" };
const ESTADOS_DE_EXECUCAO = {
  nova: "Iniciando", executando: "Executando", aguardando_aprovacao: "Aguardando decisão",
  concluida: "Concluída", falhou: "Falhou", recusada: "Recusada",
};
const CONDICOES = [
  { id: "externo", rotulo: "O endereço é externo", campo: "alvo_externo", op: "igual", fixo: true },
  { id: "interno", rotulo: "O endereço não é externo", campo: "alvo_externo", op: "igual", fixo: false },
  { id: "nivel_minimo", rotulo: "Nível a partir de", campo: "nivel", op: "minimo", tipo: "numero", padrao: 10 },
  { id: "nivel_maximo", rotulo: "Nível até", campo: "nivel", op: "maximo", tipo: "numero", padrao: 10 },
  { id: "severidade", rotulo: "Severidade a partir de", campo: "severidade", op: "minimo", tipo: "severidade", padrao: "alta" },
  { id: "na_rede", rotulo: "Endereço dentro da rede", campo: "alvo", op: "na_rede", tipo: "texto", padrao: "" },
  { id: "fora_da_rede", rotulo: "Endereço fora da rede", campo: "alvo", op: "fora_da_rede", tipo: "texto", padrao: "" },
];
const SE_EXTERNO = { campo: "alvo_externo", op: "igual", valor: true };
const NOVOS_BLOCOS = {
  bloquear_ip: () => ({ tipo: "acao", acao: "bloquear_ip", parametros: { duracao_minutos: 60, protegidos: [] } }),
  webhook: () => ({ tipo: "acao", acao: "webhook", parametros: { url: "" } }),
  registrar: () => ({ tipo: "acao", acao: "registrar", parametros: { texto: "" } }),
  aprovacao: () => ({ tipo: "aprovacao" }),
  se: () => ({ tipo: "se", condicao: { ...SE_EXTERNO }, entao: [], senao: [] }),
  paralelo: () => ({ tipo: "paralelo", ramos: [[], []] }),
};
const ROTULOS_DE_BLOCO = {
  bloquear_ip: "Bloquear o endereço no ativo", webhook: "Avisar um endereço web", registrar: "Registrar uma nota",
  aprovacao: "Pedir aprovação", se: "Se... senão", paralelo: "Fazer ao mesmo tempo",
};
const MODELOS = [
  {
    titulo: "Força bruta em SSH", texto: "Pede aprovação e bloqueia o endereço de quem está tentando.",
    nome: "Força bruta em SSH: bloquear",
    definicao: { quando: { tipo: "evento", regra_id: "5712" }, se: [{ ...SE_EXTERNO }],
      blocos: [NOVOS_BLOCOS.aprovacao(), NOVOS_BLOCOS.bloquear_ip()] },
  },
  {
    titulo: "Conta em risco", texto: "Avisa a equipe quando o risco de uma pessoa ou ativo fica crítico.",
    nome: "Conta em risco: avisar a equipe",
    definicao: { quando: { tipo: "risco", severidade: "critica" }, se: [], blocos: [NOVOS_BLOCOS.webhook()] },
  },
  {
    titulo: "Risco com origem externa", texto: "Se a origem for externa, bloqueia com aprovação. Se for interna, só avisa.",
    nome: "Risco alto: bloquear se externo, avisar se interno",
    definicao: { quando: { tipo: "risco", severidade: "alta" }, se: [], blocos: [{
      tipo: "se", condicao: { ...SE_EXTERNO }, entao: [NOVOS_BLOCOS.aprovacao(), NOVOS_BLOCOS.bloquear_ip()], senao: [NOVOS_BLOCOS.webhook()],
    }] },
  },
  {
    titulo: "Em branco", texto: "Comece do zero.", nome: "",
    definicao: { quando: { tipo: "evento", regra_id: "" }, se: [], blocos: [] },
  },
];

function descreverAcoes(texto) {
  return (texto ?? "").split(",").filter(Boolean).map((a) => NOMES_DE_ACAO[a] ?? a).join(", ") || "Nenhuma ação";
}

function descreverGatilho(definicao) {
  const { quando: q, se } = definicao;
  const base = q.tipo === "risco"
    ? `Risco a partir de ${(SEVERIDADE[q.severidade]?.texto ?? q.severidade).toLowerCase()}`
    : `Alerta da regra ${q.regra_id}`;
  const partes = (se ?? []).map(descreverCondicao);
  return partes.length ? `${base}, se ${partes.join(" e ").toLowerCase()}` : base;
}

function condicaoConhecida(c) {
  return CONDICOES.find((m) => m.campo === c.campo && m.op === c.op && (m.fixo === undefined || m.fixo === c.valor)) ?? CONDICOES[0];
}

function descreverCondicao(c) {
  const m = condicaoConhecida(c);
  return m.fixo === undefined ? `${m.rotulo} ${c.valor}` : m.rotulo;
}

function contarAcoes(lista) {
  const nomes = [];
  for (const b of lista) {
    if (b.tipo === "acao") nomes.push(NOMES_DE_ACAO[b.acao] ?? b.acao);
    if (b.tipo === "se") nomes.push(...contarAcoes(b.entao), ...contarAcoes(b.senao ?? []));
    if (b.tipo === "paralelo") b.ramos.forEach((r) => nomes.push(...contarAcoes(r)));
  }
  return [...new Set(nomes)];
}

function descreverResultado(x) {
  const partes = [];
  for (const p of Array.isArray(x.resultado) ? x.resultado : []) {
    if (p.erro) partes.push(`${NOMES_DE_ACAO[p.acao] ?? p.acao}: ${p.erro}`);
    else if (p.acao === "bloquear_ip") partes.push(x.bloqueio_confirmado ? "Bloqueio confirmado pelo ativo" : "Bloqueio enviado, sem confirmação do ativo ainda");
    else if (p.acao) partes.push(`${NOMES_DE_ACAO[p.acao] ?? p.acao}: feito`);
    else if (p.aprovacao) partes.push({ aprovada: "Aprovada", recusada: "Recusada", expirada: "Ninguém decidiu a tempo" }[p.aprovacao] ?? p.aprovacao);
  }
  return partes.join(" · ") || "-";
}

function botaoDeTabela(texto, classe, aoClicar) {
  const b = el("button", `${classe} botao-tabela`, texto);
  b.type = "button";
  b.addEventListener("click", aoClicar);
  return b;
}

async function decidirAprovacao(id, decisao) {
  const r = await pedir(`/api/automacao/aprovacoes/${id}/${decisao}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ motivo: "" }),
  });
  if (!r.ok && r.status !== 409) throw new Error("decisão recusada");
  await carregarAutomacao();
}

async function ligarPlaybook(id, acao) {
  await pedir(`/api/automacao/playbooks/${id}/${acao}`, { method: "POST" });
  await carregarAutomacao();
}

async function carregarAutomacao() {
  const r = await pedir("/api/automacao");
  const { playbooks, execucoes, aprovacoes } = await r.json();
  const pendentes = aprovacoes.filter((a) => a.estado === "pendente");
  $("tabela-pendentes").replaceChildren(pendentes.length ? montarTabela(
    [["Quando"], ["Playbook"], ["O que aconteceu"], ["Alvo"], ["Vai fazer"], ["Decisão"]],
    pendentes.map((a) => {
      const decisao = el("td");
      decisao.append(botaoDeTabela("Aprovar", "botao-primario", () => decidirAprovacao(a.id, "aprovar")), " ",
        botaoDeTabela("Recusar", "botao-discreto", () => decidirAprovacao(a.id, "recusar")));
      return [el("td", null, quando(a.criada_em)), el("td", null, a.playbook), el("td", null, a.titulo ?? "-"),
        el("td", "mono ip", a.alvo ?? "-"), el("td", null, descreverAcoes(a.descricao)), decisao];
    })) : el("p", "vazio", "Nenhuma decisão pendente."));

  $("tabela-playbooks").replaceChildren(playbooks.length ? montarTabela(
    [["Nome"], ["Quando"], ["Então"], ["Aprovação"], ["Execuções", "numero-celula"], [""]],
    playbooks.map((p) => {
      const acoes = el("td");
      acoes.append(el("span", "etiqueta", p.ativo ? "Ativo" : "Desativado"),
        botaoDeTabela("Editar", "botao-discreto", () => abrirEditorDePlaybook(p)), " ",
        botaoDeTabela(p.ativo ? "Desativar" : "Ativar", "botao-discreto", () => ligarPlaybook(p.id, p.ativo ? "desativar" : "ativar")));
      const comAprovacao = JSON.stringify(p.definicao.blocos).includes('"aprovacao"');
      return [el("td", null, p.nome), el("td", null, descreverGatilho(p.definicao)), el("td", null, contarAcoes(p.definicao.blocos).join(", ") || "-"),
        el("td", null, comAprovacao ? "Pede aprovação" : "Automático"), el("td", "numero-celula", p.execucoes), acoes];
    })) : el("p", "vazio", "Nenhum playbook criado. Comece por um modelo, ou abra um alerta e clique em Automatizar isto."));

  const decisores = new Map(aprovacoes.filter((a) => a.decidida_por).map((a) => [a.execucao_id, a.decidida_por]));
  $("tabela-execucoes").replaceChildren(execucoes.length ? montarTabela(
    [["Quando"], ["Playbook"], ["Alvo"], ["Estado"], ["Decidido por"], ["Resultado"]],
    execucoes.map((x) => [el("td", null, quando(x.criada_em)), el("td", null, x.playbook), el("td", "mono ip", x.alvo ?? "-"),
      el("td", null, ESTADOS_DE_EXECUCAO[x.estado] ?? x.estado), el("td", null, decisores.get(x.id) ?? "-"),
      el("td", null, descreverResultado(x))])) : el("p", "vazio", "Nenhuma execução ainda."));
}

function campoDoEditor(rotulo, controle) {
  const l = el("label", null, rotulo);
  l.append(controle);
  return l;
}

function selecao(opcoes, valor, aoMudar) {
  const s = el("select");
  for (const [v, texto] of opcoes) {
    const o = el("option", null, texto);
    o.value = v;
    s.append(o);
  }
  s.value = valor;
  s.addEventListener("change", () => aoMudar(s.value));
  return s;
}

function entrada(valor, aoMudar, atributos = {}) {
  const i = el("input");
  Object.assign(i, atributos);
  i.value = valor ?? "";
  i.addEventListener("input", () => aoMudar(i.value));
  return i;
}

function editorDeCondicao(c, aoRemover) {
  const linha = el("div", "linha-condicao");
  const m = condicaoConhecida(c);
  linha.append(selecao(CONDICOES.map((o) => [o.id, o.rotulo]), m.id, (id) => {
    const nova = CONDICOES.find((o) => o.id === id);
    Object.assign(c, { campo: nova.campo, op: nova.op, valor: nova.fixo ?? nova.padrao });
    desenharEditor();
  }));
  if (m.tipo === "numero") linha.append(entrada(c.valor, (v) => { c.valor = Number(v); }, { type: "number", min: 0, max: 16, ariaLabel: "Nível" }));
  if (m.tipo === "texto") linha.append(entrada(c.valor, (v) => { c.valor = v.trim(); }, { placeholder: "10.0.0.0/8", ariaLabel: "Rede" }));
  if (m.tipo === "severidade") linha.append(selecao([["alta", "Alta"], ["critica", "Crítica"]], c.valor, (v) => { c.valor = v; }));
  if (aoRemover) linha.append(botaoDeTabela("Remover", "botao-discreto", aoRemover));
  return linha;
}

function corpoDoBloco(bloco) {
  const corpo = el("div", "bloco-corpo");
  if (bloco.tipo === "aprovacao") {
    corpo.append(el("p", "texto-secao", "A execução espera aqui até alguém decidir. Sem decisão em 72 horas, conta como recusa."));
  } else if (bloco.acao === "bloquear_ip") {
    const area = el("textarea");
    area.rows = 2;
    area.spellcheck = false;
    area.placeholder = "8.8.8.8\n200.200.0.0/16";
    area.value = (bloco.parametros.protegidos ?? []).join("\n");
    area.addEventListener("input", () => { bloco.parametros.protegidos = area.value.split("\n").map((l) => l.trim()).filter(Boolean); });
    corpo.append(campoDoEditor("Desbloquear sozinho depois de", selecao([["60", "1 hora"], ["1440", "1 dia"], ["10080", "7 dias"]],
      String(bloco.parametros.duracao_minutos ?? 60), (v) => { bloco.parametros.duracao_minutos = Number(v); })),
    campoDoEditor("Nunca bloquear, um por linha", area));
  } else if (bloco.acao === "webhook") {
    corpo.append(campoDoEditor("Endereço web completo, começando por https", entrada(bloco.parametros.url, (v) => { bloco.parametros.url = v.trim(); }, { type: "url" })));
  } else if (bloco.acao === "registrar") {
    corpo.append(campoDoEditor("Nota", entrada(bloco.parametros.texto, (v) => { bloco.parametros.texto = v; }, { maxLength: 1000 })));
  } else if (bloco.tipo === "se") {
    corpo.append(editorDeCondicao(bloco.condicao), el("h4", "ramo-titulo", "Então"), editorDePilha(bloco.entao),
      el("h4", "ramo-titulo", "Senão"), editorDePilha(bloco.senao ?? (bloco.senao = [])));
  } else if (bloco.tipo === "paralelo") {
    bloco.ramos.forEach((ramo, i) => {
      const cabeca = el("div", "ramo-topo");
      cabeca.append(el("h4", "ramo-titulo", `Ramo ${i + 1}`));
      if (bloco.ramos.length > 2) cabeca.append(botaoDeTabela("Remover ramo", "botao-discreto", () => { bloco.ramos.splice(i, 1); desenharEditor(); }));
      corpo.append(cabeca, editorDePilha(ramo));
    });
    if (bloco.ramos.length < 5) corpo.append(botaoDeTabela("Adicionar ramo", "botao-discreto", () => { bloco.ramos.push([]); desenharEditor(); }));
  }
  return corpo;
}

function editorDePilha(lista) {
  const pilha = el("div", "pilha");
  lista.forEach((bloco, i) => {
    const cartao = el("div", `bloco bloco-${bloco.tipo}`);
    const topo = el("div", "bloco-topo");
    const acoes = el("div", "bloco-acoes");
    const mover = (destino) => { lista.splice(destino, 0, lista.splice(i, 1)[0]); desenharEditor(); };
    if (i > 0) acoes.append(botaoDeTabela("Subir", "botao-discreto", () => mover(i - 1)));
    if (i < lista.length - 1) acoes.append(botaoDeTabela("Descer", "botao-discreto", () => mover(i + 1)));
    acoes.append(botaoDeTabela("Remover", "botao-discreto", () => { lista.splice(i, 1); desenharEditor(); }));
    topo.append(el("strong", null, ROTULOS_DE_BLOCO[bloco.acao ?? bloco.tipo] ?? bloco.tipo), acoes);
    cartao.append(topo, corpoDoBloco(bloco));
    pilha.append(cartao);
  });
  const adicionar = selecao([["", "Adicionar bloco..."], ...Object.entries(ROTULOS_DE_BLOCO)], "", (tipo) => {
    if (!tipo) return;
    lista.push(NOVOS_BLOCOS[tipo]());
    desenharEditor();
  });
  adicionar.setAttribute("aria-label", "Adicionar bloco");
  adicionar.classList.add("adicionar-bloco");
  pilha.append(adicionar);
  return pilha;
}

function desenharEditor() {
  const { definicao } = estado.editor;
  const { quando: q } = definicao;
  const secaoQuando = el("div", "linha-campos");
  secaoQuando.append(campoDoEditor("Acontecer", selecao([["evento", "Alerta de uma regra"], ["risco", "Risco de uma pessoa ou ativo"]], q.tipo, (tipo) => {
    definicao.quando = tipo === "risco" ? { tipo, severidade: "alta" } : { tipo, regra_id: "" };
    desenharEditor();
  })));
  secaoQuando.append(q.tipo === "risco"
    ? campoDoEditor("Severidade a partir de", selecao([["alta", "Alta"], ["critica", "Crítica"]], q.severidade, (v) => { q.severidade = v; }))
    : campoDoEditor("Número da regra", entrada(q.regra_id, (v) => { q.regra_id = v.trim(); }, { inputMode: "numeric", maxLength: 8, placeholder: "5712" })));
  const condicoes = el("div");
  (definicao.se ?? (definicao.se = [])).forEach((c, i) => {
    condicoes.append(editorDeCondicao(c, () => { definicao.se.splice(i, 1); desenharEditor(); }));
  });
  const maisCondicao = botaoDeTabela("Adicionar condição", "botao-discreto", () => { definicao.se.push({ ...SE_EXTERNO }); desenharEditor(); });
  $("pb-blocos").replaceChildren(el("h3", null, "Quando"), secaoQuando, el("h3", null, "Se"),
    condicoes, maisCondicao, el("h3", null, "Então"), editorDePilha(definicao.blocos));
}

function mostrarErroDoPlaybook(texto) {
  $("pb-erro").textContent = texto;
  $("pb-erro").hidden = !texto;
}

async function detalheDoErro(r, padrao) {
  const corpo = await r.json().catch(() => ({}));
  return typeof corpo.detail === "string" ? corpo.detail : padrao;
}

async function postarJson(rota, corpo, metodo = "POST") {
  return pedir(rota, { method: metodo, headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo) });
}

function corpoDoEditor() {
  return { nome: $("pb-nome").value.trim(), intervalo_minutos: Number($("pb-intervalo").value || 0), definicao: estado.editor.definicao };
}

// No modo código o texto é a fonte: precisa virar blocos antes de simular ou salvar.
async function lerCodigoSeAberto() {
  if ($("pb-area-codigo").hidden) return true;
  const r = await postarJson("/api/automacao/de-codigo", { texto: $("pb-codigo").value });
  if (!r.ok) {
    mostrarErroDoPlaybook(await detalheDoErro(r, "Confira o texto do playbook."));
    return false;
  }
  const dados = await r.json();
  estado.editor.definicao = dados.definicao;
  $("pb-nome").value = dados.nome;
  $("pb-intervalo").value = dados.intervalo_minutos;
  return true;
}

async function trocarAbaDoEditor(codigo) {
  mostrarErroDoPlaybook("");
  if (codigo) {
    const r = await postarJson("/api/automacao/para-codigo", { ...corpoDoEditor(), nome: $("pb-nome").value.trim() || "Sem nome" });
    if (!r.ok) {
      mostrarErroDoPlaybook(await detalheDoErro(r, "Complete os blocos antes de ver o código."));
      return;
    }
    $("pb-codigo").value = (await r.json()).texto;
  } else {
    if (!(await lerCodigoSeAberto())) return;
    desenharEditor();
  }
  $("pb-area-codigo").hidden = !codigo;
  $("pb-blocos").hidden = codigo;
  $("aba-codigo").setAttribute("aria-selected", String(codigo));
  $("aba-blocos").setAttribute("aria-selected", String(!codigo));
}

function desenharSimulacao(s) {
  const area = $("pb-simulacao");
  const vezes = s.disparos === 1 ? "1 vez" : `${s.disparos.toLocaleString("pt-BR")} vezes`;
  const titulo = s.disparos ? `Nos últimos ${s.dias} dias, isto teria disparado ${vezes}.` : `Nos últimos ${s.dias} dias, isto não teria disparado nenhuma vez.`;
  const filhos = [el("strong", null, titulo)];
  if (s.limitado) filhos.push(el("p", "texto-secao", `Olhei só os primeiros ${s.analisados.toLocaleString("pt-BR")} acontecimentos: o número real pode ser maior.`));
  if (s.recusas) filhos.push(el("p", "texto-secao", `${s.recusas.toLocaleString("pt-BR")} bloqueios seriam recusados, por alvo protegido ou sem endereço público.`));
  if (s.alvos.length) {
    filhos.push(montarTabela([["Alvo"], ["Vezes", "numero-celula"]],
      s.alvos.map((a) => [el("td", "mono ip", a.alvo), el("td", "numero-celula", a.total.toLocaleString("pt-BR"))])));
  }
  area.replaceChildren(...filhos);
  area.hidden = false;
}

function abrirEditorDePlaybook(playbook) {
  estado.editor = { id: playbook?.id ?? null, definicao: structuredClone(playbook?.definicao ?? MODELOS[0].definicao) };
  $("titulo-playbook").textContent = playbook?.id ? "Editar playbook" : "Novo playbook";
  $("pb-nome").value = playbook?.nome ?? "";
  $("pb-intervalo").value = playbook?.intervalo_minutos ?? 60;
  $("modelos-playbook").hidden = Boolean(playbook?.id || playbook?.rascunho);
  $("pb-area-codigo").hidden = true;
  $("pb-blocos").hidden = false;
  $("aba-blocos").setAttribute("aria-selected", "true");
  $("aba-codigo").setAttribute("aria-selected", "false");
  $("pb-simulacao").hidden = true;
  mostrarErroDoPlaybook("");
  desenharEditor();
  $("janela-playbook").showModal();
}

function desenharModelos() {
  $("modelos-playbook").replaceChildren(...MODELOS.map((m) => {
    const b = el("button", "modelo");
    b.type = "button";
    b.append(el("strong", null, m.titulo), el("span", null, m.texto));
    b.addEventListener("click", () => {
      estado.editor.definicao = structuredClone(m.definicao);
      $("pb-nome").value = m.nome;
      $("pb-simulacao").hidden = true;
      desenharEditor();
    });
    return b;
  }));
}

// Parte do alerta que a pessoa já está vendo: ela não precisa saber número de regra.
function rascunhoDeGrupo(grupo, eventos) {
  const regra = eventos[0]?.regra_id ?? grupo.regras?.[0] ?? "";
  const nome = `Responder a: ${eventos[0]?.regra_descricao ?? `regra ${regra}`}`.slice(0, 120);
  const definicao = grupo.ip_origem
    ? { quando: { tipo: "evento", regra_id: regra }, se: [{ ...SE_EXTERNO }], blocos: [NOVOS_BLOCOS.aprovacao(), NOVOS_BLOCOS.bloquear_ip()] }
    : { quando: { tipo: "evento", regra_id: regra }, se: [], blocos: [NOVOS_BLOCOS.webhook()] };
  return { nome, definicao, rascunho: true };
}

function rascunhoDeRisco(alerta) {
  return {
    nome: `Responder a risco ${SEVERIDADE[alerta.severidade]?.texto.toLowerCase() ?? ""}`.trim(),
    definicao: { quando: { tipo: "risco", severidade: alerta.severidade }, se: [], blocos: [{
      tipo: "se", condicao: { ...SE_EXTERNO }, entao: [NOVOS_BLOCOS.aprovacao(), NOVOS_BLOCOS.bloquear_ip()], senao: [NOVOS_BLOCOS.webhook()],
    }] },
    rascunho: true,
  };
}

function botaoAutomatizar(criarRascunho) {
  const b = el("button", "botao-discreto botao-automatizar", "Automatizar isto");
  b.type = "button";
  b.addEventListener("click", () => abrirEditorDePlaybook(criarRascunho()));
  return b;
}

$("novo-playbook").addEventListener("click", () => abrirEditorDePlaybook());
$("fechar-playbook").addEventListener("click", () => $("janela-playbook").close());
$("aba-blocos").addEventListener("click", () => trocarAbaDoEditor(false));
$("aba-codigo").addEventListener("click", () => trocarAbaDoEditor(true));
$("pb-simular").addEventListener("click", async () => {
  mostrarErroDoPlaybook("");
  if (!(await lerCodigoSeAberto())) return;
  const { definicao, intervalo_minutos: intervalo } = corpoDoEditor();
  const r = await postarJson("/api/automacao/simular", { definicao, intervalo_minutos: intervalo });
  if (!r.ok) {
    $("pb-simulacao").hidden = true;
    mostrarErroDoPlaybook(await detalheDoErro(r, "Complete o playbook antes de simular."));
    return;
  }
  desenharSimulacao(await r.json());
});
$("form-playbook").addEventListener("submit", async (evento) => {
  evento.preventDefault();
  mostrarErroDoPlaybook("");
  if (!(await lerCodigoSeAberto())) return;
  const corpo = corpoDoEditor();
  if (!corpo.nome) {
    mostrarErroDoPlaybook("Dê um nome ao playbook.");
    return;
  }
  const { id } = estado.editor;
  const r = await postarJson(id ? `/api/automacao/playbooks/${id}` : "/api/automacao/playbooks", corpo, id ? "PUT" : "POST");
  if (!r.ok) {
    mostrarErroDoPlaybook(await detalheDoErro(r, "Confira os blocos do playbook."));
    return;
  }
  $("janela-playbook").close();
  trocarVista("automacao");
});
desenharModelos();

function trocarVista(vista) {
  document.querySelectorAll(".navegacao button").forEach((b) => {
    if (b.dataset.vista === vista) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  esconderDica();
  for (const nome of ["panorama", "fila", "eventos", "logs", "ataques", "ativos", "arquivos", "normas", "regras", "automacao"]) {
    $(`vista-${nome}`).hidden = vista !== nome;
  }
  if (vista === "automacao") carregarAutomacao();
  if (vista === "logs" && !estado.logs.length) carregarLogs();
  if (vista === "ataques") carregarAtaques();
  if (vista === "ativos") carregarAtivos();
  if (vista === "arquivos") carregarArquivos();
  if (vista === "normas") carregarNormas();
  if (vista === "panorama" && estado.panorama) desenharColunas(estado.panorama.por_dia);
  if (vista === "eventos" && !estado.eventos.length) carregarEventos();
  if (vista === "regras" && !estado.regras.length) carregarRegras();
}

document.querySelectorAll(".navegacao button").forEach((b) => {
  b.addEventListener("click", () => trocarVista(b.dataset.vista));
});
document.querySelectorAll(".periodo button").forEach((b) => {
  b.addEventListener("click", () => {
    estado.dias = Number(b.dataset.dias);
    document.querySelectorAll(".periodo button").forEach((o) => o.setAttribute("aria-pressed", String(o === b)));
    carregarPanorama();
  });
});
new ResizeObserver(() => {
  if (estado.panorama) desenharColunas(estado.panorama.por_dia);
}).observe($("grafico-dias"));
desenharLegenda();

$("form-entrada").addEventListener("submit", entrar);
$("sair").addEventListener("click", async () => {
  await pedir("/api/sair", { method: "POST" });
  estado.selecionado = null;
  mostrarEntrada();
});
document.querySelectorAll(".abas button").forEach((b) => {
  b.addEventListener("click", () => {
    estado.aba = b.dataset.aba;
    desenharLista();
  });
});

abrirPainel().catch(() => {});
