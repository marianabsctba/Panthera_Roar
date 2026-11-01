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

const $ = (id) => document.getElementById(id);
const estado = { aba: "riscos", fila: { riscos: [], grupos: [] }, selecionado: null, fuso: undefined, dias: 30, panorama: null };

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
      el("span", "sinal-quando", `${quando(s.ocorrido_em)} · ${s.regra_descricao ?? "evento"}`));
    linha.append(li);
  }
  $("detalhe").replaceChildren(cab, el("p", "subtitulo", `${tipo} · aberto em ${quando(alerta.aberto_em)}`),
    medidor, el("h3", null, "Por que este alerta existe"), linha);
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
  ["Quando", "Severidade", "Evento", "Usuário", "Origem"].forEach((c) => cabecalho.append(el("th", null, c)));
  const thead = el("thead");
  thead.append(cabecalho);
  const tbody = el("tbody");
  for (const e of eventos) {
    const tr = el("tr");
    const sev = el("td");
    sev.append(selo(e.severidade));
    tr.append(el("td", null, quando(e.ocorrido_em)), sev, el("td", null, e.regra_descricao ?? e.regra_id),
      el("td", "mono", e.usuario ?? "-"), el("td", "mono ip", e.ip_origem ?? "-"));
    tbody.append(tr);
  }
  tabela.append(thead, tbody);
  const rolagem = el("div", "tabela-rolagem");
  rolagem.append(tabela);
  $("detalhe").replaceChildren(cab, fatos, el("h3", null, "Eventos recentes"), rolagem);
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

function trocarVista(vista) {
  document.querySelectorAll(".navegacao button").forEach((b) => {
    if (b.dataset.vista === vista) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  $("vista-panorama").hidden = vista !== "panorama";
  $("vista-fila").hidden = vista !== "fila";
  if (vista === "panorama" && estado.panorama) desenharColunas(estado.panorama.por_dia);
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
