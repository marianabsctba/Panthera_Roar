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
const estado = { aba: "riscos", fila: { riscos: [], grupos: [] }, selecionado: null, fuso: undefined, dias: 30, panorama: null, eventos: [], regras: [], logs: [], proximoLog: null, norma: "gdpr", matriz: null, modoRegra: "guiada" };

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

function abrirLog(item) {
  $("meta-bruto").textContent = `${quando(item.bruto.timestamp)} · identificador ${item.id}`;
  $("conteudo-bruto").textContent = JSON.stringify(item.bruto, null, 2);
  $("janela-bruto").showModal();
}

async function carregarLogs(continuar = false) {
  const consulta = new URLSearchParams({ busca: $("busca-logs").value, dias: $("dias-logs").value });
  if (continuar && estado.proximoLog) consulta.set("depois_de", estado.proximoLog);
  const r = await pedir(`/api/logs?${consulta}`);
  const destino = $("tabela-logs");
  if (!r.ok) {
    destino.replaceChildren(el("p", "vazio", "Não foi possível consultar os logs agora."));
    return;
  }
  const dados = await r.json();
  estado.logs = continuar ? [...estado.logs, ...dados.logs] : dados.logs;
  estado.proximoLog = dados.proximo;
  if (!estado.logs.length) {
    destino.replaceChildren(el("p", "vazio", "Nenhum log encontrado."));
  } else {
    destino.replaceChildren(montarTabela([["Quando"], ["Ativo"], ["Fonte"], ["Log"], [""]], estado.logs.map((item) => {
      const b = item.bruto;
      const botao = el("button", "botao-discreto botao-tabela", "Ver bruto");
      botao.type = "button";
      botao.addEventListener("click", () => abrirLog(item));
      return [el("td", null, quando(b.timestamp)), el("td", null, b.agent?.name ?? "-"),
        el("td", "mono", b.location ?? "-"), el("td", "mono", b.full_log ?? "-"), celula(botao)];
    })));
  }
  $("mais-logs").hidden = !dados.proximo;
}

$("form-logs").addEventListener("submit", (ev) => { ev.preventDefault(); carregarLogs(); });
$("mais-logs").addEventListener("click", () => carregarLogs(true));

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
  const { regra, tecnicas, disparos, recentes } = await r.json();
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
      el("td", null, x.formato === "sigma" ? "Sigma" : "Guiada"), el("td", null, quando(x.criada_em)), el("td", null, x.mensagem ?? "-"), acao];
  })));
}

function escolherModo(modo) {
  estado.modoRegra = modo;
  document.querySelectorAll("#janela-regra [data-modo]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.modo === modo)));
  $("campos-guiada").hidden = modo !== "guiada";
  $("campos-sigma").hidden = modo !== "sigma";
}

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

function trocarVista(vista) {
  document.querySelectorAll(".navegacao button").forEach((b) => {
    if (b.dataset.vista === vista) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  esconderDica();
  for (const nome of ["panorama", "fila", "eventos", "logs", "ataques", "ativos", "arquivos", "normas", "regras"]) {
    $(`vista-${nome}`).hidden = vista !== nome;
  }
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
