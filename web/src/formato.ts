export const numero = (v: number | string | null | undefined) => (v === null || v === undefined ? "-" : Number(v).toLocaleString("pt-BR"));

export function compacto(v: number) {
  return v.toLocaleString("pt-BR", { notation: v >= 10000 ? "compact" : "standard", maximumFractionDigits: 1 });
}

export function tamanho(bytes: number | null | undefined) {
  if (bytes === null || bytes === undefined) return "-";
  const unidades = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < unidades.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toLocaleString("pt-BR", { maximumFractionDigits: v < 10 && i > 0 ? 1 : 0 })} ${unidades[i]}`;
}

export function quando(valor: string | null | undefined, fuso?: string) {
  if (!valor) return "-";
  return new Date(valor).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: fuso });
}

/** Tempo entre dois momentos, do jeito que se fala. */
export function duracao(ms: number) {
  const minutos = Math.round(ms / 60000);
  if (minutos < 1) return "menos de 1 min";
  if (minutos < 60) return `${minutos} min`;
  const horas = Math.floor(minutos / 60);
  if (horas < 48) return minutos % 60 && horas < 10 ? `${horas} h ${minutos % 60} min` : `${horas} h`;
  return `${Math.round(horas / 24)} dias`;
}

// A base do ATT&CK vem em inglês.
const TATICAS: Record<string, string> = {
  Reconnaissance: "Reconhecimento", "Resource Development": "Preparação de recursos", "Initial Access": "Acesso inicial", Execution: "Execução",
  Persistence: "Persistência", "Privilege Escalation": "Elevação de privilégio", "Defense Evasion": "Evasão de defesas", "Credential Access": "Acesso a credenciais",
  Discovery: "Descoberta", "Lateral Movement": "Movimento lateral", Collection: "Coleta", "Command and Control": "Comando e controle", Exfiltration: "Exfiltração", Impact: "Impacto",
};

export const nomeDaTatica = (nome: string) => TATICAS[nome] ?? nome;

export function diaCurto(valor: string) {
  const [, mes, dia] = valor.slice(0, 10).split("-");
  return `${dia}/${mes}`;
}

const CODIGOS: Record<string, string> = {
  Brazil: "BR", "United States": "US", Russia: "RU", China: "CN", Germany: "DE", France: "FR", "United Kingdom": "GB", Japan: "JP", Australia: "AU", Canada: "CA", Mexico: "MX",
  Argentina: "AR", India: "IN", Netherlands: "NL", Finland: "FI", Nigeria: "NG", "South Africa": "ZA", Singapore: "SG", "Hong Kong": "HK", Spain: "ES", Italy: "IT", Portugal: "PT",
  Ukraine: "UA", Poland: "PL", Turkey: "TR", "South Korea": "KR", Vietnam: "VN", Indonesia: "ID", Iran: "IR", Israel: "IL",
};
const nomes = new Intl.DisplayNames(["pt-BR"], { type: "region" });

/** O indexador escreve o país em inglês. */
export function codigoDoPais(nome: string) {
  return CODIGOS[nome] ?? null;
}

export function nomeDoPais(nome: string) {
  const codigo = codigoDoPais(nome);
  return codigo ? nomes.of(codigo) ?? nome : nome;
}

const UF: Record<string, string> = {
  Acre: "AC", Alagoas: "AL", Amapa: "AP", Amazonas: "AM", Bahia: "BA", Ceara: "CE", "Federal District": "DF", "Espirito Santo": "ES", Goias: "GO", Maranhao: "MA", "Mato Grosso": "MT",
  "Mato Grosso do Sul": "MS", "Minas Gerais": "MG", Para: "PA", Paraiba: "PB", Parana: "PR", Pernambuco: "PE", Piaui: "PI", "Rio de Janeiro": "RJ", "Rio Grande do Norte": "RN",
  "Rio Grande do Sul": "RS", Rondonia: "RO", Roraima: "RR", "Santa Catarina": "SC", "Sao Paulo": "SP", Sergipe: "SE", Tocantins: "TO",
};

export function nomeDaCidade(c: { cidade: string; regiao?: string | null; pais?: string | null }) {
  if (!c.regiao) return c.cidade;
  return `${c.cidade}, ${c.pais === "Brazil" ? UF[c.regiao] ?? c.regiao : c.regiao}`;
}

export const SINAIS: Record<string, string> = {
  sucesso_apos_falhas: "Acesso depois de várias falhas", viagem_impossivel: "Viagem impossível", primeiro_privilegio: "Primeiro uso deste privilégio",
  pico_de_falhas: "Pico de falhas de acesso", primeiro_host: "Ativo nunca usado", horario_incomum: "Horário fora do padrão", primeiro_ip: "Endereço nunca usado",
  host_raro_no_cliente: "Ativo incomum na organização",
};
