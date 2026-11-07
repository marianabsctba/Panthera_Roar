"""Parecer da IA local sobre um alerta: ela lê o pacote da investigação (investigacao.py) e diz o que acha, com os motivos.

A IA roda no próprio servidor (Ollama, infra/docker-compose.yml), e mesmo assim só vê apelidos: contas viram usuario-1,
endereços viram endereco-1. Ela responde num formato fixo (JSON com esquema), e o Roar confere antes de mostrar:

- cada motivo precisa citar perguntas e alertas que estavam no pacote; citação inventada sai, e motivo sem citação sai;
- veredito de ataque, suspeito ou benigno sem nenhum motivo provado vira inconclusivo;
- benigno com duas ou mais respostas que pesam contra, ou ataque sem nenhuma, fica com confiança baixa e um aviso.

Os avisos ficam no parecer, para o analista saber o que foi corrigido. A IA pode errar: o parecer ajuda a ler as provas,
não substitui a leitura.
"""

import ipaddress
import json
import re
import time

import requests

TEMPO_LIMITE = 180
# O pacote cabe com folga em 4 mil tokens; contexto menor deixa mais do modelo na placa de vídeo.
CONTEXTO = 4096
VEREDITOS = ("ataque", "suspeito", "benigno", "inconclusivo")
CONFIANCAS = ("baixa", "media", "alta")
LIMITE_DE_MOTIVOS = 6
LIMITE_DE_PASSOS = 4
LIMITE_DE_TEXTO = 400
_IP = re.compile(r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w.:])")

ESQUEMA = {
    "type": "object",
    "properties": {
        "veredito": {"type": "string", "enum": list(VEREDITOS)},
        "confianca": {"type": "string", "enum": list(CONFIANCAS)},
        "resumo": {"type": "string"},
        "motivos": {"type": "array", "minItems": 1, "maxItems": 5, "items": {
            "type": "object",
            "properties": {"texto": {"type": "string"}, "perguntas": {"type": "array", "maxItems": 2, "items": {"type": "string"}},
                           "alertas": {"type": "array", "maxItems": 5, "items": {"type": "integer"}}},
            "required": ["texto", "perguntas", "alertas"]}},
        "proximos_passos": {"type": "array", "maxItems": 4, "items": {"type": "string"}},
    },
    "required": ["veredito", "confianca", "resumo", "motivos", "proximos_passos"],
}

INSTRUCOES = """Você é analista de segurança de um SOC e dá um parecer sobre um alerta de SIEM, em português do Brasil.

Você recebe o alerta e as perguntas que o próprio SIEM já respondeu sobre ele, cada uma com um código (P1, P2...), um tom
(agrava, atenua ou informa) e os alertas que a provam, pelo número. Contas e endereços aparecem como apelidos:
usuario-1, endereco-1. Escreva os apelidos exatamente assim, sem acento, como em "a conta usuario-1" e "o endereço endereco-1".

Regras:
- Use só o que está no pacote. Não invente fato, alerta, conta, endereço ou horário.
- Dê de dois a cinco motivos. Cada motivo é uma frase com um fato só, explicada para o analista, e cita a pergunta (P1...)
  de onde o fato vem e os números dos alertas que o mostram, sempre do pacote.
- veredito: "ataque" quando as provas mostram ação maliciosa que deu certo ou está em curso; "suspeito" quando há sinais
  fortes mas falta confirmação; "benigno" quando as provas explicam o alerta como uso normal; "inconclusivo" quando o
  pacote não basta para decidir.
- confianca: "alta" só quando várias provas independentes apontam para o mesmo lado.
- resumo: duas ou três frases, diretas, para o analista de plantão.
- proximos_passos: até quatro ações concretas para o analista confirmar ou conter, em ordem de prioridade.
Responda só com o JSON pedido."""


def configuracao(env):
    """(endereço, modelo) da IA local, ou None quando ela não foi ligada (IA_MODELO vazio)."""
    modelo = (env.get("IA_MODELO") or "").strip()
    if not modelo:
        return None
    return f"http://127.0.0.1:{int(env.get('IA_PORTA') or 11434)}", modelo


class Apelidos:
    """Troca contas e endereços por apelidos antes da IA, e desfaz depois. O mapa fica só na memória deste pedido."""

    def __init__(self):
        self.ida, self.volta = {}, {}

    def _apelido(self, valor, tipo):
        if valor not in self.ida:
            numero = sum(1 for a in self.volta if a.startswith(tipo)) + 1
            self.ida[valor] = f"{tipo}-{numero}"
            self.volta[f"{tipo}-{numero}"] = valor
        return self.ida[valor]

    def conhecer(self, pacote):
        """As contas vêm dos campos; os endereços, de qualquer texto do pacote."""
        contas = {pacote["alerta"].get("usuario")} | {c.get("usuario") for p in pacote["perguntas"] for c in p["eventos"]}
        for conta in sorted((c for c in contas if c), key=len, reverse=True):
            self._apelido(conta, "usuario")

    def esconder(self, texto):
        if not isinstance(texto, str):
            return texto
        for conta in sorted((v for v in self.ida if self.ida[v].startswith("usuario")), key=len, reverse=True):
            texto = re.sub(rf"(?<![\w.@-]){re.escape(conta)}(?![\w@-])", self.ida[conta], texto)

        def ip(m):
            try:
                ipaddress.ip_address(m.group())
            except ValueError:
                return m.group()
            return self._apelido(m.group(), "endereco")
        return _IP.sub(ip, texto)

    def mostrar(self, texto):
        """O modelo às vezes acentua ou capitaliza o apelido (Endereço-1, usuário 1): vale do mesmo jeito."""
        def volta(tipo):
            return lambda m: self.volta.get(f"{tipo}-{int(m.group(1))}", m.group())
        texto = re.sub(r"(?i)\busu[aá]rio[-\s]?(\d+)\b", volta("usuario"), texto)
        return re.sub(r"(?i)\bendere[cç]o[-\s]?(\d+)\b", volta("endereco"), texto)


def entrada(pacote, apelidos):
    """O pacote em texto curto, com apelidos. Os códigos P1, P2... são o que a IA cita."""
    a = pacote["alerta"]
    linhas = [f"ALERTA nº {a['id']} em {a['quando']}: {apelidos.esconder(a['descricao'])}",
              f"Origem: {apelidos.esconder(a['ip']) or 'nenhuma'}. Conta: {apelidos.esconder(a['usuario']) or 'nenhuma'}. Ativo: {a['ativo'] or 'nenhum'}.", ""]
    for i, p in enumerate(pacote["perguntas"], 1):
        linhas.append(f"P{i} [{p['tom']}] {p['pergunta']}")
        linhas.append(f"   Resposta: {apelidos.esconder(p['resposta'])}")
        linhas.append(f"   Como: {apelidos.esconder(p['como'])}")
        for c in p["eventos"]:
            extra = ", ".join(x for x in (apelidos.esconder(c.get("usuario")), apelidos.esconder(c.get("ip")), c.get("ativo")) if x)
            linhas.append(f"   - alerta nº {c['id']} em {c['quando']}: {apelidos.esconder(c['descricao'])}" + (f" ({extra})" if extra else ""))
    return "\n".join(linhas)


def perguntar(endereco, modelo, texto, sessao=None):
    """A resposta da IA como dicionário. Erro de rede ou resposta fora do formato sobe como exceção."""
    corpo = {"model": modelo, "stream": False, "format": ESQUEMA, "options": {"temperature": 0, "num_ctx": CONTEXTO},
             "messages": [{"role": "system", "content": INSTRUCOES}, {"role": "user", "content": texto}]}
    r = (sessao or requests).post(f"{endereco}/api/chat", json=corpo, timeout=TEMPO_LIMITE)
    r.raise_for_status()
    return json.loads(r.json()["message"]["content"])


def conferir(resposta, pacote):
    """Só o que tem prova no pacote fica. Devolve o parecer limpo e os avisos do que foi tirado ou corrigido."""
    codigos = {f"P{i}": p for i, p in enumerate(pacote["perguntas"], 1)}
    alertas = {pacote["alerta"]["id"]} | {c["id"] for p in pacote["perguntas"] for c in p["eventos"]}
    avisos = []
    veredito = resposta.get("veredito") if resposta.get("veredito") in VEREDITOS else "inconclusivo"
    confianca = resposta.get("confianca") if resposta.get("confianca") in CONFIANCAS else "baixa"
    motivos, inventados = [], 0
    for m in (resposta.get("motivos") or [])[:LIMITE_DE_MOTIVOS]:
        if not isinstance(m, dict) or not isinstance(m.get("texto"), str):
            continue
        citadas = [c for c in (m.get("perguntas") or []) if isinstance(c, str)]
        numeros = [n for n in (m.get("alertas") or []) if isinstance(n, int) and not isinstance(n, bool)]
        boas = [c for c in citadas if c in codigos]
        bons = [n for n in numeros if n in alertas]
        inventados += len(citadas) - len(boas) + len(numeros) - len(bons)
        if not boas and not bons:
            continue
        motivos.append({"texto": m["texto"].strip()[:LIMITE_DE_TEXTO], "perguntas": [codigos[c]["id"] for c in boas], "alertas": bons})
    if inventados:
        avisos.append(f"{inventados} {'citação inventada foi tirada' if inventados == 1 else 'citações inventadas foram tiradas'}: a IA citou algo que não estava no pacote.")
    if veredito != "inconclusivo" and not motivos:
        avisos.append(f"A IA disse {veredito} sem nenhum motivo com prova do pacote: o parecer ficou inconclusivo.")
        veredito, confianca = "inconclusivo", "baixa"
    contra = sum(1 for p in pacote["perguntas"] if p["tom"] == "agrava")
    if veredito == "benigno" and contra >= 2:
        avisos.append(f"A IA disse benigno, mas {contra} respostas da investigação pesam contra: confira antes de encerrar.")
        confianca = "baixa"
    if veredito == "ataque" and contra == 0:
        avisos.append("A IA disse ataque, mas nenhuma resposta da investigação pesa contra: confira as provas.")
        confianca = "baixa"
    passos = [p.strip()[:LIMITE_DE_TEXTO] for p in (resposta.get("proximos_passos") or []) if isinstance(p, str) and p.strip()][:LIMITE_DE_PASSOS]
    resumo = (resposta.get("resumo") or "").strip()[:LIMITE_DE_TEXTO * 2] if isinstance(resposta.get("resumo"), str) else ""
    return {"veredito": veredito, "confianca": confianca, "resumo": resumo or "A IA não escreveu um resumo.", "motivos": motivos,
            "proximos_passos": passos}, avisos


def dar(pacote, endereco, modelo, perguntar_a_ia=perguntar):
    """O parecer pronto para guardar: conferido e com as contas e endereços de volta."""
    apelidos = Apelidos()
    apelidos.conhecer(pacote)
    texto = entrada(pacote, apelidos)
    inicio = time.monotonic()
    try:
        resposta = perguntar_a_ia(endereco, modelo, texto)
    except ValueError:
        resposta = {}
    segundos = round(time.monotonic() - inicio, 1)
    parecer, avisos = conferir(resposta if isinstance(resposta, dict) else {}, pacote)
    if not resposta:
        avisos.append("A resposta da IA veio fora do formato: o parecer ficou inconclusivo.")
    parecer["resumo"] = apelidos.mostrar(parecer["resumo"])
    parecer["motivos"] = [{**m, "texto": apelidos.mostrar(m["texto"])} for m in parecer["motivos"]]
    parecer["proximos_passos"] = [apelidos.mostrar(p) for p in parecer["proximos_passos"]]
    return {**parecer, "avisos": avisos, "segundos": segundos, "modelo": modelo}
