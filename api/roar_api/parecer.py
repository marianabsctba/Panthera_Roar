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
_CODIGO = re.compile(r"\bP\d+\b")
# "(P1, P3)" no meio da frase: a tela já mostra o nome de cada pergunta citada.
_CODIGOS_NO_TEXTO = re.compile(r"\s*\((?:P\d+(?:,\s*|\s+e\s+)?)+\)")
# Passos que servem para qualquer alerta. Começar assim já basta para sair.
_GENERICO = re.compile(r"(?i)(monitor|acompanh|continu|mant|garant|implement|refor[cç]|conscientiz|trein|realizar (um |uma )?(treinamento|auditoria)|revis\w* (as |a |os |o )?(regras|pol[ií]tica|procedimento|configura)|notific\w* (a |o )?(equipe|time|setor|ti\b)|aten[cç][aã]o)")
# O passo precisa apontar em quem agir: uma conta, um endereço, um alerta ou um ativo do pacote.
_ALVO = re.compile(r"(?i)usu[aá]rio[-\s]?\d|endere[cç]o[-\s]?\d|n[ºo°]\s*\d{3,}")
_IP = re.compile(r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w.:])")

ESQUEMA = {
    "type": "object",
    "properties": {
        "veredito": {"type": "string", "enum": list(VEREDITOS)},
        "confianca": {"type": "string", "enum": list(CONFIANCAS)},
        "resumo": {"type": "string"},
        "motivos": {"type": "array", "minItems": 1, "maxItems": 5, "items": {
            "type": "object",
            "properties": {"texto": {"type": "string"}, "perguntas": {"type": "array", "maxItems": 2, "items": {"type": "string", "pattern": "^P[0-9]+$"}},
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
  de onde o fato vem e os números dos alertas que o mostram, sempre do pacote. Não repita o mesmo fato em dois motivos.
- O que decide são as respostas, não só o título do alerta. Toda resposta "agrava" precisa ser explicada: só diga
  "benigno" se outras respostas mostram por que ela pesa pouco, e diga qual. Quando as respostas mostram a pessoa de
  sempre, do endereço de sempre, sem nenhuma que agrave, o parecer é "benigno".
- veredito: "ataque" quando as provas mostram ação maliciosa que deu certo ou está em curso; "suspeito" quando há sinais
  fortes mas falta confirmação; "benigno" quando as provas explicam o alerta como uso normal; "inconclusivo" quando o
  pacote não basta para decidir.
- confianca: "alta" só quando várias provas independentes apontam para o mesmo lado.
- resumo: uma ou duas frases que contam o que aconteceu, ligando os fatos que decidem: quem, de onde, o que deu certo e o
  que não deu. Não repita o veredito nem escreva "não há sinais de atividade suspeita": diga qual fato mostra isso.
- motivos: diga por que o fato pesa ou alivia. Não copie a resposta da pergunta, que o analista já vê na tela.
- proximos_passos: só o que muda a situação, até quatro, em ordem de prioridade. Cada passo diz a ação e em quem: a conta
  usuario-1, o endereço endereco-1, o ativo pelo nome, o alerta pelo número. Nada genérico, como monitorar, acompanhar,
  revisar regras ou políticas, notificar a equipe ou garantir que a configuração está segura. Endereço de fora se bloqueia
  ou se consulta nas listas de ameaça; não se escaneia. Máquina da rede se isola ou se examina. Quando o veredito é
  "benigno", deixe a lista vazia, a não ser que haja algo concreto a corrigir.
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


def situacao(endereco, modelo, sessao=None):
    """Se o Ollama responde, os modelos baixados e quanto do modelo em uso está na placa de vídeo (None se não carregado)."""
    http = sessao or requests
    try:
        baixados = sorted(m["name"] for m in http.get(f"{endereco}/api/tags", timeout=5).json().get("models", []))
        carregados = http.get(f"{endereco}/api/ps", timeout=5).json().get("models", [])
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return {"no_ar": False, "modelos": [], "na_placa": None}
    carregado = next((m for m in carregados if m.get("name") == modelo), None)
    na_placa = round(100 * carregado["size_vram"] / carregado["size"]) if carregado and carregado.get("size") else None
    return {"no_ar": True, "modelos": baixados, "na_placa": na_placa}


def perguntar(endereco, modelo, texto, sessao=None):
    """A resposta da IA como dicionário. Erro de rede ou resposta fora do formato sobe como exceção."""
    corpo = {"model": modelo, "stream": False, "format": ESQUEMA, "options": {"temperature": 0, "num_ctx": CONTEXTO},
             "messages": [{"role": "system", "content": INSTRUCOES}, {"role": "user", "content": texto}]}
    r = (sessao or requests).post(f"{endereco}/api/chat", json=corpo, timeout=TEMPO_LIMITE)
    r.raise_for_status()
    return json.loads(r.json()["message"]["content"])


def _contar(n, um, varios):
    return f"{n} {um if n == 1 else varios}"


def conferir(resposta, pacote):
    """Só o que tem prova no pacote fica. Devolve o parecer limpo e os avisos do que foi tirado ou corrigido."""
    codigos = {f"P{i}": p for i, p in enumerate(pacote["perguntas"], 1)}
    alertas = {pacote["alerta"]["id"]} | {c["id"] for p in pacote["perguntas"] for c in p["eventos"]}
    avisos = []
    veredito = resposta.get("veredito") if resposta.get("veredito") in VEREDITOS else "inconclusivo"
    confianca = resposta.get("confianca") if resposta.get("confianca") in CONFIANCAS else "baixa"
    # Dois motivos com as mesmas provas são o mesmo fato dito duas vezes.
    motivos, inventados, vistas = [], 0, set()
    for m in (resposta.get("motivos") or [])[:LIMITE_DE_MOTIVOS]:
        if not isinstance(m, dict) or not isinstance(m.get("texto"), str):
            continue
        # O modelo às vezes copia a linha inteira da pergunta em vez do código: vale o código que estiver nela.
        citadas = [c for item in (m.get("perguntas") or []) if isinstance(item, str) for c in (_CODIGO.findall(item) or [item])]
        numeros = [n for n in (m.get("alertas") or []) if isinstance(n, int) and not isinstance(n, bool)]
        boas = [c for c in citadas if c in codigos]
        bons = [n for n in numeros if n in alertas]
        inventados += len(citadas) - len(boas) + len(numeros) - len(bons)
        if not boas and not bons:
            continue
        provas = (frozenset(boas), frozenset(bons)) if not bons else frozenset(bons)
        if provas in vistas:
            continue
        vistas.add(provas)
        texto = _CODIGOS_NO_TEXTO.sub("", m["texto"]).strip()
        motivos.append({"texto": texto[:LIMITE_DE_TEXTO], "perguntas": list(dict.fromkeys(codigos[c]["id"] for c in boas)), "alertas": bons})
    if inventados:
        avisos.append(f"{inventados} {'citação inventada foi tirada' if inventados == 1 else 'citações inventadas foram tiradas'}: a IA citou algo que não estava no pacote.")
    if veredito != "inconclusivo" and not motivos:
        avisos.append(f"A IA disse {veredito} sem nenhum motivo com prova do pacote: o parecer ficou inconclusivo.")
        veredito, confianca = "inconclusivo", "baixa"
    contra = sum(1 for p in pacote["perguntas"] if p["tom"] == "agrava")
    if veredito == "benigno" and contra:
        avisos.append(f"A IA disse benigno, mas {_contar(contra, 'resposta da investigação pesa', 'respostas da investigação pesam')} contra: confira antes de encerrar.")
        confianca = "baixa"
    if veredito == "ataque" and contra == 0:
        avisos.append("A IA disse ataque, mas nenhuma resposta da investigação pesa contra: confira as provas.")
        confianca = "baixa"
    passos, genericos = [], 0
    concretos = {pacote["alerta"].get("ativo")} | {c.get("ativo") for p in pacote["perguntas"] for c in p["eventos"]}
    for passo in (resposta.get("proximos_passos") or []):
        if not isinstance(passo, str) or not passo.strip():
            continue
        # O óbvio sai: o passo que serve para qualquer alerta, ou que não diz em quem agir.
        alvo = _ALVO.search(passo) or any(a and a.lower() in passo.lower() for a in concretos)
        if _GENERICO.match(passo.strip()) or not alvo:
            genericos += 1
            continue
        passos.append(passo.strip()[:LIMITE_DE_TEXTO])
    passos = passos[:LIMITE_DE_PASSOS]
    resumo = (resposta.get("resumo") or "").strip()[:LIMITE_DE_TEXTO * 2] if isinstance(resposta.get("resumo"), str) else ""
    return {"veredito": veredito, "confianca": confianca, "resumo": resumo or "A IA não escreveu um resumo.", "motivos": motivos,
            "proximos_passos": passos, "passos_genericos": genericos}, avisos


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
    genericos = parecer.pop("passos_genericos")
    if not resposta:
        avisos.append("A resposta da IA veio fora do formato: o parecer ficou inconclusivo.")
    parecer["resumo"] = apelidos.mostrar(parecer["resumo"])
    parecer["motivos"] = [{**m, "texto": apelidos.mostrar(m["texto"])} for m in parecer["motivos"]]
    parecer["proximos_passos"] = [apelidos.mostrar(p) for p in parecer["proximos_passos"]]
    return {**parecer, "avisos": avisos, "segundos": segundos, "modelo": modelo, "passos_genericos": genericos}
