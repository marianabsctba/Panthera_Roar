"""Inteligência de ameaças: traz indicadores de MISP e TAXII e procura neles os eventos do cliente.

    python -m roar_ingestao.inteligencia [--uma-vez]

Só leitura, de propósito. Nada volta para a fonte, porque dizer "vi este indicador" revelaria o que o cliente
tem. E nada é bloqueado daqui: quem decide agir é uma pessoa ou um playbook com aprovação.
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

import requests

from . import cofre, rede_externa
from .normalizar import CAMPOS_DE_IP_DE_DESTINO, CAMPOS_DE_IP_DE_ORIGEM

log = logging.getLogger("roar.inteligencia")

MAIOR_RESPOSTA = 64 * 1024 * 1024
POR_PAGINA = 2000
TEMPO_DA_PLATAFORMA_LOCAL = 300
MAXIMO_DE_PAGINAS = 200
EVENTOS_POR_CICLO = 2000
DIAS_NO_PASSADO = 90
INDICADORES_POR_BUSCA = 500
SEGUNDOS_ENTRE_CICLOS = 30
TIPOS_MISP = {"ip-src": "ip", "ip-dst": "ip", "domain": "dominio", "hostname": "dominio", "url": "url", "md5": "md5", "sha1": "sha1", "sha256": "sha256"}
HEXA = {"md5": 32, "sha1": 40, "sha256": 64}
# Comparação simples de um padrão STIX. Padrão com seguidilha temporal ou negação não vira indicador solto.
COMPARACAO_STIX = re.compile(r"(ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'((?:[^'\\]|\\.)*)'|file:hashes\.'?(MD5|SHA-1|SHA-256)'?\s*=\s*'([0-9a-fA-F]+)'")
ALGORITMO_STIX = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256"}


class FonteComProblema(Exception):
    """A mensagem aparece na tela: sem resposta crua da fonte."""


def normalizar(tipo, valor):
    """Devolve o valor comparável, ou None se não presta. Endereço interno em lista externa só geraria alarme falso."""
    valor = str(valor or "").strip()
    if not valor or len(valor) > 2048:
        return None
    if tipo == "ip":
        try:
            ip = ipaddress.ip_address(valor)
        except ValueError:
            return None
        return str(ip) if ip.is_global else None
    if tipo == "dominio":
        valor = valor.lower().rstrip(".")
        return valor if re.fullmatch(r"(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+", valor) else None
    if tipo == "url":
        return valor if re.match(r"(?i)^https?://", valor) else None
    if tipo in HEXA:
        valor = valor.lower()
        return valor if re.fullmatch(rf"[0-9a-f]{{{HEXA[tipo]}}}", valor) else None
    return None


def ler_misp(corpo):
    atributos = (corpo.get("response") or {}).get("Attribute") or []
    saida = []
    for a in atributos:
        tipo_misp, valor = str(a.get("type", "")), a.get("value")
        if a.get("to_ids") is False:
            continue
        # filename|sha256 e semelhantes: o que interessa é o resumo.
        if tipo_misp.startswith("filename|") and "|" in str(valor):
            tipo_misp, valor = tipo_misp.split("|", 1)[1], str(valor).split("|", 1)[1]
        tipo = TIPOS_MISP.get(tipo_misp)
        normal = normalizar(tipo, valor) if tipo else None
        if normal:
            saida.append({"tipo": tipo, "valor": normal, "descricao": str(a.get("comment") or (a.get("Event") or {}).get("info") or "")[:500]})
    return saida


def ler_stix(objetos, agora=None):
    agora = agora or datetime.now(timezone.utc)
    saida = []
    for o in objetos:
        if o.get("type") != "indicator" or o.get("revoked") or o.get("pattern_type", "stix") != "stix":
            continue
        fim = o.get("valid_until")
        if fim:
            try:
                if datetime.fromisoformat(str(fim).replace("Z", "+00:00")) < agora:
                    continue
            except ValueError:
                pass
        for campo, valor, algoritmo, resumo in COMPARACAO_STIX.findall(str(o.get("pattern", ""))):
            if algoritmo:
                tipo, bruto = ALGORITMO_STIX[algoritmo], resumo
            else:
                tipo, bruto = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "dominio", "url": "url"}[campo], valor.replace("\\'", "'").replace("\\\\", "\\")
            normal = normalizar(tipo, bruto)
            if normal:
                saida.append({"tipo": tipo, "valor": normal, "descricao": str(o.get("name") or o.get("description") or "")[:500]})
    return saida


def _pedir(metodo, endereco, cabecalhos, **kwargs):
    try:
        resposta, corpo = rede_externa.chamar(metodo, endereco, cabecalhos=cabecalhos, limite_de_bytes=MAIOR_RESPOSTA, **kwargs)
    except rede_externa.DestinoRecusado as erro:
        raise FonteComProblema(str(erro))
    except Exception as erro:
        raise FonteComProblema(f"A fonte não respondeu ({type(erro).__name__}).")
    if resposta.status_code in (401, 403):
        raise FonteComProblema("A fonte recusou a credencial.")
    if resposta.status_code >= 300:
        raise FonteComProblema(f"A fonte respondeu com o código {resposta.status_code}.")
    try:
        return json.loads(corpo)
    except ValueError:
        raise FonteComProblema("A fonte respondeu algo que não é JSON.")


def buscar_misp(fonte, segredo, chamar=_pedir):
    """Só o que a própria fonte marca como bom para detecção (to_ids), e com o mínimo de campos."""
    base = fonte["endereco"].rstrip("/")
    cabecalhos = {"Authorization": segredo or "", "Accept": "application/json", "Content-Type": "application/json"}
    saida = []
    for pagina in range(1, MAXIMO_DE_PAGINAS + 1):
        filtro = {"returnFormat": "json", "to_ids": True, "published": True, "deleted": False, "limit": POR_PAGINA, "page": pagina,
                  "type": [*TIPOS_MISP, "filename|md5", "filename|sha1", "filename|sha256"]}
        corpo = chamar("POST", f"{base}/attributes/restSearch", cabecalhos, data=json.dumps(filtro))
        saida += ler_misp(corpo)
        if len((corpo.get("response") or {}).get("Attribute") or []) < POR_PAGINA:
            return saida
    return saida


def buscar_taxii(fonte, segredo, chamar=_pedir):
    """TAXII 2.1. O endereço é a raiz da API; a coleção vem à parte."""
    base = fonte["endereco"].rstrip("/")
    cabecalhos = {"Accept": "application/taxii+json;version=2.1"}
    if segredo:
        cabecalhos["Authorization"] = segredo
    if not fonte.get("colecao"):
        raise FonteComProblema("Informe a coleção da fonte.")
    saida, seguinte = [], None
    for _ in range(MAXIMO_DE_PAGINAS):
        endereco = f"{base}/collections/{fonte['colecao']}/objects/?match[type]=indicator&limit={POR_PAGINA}"
        if seguinte:
            endereco += f"&next={seguinte}"
        corpo = chamar("GET", endereco, cabecalhos)
        saida += ler_stix(corpo.get("objects") or [])
        seguinte = corpo.get("next")
        if not corpo.get("more") or not seguinte:
            return saida
    return saida


def _com_cliente(banco, cliente):
    banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))


def gravar_indicadores(banco, cliente, fonte_id, indicadores):
    """Devolve os novos, para a busca no passado olhar só o que mudou."""
    novos, vistos = [], set()
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        for i in indicadores:
            chave = (i["tipo"], i["valor"])
            if chave in vistos:
                continue
            vistos.add(chave)
            linha = banco.con.execute(
                """INSERT INTO intel_indicadores (cliente_id, fonte_id, tipo, valor, descricao) VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (fonte_id, tipo, valor) DO UPDATE SET ultima_vez = now(), descricao = EXCLUDED.descricao
                   RETURNING id, (xmax = 0) AS novo""", (cliente, fonte_id, i["tipo"], i["valor"], i.get("descricao"))).fetchone()
            if linha[1]:
                novos.append({"id": linha[0], **i})
    return novos


def observaveis(evento_ip, bruto):
    """O que dá para comparar num evento. Tudo vem do log, que pode ter sido escrito por um atacante: só serve para comparar."""
    saida = set()
    bruto = bruto if isinstance(bruto, dict) else {}
    dados = bruto.get("data") if isinstance(bruto.get("data"), dict) else {}
    arquivo = bruto.get("syscheck") if isinstance(bruto.get("syscheck"), dict) else {}
    for candidato in (evento_ip, *(dados.get(c) for c in CAMPOS_DE_IP_DE_ORIGEM + CAMPOS_DE_IP_DE_DESTINO)):
        normal = normalizar("ip", candidato)
        if normal:
            saida.add(("ip", normal))
    for campo in ("hostname", "domain", "query", "dest_host"):
        normal = normalizar("dominio", dados.get(campo))
        if normal:
            saida.add(("dominio", normal))
    normal = normalizar("url", dados.get("url"))
    if normal:
        saida.add(("url", normal))
    for tipo, campo in (("md5", "md5_after"), ("sha1", "sha1_after"), ("sha256", "sha256_after")):
        normal = normalizar(tipo, arquivo.get(campo))
        if normal:
            saida.add((tipo, normal))
    return saida


def _registrar(banco, cliente, ocorrencias, no_passado):
    novas = 0
    for indicador, valor, evento, momento in ocorrencias:
        criada = banco.con.execute(
            """INSERT INTO intel_ocorrencias (indicador_id, evento_id, cliente_id, ocorrido_em, no_passado) VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT DO NOTHING RETURNING 1""", (indicador, evento, cliente, momento, no_passado)).fetchone()
        if criada:
            novas += 1
            banco.con.execute("SELECT roar_avisar_inteligencia(%s, %s)", (cliente, valor))
    return novas


def buscar_nos_eventos_novos(banco, cliente, limite=EVENTOS_POR_CICLO):
    """Eventos que chegaram depois da última volta."""
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        linha = banco.con.execute("SELECT ultimo_evento FROM intel_cursor WHERE cliente_id = %s", (cliente,)).fetchone()
        ultimo = linha[0] if linha else 0
        eventos = banco.con.execute("SELECT id, host(ip_origem), bruto, ocorrido_em FROM eventos WHERE id > %s ORDER BY id LIMIT %s", (ultimo, limite)).fetchall()
        if not eventos:
            return 0
        tem_indicador = banco.con.execute("SELECT EXISTS (SELECT 1 FROM intel_indicadores)").fetchone()[0]
        novas = 0
        if tem_indicador:
            por_chave = {}
            for evento, ip, bruto, momento in eventos:
                for chave in observaveis(ip, bruto):
                    por_chave.setdefault(chave, []).append((evento, momento))
            if por_chave:
                tipos = [t for t, _ in por_chave]
                valores = [v for _, v in por_chave]
                achados = banco.con.execute(
                    """SELECT i.id, i.tipo, i.valor FROM intel_indicadores i JOIN unnest(%s::text[], %s::text[]) AS c(tipo, valor) ON c.tipo = i.tipo AND c.valor = i.valor""",
                    (tipos, valores)).fetchall()
                ocorrencias = [(i, valor, evento, momento) for i, tipo, valor in achados for evento, momento in por_chave[(tipo, valor)]]
                novas = _registrar(banco, cliente, ocorrencias, False)
        banco.con.execute("""INSERT INTO intel_cursor (cliente_id, ultimo_evento) VALUES (%s, %s)
                             ON CONFLICT (cliente_id) DO UPDATE SET ultimo_evento = EXCLUDED.ultimo_evento""", (cliente, eventos[-1][0]))
    return novas


CAMPOS_NO_PASSADO = {
    "ip": "(host(ip_origem) = ANY(%(v)s) OR bruto #>> '{data,srcip}' = ANY(%(v)s) OR bruto #>> '{data,dstip}' = ANY(%(v)s))",
    "dominio": "(lower(bruto #>> '{data,hostname}') = ANY(%(v)s) OR lower(bruto #>> '{data,domain}') = ANY(%(v)s) OR lower(bruto #>> '{data,query}') = ANY(%(v)s) OR lower(bruto #>> '{data,dest_host}') = ANY(%(v)s))",
    "url": "bruto #>> '{data,url}' = ANY(%(v)s)",
    "md5": "lower(bruto #>> '{syscheck,md5_after}') = ANY(%(v)s)",
    "sha1": "lower(bruto #>> '{syscheck,sha1_after}') = ANY(%(v)s)",
    "sha256": "lower(bruto #>> '{syscheck,sha256_after}') = ANY(%(v)s)",
}


def buscar_no_passado(banco, cliente, novos, dias=DIAS_NO_PASSADO):
    """Indicador novo pode explicar um evento antigo: é aí que aparece a invasão que passou despercebida."""
    total = 0
    por_tipo = {}
    for i in novos:
        por_tipo.setdefault(i["tipo"], []).append(i)
    for tipo, lista in por_tipo.items():
        for inicio in range(0, len(lista), INDICADORES_POR_BUSCA):
            lote = lista[inicio:inicio + INDICADORES_POR_BUSCA]
            ids = {i["valor"]: i["id"] for i in lote}
            with banco.con.transaction():
                _com_cliente(banco, cliente)
                eventos = banco.con.execute(
                    f"SELECT id, host(ip_origem), bruto, ocorrido_em FROM eventos WHERE ocorrido_em > now() - make_interval(days => %(d)s) AND {CAMPOS_NO_PASSADO[tipo]}",
                    {"v": list(ids), "d": dias}).fetchall()
                ocorrencias = []
                for evento, ip, bruto, momento in eventos:
                    for t, valor in observaveis(ip, bruto):
                        if t == tipo and valor in ids:
                            ocorrencias.append((ids[valor], valor, evento, momento))
                total += _registrar(banco, cliente, ocorrencias, True)
    return total


# ------------------------------------------------------------------ fluxos de rede

# Os ips vão num parâmetro da consulta, no endereço do pedido: em lotes, para o endereço não passar do limite. Com listas de
# milhões de indicadores, o certo é uma tabela de indicadores no próprio armazém.
IPS_POR_BUSCA_NOS_FLUXOS = 2000
# Os fluxos que chegam ao armazém nos últimos segundos ainda podem estar sendo gravados.
FOLGA_DOS_FLUXOS = timedelta(seconds=15)
# Na primeira volta, sem posição guardada, só a última hora: o passado é a busca dos indicadores novos.
PRIMEIRA_JANELA_DOS_FLUXOS = timedelta(hours=1)


def _consultar_fluxos(armazem, banco, ips, onde, parametros):
    """[(indicador, interno, sentido, dia, fluxos, bytes, primeira, ultima, exportador)] dos fluxos com algum ip da lista.
    A conta é toda no armazém: só sobe um resumo por indicador, endereço da rede e dia."""
    linhas = armazem.linhas(f"""
        SELECT if(has({{ips:Array(String)}}, destino), destino, origem) AS indicador,
               if(has({{ips:Array(String)}}, destino), origem, destino) AS interno,
               if(has({{ips:Array(String)}}, destino), 'saida', 'entrada') AS sentido,
               toString(toDate(ocorrido_em)) AS dia, count() AS fluxos, sum(bytes) AS bytes,
               toString(min(ocorrido_em)) AS primeira, toString(max(ocorrido_em)) AS ultima, any(exportador) AS exportador
        FROM {banco}.fluxos WHERE {onde} AND (has({{ips:Array(String)}}, origem) OR has({{ips:Array(String)}}, destino))
        GROUP BY indicador, interno, sentido, dia""", {**parametros, "ips": "[" + ",".join(f"'{ip}'" for ip in ips if _so_endereco(ip)) + "]"})
    return [(l["indicador"], l["interno"], l["sentido"], l["dia"], int(l["fluxos"]), int(l["bytes"]), l["primeira"], l["ultima"], l["exportador"]) for l in linhas]


def _so_endereco(valor):
    """O ip vai escrito na lista do parâmetro: só passa o que é endereço de verdade."""
    try:
        return str(ipaddress.ip_address(valor)) == valor
    except ValueError:
        return False


def _registrar_nos_fluxos(banco, cliente, por_valor, achados, no_passado):
    """Soma no resumo do dia. O primeiro achado de cada indicador, endereço e dia avisa no sino."""
    novas = 0
    for indicador, interno, sentido, dia, fluxos, bytes_, primeira, ultima, exportador in achados:
        indicador_id = por_valor.get(indicador)
        if indicador_id is None:
            continue
        nova = banco.con.execute(
            """INSERT INTO intel_fluxos (cliente_id, indicador_id, dia, interno, sentido, fluxos, bytes, primeira, ultima, exportador, no_passado)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s::timestamp AT TIME ZONE 'UTC', %s::timestamp AT TIME ZONE 'UTC', %s, %s)
               ON CONFLICT (indicador_id, dia, interno, sentido) DO UPDATE SET fluxos = intel_fluxos.fluxos + EXCLUDED.fluxos,
                 bytes = intel_fluxos.bytes + EXCLUDED.bytes, primeira = least(intel_fluxos.primeira, EXCLUDED.primeira),
                 ultima = greatest(intel_fluxos.ultima, EXCLUDED.ultima)
               RETURNING (xmax = 0)""", (cliente, indicador_id, dia, interno, sentido, fluxos, bytes_, primeira, ultima, exportador, no_passado)).fetchone()[0]
        if nova:
            novas += 1
            banco.con.execute("SELECT roar_avisar_inteligencia(%s, %s)", (cliente, indicador))
    return novas


def _ips_dos_indicadores(banco, cliente, ids=None):
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        sql, args = "SELECT valor, id FROM intel_indicadores WHERE tipo = 'ip'", ()
        if ids is not None:
            sql, args = sql + " AND id = ANY(%s)", (list(ids),)
        return dict(banco.con.execute(sql, args).fetchall())


def _tem_fluxos(armazem, banco_do_armazem):
    return armazem.linhas("SELECT count() AS n FROM system.tables WHERE database = {b:String} AND name = 'fluxos'", {"b": banco_do_armazem})[0]["n"] not in (0, "0")


def buscar_nos_fluxos(banco, armazem, cliente, agora=None):
    """Os fluxos que chegaram ao armazém desde a última volta, com algum ip de indicador de um lado ou do outro."""
    from .armazem import banco_do

    if armazem is None:
        return 0
    nome = banco_do(cliente)
    if not _tem_fluxos(armazem, nome):
        return 0
    agora = agora or datetime.now(timezone.utc)
    ate = agora - FOLGA_DOS_FLUXOS
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        linha = banco.con.execute("SELECT ate FROM intel_cursor_fluxos WHERE cliente_id = %s", (cliente,)).fetchone()
    de = linha[0] if linha else ate - PRIMEIRA_JANELA_DOS_FLUXOS
    por_valor = _ips_dos_indicadores(banco, cliente)
    novas = 0
    valores = sorted(por_valor)
    for inicio in range(0, len(valores), IPS_POR_BUSCA_NOS_FLUXOS):
        achados = _consultar_fluxos(armazem, nome, valores[inicio:inicio + IPS_POR_BUSCA_NOS_FLUXOS],
                                    "recebido_em > parseDateTime64BestEffort({de:String}, 3) AND recebido_em <= parseDateTime64BestEffort({ate:String}, 3)",
                                    {"de": de.isoformat(), "ate": ate.isoformat()})
        with banco.con.transaction():
            _com_cliente(banco, cliente)
            novas += _registrar_nos_fluxos(banco, cliente, por_valor, achados, False)
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        banco.con.execute("""INSERT INTO intel_cursor_fluxos (cliente_id, ate) VALUES (%s, %s)
                             ON CONFLICT (cliente_id) DO UPDATE SET ate = EXCLUDED.ate""", (cliente, ate))
    return novas


def buscar_nos_fluxos_do_passado(banco, armazem, cliente, novos, dias=DIAS_NO_PASSADO):
    """Indicador de ip novo: os fluxos dos últimos dias que já tinham passado pela conferência."""
    from .armazem import banco_do

    ids = [i["id"] for i in novos if i["tipo"] == "ip"]
    if armazem is None or not ids:
        return 0
    nome = banco_do(cliente)
    if not _tem_fluxos(armazem, nome):
        return 0
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        linha = banco.con.execute("SELECT ate FROM intel_cursor_fluxos WHERE cliente_id = %s", (cliente,)).fetchone()
    if not linha:
        return 0  # Nada conferido ainda: a volta normal pega tudo.
    por_valor = _ips_dos_indicadores(banco, cliente, ids)
    valores = sorted(por_valor)
    novas = 0
    for inicio in range(0, len(valores), IPS_POR_BUSCA_NOS_FLUXOS):
        # Só o que já tinha sido conferido: o que chega depois, a volta normal pega, sem contar duas vezes.
        achados = _consultar_fluxos(armazem, nome, valores[inicio:inicio + IPS_POR_BUSCA_NOS_FLUXOS],
                                    f"ocorrido_em >= now64(3) - INTERVAL {int(dias)} DAY AND recebido_em <= parseDateTime64BestEffort({{ate:String}}, 3)",
                                    {"ate": linha[0].isoformat()})
        with banco.con.transaction():
            _com_cliente(banco, cliente)
            novas += _registrar_nos_fluxos(banco, cliente, por_valor, achados, True)
    return novas


def _pedir_local(metodo, endereco, cabecalhos, **kwargs):
    """A plataforma da própria instalação mora em endereço interno, que a proteção das fontes externas recusaria."""
    try:
        resposta = requests.request(metodo, endereco, headers=cabecalhos, timeout=TEMPO_DA_PLATAFORMA_LOCAL, **kwargs)
    except requests.RequestException as erro:
        raise FonteComProblema(f"A plataforma local não respondeu ({type(erro).__name__}).")
    if resposta.status_code >= 300:
        raise FonteComProblema(f"A plataforma local respondeu com o código {resposta.status_code}.")
    return resposta.json()


def plataforma_local():
    """Endereço e chave ficam só no serviço: a organização nunca recebe a chave da instalação."""
    from .ciclo import ler_env
    env = ler_env(os.getenv("ROAR_ENV", "/opt/panthera-roar/.env"))
    endereco, chave = env.get("ROAR_MISP_ENDERECO"), env.get("MISP_CHAVE")
    return (endereco, chave) if endereco and chave else None


def garantir_fonte_local(banco, cliente, local=None):
    """Toda organização já nasce com a fonte. Quem a desligou continua com ela desligada: a linha fica."""
    if not (local or plataforma_local()):
        return False
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        return bool(banco.con.execute(
            """INSERT INTO intel_fontes (cliente_id, nome, tipo, endereco, a_cada_minutos, criado_por, interna)
               VALUES (%s, 'Plataforma local', 'misp', 'interno', 60, '00000000-0000-0000-0000-000000000000', true)
               ON CONFLICT (cliente_id) WHERE interna DO NOTHING RETURNING id""", (cliente,)).fetchone())


def sincronizar_fonte(banco, cliente, fonte, privada=None, buscar=None, armazem=None):
    buscadores = {"misp": buscar_misp, "taxii": buscar_taxii}
    segredo = None
    try:
        if fonte.get("interna"):
            local = plataforma_local()
            if not local:
                raise FonteComProblema("A plataforma local não está instalada.")
            fonte = {**fonte, "endereco": local[0]}
            segredo = local[1]
            if not buscar:
                buscar = lambda f, s: buscar_misp(f, s, chamar=_pedir_local)  # noqa: E731
        elif fonte["segredo"]:
            with banco.con.transaction():
                _com_cliente(banco, cliente)
                selado = banco.con.execute("SELECT selado FROM segredos WHERE nome = %s", (fonte["segredo"],)).fetchone()
            if not selado:
                raise FonteComProblema("A credencial desta fonte não foi encontrada.")
            segredo = cofre.abrir(privada or cofre.ler_privada(), cliente, fonte["segredo"], bytes(selado[0]))
        indicadores = (buscar or buscadores[fonte["tipo"]])(fonte, segredo)
        novos = gravar_indicadores(banco, cliente, fonte["id"], indicadores)
        passado = buscar_no_passado(banco, cliente, novos)
        try:
            passado += buscar_nos_fluxos_do_passado(banco, armazem, cliente, novos)
        except Exception:
            log.exception("indicadores novos nos fluxos de %s", cliente)
        erro = None
    except FonteComProblema as e:
        erro, novos, passado = str(e), [], 0
    except Exception:
        log.exception("fonte %s", fonte["id"])
        erro, novos, passado = "Não foi possível sincronizar esta fonte.", [], 0
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        banco.con.execute("UPDATE intel_fontes SET ultima_em = now(), ultimo_erro = %s, proxima_em = now() + make_interval(mins => a_cada_minutos) WHERE id = %s", (erro, fonte["id"]))
    return {"novos": len(novos), "no_passado": passado, "erro": erro}


def fontes_vencidas(banco, cliente, agora=None):
    with banco.con.transaction():
        _com_cliente(banco, cliente)
        linhas = banco.con.execute("SELECT id, tipo, endereco, colecao, segredo, interna FROM intel_fontes WHERE ativa AND tipo <> 'manual' AND proxima_em <= %s ORDER BY id", (agora or datetime.now(timezone.utc),)).fetchall()
    return [dict(zip(("id", "tipo", "endereco", "colecao", "segredo", "interna"), l)) for l in linhas]


def ciclo(banco, cliente, armazem=None):
    garantir_fonte_local(banco, cliente)
    for fonte in fontes_vencidas(banco, cliente):
        sincronizar_fonte(banco, cliente, fonte, armazem=armazem)
    achados = buscar_nos_eventos_novos(banco, cliente)
    try:
        achados += buscar_nos_fluxos(banco, armazem, cliente)
    except Exception:
        # Os fluxos não podem parar a conferência dos eventos.
        log.exception("indicadores nos fluxos de %s", cliente)
    return achados


def main():
    from .ciclo import conexoes

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--uma-vez", action="store_true")
    a = args.parse_args()
    _, banco, env = conexoes()
    # Os fluxos de rede ficam no armazém de eventos (roar_ingestao.fluxos): sem a leitura dele, só os eventos.
    from .armazem import leitor

    armazem = leitor(env) if env.get("ARMAZEM_LEITOR_SENHA") else None
    while True:
        for cliente in {c for _, c in banco.gerenciadores()}:
            try:
                ciclo(banco, cliente, armazem)
            except Exception:
                log.exception("inteligência de %s", cliente)
        if a.uma_vez:
            return
        time.sleep(SEGUNDOS_ENTRE_CICLOS)


if __name__ == "__main__":
    main()
