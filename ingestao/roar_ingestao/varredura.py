"""Roda as ferramentas de varredura e traduz o que elas devolvem para os achados do Roar.

    python -m roar_ingestao.varredura [--uma-vez]

Nada de scanner próprio: cada ferramenta é um programa separado, em imagem fixa. Os argumentos vão em lista,
sem shell, e o alvo já foi validado antes de entrar na fila.
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from .vulnerabilidades import Achado, Resultado, agendar_vencidas, concluir_varredura, falhar_varredura

log = logging.getLogger("roar.varredura")

IMAGENS = {
    "nuclei": "projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb",
    "zap": "ghcr.io/zaproxy/zaproxy@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238",
    "trivy": "aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c",
}
PASTA = Path(os.getenv("ROAR_VARREDURA_PASTA", "/opt/panthera-roar/varredura"))
PASTA_DOS_SENSORES = Path(os.getenv("ROAR_SENSORES_PASTA", "/opt/panthera-roar/sensores"))
TEMPO_LIMITE = 3600
SEGUNDOS_ENTRE_CICLOS = 30
SEVERIDADE_NUCLEI = {"critical": "critica", "high": "alta", "medium": "media", "low": "baixa", "info": "informativa", "unknown": "informativa"}
SEVERIDADE_ZAP = {"3": "alta", "2": "media", "1": "baixa", "0": "informativa"}
SEVERIDADE_TRIVY = {"CRITICAL": "critica", "HIGH": "alta", "MEDIUM": "media", "LOW": "baixa", "UNKNOWN": "informativa"}


class FerramentaFalhou(Exception):
    """A mensagem aparece na tela: sem caminho interno nem saída crua da ferramenta."""


# ------------------------------------------------------------------ tradução, a partir da saída real de cada uma

def _host_da_url(url):
    return (urlsplit(url).hostname or "").lower()


def _porta_da_url(url):
    partes = urlsplit(url)
    return f"{partes.port or (443 if partes.scheme == 'https' else 80)}/tcp"


def ler_nuclei(texto):
    achados = []
    for linha in texto.splitlines():
        if not linha.strip():
            continue
        d = json.loads(linha)
        info = d.get("info") or {}
        classificacao = info.get("classification") or {}
        endereco = d.get("matched-at") or d.get("url") or ""
        achados.append(Achado(
            host=_host_da_url(endereco) or str(d.get("host", "")).lower(),
            # O mesmo modelo pode achar em caminhos diferentes, e cada um é uma correção.
            regra=f"{d.get('template-id')}|{urlsplit(endereco).path}",
            titulo=str(info.get("name") or d.get("template-id")),
            cvss=classificacao.get("cvss-score"),
            cves=[c for c in (classificacao.get("cve-id") or []) if c],
            porta=_porta_da_url(endereco) if endereco else "",
            evidencia=endereco,
            solucao=str(info.get("remediation") or ""),
            severidade=SEVERIDADE_NUCLEI.get(str(info.get("severity")).lower(), "informativa"),
        ))
    return achados


def ler_zap(texto):
    achados = []
    for site in json.loads(texto).get("site", []):
        host = str(site.get("@host") or _host_da_url(site.get("@name", ""))).lower()
        porta = f"{site.get('@port')}/tcp" if site.get("@port") else ""
        for alerta in site.get("alerts", []):
            instancias = alerta.get("instances") or []
            achados.append(Achado(
                host=host,
                regra=str(alerta.get("alertRef") or alerta.get("pluginid")),
                titulo=str(alerta.get("name") or alerta.get("alert")),
                porta=porta,
                evidencia="\n".join(f"{i.get('method', '')} {i.get('uri', '')}".strip() for i in instancias[:20]),
                # O ZAP devolve HTML simples na solução.
                solucao=str(alerta.get("solution") or "").replace("<p>", "").replace("</p>", "\n").strip(),
                severidade=SEVERIDADE_ZAP.get(str(alerta.get("riskcode")), "informativa"),
            ))
    return achados


def _cvss_do_trivy(vuln):
    notas = vuln.get("CVSS") or {}
    for fonte in ("nvd", "redhat", "ghsa"):
        nota = (notas.get(fonte) or {}).get("V3Score")
        if nota is not None:
            return nota
    return next((n["V3Score"] for n in notas.values() if n.get("V3Score") is not None), None)


def ler_trivy(texto, imagem):
    achados = []
    for resultado in json.loads(texto).get("Results") or []:
        for v in resultado.get("Vulnerabilities") or []:
            identificador = str(v.get("VulnerabilityID"))
            correcao = v.get("FixedVersion")
            achados.append(Achado(
                host=imagem,
                regra=f"{identificador}|{v.get('PkgName')}",
                titulo=str(v.get("Title") or f"{identificador} em {v.get('PkgName')}"),
                cvss=_cvss_do_trivy(v),
                cves=[identificador] if identificador.startswith("CVE-") else [],
                porta=str(v.get("PkgName") or ""),
                evidencia=f"{v.get('PkgName')} {v.get('InstalledVersion')} em {resultado.get('Target')}",
                solucao=f"Atualize para a versão {correcao}." if correcao else "",
                severidade=SEVERIDADE_TRIVY.get(str(v.get("Severity")), "informativa"),
            ))
    return achados


def _linhas_json(caminho):
    if not caminho.exists():
        return
    for linha in caminho.read_text(encoding="utf-8", errors="replace").splitlines():
        if linha.strip():
            yield json.loads(linha)


def ler_zeek(pasta):
    """A escuta só vê: nunca toca no ativo. Serviço e versão entram como informação, para cruzar com o que as varreduras acham."""
    pasta = Path(pasta)
    achados = {}
    for s in _linhas_json(pasta / "known_services.log"):
        servicos = [x for x in (s.get("service") or []) if x]
        if not servicos:
            continue
        porta = f"{s.get('port_num')}/{s.get('port_proto')}"
        achados[("servico", s["host"], porta)] = Achado(host=s["host"], regra=f"servico|{porta}", titulo=f"Serviço visto na escuta: {', '.join(servicos)}", porta=porta,
                                                        evidencia="Identificado pelo tráfego, sem tocar no ativo.", severidade="informativa")
    for s in _linhas_json(pasta / "software.log"):
        versao = s.get("unparsed_version") or s.get("name") or ""
        if str(s.get("software_type", "")).endswith("BROWSER") or not versao:
            continue  # O navegador de quem acessa não é o ativo.
        porta = f"{s.get('host_p')}/tcp" if s.get("host_p") else ""
        achados[("software", s["host"], versao)] = Achado(host=s["host"], regra=f"software|{versao}", titulo=f"Programa visto na escuta: {versao}", porta=porta,
                                                          evidencia="Identificado pelo tráfego, sem tocar no ativo.", severidade="informativa")
    return list(achados.values())


# ------------------------------------------------------------------ execução

def _rede():
    return ["--network", os.getenv("ROAR_VARREDURA_REDE", "bridge")]


def _executar(argumentos, tempo=TEMPO_LIMITE):
    try:
        return subprocess.run(argumentos, capture_output=True, text=True, timeout=tempo, check=False)
    except subprocess.TimeoutExpired:
        raise FerramentaFalhou("A varredura passou do tempo limite.")
    except OSError:
        raise FerramentaFalhou("A ferramenta de varredura não está disponível neste servidor.")


def rodar_nuclei(url, intrusiva):
    cache = PASTA / "nuclei"
    cache.mkdir(parents=True, exist_ok=True)
    modelos = cache / "nuclei-templates"
    # Só a pasta dos modelos conta: a ferramenta também grava configuração em .yaml.
    if not any(modelos.rglob("*.yaml")):
        # Na rede padrão: a rede da varredura serve para chegar ao alvo, e pode não ter saída.
        _executar(["docker", "run", "--rm", "-v", f"{cache}:/root", IMAGENS["nuclei"], "-ut"], 600)
        if not any(modelos.rglob("*.yaml")):
            raise FerramentaFalhou("A base de testes da varredura web não pôde ser baixada.")
    comando = ["docker", "run", "--rm", *_rede(), "-v", f"{cache}:/root", IMAGENS["nuclei"], "-u", url, "-jsonl", "-silent", "-duc", "-ni", "-rl", "50"]
    etiquetas = os.getenv("ROAR_NUCLEI_ETIQUETAS")
    if etiquetas:
        comando += ["-tags", etiquetas]
    # Derrubar serviço nunca é aceitável; o resto do que é intrusivo só quando o modelo pede.
    comando += ["-etags", "dos" if intrusiva else "dos,intrusive,fuzz"]
    r = _executar(comando)
    if r.returncode != 0:
        log.error("nuclei saiu com %s: %s", r.returncode, r.stderr[-300:])
        raise FerramentaFalhou("A ferramenta de varredura web não conseguiu terminar.")
    return ler_nuclei(r.stdout)


def rodar_zap(url, intrusiva):
    PASTA.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=PASTA) as pasta:
        os.chmod(pasta, 0o777)
        programa = "zap-full-scan.py" if intrusiva else "zap-baseline.py"
        r = _executar(["docker", "run", "--rm", *_rede(), "-v", f"{pasta}:/zap/wrk:rw", IMAGENS["zap"], programa, "-t", url, "-m", "2", "-J", "relatorio.json", "-I"])
        relatorio = Path(pasta) / "relatorio.json"
        if not relatorio.exists():
            log.error("zap saiu com %s: %s", r.returncode, r.stdout[-300:])
            raise FerramentaFalhou("A ferramenta de varredura web não conseguiu terminar.")
        return ler_zap(relatorio.read_text(encoding="utf-8"))


def rodar_trivy(imagem):
    cache = PASTA / "trivy"
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=PASTA) as pasta:
        comando = ["docker", "run", "--rm", "-v", f"{cache}:/root/.cache"]
        # Imagem que só existe neste servidor não dá para baixar do registro.
        if _executar(["docker", "image", "inspect", imagem], 60).returncode == 0:
            arquivo = Path(pasta) / "alvo.tar"
            if _executar(["docker", "save", imagem, "-o", str(arquivo)], 900).returncode != 0:
                raise FerramentaFalhou("Não foi possível ler a imagem do contêiner.")
            comando += ["-v", f"{arquivo}:/alvo.tar:ro", IMAGENS["trivy"], "image", "--input", "/alvo.tar"]
        else:
            comando += [IMAGENS["trivy"], "image", imagem]
        r = _executar([*comando, "--format", "json", "-q"])
    if r.returncode != 0:
        log.error("trivy saiu com %s: %s", r.returncode, r.stderr[-300:])
        raise FerramentaFalhou("Não foi possível analisar a imagem do contêiner.")
    return ler_trivy(r.stdout, imagem)


def varrer(ferramenta, alvos, intrusiva, todas_portas):
    """Devolve o Resultado. Quem não respondeu fica de fora, e por isso não tem nada fechado por engano."""
    if ferramenta == "web":
        achados, respondendo = [], []
        for url in alvos:
            # Ferramentas diferentes com a mesma origem: um não fecha achado do outro.
            achados += [*rodar_nuclei(url, intrusiva), *rodar_zap(url, intrusiva)]
            respondendo.append(_host_da_url(url))
        return Resultado("web", respondendo, achados, intrusiva=intrusiva, todas_portas=todas_portas)
    if ferramenta == "conteiner":
        achados = []
        for imagem in alvos:
            achados += rodar_trivy(imagem)
        return Resultado("conteiner", list(alvos), achados, autenticada=True)
    raise FerramentaFalhou({"rede": "O scanner de rede ainda não está ligado neste servidor.", "nuvem": "A análise de nuvem ainda não está ligada neste servidor."}.get(ferramenta, "Tipo de varredura desconhecido."))


def _reservar(banco, cliente):
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        # Uma por vez, a mais antiga primeiro. O UPDATE com trava impede dois serviços de pegarem a mesma.
        return banco.con.execute(
            """UPDATE vuln_varreduras v SET estado = 'em_andamento', iniciada_em = now()
               FROM vuln_alvos a, vuln_modelos m
               WHERE v.id = (SELECT id FROM vuln_varreduras WHERE estado = 'pendente' AND cliente_id = %s ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
                 AND a.id = v.alvo_id AND m.id = v.modelo_id
               RETURNING v.id, a.hosts, m.ferramenta, m.intrusiva, m.todas_portas""", (cliente,)).fetchone()


def processar_cliente(banco, cliente, varrer_com=varrer):
    agendar_vencidas(banco, cliente)
    feitas = 0
    while (pedido := _reservar(banco, cliente)) is not None:
        varredura, alvos, ferramenta, intrusiva, todas_portas = pedido
        try:
            concluir_varredura(banco, cliente, varredura, varrer_com(ferramenta, alvos, intrusiva, todas_portas))
        except FerramentaFalhou as erro:
            falhar_varredura(banco, cliente, varredura, str(erro))
        except Exception:
            log.exception("varredura %s falhou", varredura)
            falhar_varredura(banco, cliente, varredura, "A varredura falhou por um erro interno.")
        feitas += 1
    return feitas


def ingerir_sensor(banco, cliente, pasta):
    """Escuta contínua: registra o que viu e nunca fecha nada, porque não ver tráfego não prova que o serviço saiu."""
    from .vulnerabilidades import gravar_resultado

    achados = ler_zeek(pasta)
    if achados:
        with banco.con.transaction():
            banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            gravar_resultado(banco.con, cliente, None, Resultado("escuta", [], achados))
    return len(achados)


def recuperar_interrompidas(banco, clientes):
    """Se o serviço caiu no meio, ninguém termina aquela varredura, e o alvo ficaria preso para sempre."""
    for cliente in clientes:
        with banco.con.transaction():
            banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            banco.con.execute("UPDATE vuln_varreduras SET estado = 'falhou', terminada_em = now(), mensagem = 'O serviço de varredura foi reiniciado no meio.' WHERE estado = 'em_andamento'")


def main():
    from .ciclo import conexoes

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = argparse.ArgumentParser()
    args.add_argument("--uma-vez", action="store_true")
    a = args.parse_args()
    _, banco, _ = conexoes()
    if not shutil.which("docker"):
        log.warning("docker não encontrado: as varreduras vão falhar com aviso na tela")
    clientes = sorted({c for _, c in banco.gerenciadores()})
    recuperar_interrompidas(banco, clientes)
    while True:
        for cliente in sorted({c for _, c in banco.gerenciadores()}):
            try:
                processar_cliente(banco, cliente)
                sensor = PASTA_DOS_SENSORES / str(cliente)
                if sensor.is_dir():
                    ingerir_sensor(banco, cliente, sensor)
            except Exception:
                log.exception("varreduras de %s falharam", cliente)
        if a.uma_vez:
            return
        time.sleep(SEGUNDOS_ENTRE_CICLOS)


if __name__ == "__main__":
    main()
