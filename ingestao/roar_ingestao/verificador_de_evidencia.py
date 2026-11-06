#!/usr/bin/env python3
"""Confere um pacote de evidência do Panthera Roar, sem precisar do Roar.

    python verificar.py evidencia.json

Roda em qualquer máquina com Python 3. A assinatura precisa do pacote "cryptography"; sem ele, todo o
resto é conferido e o resultado avisa que a assinatura ficou de fora.

O que um resultado positivo quer dizer: estes eventos são os mesmos que foram selados no momento indicado,
e a sequência de selos mostrada não foi reescrita. Não quer dizer que o conteúdo do log seja verdadeiro:
um log forjado antes da selagem é selado como qualquer outro.
"""

import hashlib
import json
import sys


def canonico(valor):
    return json.dumps(valor, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _no(esquerda, direita):
    return hashlib.sha256(b"\x01" + esquerda + direita).digest()


def hash_da_folha(sal, identificador, documento):
    return hashlib.sha256(b"\x00" + sal + identificador.encode() + b"\n" + canonico(documento)).digest()


def raiz_pelo_caminho(folha, indice, total, caminho):
    """RFC 9162, seção 2.1.3.2."""
    if not 0 <= indice < total:
        return None
    fn, sn, atual = indice, total - 1, folha
    for irmao in caminho:
        if sn == 0:
            return None
        irmao = bytes.fromhex(irmao)
        if fn & 1 or fn == sn:
            atual = _no(irmao, atual)
            if not fn & 1:
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            atual = _no(atual, irmao)
        fn >>= 1
        sn >>= 1
    return atual if sn == 0 else None


CAMPOS_DO_SELO = ("versao", "gerenciador", "cliente", "n", "fonte", "inicio", "fim", "total", "tardio", "raiz", "anterior", "chave", "selado_em")


def hash_do_selo(selo):
    cabecalho = {c: selo[c] for c in CAMPOS_DO_SELO}
    # Selo feito sobre o armazém de eventos diz isso no cabeçalho; os outros não têm o campo.
    if selo.get("origem", "indexador") != "indexador":
        cabecalho["origem"] = selo["origem"]
    return hashlib.sha256(canonico(cabecalho)).hexdigest()


def _assinatura_confere(publica, selo):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(publica)).verify(bytes.fromhex(selo["assinatura"]), bytes.fromhex(selo["hash"]))
        return True
    except (InvalidSignature, ValueError):
        return False


def conferir(pacote):
    """Devolve (problemas, avisos). Sem problemas, o pacote confere."""
    problemas, avisos = [], []
    try:
        publica = pacote["chave_publica"]
        impressao = hashlib.sha256(bytes.fromhex(publica)).hexdigest()
        selos = {s["n"]: s for s in pacote["selos"]}
        numeros = sorted(selos)
        if not numeros:
            return ["O pacote não tem selos."], avisos
        if numeros != list(range(numeros[0], numeros[-1] + 1)):
            problemas.append("Falta selo no meio da sequência.")
        try:
            import cryptography  # noqa: F401
            tem_assinatura = True
        except ImportError:
            tem_assinatura = False
            avisos.append('A assinatura não foi conferida: instale o pacote "cryptography".')
        for n in numeros:
            selo = selos[n]
            if hash_do_selo(selo) != selo["hash"]:
                problemas.append(f"O selo {n} foi alterado.")
            if selo["chave"] != impressao:
                problemas.append(f"O selo {n} foi feito com outra chave.")
            if tem_assinatura and not _assinatura_confere(publica, selo):
                problemas.append(f"A assinatura do selo {n} não confere.")
            if n - 1 in selos and selo["anterior"] != selos[n - 1]["hash"]:
                problemas.append(f"O selo {n} não continua o selo {n - 1}.")
        if not pacote["eventos"]:
            problemas.append("O pacote não tem eventos.")
        for evento in pacote["eventos"]:
            identificador = evento["id"]
            selo = selos.get(evento["selo"])
            if selo is None:
                problemas.append(f"O selo do evento {identificador} não está no pacote.")
                continue
            folha = hash_da_folha(bytes.fromhex(evento["sal"]), identificador, evento["documento"])
            raiz = raiz_pelo_caminho(folha, evento["indice"], selo["total"], evento["caminho"])
            if raiz is None or raiz.hex() != selo["raiz"]:
                problemas.append(f"O evento {identificador} não confere com o selo {selo['n']}.")
    except (KeyError, TypeError, ValueError, AttributeError) as erro:
        problemas.append(f"O pacote está malformado: {type(erro).__name__} {erro}")
    return problemas, avisos


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        pacote = json.load(f)
    problemas, avisos = conferir(pacote)
    for aviso in avisos:
        print(f"AVISO: {aviso}")
    if problemas:
        print("NÃO CONFERE:")
        for problema in problemas:
            print(f"  - {problema}")
        return 1
    print(f"CONFERE: {len(pacote['eventos'])} evento(s) e {len(pacote['selos'])} selo(s).")
    print(f"Impressão da chave: {hashlib.sha256(bytes.fromhex(pacote['chave_publica'])).hexdigest()}")
    print("Compare essa impressão com a publicada pela organização: quem tem a chave certa é que dá valor à assinatura.")
    if pacote.get("ancoras"):
        print(f"Há {len(pacote['ancoras'])} âncora(s) pública(s) em ancoras/: confira com a ferramenta do OpenTimestamps.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
