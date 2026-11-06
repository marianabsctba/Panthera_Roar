#!/usr/bin/env python3
"""E-mail do domínio: SPF, DKIM e DMARC lidos do DNS. O DNS é de mentira: o teste diz o que cada nome responde.

    /opt/panthera-roar/venv/bin/python testes/fase4/testar_email_dominio.py
"""

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "ingestao")]

from roar_ingestao import email_dominio  # noqa: E402

RESULTADOS = []


def registrar(nome, passou, detalhe=""):
    RESULTADOS.append((nome, bool(passou)))
    print(f"[{'PASSOU' if passou else 'FALHOU'}] {nome}" + (f": {detalhe}" if detalhe else ""), flush=True)


def chave(bits):
    # A biblioteca não gera chave abaixo de 1024 bits; para a fraca, basta o número com o tamanho certo.
    publica = (rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key() if bits >= 1024
               else rsa.RSAPublicNumbers(65537, (1 << (bits - 1)) | 1).public_key())
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(publica.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()


def regras(dns):
    resultado = email_dominio.conferir("exemplo.test", lambda nome: dns.get(nome, []))
    return {a[0]: a[2] for a in resultado["achados"]}, resultado


def main():
    print("== Tudo certo", flush=True)
    boa = {"exemplo.test": ["v=spf1 include:spf.protection.outlook.com -all", "google-site-verification=x"],
           "spf.protection.outlook.com": ["v=spf1 ip4:40.92.0.0/15 -all"],
           "_dmarc.exemplo.test": ["v=DMARC1; p=reject; rua=mailto:dmarc@exemplo.test"],
           "selector1._domainkey.exemplo.test": [chave(2048)]}
    achados, resultado = regras(boa)
    registrar("domínio bem configurado não tem achado", achados == {}, str(achados))
    registrar("e mostra o que achou", resultado["dmarc"] == "reject" and resultado["dkim"] == ["selector1"] and resultado["spf"].startswith("v=spf1"))

    print("\n== SPF", flush=True)
    registrar("sem SPF", regras({**boa, "exemplo.test": []})[0].get("email|spf-ausente") == "media")
    registrar("dois SPF quebram os dois", regras({**boa, "exemplo.test": ["v=spf1 -all", "v=spf1 mx -all"]})[0].get("email|spf-duplicado") == "media")
    registrar("+all libera qualquer servidor", regras({**boa, "exemplo.test": ["v=spf1 mx +all"]})[0].get("email|spf-aberto") == "alta")
    registrar("?all não barra ninguém", regras({**boa, "exemplo.test": ["v=spf1 mx ?all"]})[0].get("email|spf-neutro") == "media")
    registrar("~all é aceito", "email|spf-neutro" not in regras({**boa, "exemplo.test": ["v=spf1 mx ~all"]})[0])
    registrar("redirect sem all é aceito", "email|spf-neutro" not in regras({**boa, "exemplo.test": ["v=spf1 redirect=_spf.exemplo.test"]})[0])
    muitos = {**boa, "exemplo.test": ["v=spf1 " + " ".join(f"include:s{i}.test" for i in range(6)) + " -all"],
              **{f"s{i}.test": ["v=spf1 a mx -all"] for i in range(6)}}
    registrar("conta as consultas dos includes por dentro", email_dominio.consultas_do_spf("exemplo.test", lambda n: muitos.get(n, [])) == 18)
    registrar("passar de 10 consultas é achado", regras(muitos)[0].get("email|spf-consultas") == "media")
    laco = {"a.test": ["v=spf1 include:b.test -all"], "b.test": ["v=spf1 include:a.test -all"]}
    registrar("include em laço não trava", email_dominio.consultas_do_spf("a.test", lambda n: laco.get(n, [])) == 2)

    print("\n== DMARC", flush=True)
    registrar("sem DMARC é alto", regras({**boa, "_dmarc.exemplo.test": []})[0].get("email|dmarc-ausente") == "alta")
    registrar("p=none só observa", regras({**boa, "_dmarc.exemplo.test": ["v=DMARC1; p=none; rua=mailto:a@exemplo.test"]})[0].get("email|dmarc-sem-efeito") == "media")
    registrar("pct menor que 100 vale só para parte", regras({**boa, "_dmarc.exemplo.test": ["v=DMARC1; p=quarantine; pct=20"]})[0].get("email|dmarc-parcial") == "baixa")
    registrar("maiúsculas e espaços não atrapalham", regras({**boa, "_dmarc.exemplo.test": ["v=DMARC1;P=Reject ; pct = 100"]})[0] == {})

    print("\n== DKIM", flush=True)
    registrar("chave de 512 bits é fraca", regras({**boa, "selector1._domainkey.exemplo.test": [chave(512)]})[0].get("email|dkim-fraco") == "media")
    sem_dkim = {k: v for k, v in boa.items() if "_domainkey" not in k}
    registrar("sem DKIM nos seletores comuns é só aviso", regras(sem_dkim)[0] == {"email|dkim-nao-achado": "informativa"})
    registrar("chave revogada (p vazio) não conta como fraca", "email|dkim-fraco" not in regras({**boa, "selector1._domainkey.exemplo.test": ["v=DKIM1; p="]})[0])

    falhas = [n for n, ok in RESULTADOS if not ok]
    print(f"\n{len(RESULTADOS) - len(falhas)} de {len(RESULTADOS)} passaram.")
    for n in falhas:
        print(f"  falhou: {n}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
