"""Dado pessoal mascarado na saída, para quem não tem a permissão de vê-lo.

O que está guardado não muda: os selos e o pacote de evidência dependem do log como chegou.
Usuário vira um apelido estável dentro da organização, para dar para ligar um evento ao outro sem saber quem é.
"""

import hashlib
import hmac
import re

CATEGORIAS = ("cpf", "cnpj", "email", "cartao", "telefone", "usuario", "ip")

# Nomes de campo, em minúsculas, como aparecem na API e no log do Wazuh.
CAMPOS_DE_USUARIO = {"usuario", "usuarios", "user", "username", "user_name", "srcuser", "dstuser", "targetusername", "subjectusername",
                     "accountname", "login", "uname_after", "uname_before", "dono"}
CAMPOS_DE_IP = {"ip", "ip_origem", "ip_destino", "srcip", "dstip", "ipaddress", "ipaddr", "source_ip", "destination_ip"}

# Nome curto demais vira coincidência no texto: "a" estaria em toda parte.
MINIMO_PARA_TROCAR_NO_TEXTO = 3

_CPF = re.compile(r"(?<![\d./-])\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?![\d/-]|\.\d)")
_CNPJ = re.compile(r"(?<![\d./-])\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?![\d/-]|\.\d)")
_EMAIL = re.compile(r"(?<![\w.+-])([\w.+-])[\w.+-]*@((?:[\w-]+\.)+[A-Za-z]{2,})")
_CARTAO = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
# Com hífen no fim: sem ele, qualquer sequência de dez dígitos pareceria telefone.
_TELEFONE = re.compile(r"(?<![\w.])(?:\+?55[\s-]?)?(?:\(\d{2}\)|\d{2})[\s-]?9?\d{4}-\d{4}(?!\w)")
_OCTETO = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = re.compile(rf"(?<![\d.])({_OCTETO}\.{_OCTETO})\.{_OCTETO}\.{_OCTETO}(?!\.?\d)")


def _digitos(texto):
    return [int(c) for c in texto if c.isdigit()]


def _cpf_valido(d):
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        if (sum(d[i] * (n + 1 - i) for i in range(n)) * 10) % 11 % 10 != d[n]:
            return False
    return True


def _cnpj_valido(d):
    if len(d) != 14 or len(set(d)) == 1:
        return False
    for n in (12, 13):
        pesos = list(range(n - 7, 1, -1)) + list(range(9, 1, -1))
        resto = sum(a * b for a, b in zip(d, pesos)) % 11
        if (0 if resto < 2 else 11 - resto) != d[n]:
            return False
    return True


def _luhn(d):
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def mascarar_ip(valor):
    if ":" in valor:
        return valor.split(":")[0] + ":x:x" if valor.count(":") > 1 else "x.x.x.x"
    partes = valor.split(".")
    return f"{partes[0]}.{partes[1]}.x.x" if len(partes) == 4 else "x.x.x.x"


class Mascara:
    def __init__(self, categorias, chave, cliente):
        self.categorias = set(categorias)
        self._chave = hmac.new(chave, str(cliente).encode(), hashlib.sha256).digest()
        self._usuarios = {}

    def apelido(self, usuario):
        resumo = hmac.new(self._chave, usuario.strip().lower().encode(), hashlib.sha256).hexdigest()[:6]
        return f"usuario-{resumo}"

    def texto(self, valor):
        c = self.categorias
        if "email" in c:
            valor = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", valor)
        if "cnpj" in c:
            valor = _CNPJ.sub(lambda m: "**.***.***/****-**" if _cnpj_valido(_digitos(m.group())) else m.group(), valor)
        if "cpf" in c:
            valor = _CPF.sub(lambda m: "***.***.***-**" if _cpf_valido(_digitos(m.group())) else m.group(), valor)
        if "cartao" in c:
            valor = _CARTAO.sub(lambda m: f"**** **** **** {''.join(map(str, _digitos(m.group())[-4:]))}"
                                if _luhn(_digitos(m.group())) else m.group(), valor)
        if "telefone" in c:
            valor = _TELEFONE.sub("(**) *****-****", valor)
        if "ip" in c:
            valor = _IPV4.sub(lambda m: f"{m.group(1)}.x.x", valor)
        for nome, apelido in self._usuarios.items():
            valor = re.sub(rf"(?<!\w){re.escape(nome)}(?!\w)", apelido, valor, flags=re.IGNORECASE)
        return valor

    def _juntar_usuarios(self, dado, chave=None, vizinhos=None):
        if isinstance(dado, dict):
            for k, v in dado.items():
                self._juntar_usuarios(v, k, dado)
        elif isinstance(dado, list):
            for v in dado:
                self._juntar_usuarios(v, chave, vizinhos)
        elif isinstance(dado, str) and self._e_usuario(chave, vizinhos) and len(dado.strip()) >= MINIMO_PARA_TROCAR_NO_TEXTO:
            self._usuarios[dado] = self.apelido(dado)

    def _e_usuario(self, chave, vizinhos):
        if "usuario" not in self.categorias or chave is None:
            return False
        chave = str(chave).lower()
        # Na fila, no risco e no relatório, "entidade" é usuário ou ativo: só o usuário é dado pessoal.
        if chave == "entidade":
            return bool(vizinhos) and vizinhos.get("entidade_tipo", vizinhos.get("tipo")) == "usuario"
        return chave in CAMPOS_DE_USUARIO

    def _valor(self, dado, chave, vizinhos):
        if isinstance(dado, dict):
            return {k: self._valor(v, k, dado) for k, v in dado.items()}
        if isinstance(dado, list):
            return [self._valor(v, chave, vizinhos) for v in dado]
        if not isinstance(dado, str):
            return dado
        if self._e_usuario(chave, vizinhos):
            return self.apelido(dado) if dado.strip() else dado
        if "ip" in self.categorias and chave is not None and str(chave).lower() in CAMPOS_DE_IP:
            return mascarar_ip(dado)
        return self.texto(dado)

    def dado(self, dado):
        """Primeiro junta os nomes de usuário da resposta inteira: o mesmo nome aparece solto no texto do log."""
        self._juntar_usuarios(dado)
        # O nome mais longo antes: "maria.silva" não pode virar "usuario-x.silva".
        self._usuarios = dict(sorted(self._usuarios.items(), key=lambda kv: -len(kv[0])))
        return self._valor(dado, None, None)
