"""Aviso no sino quando uma fonte de dados fica quieta: a última hora com bem menos eventos que o normal daquela hora.

Roda no serviço de buscas, que já lê o armazém. A conta é a mesma da tela (api/roar_api/saude_das_fontes.py). No syslog,
o aviso é por equipamento: o firewall que parou aparece pelo endereço. Cada queda avisa uma vez; se a fonte volta ao
normal e cai de novo, avisa de novo.
"""

import logging

from roar_api import saude_das_fontes as saude

from .armazem import banco_do as banco_do_armazem
from .regras import PASTA_GERENCIADORES

log = logging.getLogger("roar.fontes_quietas")
TIPOS = ("syslog", "github", "office365", "msgraph", "aws", "azure", "gcp")
# O que já foi avisado e continua quieto: (cliente, fonte, equipamento).
_avisadas = set()


def _com_cliente(banco, cliente, sql, *args):
    with banco.con.transaction():
        banco.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
        cursor = banco.con.execute(sql, args)
        return cursor.fetchall() if cursor.description else None


def _numero(n):
    return f"{n:,}".replace(",", ".")


def quietas(fonte, conta):
    """[(chave do equipamento, texto do aviso)] do que está abaixo do normal nesta fonte."""
    def texto(rotulo, c):
        return f"{rotulo}: {_numero(c['ultima_hora'])} eventos na última hora; o normal nesse horário é {_numero(c['normal_da_hora'])}"
    if fonte["tipo"] == "syslog":
        return [(q["endereco"], texto(f"{fonte['nome']} ({q['endereco']})", q)) for q in conta.get("equipamentos", []) if q["abaixo_do_normal"]]
    return [("", texto(fonte["nome"], conta))] if conta["abaixo_do_normal"] else []


def conferir(banco, armazem, agora=None):
    """Devolve quantos avisos novos saíram. Uma organização com problema não impede as outras."""
    avisos = 0
    vistas = set()
    for gerenciador_id, cliente in banco.gerenciadores():
        if not (PASTA_GERENCIADORES / gerenciador_id).is_dir():
            continue
        try:
            if not _com_cliente(banco, cliente, "SELECT ler_do_armazem FROM clientes WHERE id = %s", cliente)[0][0]:
                continue
            linhas = _com_cliente(banco, cliente, "SELECT id, tipo, nome, config FROM fontes WHERE estado = 'ativa' AND gerenciador_id = %s AND tipo = ANY(%s)",
                                  gerenciador_id, list(TIPOS))
            if not linhas:
                continue
            resumo = saude.ler(armazem, banco_do_armazem(cliente), gerenciador_id, agora)
            for fonte_id, tipo, nome, config in linhas:
                fonte = {"id": fonte_id, "tipo": tipo, "nome": nome, "config": config}
                for equipamento, texto in quietas(fonte, saude.da_fonte(fonte, resumo, agora)):
                    chave = (str(cliente), fonte_id, equipamento)
                    vistas.add(chave)
                    if chave in _avisadas:
                        continue
                    _com_cliente(banco, cliente, "SELECT roar_avisar(%s, 'fonte_quieta', %s)", cliente, texto)
                    _avisadas.add(chave)
                    avisos += 1
        except Exception:
            log.exception("fontes quietas do gerenciador %s", gerenciador_id)
            # Sem conferir agora, não dá para dizer que voltou: o que estava avisado continua avisado.
            vistas |= {c for c in _avisadas if c[0] == str(cliente)}
    # A que voltou ao normal pode avisar de novo numa próxima queda.
    _avisadas.intersection_update(vistas)
    return avisos
