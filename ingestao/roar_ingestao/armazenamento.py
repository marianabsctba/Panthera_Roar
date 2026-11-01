"""Grava eventos no banco. Reprocessar o mesmo alerta nunca conta duas vezes."""

from collections import defaultdict

import psycopg
from psycopg.types.json import Jsonb

from .normalizar import (
    AGENTE_DO_GERENCIADOR,
    AlertaInvalido,
    agente_do_alerta,
    bruto_seguro,
    chave_do_grupo,
    limpar,
    normalizar,
    severidade_do_nivel,
)


class Armazenamento:
    def __init__(self, url, origem="wazuh", gerenciador="padrao"):
        self.con = psycopg.connect(url)
        self.origem = origem
        self.gerenciador = gerenciador

    def fechar(self):
        self.con.close()

    def mapa_de_agentes(self):
        with self.con.transaction():
            linhas = self.con.execute(
                "SELECT agente_id, cliente_id FROM agentes WHERE gerenciador = %s", (self.gerenciador,)
            ).fetchall()
        return {agente: cliente for agente, cliente in linhas}

    def _quarentena(self, origem_id, motivo, agente_id, alerta):
        # Atualiza o motivo: assim a recuperação não apaga um alerta que falhou de novo.
        self.con.execute(
            "INSERT INTO quarentena (origem, origem_id, motivo, agente_id, bruto)"
            " VALUES (%s, %s, %s, %s, %s)"
            " ON CONFLICT (origem, origem_id) DO UPDATE SET motivo = EXCLUDED.motivo",
            (self.origem, limpar(origem_id), motivo, agente_id and limpar(agente_id),
             Jsonb(bruto_seguro(alerta))),
        )

    def _gravar_evento(self, cliente, ev):
        """Devolve True se o evento é novo. O grupo só conta quando o evento é inédito."""
        novo = self.con.execute(
            """INSERT INTO eventos (cliente_id, origem, origem_id, ocorrido_em, nivel, severidade,
                 regra_id, regra_descricao, regra_grupos, mitre, agente_id, agente_nome,
                 ip_origem, usuario, bruto)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cliente_id, origem, origem_id) DO NOTHING
               RETURNING id""",
            (cliente, self.origem, ev.origem_id, ev.ocorrido_em, ev.nivel, ev.severidade,
             ev.regra_id, ev.regra_descricao, ev.regra_grupos, ev.mitre, ev.agente_id,
             ev.agente_nome, ev.ip_origem, ev.usuario, Jsonb(ev.bruto)),
        ).fetchone()
        if not novo:
            return False

        # A severidade do grupo é a maior já vista: ruído não esconde o evento grave.
        grupo = self.con.execute(
            """INSERT INTO grupos_alerta AS g (cliente_id, chave, dia, agente_id, ip_origem, nivel,
                 severidade, regras, primeira_em, ultima_em)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cliente_id, chave) DO UPDATE SET
                 total = g.total + 1,
                 nivel = GREATEST(g.nivel, EXCLUDED.nivel),
                 severidade = CASE WHEN EXCLUDED.nivel > g.nivel THEN EXCLUDED.severidade ELSE g.severidade END,
                 regras = ARRAY(SELECT DISTINCT unnest(g.regras || EXCLUDED.regras) ORDER BY 1),
                 primeira_em = LEAST(g.primeira_em, EXCLUDED.primeira_em),
                 ultima_em = GREATEST(g.ultima_em, EXCLUDED.ultima_em)
               RETURNING id""",
            (cliente, chave_do_grupo(ev), ev.ocorrido_em.date(), ev.agente_id, ev.ip_origem, ev.nivel,
             severidade_do_nivel(ev.nivel), [ev.regra_id], ev.ocorrido_em, ev.ocorrido_em),
        ).fetchone()
        self.con.execute("UPDATE eventos SET grupo_id = %s WHERE id = %s", (grupo[0], novo[0]))
        return True

    def gravar_lote(self, documentos, mapa):
        """Separa por cliente e grava cada um na sua transação, sob o RLS dele."""
        contagem = defaultdict(int)
        por_cliente = defaultdict(list)

        with self.con.transaction():
            for origem_id, alerta in documentos:
                try:
                    evento = normalizar(origem_id, alerta)
                except AlertaInvalido as erro:
                    self._quarentena(origem_id, str(erro), agente_do_alerta(alerta), alerta)
                    contagem["invalidos"] += 1
                    continue
                cliente = mapa.get(evento.agente_id)
                if cliente is None:
                    motivo = ("agente_do_gerenciador" if evento.agente_id == AGENTE_DO_GERENCIADOR
                              else "agente_desconhecido")
                    self._quarentena(origem_id, motivo, evento.agente_id, alerta)
                    contagem["quarentena"] += 1
                    continue
                por_cliente[cliente].append((evento, alerta))

        for cliente, itens in por_cliente.items():
            with self.con.transaction():
                self.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
                for evento, alerta in itens:
                    try:
                        with self.con.transaction():
                            contagem["novos" if self._gravar_evento(cliente, evento) else "repetidos"] += 1
                    except psycopg.Error as erro:
                        # Um alerta ruim não pode travar a fila do cliente.
                        self._quarentena(evento.origem_id, f"erro_gravacao:{type(erro).__name__}",
                                         evento.agente_id, alerta)
                        contagem["erros"] += 1
        return contagem

    def recuperar_quarentena(self, mapa, tamanho=500):
        """Agente mapeado depois do alerta: os alertas dele saem da quarentena para o cliente."""
        if not mapa:
            return 0
        recuperados = 0
        while True:
            with self.con.transaction():
                linhas = self.con.execute(
                    "SELECT origem_id, bruto FROM quarentena WHERE origem = %s"
                    " AND motivo = 'agente_desconhecido' AND agente_id = ANY(%s) LIMIT %s",
                    (self.origem, list(mapa), tamanho),
                ).fetchall()
            if not linhas:
                return recuperados
            self.gravar_lote(linhas, mapa)
            with self.con.transaction():
                self.con.execute(
                    "DELETE FROM quarentena WHERE origem = %s AND origem_id = ANY(%s)"
                    " AND motivo = 'agente_desconhecido'",
                    (self.origem, [o for o, _ in linhas]),
                )
            recuperados += len(linhas)

    def ler_checkpoint(self, fonte):
        with self.con.transaction():
            linha = self.con.execute(
                "SELECT ocorrido_em FROM checkpoints WHERE fonte = %s", (fonte,)
            ).fetchone()
        return linha[0] if linha else None

    def gravar_checkpoint(self, fonte, momento):
        with self.con.transaction():
            self.con.execute(
                """INSERT INTO checkpoints AS c (fonte, ocorrido_em) VALUES (%s, %s)
                   ON CONFLICT (fonte) DO UPDATE SET
                     ocorrido_em = GREATEST(c.ocorrido_em, EXCLUDED.ocorrido_em), atualizado_em = now()""",
                (fonte, momento),
            )
