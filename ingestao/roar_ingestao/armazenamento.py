"""Grava eventos no banco. Reprocessar o mesmo alerta nunca conta duas vezes."""

from collections import Counter

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
    def __init__(self, url, origem="wazuh"):
        self.con = psycopg.connect(url)
        self.origem = origem

    def fechar(self):
        self.con.close()

    def gerenciadores(self):
        with self.con.transaction():
            return self.con.execute("SELECT id, cliente_id FROM gerenciadores ORDER BY id").fetchall()

    def _quarentena(self, gerenciador_id, origem_id, motivo, agente_id, alerta):
        # Atualiza o motivo para reprocessar sem erro; o conteúdo original é mantido.
        self.con.execute(
            "INSERT INTO quarentena (gerenciador_id, origem, origem_id, motivo, agente_id, bruto)"
            " VALUES (%s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (gerenciador_id, origem, origem_id) DO UPDATE SET motivo = EXCLUDED.motivo",
            (gerenciador_id, self.origem, limpar(origem_id), motivo, agente_id and limpar(agente_id),
             Jsonb(bruto_seguro(alerta))),
        )

    def _gravar_evento(self, gerenciador_id, cliente, ev):
        """Devolve True se o evento é novo. O grupo só conta quando o evento é inédito."""
        novo = self.con.execute(
            """INSERT INTO eventos (cliente_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel,
                 severidade, regra_id, regra_descricao, regra_grupos, mitre, agente_id, agente_nome,
                 ip_origem, usuario, bruto)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cliente_id, origem, origem_id) DO NOTHING
               RETURNING id""",
            (cliente, gerenciador_id, self.origem, ev.origem_id, ev.ocorrido_em, ev.nivel, ev.severidade,
             ev.regra_id, ev.regra_descricao, ev.regra_grupos, ev.mitre, ev.agente_id,
             ev.agente_nome, ev.ip_origem, ev.usuario, Jsonb(ev.bruto)),
        ).fetchone()
        if not novo:
            return False

        # A severidade do grupo é a maior já vista: ruído não esconde o evento grave.
        grupo = self.con.execute(
            """INSERT INTO grupos_alerta AS g (cliente_id, chave, dia, gerenciador_id, agente_id, ip_origem,
                 nivel, severidade, regras, primeira_em, ultima_em)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cliente_id, chave) DO UPDATE SET
                 total = g.total + 1,
                 nivel = GREATEST(g.nivel, EXCLUDED.nivel),
                 severidade = CASE WHEN EXCLUDED.nivel > g.nivel THEN EXCLUDED.severidade ELSE g.severidade END,
                 regras = ARRAY(SELECT DISTINCT unnest(g.regras || EXCLUDED.regras) ORDER BY 1),
                 primeira_em = LEAST(g.primeira_em, EXCLUDED.primeira_em),
                 ultima_em = GREATEST(g.ultima_em, EXCLUDED.ultima_em)
               RETURNING id""",
            (cliente, chave_do_grupo(ev, gerenciador_id), ev.ocorrido_em.date(), gerenciador_id, ev.agente_id,
             ev.ip_origem, ev.nivel, severidade_do_nivel(ev.nivel), [ev.regra_id], ev.ocorrido_em, ev.ocorrido_em),
        ).fetchone()
        self.con.execute("UPDATE eventos SET grupo_id = %s WHERE id = %s", (grupo[0], novo[0]))
        return True

    def gravar_lote(self, documentos, gerenciador_id, cliente):
        """Grava sob o RLS do dono do gerenciador. Um alerta ruim não trava a fila do cliente."""
        contagem = Counter()
        with self.con.transaction():
            self.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
            for origem_id, alerta in documentos:
                try:
                    evento = normalizar(origem_id, alerta)
                except AlertaInvalido as erro:
                    self._quarentena(gerenciador_id, origem_id, str(erro), agente_do_alerta(alerta), alerta)
                    contagem["invalidos"] += 1
                    continue
                if evento.agente_id == AGENTE_DO_GERENCIADOR:
                    # Eventos do próprio gerenciador são da nossa infraestrutura, não do cliente.
                    self._quarentena(gerenciador_id, origem_id, "agente_do_gerenciador", evento.agente_id, alerta)
                    contagem["quarentena"] += 1
                    continue
                try:
                    with self.con.transaction():
                        novo = self._gravar_evento(gerenciador_id, cliente, evento)
                    contagem["novos" if novo else "repetidos"] += 1
                except psycopg.Error as erro:
                    self._quarentena(gerenciador_id, origem_id, f"erro_gravacao:{type(erro).__name__}",
                                     evento.agente_id, alerta)
                    contagem["erros"] += 1
        return contagem

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
