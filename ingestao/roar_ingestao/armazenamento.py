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
               ON CONFLICT (cliente_id, origem, origem_id, ocorrido_em) DO NOTHING
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
        self.con.execute("UPDATE eventos SET grupo_id = %s WHERE id = %s AND ocorrido_em = %s", (grupo[0], novo[0], ev.ocorrido_em))
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

    def gravar_em_lote(self, documentos, gerenciador_id, cliente):
        """O mesmo que gravar_lote, em três comandos por lote em vez de três por alerta: os eventos, os grupos (somados no
        lote) e a ligação de cada evento ao seu grupo. Se o lote der erro, cai no caminho de um por um, que isola o
        alerta ruim na quarentena."""
        contagem, eventos, separados = Counter(), [], []
        for origem_id, alerta in documentos:
            try:
                evento = normalizar(origem_id, alerta)
            except AlertaInvalido as erro:
                separados.append((origem_id, str(erro), agente_do_alerta(alerta), alerta))
                contagem["invalidos"] += 1
                continue
            if evento.agente_id == AGENTE_DO_GERENCIADOR:
                separados.append((origem_id, "agente_do_gerenciador", evento.agente_id, alerta))
                contagem["quarentena"] += 1
                continue
            eventos.append(evento)
        try:
            with self.con.transaction():
                self.con.execute("SELECT set_config('roar.cliente', %s, true)", (str(cliente),))
                for origem_id, motivo, agente_id, alerta in separados:
                    self._quarentena(gerenciador_id, origem_id, motivo, agente_id, alerta)
                novos = self._inserir_eventos(gerenciador_id, cliente, eventos) if eventos else []
        except psycopg.Error:
            return self.gravar_lote(documentos, gerenciador_id, cliente)
        contagem["novos"] += len(novos)
        contagem["repetidos"] += len(eventos) - len(novos)
        return contagem

    def _inserir_eventos(self, gerenciador_id, cliente, eventos):
        linhas = [{"cliente_id": str(cliente), "gerenciador_id": gerenciador_id, "origem": self.origem, "origem_id": ev.origem_id,
                   "ocorrido_em": ev.ocorrido_em.isoformat(), "nivel": ev.nivel, "severidade": ev.severidade, "regra_id": ev.regra_id,
                   "regra_descricao": ev.regra_descricao, "regra_grupos": ev.regra_grupos, "mitre": ev.mitre, "agente_id": ev.agente_id,
                   "agente_nome": ev.agente_nome, "ip_origem": ev.ip_origem, "usuario": ev.usuario, "bruto": ev.bruto} for ev in eventos]
        novos = self.con.execute(
            """INSERT INTO eventos (cliente_id, gerenciador_id, origem, origem_id, ocorrido_em, nivel, severidade, regra_id, regra_descricao,
                                    regra_grupos, mitre, agente_id, agente_nome, ip_origem, usuario, bruto)
               SELECT * FROM jsonb_to_recordset(%s) AS x(cliente_id uuid, gerenciador_id text, origem text, origem_id text, ocorrido_em timestamptz,
                    nivel smallint, severidade text, regra_id text, regra_descricao text, regra_grupos text[], mitre text[], agente_id text,
                    agente_nome text, ip_origem inet, usuario text, bruto jsonb)
               ON CONFLICT (cliente_id, origem, origem_id, ocorrido_em) DO NOTHING
               RETURNING id, origem_id, ocorrido_em""", (Jsonb(linhas),)).fetchall()
        if not novos:
            return []
        # Os grupos contam só o que é inédito, somados no lote; a severidade do grupo é a maior já vista.
        por_origem = {(ev.origem_id, ev.ocorrido_em): ev for ev in eventos}
        grupos, chave_do_evento = {}, []
        for evento_id, origem_id, ocorrido_em in novos:
            ev = por_origem[(origem_id, ocorrido_em)]
            chave = chave_do_grupo(ev, gerenciador_id)
            chave_do_evento.append((evento_id, ocorrido_em, chave))
            g = grupos.get(chave)
            if g is None:
                grupos[chave] = {"chave": chave, "dia": ev.ocorrido_em.date().isoformat(), "agente_id": ev.agente_id, "ip_origem": ev.ip_origem,
                                 "nivel": ev.nivel, "regras": {ev.regra_id}, "primeira_em": ev.ocorrido_em, "ultima_em": ev.ocorrido_em, "total": 1}
                continue
            g["total"] += 1
            g["nivel"] = max(g["nivel"], ev.nivel)
            g["regras"].add(ev.regra_id)
            g["primeira_em"], g["ultima_em"] = min(g["primeira_em"], ev.ocorrido_em), max(g["ultima_em"], ev.ocorrido_em)
        dados = [{**g, "cliente_id": str(cliente), "gerenciador_id": gerenciador_id, "severidade": severidade_do_nivel(g["nivel"]),
                  "regras": sorted(g["regras"]), "primeira_em": g["primeira_em"].isoformat(), "ultima_em": g["ultima_em"].isoformat()} for g in grupos.values()]
        ids = dict(self.con.execute(
            """INSERT INTO grupos_alerta AS g (cliente_id, chave, dia, gerenciador_id, agente_id, ip_origem, nivel, severidade, regras, primeira_em, ultima_em, total)
               SELECT * FROM jsonb_to_recordset(%s) AS x(cliente_id uuid, chave text, dia date, gerenciador_id text, agente_id text, ip_origem inet,
                    nivel smallint, severidade text, regras text[], primeira_em timestamptz, ultima_em timestamptz, total bigint)
               ON CONFLICT (cliente_id, chave) DO UPDATE SET
                 total = g.total + EXCLUDED.total,
                 nivel = GREATEST(g.nivel, EXCLUDED.nivel),
                 severidade = CASE WHEN EXCLUDED.nivel > g.nivel THEN EXCLUDED.severidade ELSE g.severidade END,
                 regras = ARRAY(SELECT DISTINCT unnest(g.regras || EXCLUDED.regras) ORDER BY 1),
                 primeira_em = LEAST(g.primeira_em, EXCLUDED.primeira_em),
                 ultima_em = GREATEST(g.ultima_em, EXCLUDED.ultima_em)
               RETURNING chave, id""", (Jsonb(dados),)).fetchall())
        self.con.execute(
            """UPDATE eventos e SET grupo_id = x.grupo FROM jsonb_to_recordset(%s) AS x(id bigint, ocorrido_em timestamptz, grupo bigint)
               WHERE e.id = x.id AND e.ocorrido_em = x.ocorrido_em""",
            (Jsonb([{"id": i, "ocorrido_em": o.isoformat(), "grupo": ids[c]} for i, o, c in chave_do_evento]),))
        return novos

    def manter_dias(self, dias_guardados):
        """Cria os dias seguintes da tabela de alertas e descarta os que venceram."""
        with self.con.transaction():
            return self.con.execute("SELECT roar_manter_dias_de_eventos(%s)", (int(dias_guardados),)).fetchone()[0]

    def ler_posicao(self, fonte):
        with self.con.transaction():
            linha = self.con.execute("SELECT ocorrido_em, posicao FROM checkpoints WHERE fonte = %s", (fonte,)).fetchone()
        return (linha[0], linha[1]) if linha else None

    def gravar_posicao(self, fonte, momento, posicao):
        """Posição de quem lê do armazém de eventos: (recebido_em, id) do último lido. Sempre a última, sem GREATEST."""
        with self.con.transaction():
            self.con.execute(
                """INSERT INTO checkpoints (fonte, ocorrido_em, posicao) VALUES (%s, %s, %s)
                   ON CONFLICT (fonte) DO UPDATE SET ocorrido_em = EXCLUDED.ocorrido_em, posicao = EXCLUDED.posicao, atualizado_em = now()""",
                (fonte, momento, posicao))

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
