-- Fontes de dados de cada cliente. Quem aplica no gerenciador é a ingestão; a API só registra o pedido.

CREATE TABLE fontes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  tipo text NOT NULL CHECK (tipo IN ('syslog')),
  nome text NOT NULL,
  -- Nunca guarda segredo: só o que a tela pode mostrar de volta.
  config jsonb NOT NULL,
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'ativa', 'recusada', 'desativada')),
  mensagem text,
  criada_por uuid NOT NULL,
  criada_em timestamptz NOT NULL DEFAULT now(),
  aplicada_em timestamptz
);
CREATE INDEX ON fontes (cliente_id, estado);

-- Fica fora de gerenciadores porque o motor e a ingestão leem aquela tabela e não precisam disto.
CREATE TABLE inscricao_de_agentes (
  gerenciador_id text PRIMARY KEY REFERENCES gerenciadores (id),
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  senha text NOT NULL
);

ALTER TABLE fontes ENABLE ROW LEVEL SECURITY;
ALTER TABLE fontes FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON fontes TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
ALTER TABLE inscricao_de_agentes ENABLE ROW LEVEL SECURITY;
ALTER TABLE inscricao_de_agentes FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON inscricao_de_agentes FOR SELECT TO roar_api USING (cliente_id = roar_cliente_atual());

GRANT SELECT, INSERT ON fontes TO roar_api;
GRANT UPDATE (estado) ON fontes TO roar_api;
GRANT SELECT ON fontes TO roar_ingestao;
GRANT UPDATE (estado, mensagem, aplicada_em) ON fontes TO roar_ingestao;
GRANT SELECT ON inscricao_de_agentes TO roar_api;
