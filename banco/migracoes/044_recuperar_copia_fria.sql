-- Pedidos para trazer dias da cópia fria de volta ao índice, por um prazo curto. A API registra; o serviço de organizações executa.
CREATE TABLE recuperacoes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id) ON DELETE CASCADE,
  de date NOT NULL,
  ate date NOT NULL,
  tipo text NOT NULL CHECK (tipo IN ('alertas', 'logs', 'ambos')),
  dias_de_consulta integer NOT NULL CHECK (dias_de_consulta BETWEEN 1 AND 30),
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'em_andamento', 'pronto', 'falhou', 'devolver', 'devolvido')),
  mensagem text,
  indices text[] NOT NULL DEFAULT '{}',
  pedido_por uuid NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  pronto_em timestamptz,
  expira_em timestamptz,
  CHECK (ate >= de AND ate - de < 31)
);
CREATE INDEX ON recuperacoes (cliente_id, criado_em DESC);
ALTER TABLE recuperacoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE recuperacoes FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON recuperacoes TO roar_api
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT ON recuperacoes TO roar_api;
GRANT INSERT (cliente_id, de, ate, tipo, dias_de_consulta, pedido_por) ON recuperacoes TO roar_api;
-- A tela só pode pedir para devolver antes: o resto do estado é do serviço.
GRANT UPDATE (estado) ON recuperacoes TO roar_api;
CREATE POLICY so_devolver ON recuperacoes AS RESTRICTIVE FOR UPDATE TO roar_api
  USING (estado = 'pronto') WITH CHECK (estado = 'devolver');
