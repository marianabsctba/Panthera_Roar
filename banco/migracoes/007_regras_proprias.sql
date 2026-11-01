-- Condições de cada regra do catálogo e regras criadas pelo próprio cliente.
ALTER TABLE regras ADD COLUMN detalhes jsonb NOT NULL DEFAULT '{}';

CREATE TABLE regras_proprias (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  titulo text NOT NULL,
  formato text NOT NULL CHECK (formato IN ('sigma', 'guiada')),
  origem text NOT NULL,
  xml_regras text NOT NULL DEFAULT '',
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'ativa', 'recusada', 'desativada')),
  mensagem text,
  criada_por uuid NOT NULL,
  criada_em timestamptz NOT NULL DEFAULT now(),
  aplicada_em timestamptz
);
CREATE INDEX ON regras_proprias (cliente_id, criada_em DESC);
CREATE INDEX ON regras_proprias (estado);

ALTER TABLE regras_proprias ENABLE ROW LEVEL SECURITY;
ALTER TABLE regras_proprias FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON regras_proprias TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT, INSERT ON regras_proprias TO roar_api;
GRANT UPDATE (estado, mensagem) ON regras_proprias TO roar_api;
GRANT SELECT, UPDATE ON regras_proprias TO roar_ingestao;
