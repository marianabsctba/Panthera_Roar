-- Regras YARA de cada cliente. Quem varre é o agente, sobre o arquivo que a integridade viu mudar.
CREATE TABLE yara_regras (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id) ON DELETE CASCADE,
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id) ON DELETE CASCADE,
  nome text NOT NULL,
  fonte text NOT NULL,
  identificadores text[] NOT NULL,
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'ativa', 'recusada', 'desativada')),
  mensagem text,
  criado_por uuid NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ON yara_regras (gerenciador_id, nome) WHERE estado <> 'desativada';
CREATE INDEX ON yara_regras (cliente_id, estado);

ALTER TABLE yara_regras ENABLE ROW LEVEL SECURITY;
ALTER TABLE yara_regras FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON yara_regras TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());

GRANT SELECT, INSERT ON yara_regras TO roar_api;
GRANT UPDATE (estado) ON yara_regras TO roar_api;
GRANT SELECT ON yara_regras TO roar_ingestao;
GRANT UPDATE (estado, mensagem) ON yara_regras TO roar_ingestao;
