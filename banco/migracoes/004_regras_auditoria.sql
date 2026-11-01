-- Catálogo de regras de cada gerenciador e registro de quem viu dado bruto.
-- A tela nunca fala com o gerenciador: a ingestão sincroniza as regras para cá.

CREATE TABLE regras (
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  regra_id text NOT NULL,
  nivel smallint NOT NULL,
  descricao text,
  grupos text[] NOT NULL DEFAULT '{}',
  mitre text[] NOT NULL DEFAULT '{}',
  arquivo text,
  ativa boolean NOT NULL DEFAULT true,
  atualizado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gerenciador_id, regra_id)
);
CREATE INDEX ON regras (cliente_id, nivel DESC);
CREATE INDEX ON eventos (cliente_id, regra_id, ocorrido_em DESC);

-- Só acrescenta: nenhum papel da aplicação altera ou apaga.
CREATE TABLE auditoria (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  usuario_id uuid NOT NULL,
  acao text NOT NULL,
  alvo text NOT NULL,
  em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON auditoria (cliente_id, em DESC);

ALTER TABLE regras ENABLE ROW LEVEL SECURITY;
ALTER TABLE regras FORCE ROW LEVEL SECURITY;
ALTER TABLE auditoria ENABLE ROW LEVEL SECURITY;
ALTER TABLE auditoria FORCE ROW LEVEL SECURITY;

CREATE POLICY isolamento ON regras TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
CREATE POLICY isolamento ON auditoria TO roar_api
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());

GRANT SELECT ON regras TO roar_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON regras TO roar_ingestao;
GRANT SELECT, INSERT ON auditoria TO roar_api;
