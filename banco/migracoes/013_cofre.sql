-- Credenciais dos clientes, cifradas com a chave pública do cofre. A chave privada nunca vem ao banco.
CREATE TABLE segredos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  nome text NOT NULL,
  selado bytea NOT NULL,
  criado_por uuid NOT NULL,
  atualizado_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cliente_id, nome)
);

ALTER TABLE segredos ENABLE ROW LEVEL SECURITY;
ALTER TABLE segredos FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON segredos TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());

-- A API grava e troca, mas não lê o valor. A tela só mostra que a credencial existe e quando mudou.
GRANT SELECT (id, cliente_id, nome, atualizado_em) ON segredos TO roar_api;
GRANT INSERT, DELETE ON segredos TO roar_api;
GRANT UPDATE (selado, criado_por, atualizado_em) ON segredos TO roar_api;
GRANT SELECT ON segredos TO roar_ingestao;
