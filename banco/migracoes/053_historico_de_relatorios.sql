-- Cada relatório gerado fica guardado para baixar de novo, até alguém apagar.
CREATE TABLE relatorios_gerados (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  tipo text NOT NULL CHECK (tipo IN ('completo', 'executivo', 'norma')),
  norma text,
  dias integer NOT NULL,
  formato text NOT NULL CHECK (formato IN ('pdf', 'json')),
  nome text NOT NULL,
  conteudo bytea NOT NULL,
  tamanho integer NOT NULL,
  sha256 text NOT NULL,
  -- Gerado por quem vê dado pessoal mascarado. O que saiu sem máscara não pode ser baixado por quem não vê o original.
  mascarado boolean NOT NULL,
  gerado_por uuid NOT NULL,
  gerado_por_nome text NOT NULL,
  gerado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON relatorios_gerados (cliente_id, gerado_em DESC);

ALTER TABLE relatorios_gerados ENABLE ROW LEVEL SECURITY;
ALTER TABLE relatorios_gerados FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON relatorios_gerados TO roar_api
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT, INSERT, DELETE ON relatorios_gerados TO roar_api;
