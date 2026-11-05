-- O analista encerra o risco e diz por quê. Antes, o alerta só se encerrava sozinho, quando o risco caía.
ALTER TABLE alertas_risco
  ADD COLUMN motivo text CHECK (motivo IN ('risco_caiu', 'resolvido', 'falso_positivo', 'esperado')),
  ADD COLUMN nota text CHECK (length(nota) <= 500),
  ADD COLUMN decidido_por uuid,
  ADD COLUMN decidido_por_nome text;
UPDATE alertas_risco SET motivo = 'risco_caiu' WHERE estado = 'encerrado';

-- O que veio antes da decisão do analista não soma mais: senão o próximo evento reabriria o mesmo alerta.
ALTER TABLE entidades ADD COLUMN risco_desde timestamptz;

GRANT UPDATE (estado, encerrado_em, motivo, nota, decidido_por, decidido_por_nome) ON alertas_risco TO roar_api;
GRANT UPDATE (risco, risco_em, risco_desde) ON entidades TO roar_api;
-- "Esperado" ensina: o ativo, o IP e o privilégio do alerta passam a ser normais para a pessoa.
GRANT INSERT ON vistos TO roar_api;

-- Um tipo de sinal que não soma mais para uma pessoa, ou para todas. Ajuste de detecção: quem fez e por quê ficam.
CREATE TABLE silencios (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  entidade_id bigint,
  tipo text NOT NULL,
  motivo text NOT NULL CHECK (length(motivo) BETWEEN 1 AND 500),
  criado_por uuid,
  criado_por_nome text,
  criado_em timestamptz NOT NULL DEFAULT now(),
  expira_em timestamptz,
  FOREIGN KEY (cliente_id, entidade_id) REFERENCES entidades (cliente_id, id)
);
CREATE INDEX ON silencios (cliente_id, tipo);

-- Quem acessa os mesmos ativos. Calculado pelo UEBA de tempos em tempos.
CREATE TABLE pares (
  cliente_id uuid NOT NULL,
  entidade_id bigint NOT NULL,
  par_id bigint NOT NULL,
  semelhanca double precision NOT NULL,
  calculado_em timestamptz NOT NULL,
  PRIMARY KEY (cliente_id, entidade_id, par_id),
  FOREIGN KEY (cliente_id, entidade_id) REFERENCES entidades (cliente_id, id),
  FOREIGN KEY (cliente_id, par_id) REFERENCES entidades (cliente_id, id)
);
ALTER TABLE ueba_cursor ADD COLUMN pares_em timestamptz;

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['silencios', 'pares'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ueba
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;
GRANT SELECT, INSERT, DELETE ON silencios TO roar_api;
GRANT SELECT ON silencios TO roar_ueba;
GRANT SELECT ON pares TO roar_api;
GRANT SELECT, INSERT, DELETE ON pares TO roar_ueba;
