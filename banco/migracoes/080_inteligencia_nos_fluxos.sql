-- Indicadores de ameaça nos fluxos de rede (roar_ingestao.inteligencia.buscar_nos_fluxos). Os fluxos ficam no armazém de
-- eventos e podem ser milhões: o achado é resumido por indicador, endereço da rede e dia, com quantos fluxos e bytes.
CREATE TABLE intel_fluxos (
  cliente_id uuid NOT NULL,
  indicador_id bigint NOT NULL REFERENCES intel_indicadores (id) ON DELETE CASCADE,
  dia date NOT NULL,
  -- O outro lado da conversa: o endereço da rede que falou com o indicador.
  interno text NOT NULL,
  -- saida: a rede chamou o indicador; entrada: o indicador chamou a rede.
  sentido text NOT NULL CHECK (sentido IN ('saida', 'entrada')),
  fluxos bigint NOT NULL,
  bytes bigint NOT NULL,
  primeira timestamptz NOT NULL,
  ultima timestamptz NOT NULL,
  exportador text NOT NULL,
  -- Achado olhando para trás: o indicador chegou depois do fluxo.
  no_passado boolean NOT NULL DEFAULT false,
  PRIMARY KEY (indicador_id, dia, interno, sentido)
);
CREATE INDEX ON intel_fluxos (cliente_id, ultima DESC);

-- Até que hora de chegada ao armazém os fluxos já foram conferidos.
CREATE TABLE intel_cursor_fluxos (
  cliente_id uuid PRIMARY KEY,
  ate timestamptz NOT NULL
);

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['intel_fluxos', 'intel_cursor_fluxos'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ingestao
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

GRANT SELECT ON intel_fluxos TO roar_api;
GRANT SELECT, INSERT, UPDATE ON intel_fluxos, intel_cursor_fluxos TO roar_ingestao;
