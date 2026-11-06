-- Para onde o nome aponta (CNAME), conferido a cada vez: nome que aponta para serviço de nuvem apagado pode ser tomado.
ALTER TABLE superficie_hosts ADD COLUMN cname text;

-- O que mudou na superfície entre uma conferência e outra: nome novo, porta que abriu, certificado trocado.
-- A primeira conferência não gera mudança: tudo seria novo.
CREATE TABLE superficie_mudancas (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  dominio_id bigint NOT NULL REFERENCES superficie_dominios (id) ON DELETE CASCADE,
  nome text NOT NULL,
  tipo text NOT NULL CHECK (tipo IN ('nome_novo', 'nome_sumiu', 'porta_abriu', 'porta_fechou', 'certificado_trocou', 'servico_mudou', 'cname_mudou')),
  detalhe text NOT NULL,
  em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON superficie_mudancas (dominio_id, em DESC);
ALTER TABLE superficie_mudancas ENABLE ROW LEVEL SECURITY;
ALTER TABLE superficie_mudancas FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON superficie_mudancas TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual()) WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT ON superficie_mudancas TO roar_api;
GRANT SELECT, INSERT, DELETE ON superficie_mudancas TO roar_ingestao;
