-- Prazo para corrigir, em dias desde que a falha foi vista, por severidade. Falha já explorada por atacantes
-- tem um prazo próprio, que vale quando é menor. Sem linha aqui, valem os prazos padrão (api/roar_api/correcao.py).
CREATE TABLE vuln_prazos (
  cliente_id uuid PRIMARY KEY REFERENCES clientes (id) ON DELETE CASCADE,
  critica integer NOT NULL CHECK (critica BETWEEN 1 AND 730),
  alta integer NOT NULL CHECK (alta BETWEEN 1 AND 730),
  media integer NOT NULL CHECK (media BETWEEN 1 AND 730),
  baixa integer NOT NULL CHECK (baixa BETWEEN 1 AND 730),
  explorada integer NOT NULL CHECK (explorada BETWEEN 1 AND 730),
  definido_por uuid,
  definido_em timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE vuln_prazos ENABLE ROW LEVEL SECURITY;
ALTER TABLE vuln_prazos FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON vuln_prazos TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT, INSERT, UPDATE ON vuln_prazos TO roar_api;
GRANT SELECT ON vuln_prazos TO roar_ingestao;
