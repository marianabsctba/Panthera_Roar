-- Quanto um ativo importa: o mesmo sinal pesa mais no servidor de folha de pagamento do que numa estação de teste.
ALTER TABLE ativos ADD COLUMN criticidade text NOT NULL DEFAULT 'normal'
  CHECK (criticidade IN ('baixa', 'normal', 'alta', 'critica'));
GRANT UPDATE (criticidade) ON ativos TO roar_api;

CREATE POLICY isolamento_ueba ON ativos FOR SELECT TO roar_ueba
  USING (cliente_id = roar_cliente_atual());
GRANT SELECT (cliente_id, gerenciador_id, agente_id, criticidade) ON ativos TO roar_ueba;
