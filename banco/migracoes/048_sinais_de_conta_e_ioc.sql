-- O UEBA passa a olhar a inteligência: tocar um indicador soma no risco de quem tocou.
CREATE POLICY isolamento_ueba ON intel_indicadores FOR SELECT TO roar_ueba
  USING (cliente_id = roar_cliente_atual());
GRANT SELECT (cliente_id, tipo, valor, descricao) ON intel_indicadores TO roar_ueba;

-- Quem já criou contas num ativo: criar de novo ali não é novidade.
ALTER TABLE vistos DROP CONSTRAINT vistos_dimensao_check;
ALTER TABLE vistos ADD CONSTRAINT vistos_dimensao_check CHECK (dimensao IN ('host', 'ip', 'privilegio', 'cria_conta'));
