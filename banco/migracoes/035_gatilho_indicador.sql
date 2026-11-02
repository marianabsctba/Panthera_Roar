-- Playbook que dispara quando um evento bate com um indicador de ameaça.
-- É um gatilho próprio, e não uma condição: o evento chega antes de a inteligência olhar para ele.
ALTER TABLE intel_ocorrencias ADD COLUMN id bigint GENERATED ALWAYS AS IDENTITY;
CREATE INDEX ON intel_ocorrencias (cliente_id, id);

ALTER TABLE soar_cursor ADD COLUMN ultima_ocorrencia bigint;

ALTER TABLE execucoes DROP CONSTRAINT execucoes_origem_tipo_check;
ALTER TABLE execucoes ADD CONSTRAINT execucoes_origem_tipo_check CHECK (origem_tipo IN ('risco', 'evento', 'indicador'));

CREATE POLICY leitura_soar ON intel_ocorrencias FOR SELECT TO roar_soar USING (cliente_id = roar_cliente_atual());
CREATE POLICY leitura_soar ON intel_indicadores FOR SELECT TO roar_soar USING (cliente_id = roar_cliente_atual());
GRANT SELECT (id, indicador_id, evento_id, cliente_id, encontrada_em, no_passado) ON intel_ocorrencias TO roar_soar;
GRANT SELECT (id, cliente_id, tipo, valor) ON intel_indicadores TO roar_soar;
