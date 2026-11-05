-- Lista manual: indicadores que o analista caçou e quer continuar vigiando, sem fonte externa.
ALTER TABLE intel_fontes DROP CONSTRAINT intel_fontes_tipo_check;
ALTER TABLE intel_fontes ADD CONSTRAINT intel_fontes_tipo_check CHECK (tipo IN ('misp', 'taxii', 'manual'));
CREATE UNIQUE INDEX ON intel_fontes (cliente_id) WHERE tipo = 'manual';

GRANT INSERT ON intel_indicadores TO roar_api;
GRANT UPDATE (ultima_vez, descricao) ON intel_indicadores TO roar_api;
