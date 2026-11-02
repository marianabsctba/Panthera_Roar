-- Operadora e rede de origem, do mesmo pipeline que dá país e cidade.
-- Fica como texto: vem do alerta, e uma conversão que falhasse impediria a gravação do evento.
ALTER TABLE eventos ADD COLUMN operadora text GENERATED ALWAYS AS (bruto #>> '{Operadora,organization_name}') STORED;
ALTER TABLE eventos ADD COLUMN asn text GENERATED ALWAYS AS (bruto #>> '{Operadora,asn}') STORED;
CREATE INDEX eventos_operadora ON eventos (cliente_id, operadora) WHERE operadora IS NOT NULL;
