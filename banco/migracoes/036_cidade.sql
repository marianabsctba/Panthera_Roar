-- Cidade e estado prováveis do endereço, do mesmo pipeline que dá o país.
-- A automação não recebe: nenhum playbook decide por cidade, e o dado aponta mais perto de uma pessoa do que o país.
ALTER TABLE eventos ADD COLUMN cidade text GENERATED ALWAYS AS (bruto #>> '{GeoLocation,city_name}') STORED;
ALTER TABLE eventos ADD COLUMN regiao text GENERATED ALWAYS AS (bruto #>> '{GeoLocation,region_name}') STORED;
CREATE INDEX eventos_cidade ON eventos (cliente_id, pais, cidade) WHERE pais IS NOT NULL;
