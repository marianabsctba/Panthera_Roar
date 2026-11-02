-- A automação não pode ler o log bruto, que tem dado pessoal. O país ganha coluna própria, e ela só recebe isso.
DROP INDEX eventos_pais;
ALTER TABLE eventos ADD COLUMN pais text GENERATED ALWAYS AS (bruto #>> '{GeoLocation,country_name}') STORED;
CREATE INDEX eventos_pais ON eventos (cliente_id, pais) WHERE pais IS NOT NULL;
GRANT SELECT (pais) ON eventos TO roar_soar;
