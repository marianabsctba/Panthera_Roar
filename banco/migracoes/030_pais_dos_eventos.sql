-- O país vem do próprio pipeline do indexador, dentro do alerta. O índice serve ao mapa e ao filtro de eventos.
CREATE INDEX eventos_pais ON eventos (cliente_id, (bruto #>> '{GeoLocation,country_name}')) WHERE bruto ? 'GeoLocation';
