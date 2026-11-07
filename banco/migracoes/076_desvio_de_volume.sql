-- Desvio de volume (roar_ingestao.coletor_syslog): com ele ligado, o tráfego permitido dos firewalls conhecidos vai do
-- coletor direto ao armazém, sem passar pelo gerenciador. Começa desligado: uma regra própria sobre tráfego permitido
-- deixa de disparar com ele ligado.
ALTER TABLE clientes ADD COLUMN desvio_de_volume boolean NOT NULL DEFAULT false;
GRANT SELECT (desvio_de_volume) ON clientes TO roar_api, roar_ingestao;

CREATE FUNCTION roar_definir_desvio_de_volume(p_desviar boolean) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ UPDATE clientes SET desvio_de_volume = p_desviar WHERE id = roar_cliente_atual() $$;
REVOKE ALL ON FUNCTION roar_definir_desvio_de_volume(boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_definir_desvio_de_volume(boolean) TO roar_api;
