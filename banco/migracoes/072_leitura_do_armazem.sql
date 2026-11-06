-- Durante a migração para o armazém de eventos (docs/clickhouse.md), cada organização escolhe de onde a tela de logs, os
-- painéis e as buscas agendadas leem. Os dois lados recebem os mesmos logs, então trocar não perde nada e pode voltar.
ALTER TABLE clientes ADD COLUMN ler_do_armazem boolean NOT NULL DEFAULT false;
GRANT SELECT (ler_do_armazem) ON clientes TO roar_api, roar_ingestao;

CREATE FUNCTION roar_definir_leitura_do_armazem(p_ler boolean) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ UPDATE clientes SET ler_do_armazem = p_ler WHERE id = roar_cliente_atual() $$;
REVOKE ALL ON FUNCTION roar_definir_leitura_do_armazem(boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_definir_leitura_do_armazem(boolean) TO roar_api;
