-- Quanto tempo cada organização guarda, e se guarda o log bruto. Quem aplica no indexador e no gerenciador é o serviço de fontes.
ALTER TABLE clientes
  ADD COLUMN retencao_alertas_dias integer NOT NULL DEFAULT 180 CHECK (retencao_alertas_dias BETWEEN 30 AND 3650),
  ADD COLUMN retencao_logs_dias integer NOT NULL DEFAULT 180 CHECK (retencao_logs_dias BETWEEN 7 AND 3650),
  ADD COLUMN guardar_logs boolean NOT NULL DEFAULT true,
  -- Começa pendente: cada gerenciador já existente passa para a política própria na primeira volta do serviço.
  ADD COLUMN armazenamento_estado text NOT NULL DEFAULT 'pendente' CHECK (armazenamento_estado IN ('pendente', 'aplicado', 'falhou')),
  ADD COLUMN armazenamento_mensagem text;

GRANT SELECT (retencao_alertas_dias, retencao_logs_dias, guardar_logs, armazenamento_estado, armazenamento_mensagem) ON clientes TO roar_ingestao;
GRANT UPDATE (armazenamento_estado, armazenamento_mensagem) ON clientes TO roar_ingestao;
CREATE POLICY marcar_armazenamento ON clientes FOR UPDATE TO roar_ingestao USING (true) WITH CHECK (true);

CREATE FUNCTION roar_definir_armazenamento(p_alertas integer, p_logs integer, p_guardar boolean)
  RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ UPDATE clientes SET retencao_alertas_dias = p_alertas, retencao_logs_dias = p_logs, guardar_logs = p_guardar,
                            armazenamento_estado = 'pendente', armazenamento_mensagem = NULL
        WHERE id = roar_cliente_atual() $$;
REVOKE ALL ON FUNCTION roar_definir_armazenamento(integer, integer, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_definir_armazenamento(integer, integer, boolean) TO roar_api;
