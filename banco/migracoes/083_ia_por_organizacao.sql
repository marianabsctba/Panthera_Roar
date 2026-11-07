-- IA local (roar_api.parecer): cada organização liga ou desliga, e escolhe a partir de que nível a IA dá o parecer
-- sozinha (roar_api.ia_automatica). O modelo é da instalação inteira.
ALTER TABLE clientes ADD COLUMN ia_ligada boolean NOT NULL DEFAULT true;
ALTER TABLE clientes ADD COLUMN ia_automatico_nivel smallint CHECK (ia_automatico_nivel BETWEEN 3 AND 15);
-- Desde quando o automático vale: ligar não manda a IA ler o passado inteiro.
ALTER TABLE clientes ADD COLUMN ia_automatico_desde timestamptz;
GRANT SELECT (ia_ligada, ia_automatico_nivel) ON clientes TO roar_api;

CREATE FUNCTION roar_definir_ia(p_ligada boolean, p_nivel smallint) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ UPDATE clientes SET ia_ligada = p_ligada,
                            ia_automatico_nivel = CASE WHEN p_ligada THEN p_nivel END,
                            ia_automatico_desde = CASE WHEN p_ligada AND p_nivel IS NOT NULL
                                                       THEN coalesce(CASE WHEN ia_automatico_nivel IS NOT NULL THEN ia_automatico_desde END, now()) END
         WHERE id = roar_cliente_atual() $$;
REVOKE ALL ON FUNCTION roar_definir_ia(boolean, smallint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_definir_ia(boolean, smallint) TO roar_api;

-- O serviço do parecer automático passa por todas as organizações: leva só o id, o nível e desde quando.
CREATE FUNCTION roar_ia_automatica() RETURNS TABLE (cliente_id uuid, nivel smallint, desde timestamptz)
  LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public, pg_temp
  AS $$ SELECT id, ia_automatico_nivel, ia_automatico_desde FROM clientes WHERE ia_ligada AND ia_automatico_nivel IS NOT NULL $$;
REVOKE ALL ON FUNCTION roar_ia_automatica() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_ia_automatica() TO roar_api;

-- O modelo da instalação, escolhido na tela entre os que o Ollama já tem. Vazio, vale o IA_MODELO do .env.
CREATE TABLE ia_instalacao (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  modelo text,
  alterado_em timestamptz,
  alterado_por uuid
);
INSERT INTO ia_instalacao DEFAULT VALUES;
GRANT SELECT, UPDATE (modelo, alterado_em, alterado_por) ON ia_instalacao TO roar_api;
