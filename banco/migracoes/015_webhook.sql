-- Webhook de entrada. O token só existe em hash, e o cliente de cada mensagem vem dele, nunca do conteúdo.
ALTER TABLE fontes DROP CONSTRAINT fontes_tipo_check;
ALTER TABLE fontes ADD CONSTRAINT fontes_tipo_check CHECK (tipo IN ('syslog', 'github', 'office365', 'webhook'));
ALTER TABLE fontes ADD COLUMN token_hash text UNIQUE;
ALTER TABLE fontes ADD COLUMN ultimo_dado_em timestamptz;

CREATE TABLE entrada_webhook (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  fonte_id bigint NOT NULL REFERENCES fontes (id),
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  corpo text NOT NULL,
  recebido_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON entrada_webhook (fonte_id);
CREATE INDEX ON entrada_webhook (gerenciador_id, id);

ALTER TABLE entrada_webhook ENABLE ROW LEVEL SECURITY;
ALTER TABLE entrada_webhook FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON entrada_webhook TO roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT, DELETE ON entrada_webhook TO roar_ingestao;

-- Quem chama não tem sessão, então não há cliente para o RLS: esta função é o único caminho,
-- e só aceita um token válido. A API não lê a fila nem escreve nela de outro jeito.
CREATE FUNCTION roar_receber_webhook(p_token_hash text, p_corpos text[], p_limite integer) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
  AS $$
DECLARE
  f record;
  pendentes integer;
BEGIN
  SELECT id, cliente_id, gerenciador_id INTO f FROM fontes
    WHERE token_hash = p_token_hash AND tipo = 'webhook' AND estado = 'ativa';
  IF NOT FOUND THEN
    RETURN 'desconhecida';
  END IF;
  SELECT count(*) INTO pendentes FROM entrada_webhook WHERE fonte_id = f.id;
  IF pendentes + coalesce(array_length(p_corpos, 1), 0) > p_limite THEN
    RETURN 'cheia';
  END IF;
  INSERT INTO entrada_webhook (cliente_id, fonte_id, gerenciador_id, corpo)
    SELECT f.cliente_id, f.id, f.gerenciador_id, c FROM unnest(p_corpos) AS c;
  UPDATE fontes SET ultimo_dado_em = now() WHERE id = f.id;
  RETURN 'ok';
END $$;
REVOKE ALL ON FUNCTION roar_receber_webhook(text, text[], integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_receber_webhook(text, text[], integer) TO roar_api;
