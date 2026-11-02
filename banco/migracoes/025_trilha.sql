-- Trilha completa: acessos, recusas e ativos, com aviso em tempo real do que pede atenção.
-- O registro vive mais que o cliente e pode não ter pessoa: quem incluiu um ativo pode ter sido o sistema.
ALTER TABLE auditoria DROP CONSTRAINT auditoria_cliente_id_fkey;
ALTER TABLE auditoria ALTER COLUMN usuario_id DROP NOT NULL;
ALTER TABLE auditoria ADD COLUMN origem text;
CREATE INDEX ON auditoria (cliente_id, acao, em DESC);

CREATE TABLE notificacoes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  tipo text NOT NULL,
  alvo text NOT NULL,
  origem text,
  contagem integer NOT NULL DEFAULT 1,
  criada_em timestamptz NOT NULL DEFAULT now(),
  atualizada_em timestamptz NOT NULL DEFAULT now(),
  lida_em timestamptz,
  lida_por uuid
);
CREATE INDEX ON notificacoes (cliente_id, atualizada_em DESC) WHERE lida_em IS NULL;
ALTER TABLE notificacoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE notificacoes FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON notificacoes TO roar_api
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT ON notificacoes TO roar_api;
GRANT UPDATE (lida_em, lida_por) ON notificacoes TO roar_api;

-- Antes do login não há cliente na sessão, por isso estas funções não dependem do RLS.
CREATE FUNCTION roar_registrar_acesso(p_usuario uuid, p_acao text, p_origem text) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo, origem)
        SELECT cliente_id, id, p_acao, email, left(p_origem, 64) FROM usuarios WHERE id = p_usuario $$;

-- Tentativas repetidas somam em um aviso só: quem erra mil vezes não enche a tela de ninguém.
CREATE FUNCTION roar_registrar_recusa_de(p_usuario uuid, p_acao text, p_origem text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE v_cliente uuid; v_email text;
BEGIN
  SELECT cliente_id, email INTO v_cliente, v_email FROM usuarios WHERE id = p_usuario;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo, origem) VALUES (v_cliente, p_usuario, p_acao, v_email, left(p_origem, 64));
  UPDATE notificacoes SET contagem = contagem + 1, atualizada_em = now(), origem = left(p_origem, 64)
    WHERE cliente_id = v_cliente AND tipo = p_acao AND alvo = v_email AND lida_em IS NULL AND atualizada_em > now() - interval '15 minutes';
  IF NOT FOUND THEN
    INSERT INTO notificacoes (cliente_id, tipo, alvo, origem) VALUES (v_cliente, p_acao, v_email, left(p_origem, 64));
  END IF;
END $$;

CREATE FUNCTION roar_registrar_recusa(p_email text, p_acao text, p_origem text) RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE v_usuario uuid;
BEGIN
  SELECT id INTO v_usuario FROM usuarios WHERE email = lower(p_email);
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  PERFORM roar_registrar_recusa_de(v_usuario, p_acao, p_origem);
  RETURN true;
END $$;

-- Ativo entra e sai pelo gerenciador, sem passar pela API: o gatilho pega qualquer caminho.
CREATE FUNCTION roar_auditar_ativo() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO auditoria (cliente_id, acao, alvo) VALUES (NEW.cliente_id, 'incluir_ativo', coalesce(NEW.nome, '') || ' (' || NEW.agente_id || ')');
    RETURN NEW;
  END IF;
  INSERT INTO auditoria (cliente_id, acao, alvo) VALUES (OLD.cliente_id, 'excluir_ativo', coalesce(OLD.nome, '') || ' (' || OLD.agente_id || ')');
  RETURN OLD;
END $$;
CREATE TRIGGER auditar_ativo AFTER INSERT OR DELETE ON ativos FOR EACH ROW EXECUTE FUNCTION roar_auditar_ativo();

DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY['roar_registrar_acesso(uuid, text, text)', 'roar_registrar_recusa_de(uuid, text, text)', 'roar_registrar_recusa(text, text, text)'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO roar_api', f);
  END LOOP;
END $$;
