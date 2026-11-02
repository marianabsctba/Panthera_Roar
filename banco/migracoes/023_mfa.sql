-- Segundo fator por aplicativo autenticador. O segredo fica cifrado, e os códigos de recuperação só em hash.
ALTER TABLE usuarios ADD COLUMN mfa_selado bytea;
ALTER TABLE usuarios ADD COLUMN mfa_ativo boolean NOT NULL DEFAULT false;
ALTER TABLE usuarios ADD COLUMN mfa_ultimo_passo bigint NOT NULL DEFAULT 0;
ALTER TABLE clientes ADD COLUMN mfa_obrigatorio boolean NOT NULL DEFAULT false;
-- Sessão de quem passou da senha, mas ainda não do segundo fator: não vê nada até confirmar.
ALTER TABLE sessoes ADD COLUMN mfa_pendente boolean NOT NULL DEFAULT false;

CREATE TABLE mfa_recuperacao (
  usuario_id uuid NOT NULL REFERENCES usuarios (id) ON DELETE CASCADE,
  codigo_hash text NOT NULL,
  usado_em timestamptz,
  PRIMARY KEY (usuario_id, codigo_hash)
);
REVOKE ALL ON mfa_recuperacao FROM PUBLIC;

DROP FUNCTION roar_sessao(text);
CREATE FUNCTION roar_sessao(p_token_hash text)
  RETURNS TABLE (usuario_id uuid, cliente_id uuid, nome text, cliente_nome text, fuso text, perfil text, trocar_senha boolean,
                 mfa_pendente boolean, mfa_ativo boolean, mfa_obrigatorio boolean)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    SELECT u.id, u.cliente_id, u.nome, c.nome, c.fuso, u.perfil, u.trocar_senha, s.mfa_pendente, u.mfa_ativo, c.mfa_obrigatorio
    FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id JOIN clientes c ON c.id = u.cliente_id
    WHERE s.token_hash = p_token_hash AND s.expira_em > now() AND u.ativo
  $$;

CREATE FUNCTION roar_mfa_ativo(p_usuario uuid) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT mfa_ativo FROM usuarios WHERE id = p_usuario $$;

CREATE FUNCTION roar_criar_sessao_mfa(p_token_hash text, p_usuario uuid, p_minutos integer) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    DELETE FROM sessoes WHERE expira_em < now();
    INSERT INTO sessoes (token_hash, usuario_id, expira_em, mfa_pendente)
    VALUES (p_token_hash, p_usuario, now() + make_interval(mins => p_minutos), true);
  $$;

CREATE FUNCTION roar_concluir_mfa(p_token_hash text, p_horas integer) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ UPDATE sessoes SET mfa_pendente = false, expira_em = now() + make_interval(hours => p_horas) WHERE token_hash = p_token_hash $$;

CREATE FUNCTION roar_mfa_segredo(p_usuario uuid) RETURNS bytea
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT mfa_selado FROM usuarios WHERE id = p_usuario $$;

CREATE FUNCTION roar_mfa_guardar(p_usuario uuid, p_selado bytea) RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  UPDATE usuarios SET mfa_selado = p_selado WHERE id = p_usuario AND NOT mfa_ativo;
  RETURN FOUND;
END $$;

-- Só um uso por passo de tempo: um código visto por alguém não entra de novo. A trava vale para dois pedidos juntos.
CREATE FUNCTION roar_mfa_usar_passo(p_usuario uuid, p_passo bigint) RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  UPDATE usuarios SET mfa_ultimo_passo = p_passo WHERE id = p_usuario AND mfa_ultimo_passo < p_passo;
  RETURN FOUND;
END $$;

CREATE FUNCTION roar_mfa_ativar(p_usuario uuid, p_hashes text[]) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    DELETE FROM mfa_recuperacao WHERE usuario_id = p_usuario;
    INSERT INTO mfa_recuperacao (usuario_id, codigo_hash) SELECT p_usuario, h FROM unnest(p_hashes) AS h;
    UPDATE usuarios SET mfa_ativo = true WHERE id = p_usuario;
  $$;

CREATE FUNCTION roar_mfa_usar_recuperacao(p_usuario uuid, p_hash text) RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  UPDATE mfa_recuperacao SET usado_em = now() WHERE usuario_id = p_usuario AND codigo_hash = p_hash AND usado_em IS NULL;
  RETURN FOUND;
END $$;

CREATE FUNCTION roar_mfa_codigos_restantes(p_usuario uuid) RETURNS bigint
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT count(*) FROM mfa_recuperacao WHERE usuario_id = p_usuario AND usado_em IS NULL $$;

CREATE FUNCTION roar_mfa_desligar(p_usuario uuid) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    DELETE FROM mfa_recuperacao WHERE usuario_id = p_usuario;
    UPDATE usuarios SET mfa_ativo = false, mfa_selado = NULL WHERE id = p_usuario;
  $$;

-- Quem perdeu o celular: outra pessoa administradora do mesmo cliente tira, e as sessões da pessoa caem.
CREATE FUNCTION roar_mfa_remover_de(p_usuario uuid) RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  PERFORM 1 FROM usuarios WHERE id = p_usuario AND cliente_id = roar_cliente_atual();
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  DELETE FROM mfa_recuperacao WHERE usuario_id = p_usuario;
  UPDATE usuarios SET mfa_ativo = false, mfa_selado = NULL WHERE id = p_usuario;
  DELETE FROM sessoes WHERE usuario_id = p_usuario;
  RETURN true;
END $$;

CREATE FUNCTION roar_definir_mfa_obrigatorio(p_valor boolean) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ UPDATE clientes SET mfa_obrigatorio = p_valor WHERE id = roar_cliente_atual() $$;

DROP FUNCTION roar_listar_usuarios();
CREATE FUNCTION roar_listar_usuarios()
  RETURNS TABLE (id uuid, email text, nome text, perfil text, ativo boolean, criado_em timestamptz, mfa_ativo boolean)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT u.id, u.email, u.nome, u.perfil, u.ativo, u.criado_em, u.mfa_ativo FROM usuarios u
        WHERE u.cliente_id = roar_cliente_atual() ORDER BY u.nome $$;

DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY['roar_sessao(text)', 'roar_mfa_ativo(uuid)', 'roar_criar_sessao_mfa(text, uuid, integer)', 'roar_concluir_mfa(text, integer)', 'roar_mfa_segredo(uuid)',
                           'roar_mfa_guardar(uuid, bytea)', 'roar_mfa_usar_passo(uuid, bigint)', 'roar_mfa_ativar(uuid, text[])', 'roar_mfa_usar_recuperacao(uuid, text)',
                           'roar_mfa_codigos_restantes(uuid)', 'roar_mfa_desligar(uuid)', 'roar_mfa_remover_de(uuid)', 'roar_definir_mfa_obrigatorio(boolean)', 'roar_listar_usuarios()'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO roar_api', f);
  END LOOP;
END $$;
