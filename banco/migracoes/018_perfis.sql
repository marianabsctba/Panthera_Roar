-- Perfil de cada pessoa. A permissão é checada em cada rota da API, não só escondida na tela.
ALTER TABLE usuarios ADD COLUMN perfil text NOT NULL DEFAULT 'analista_n1'
  CHECK (perfil IN ('administrador', 'engenharia', 'analista_n2', 'analista_n1', 'auditor'));
ALTER TABLE usuarios ADD COLUMN trocar_senha boolean NOT NULL DEFAULT false;

-- Quem já usava o sistema podia tudo: ninguém perde acesso ao atualizar. Novos entram com o mínimo.
UPDATE usuarios SET perfil = 'administrador';

DROP FUNCTION roar_sessao(text);
CREATE FUNCTION roar_sessao(p_token_hash text)
  RETURNS TABLE (usuario_id uuid, cliente_id uuid, nome text, cliente_nome text, fuso text, perfil text, trocar_senha boolean)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    SELECT u.id, u.cliente_id, u.nome, c.nome, c.fuso, u.perfil, u.trocar_senha
    FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id JOIN clientes c ON c.id = u.cliente_id
    WHERE s.token_hash = p_token_hash AND s.expira_em > now() AND u.ativo
  $$;
REVOKE ALL ON FUNCTION roar_sessao(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_sessao(text) TO roar_api;

-- Tudo abaixo vale só dentro do cliente da transação, e nunca devolve o hash da senha.
CREATE FUNCTION roar_listar_usuarios()
  RETURNS TABLE (id uuid, email text, nome text, perfil text, ativo boolean, criado_em timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT u.id, u.email, u.nome, u.perfil, u.ativo, u.criado_em FROM usuarios u
        WHERE u.cliente_id = roar_cliente_atual() ORDER BY u.nome $$;

CREATE FUNCTION roar_criar_usuario(p_email text, p_nome text, p_senha_hash text, p_perfil text)
  RETURNS uuid
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ INSERT INTO usuarios (cliente_id, email, nome, senha_hash, perfil, trocar_senha)
        VALUES (roar_cliente_atual(), lower(p_email), p_nome, p_senha_hash, p_perfil, true) RETURNING id $$;

-- O último administrador ativo não pode sair: o cliente ficaria sem ninguém para gerir o acesso.
-- A trava fica aqui para valer também em duas requisições ao mesmo tempo.
CREATE FUNCTION roar_alterar_usuario(p_id uuid, p_perfil text, p_ativo boolean)
  RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE
  atual record;
  outros integer;
BEGIN
  PERFORM 1 FROM usuarios WHERE cliente_id = roar_cliente_atual() AND perfil = 'administrador' FOR UPDATE;
  SELECT * INTO atual FROM usuarios WHERE id = p_id AND cliente_id = roar_cliente_atual();
  IF NOT FOUND THEN
    RETURN 'desconhecido';
  END IF;
  IF atual.perfil = 'administrador' AND atual.ativo AND (p_perfil <> 'administrador' OR NOT p_ativo) THEN
    SELECT count(*) INTO outros FROM usuarios
      WHERE cliente_id = roar_cliente_atual() AND perfil = 'administrador' AND ativo AND id <> p_id;
    IF outros = 0 THEN
      RETURN 'ultimo_administrador';
    END IF;
  END IF;
  UPDATE usuarios SET perfil = p_perfil, ativo = p_ativo WHERE id = p_id;
  -- Mudou o que a pessoa pode fazer: a sessão aberta não pode continuar com o poder antigo.
  DELETE FROM sessoes WHERE usuario_id = p_id AND (atual.perfil <> p_perfil OR NOT p_ativo);
  RETURN 'ok';
END $$;

-- Nova senha gerada por um administrador: quem recebe precisa trocar, e o que estava aberto cai.
CREATE FUNCTION roar_redefinir_senha(p_id uuid, p_senha_hash text)
  RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  UPDATE usuarios SET senha_hash = p_senha_hash, trocar_senha = true WHERE id = p_id AND cliente_id = roar_cliente_atual();
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  DELETE FROM sessoes WHERE usuario_id = p_id;
  RETURN true;
END $$;

-- A própria pessoa, já autenticada. Derruba as outras sessões dela e mantém a atual.
CREATE FUNCTION roar_trocar_minha_senha(p_id uuid, p_senha_hash text, p_token_atual text)
  RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    UPDATE usuarios SET senha_hash = p_senha_hash, trocar_senha = false WHERE id = p_id;
    DELETE FROM sessoes WHERE usuario_id = p_id AND token_hash <> p_token_atual;
  $$;

CREATE FUNCTION roar_hash_da_senha(p_id uuid)
  RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT senha_hash FROM usuarios WHERE id = p_id $$;

REVOKE ALL ON FUNCTION roar_listar_usuarios(), roar_criar_usuario(text, text, text, text), roar_alterar_usuario(uuid, text, boolean),
  roar_redefinir_senha(uuid, text), roar_trocar_minha_senha(uuid, text, text), roar_hash_da_senha(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_listar_usuarios(), roar_criar_usuario(text, text, text, text), roar_alterar_usuario(uuid, text, boolean),
  roar_redefinir_senha(uuid, text), roar_trocar_minha_senha(uuid, text, text), roar_hash_da_senha(uuid) TO roar_api;
