-- Quem administra a instalação atua dentro de outra organização. Vale só para a sessão, e a função que escolhe é a única porta.
ALTER TABLE sessoes ADD COLUMN cliente_em_uso uuid REFERENCES clientes (id) ON DELETE SET NULL;

-- O autenticador segue a regra da organização de origem: é lá que a conta nasceu.
-- Perdeu o poder de plataforma, a sessão volta sozinha para a organização de origem.
DROP FUNCTION roar_sessao(text);
CREATE FUNCTION roar_sessao(p_token_hash text)
  RETURNS TABLE (usuario_id uuid, cliente_id uuid, nome text, cliente_nome text, fuso text, perfil text, trocar_senha boolean,
                 mfa_pendente boolean, mfa_ativo boolean, mfa_obrigatorio boolean, cliente_proprio uuid, cliente_proprio_nome text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    SELECT u.id, coalesce(t.id, u.cliente_id), u.nome, coalesce(t.nome, c.nome), coalesce(t.fuso, c.fuso), u.perfil, u.trocar_senha,
           s.mfa_pendente, u.mfa_ativo, c.mfa_obrigatorio, u.cliente_id, c.nome
    FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id JOIN clientes c ON c.id = u.cliente_id
    LEFT JOIN clientes t ON t.id = s.cliente_em_uso AND u.plataforma
    WHERE s.token_hash = p_token_hash AND s.expira_em > now() AND u.ativo
  $$;
REVOKE ALL ON FUNCTION roar_sessao(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_sessao(text) TO roar_api;

-- Devolve o nome da organização em uso, ou NULL se recusou. O registro fica nas duas organizações, feito aqui para ninguém esquecer.
CREATE FUNCTION roar_usar_organizacao(p_token_hash text, p_usuario uuid, p_cliente uuid, p_origem text)
  RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE
  v_proprio uuid;
  v_atual uuid;
  v_alvo text;
  v_nome_atual text;
BEGIN
  IF NOT roar_e_plataforma(p_usuario) THEN
    RAISE EXCEPTION 'sem permissão' USING ERRCODE = '42501';
  END IF;
  SELECT cliente_id INTO v_proprio FROM usuarios WHERE id = p_usuario;
  SELECT cliente_em_uso INTO v_atual FROM sessoes WHERE token_hash = p_token_hash AND usuario_id = p_usuario AND expira_em > now();
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  SELECT nome INTO v_alvo FROM clientes WHERE id = p_cliente;
  IF v_alvo IS NULL THEN
    RETURN NULL;
  END IF;
  IF v_atual IS NOT NULL AND v_atual <> p_cliente THEN
    SELECT nome INTO v_nome_atual FROM clientes WHERE id = v_atual;
    INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo, origem) VALUES (v_atual, p_usuario, 'sair_da_organizacao', v_nome_atual, left(p_origem, 64));
  END IF;
  IF p_cliente = v_proprio THEN
    UPDATE sessoes SET cliente_em_uso = NULL WHERE token_hash = p_token_hash;
    IF v_atual IS NOT NULL THEN
      INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo, origem) VALUES (v_proprio, p_usuario, 'voltar_para_a_organizacao', v_alvo, left(p_origem, 64));
    END IF;
    RETURN v_alvo;
  END IF;
  UPDATE sessoes SET cliente_em_uso = p_cliente WHERE token_hash = p_token_hash;
  IF v_atual IS DISTINCT FROM p_cliente THEN
    INSERT INTO auditoria (cliente_id, usuario_id, acao, alvo, origem) VALUES
      (p_cliente, p_usuario, 'entrar_na_organizacao', v_alvo, left(p_origem, 64)),
      (v_proprio, p_usuario, 'entrar_em_outra_organizacao', v_alvo, left(p_origem, 64));
  END IF;
  RETURN v_alvo;
END $$;

-- A organização precisa saber quem de fora atuou nela: o nome aparece só para quem deixou registro aqui.
CREATE FUNCTION roar_pessoas_de_fora()
  RETURNS TABLE (id uuid, nome text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    SELECT u.id, u.nome FROM usuarios u
    WHERE u.cliente_id <> roar_cliente_atual()
      AND EXISTS (SELECT 1 FROM auditoria a WHERE a.usuario_id = u.id AND a.cliente_id = roar_cliente_atual())
  $$;

REVOKE ALL ON FUNCTION roar_usar_organizacao(text, uuid, uuid, text), roar_pessoas_de_fora() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_usar_organizacao(text, uuid, uuid, text), roar_pessoas_de_fora() TO roar_api;
