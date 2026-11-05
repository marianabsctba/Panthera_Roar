-- Qual provedor a organização usa: a tela de entrada mostra o botão dele.
ALTER TABLE sso ADD COLUMN provedor text NOT NULL DEFAULT 'outro' CHECK (provedor IN ('google', 'microsoft', 'outro'));

DROP FUNCTION roar_entrada_por_email(text);
CREATE FUNCTION roar_entrada_por_email(p_email text)
  RETURNS TABLE (usuario_id uuid, cliente_id uuid, perfil text, sso_ativo boolean, sso_exigido boolean, sso_provedor text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    SELECT u.id, u.cliente_id, u.perfil, coalesce(s.ativo, false), coalesce(s.ativo AND s.exigir, false), CASE WHEN s.ativo THEN s.provedor END
    FROM usuarios u LEFT JOIN sso s ON s.cliente_id = u.cliente_id
    WHERE u.email = lower(p_email) AND u.ativo
  $$;
REVOKE ALL ON FUNCTION roar_entrada_por_email(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_entrada_por_email(text) TO roar_api;
