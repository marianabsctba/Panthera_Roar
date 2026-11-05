-- O que aparece mascarado para quem não pode ver dado pessoal. Começa tudo ligado: desligar é escolha da organização.
ALTER TABLE clientes ADD COLUMN ofuscar text[] NOT NULL DEFAULT '{cpf,cnpj,email,cartao,telefone,usuario,ip}'
  CHECK (ofuscar <@ '{cpf,cnpj,email,cartao,telefone,usuario,ip}');

-- Vale a regra da organização dona do dado, mesmo para quem administra a instalação e está atuando nela.
DROP FUNCTION roar_sessao(text);
CREATE FUNCTION roar_sessao(p_token_hash text)
  RETURNS TABLE (usuario_id uuid, cliente_id uuid, nome text, cliente_nome text, fuso text, perfil text, trocar_senha boolean,
                 mfa_pendente boolean, mfa_ativo boolean, mfa_obrigatorio boolean, cliente_proprio uuid, cliente_proprio_nome text, ofuscar text[])
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    SELECT u.id, coalesce(t.id, u.cliente_id), u.nome, coalesce(t.nome, c.nome), coalesce(t.fuso, c.fuso), u.perfil, u.trocar_senha,
           s.mfa_pendente, u.mfa_ativo, c.mfa_obrigatorio, u.cliente_id, c.nome, coalesce(t.ofuscar, c.ofuscar)
    FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id JOIN clientes c ON c.id = u.cliente_id
    LEFT JOIN clientes t ON t.id = s.cliente_em_uso AND u.plataforma
    WHERE s.token_hash = p_token_hash AND s.expira_em > now() AND u.ativo
  $$;

CREATE FUNCTION roar_definir_ofuscacao(p_categorias text[]) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ UPDATE clientes SET ofuscar = p_categorias WHERE id = roar_cliente_atual() $$;

DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY['roar_sessao(text)', 'roar_definir_ofuscacao(text[])'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO roar_api', f);
  END LOOP;
END $$;
