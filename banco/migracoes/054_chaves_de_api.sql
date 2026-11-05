-- Chave de API: outro sistema usa a API com um perfil escolhido, em nome de quem criou a chave.
-- Só o resumo do segredo fica aqui; o segredo aparece uma vez, na criação.
CREATE TABLE chaves_api (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  usuario_id uuid NOT NULL REFERENCES usuarios (id) ON DELETE CASCADE,
  nome text NOT NULL CHECK (length(nome) BETWEEN 1 AND 80),
  prefixo text NOT NULL,
  resumo text NOT NULL UNIQUE,
  -- Administrador nunca: uma chave vazada não pode criar pessoas nem outras chaves.
  perfil text NOT NULL CHECK (perfil IN ('analista_n1', 'analista_n2', 'engenharia', 'auditor')),
  criada_em timestamptz NOT NULL DEFAULT now(),
  expira_em timestamptz,
  ultima_vez timestamptz,
  revogada_em timestamptz
);
CREATE INDEX ON chaves_api (cliente_id, criada_em DESC);

ALTER TABLE chaves_api ENABLE ROW LEVEL SECURITY;
ALTER TABLE chaves_api FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON chaves_api TO roar_api
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT (id, cliente_id, usuario_id, nome, prefixo, perfil, criada_em, expira_em, ultima_vez, revogada_em) ON chaves_api TO roar_api;
GRANT INSERT ON chaves_api TO roar_api;
GRANT UPDATE (revogada_em) ON chaves_api TO roar_api;

-- A sessão de quem chama com a chave, nas mesmas colunas da sessão de quem entra pela tela.
-- Antes de saber o cliente não há RLS que valha: por isso a função é do dono, e só confere o resumo.
CREATE FUNCTION roar_sessao_por_chave(p_resumo text)
  RETURNS TABLE (usuario_id uuid, cliente_id uuid, nome text, cliente_nome text, fuso text, perfil text, trocar_senha boolean,
                 mfa_pendente boolean, mfa_ativo boolean, mfa_obrigatorio boolean, cliente_proprio uuid, cliente_proprio_nome text, ofuscar text[],
                 chave_id bigint)
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  -- Uma escrita por minuto basta para saber se a chave está em uso.
  UPDATE chaves_api k SET ultima_vez = now()
    WHERE k.resumo = p_resumo AND (k.ultima_vez IS NULL OR k.ultima_vez < now() - interval '1 minute');
  RETURN QUERY
    SELECT u.id, k.cliente_id, u.nome || ' (chave ' || k.nome || ')', c.nome, c.fuso, k.perfil, false, false, true, false,
           u.cliente_id, c.nome, c.ofuscar, k.id
    FROM chaves_api k JOIN usuarios u ON u.id = k.usuario_id JOIN clientes c ON c.id = k.cliente_id
    WHERE k.resumo = p_resumo AND k.revogada_em IS NULL AND (k.expira_em IS NULL OR k.expira_em > now()) AND u.ativo;
END $$;
REVOKE ALL ON FUNCTION roar_sessao_por_chave(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_sessao_por_chave(text) TO roar_api;
