-- Quem entra na tela. O cliente de cada requisição vem da sessão, nunca do que o navegador envia.
-- A API não lê estas tabelas: fala com elas só por funções, porque antes do login ainda não
-- existe cliente definido para o RLS.

CREATE TABLE usuarios (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  email text NOT NULL UNIQUE CHECK (email = lower(email)),
  nome text NOT NULL,
  senha_hash text NOT NULL,
  ativo boolean NOT NULL DEFAULT true,
  criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON usuarios (cliente_id);

-- Guarda só o hash do token: quem lê o banco não consegue se passar por ninguém.
CREATE TABLE sessoes (
  token_hash text PRIMARY KEY,
  usuario_id uuid NOT NULL REFERENCES usuarios (id) ON DELETE CASCADE,
  criada_em timestamptz NOT NULL DEFAULT now(),
  expira_em timestamptz NOT NULL
);
CREATE INDEX ON sessoes (expira_em);

REVOKE ALL ON usuarios, sessoes FROM PUBLIC;

CREATE FUNCTION roar_usuario_para_login(p_email text)
  RETURNS TABLE (id uuid, senha_hash text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT u.id, u.senha_hash FROM usuarios u WHERE u.email = lower(p_email) AND u.ativo $$;

CREATE FUNCTION roar_criar_sessao(p_token_hash text, p_usuario uuid, p_horas integer)
  RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    DELETE FROM sessoes WHERE expira_em < now();
    INSERT INTO sessoes (token_hash, usuario_id, expira_em)
    VALUES (p_token_hash, p_usuario, now() + make_interval(hours => p_horas));
  $$;

CREATE FUNCTION roar_sessao(p_token_hash text)
  RETURNS TABLE (usuario_id uuid, cliente_id uuid, nome text, cliente_nome text, fuso text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    SELECT u.id, u.cliente_id, u.nome, c.nome, c.fuso
    FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id JOIN clientes c ON c.id = u.cliente_id
    WHERE s.token_hash = p_token_hash AND s.expira_em > now() AND u.ativo
  $$;

CREATE FUNCTION roar_encerrar_sessao(p_token_hash text)
  RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ DELETE FROM sessoes WHERE token_hash = p_token_hash $$;

REVOKE ALL ON FUNCTION roar_usuario_para_login(text), roar_criar_sessao(text, uuid, integer),
  roar_sessao(text), roar_encerrar_sessao(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_usuario_para_login(text), roar_criar_sessao(text, uuid, integer),
  roar_sessao(text), roar_encerrar_sessao(text) TO roar_api;
