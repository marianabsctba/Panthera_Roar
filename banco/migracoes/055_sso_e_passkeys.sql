-- Passkey: entrar sem senha, com a chave guardada no aparelho. Vale como os dois fatores e não cai em phishing.
CREATE TABLE passkeys (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  usuario_id uuid NOT NULL REFERENCES usuarios (id) ON DELETE CASCADE,
  credencial bytea NOT NULL UNIQUE,
  chave_publica bytea NOT NULL,
  -- O aparelho conta cada uso. Contador que volta para trás é credencial clonada.
  contador bigint NOT NULL DEFAULT 0,
  nome text NOT NULL CHECK (length(nome) BETWEEN 1 AND 80),
  transportes text[] NOT NULL DEFAULT '{}',
  criada_em timestamptz NOT NULL DEFAULT now(),
  ultima_vez timestamptz
);
CREATE INDEX ON passkeys (usuario_id);
REVOKE ALL ON passkeys FROM PUBLIC;

-- Login único (OIDC) por organização. O segredo do cliente chega cifrado pela API.
CREATE TABLE sso (
  cliente_id uuid PRIMARY KEY REFERENCES clientes (id),
  emissor text NOT NULL CHECK (emissor ~ '^https://'),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 300),
  segredo bytea,
  dominios text[] NOT NULL DEFAULT '{}',
  ativo boolean NOT NULL DEFAULT true,
  -- Senha e passkey param de valer para quem não administra. Quem administra fica com a senha, se o provedor cair.
  exigir boolean NOT NULL DEFAULT false,
  atualizado_por uuid NOT NULL,
  atualizado_em timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE sso ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON sso TO roar_api USING (cliente_id = roar_cliente_atual()) WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT, INSERT, UPDATE, DELETE ON sso TO roar_api;

-- Desafios de passkey e pedidos de SSO: vivem minutos, e cada um só serve uma vez.
CREATE TABLE pedidos_de_entrada (
  chave text PRIMARY KEY,
  tipo text NOT NULL CHECK (tipo IN ('passkey_cadastro', 'passkey_entrada', 'sso')),
  dados jsonb NOT NULL,
  expira_em timestamptz NOT NULL
);
REVOKE ALL ON pedidos_de_entrada FROM PUBLIC;

CREATE FUNCTION roar_guardar_pedido(p_chave text, p_tipo text, p_dados jsonb, p_minutos integer) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    DELETE FROM pedidos_de_entrada WHERE expira_em < now();
    INSERT INTO pedidos_de_entrada (chave, tipo, dados, expira_em) VALUES (p_chave, p_tipo, p_dados, now() + make_interval(mins => p_minutos));
  $$;

CREATE FUNCTION roar_tomar_pedido(p_chave text, p_tipo text) RETURNS jsonb
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ DELETE FROM pedidos_de_entrada WHERE chave = p_chave AND tipo = p_tipo AND expira_em > now() RETURNING dados $$;

-- Quem pode entrar, pelo e-mail, e se a organização exige o SSO.
CREATE FUNCTION roar_entrada_por_email(p_email text)
  RETURNS TABLE (usuario_id uuid, cliente_id uuid, perfil text, sso_ativo boolean, sso_exigido boolean)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    SELECT u.id, u.cliente_id, u.perfil, coalesce(s.ativo, false), coalesce(s.ativo AND s.exigir, false)
    FROM usuarios u LEFT JOIN sso s ON s.cliente_id = u.cliente_id
    WHERE u.email = lower(p_email) AND u.ativo
  $$;

-- A configuração do SSO da organização de quem vai entrar. Antes do login não há cliente na sessão, e o RLS não deixaria ler.
CREATE FUNCTION roar_sso_da_organizacao(p_cliente uuid)
  RETURNS TABLE (emissor text, client_id text, segredo bytea, dominios text[])
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT emissor, client_id, segredo, dominios FROM sso WHERE cliente_id = p_cliente AND ativo $$;

CREATE FUNCTION roar_passkeys_do_usuario(p_usuario uuid)
  RETURNS TABLE (id bigint, credencial bytea, nome text, transportes text[], criada_em timestamptz, ultima_vez timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT id, credencial, nome, transportes, criada_em, ultima_vez FROM passkeys WHERE usuario_id = p_usuario ORDER BY criada_em $$;

CREATE FUNCTION roar_criar_passkey(p_usuario uuid, p_credencial bytea, p_chave bytea, p_contador bigint, p_nome text, p_transportes text[]) RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ INSERT INTO passkeys (usuario_id, credencial, chave_publica, contador, nome, transportes)
        VALUES (p_usuario, p_credencial, p_chave, p_contador, p_nome, p_transportes) RETURNING id $$;

CREATE FUNCTION roar_apagar_passkey(p_usuario uuid, p_id bigint) RETURNS boolean
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ WITH apagada AS (DELETE FROM passkeys WHERE id = p_id AND usuario_id = p_usuario RETURNING 1) SELECT EXISTS (SELECT 1 FROM apagada) $$;

CREATE FUNCTION roar_passkey_para_entrar(p_credencial bytea)
  RETURNS TABLE (id bigint, usuario_id uuid, chave_publica bytea, contador bigint, perfil text, sso_exigido boolean)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
    SELECT p.id, p.usuario_id, p.chave_publica, p.contador, u.perfil, coalesce(s.ativo AND s.exigir, false)
    FROM passkeys p JOIN usuarios u ON u.id = p.usuario_id LEFT JOIN sso s ON s.cliente_id = u.cliente_id
    WHERE p.credencial = p_credencial AND u.ativo
  $$;

CREATE FUNCTION roar_passkey_usada(p_id bigint, p_contador bigint) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ UPDATE passkeys SET contador = p_contador, ultima_vez = now() WHERE id = p_id $$;

DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY['roar_guardar_pedido(text, text, jsonb, integer)', 'roar_tomar_pedido(text, text)', 'roar_entrada_por_email(text)',
                           'roar_sso_da_organizacao(uuid)', 'roar_passkeys_do_usuario(uuid)', 'roar_criar_passkey(uuid, bytea, bytea, bigint, text, text[])',
                           'roar_apagar_passkey(uuid, bigint)', 'roar_passkey_para_entrar(bytea)', 'roar_passkey_usada(bigint, bigint)'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO roar_api', f);
  END LOOP;
END $$;
