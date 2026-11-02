-- Quem administra a instalação cria e remove organizações. O perfil dentro de uma organização não dá esse poder.
-- A API não toca nestas tabelas: só nas funções abaixo, que conferem quem pede.
ALTER TABLE usuarios ADD COLUMN plataforma boolean NOT NULL DEFAULT false;

UPDATE usuarios SET plataforma = true WHERE id = (
  SELECT u.id FROM usuarios u JOIN clientes c ON c.id = u.cliente_id WHERE u.perfil = 'administrador' ORDER BY c.criado_em, u.criado_em LIMIT 1);

CREATE TABLE organizacoes_pedidos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  acao text NOT NULL CHECK (acao IN ('criar', 'remover')),
  nome text NOT NULL,
  email text,
  senha_hash text,
  cliente_id uuid,
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'em_andamento', 'pronto', 'falhou')),
  mensagem text,
  pedido_por uuid NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  concluido_em timestamptz
);
REVOKE ALL ON organizacoes_pedidos FROM PUBLIC;

CREATE FUNCTION roar_e_plataforma(p_usuario uuid)
  RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT coalesce((SELECT plataforma AND ativo FROM usuarios WHERE id = p_usuario), false) $$;

CREATE FUNCTION roar_listar_organizacoes(p_usuario uuid)
  RETURNS TABLE (id uuid, nome text, criado_em timestamptz, usuarios bigint, ativos bigint, eventos_24h bigint, ultimo_evento timestamptz, removivel boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  IF NOT roar_e_plataforma(p_usuario) THEN
    RAISE EXCEPTION 'sem permissão' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT c.id, c.nome, c.criado_em,
           (SELECT count(*) FROM public.usuarios u WHERE u.cliente_id = c.id),
           (SELECT count(*) FROM public.ativos a WHERE a.cliente_id = c.id AND a.agente_id <> '000'),
           (SELECT count(*) FROM public.eventos e WHERE e.cliente_id = c.id AND e.ocorrido_em >= now() - interval '24 hours'),
           (SELECT max(e.ocorrido_em) FROM public.eventos e WHERE e.cliente_id = c.id),
           c.id <> (SELECT u.cliente_id FROM public.usuarios u WHERE u.id = p_usuario)
    FROM clientes c ORDER BY c.nome;
END $$;

CREATE FUNCTION roar_listar_pedidos_de_organizacao(p_usuario uuid)
  RETURNS TABLE (id bigint, acao text, nome text, email text, estado text, mensagem text, criado_em timestamptz)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  IF NOT roar_e_plataforma(p_usuario) THEN
    RAISE EXCEPTION 'sem permissão' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT p.id, p.acao, p.nome, p.email, p.estado, p.mensagem, p.criado_em FROM organizacoes_pedidos p
    WHERE p.estado IN ('pendente', 'em_andamento') OR p.criado_em >= now() - interval '1 day' ORDER BY p.id DESC LIMIT 50;
END $$;

CREATE FUNCTION roar_pedir_organizacao(p_usuario uuid, p_nome text, p_email text, p_senha_hash text)
  RETURNS bigint
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE
  novo bigint;
BEGIN
  IF NOT roar_e_plataforma(p_usuario) THEN
    RAISE EXCEPTION 'sem permissão' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM clientes WHERE lower(nome) = lower(p_nome))
     OR EXISTS (SELECT 1 FROM organizacoes_pedidos WHERE acao = 'criar' AND lower(nome) = lower(p_nome) AND estado IN ('pendente', 'em_andamento')) THEN
    RETURN -1;
  END IF;
  IF EXISTS (SELECT 1 FROM usuarios WHERE email = lower(p_email))
     OR EXISTS (SELECT 1 FROM organizacoes_pedidos WHERE email = lower(p_email) AND estado IN ('pendente', 'em_andamento')) THEN
    RETURN -2;
  END IF;
  INSERT INTO organizacoes_pedidos (acao, nome, email, senha_hash, pedido_por) VALUES ('criar', p_nome, lower(p_email), p_senha_hash, p_usuario) RETURNING organizacoes_pedidos.id INTO novo;
  RETURN novo;
END $$;

CREATE FUNCTION roar_pedir_remocao_de_organizacao(p_usuario uuid, p_cliente uuid, p_nome_confirmado text)
  RETURNS bigint
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE
  o_nome text;
  novo bigint;
BEGIN
  IF NOT roar_e_plataforma(p_usuario) THEN
    RAISE EXCEPTION 'sem permissão' USING ERRCODE = '42501';
  END IF;
  -- A própria organização não sai: a instalação ficaria sem ninguém para administrá-la.
  IF p_cliente = (SELECT cliente_id FROM usuarios WHERE id = p_usuario) THEN
    RETURN NULL;
  END IF;
  SELECT nome INTO o_nome FROM clientes WHERE id = p_cliente;
  IF o_nome IS NULL OR o_nome <> p_nome_confirmado THEN
    RETURN NULL;
  END IF;
  INSERT INTO organizacoes_pedidos (acao, nome, cliente_id, pedido_por) VALUES ('remover', o_nome, p_cliente, p_usuario) RETURNING organizacoes_pedidos.id INTO novo;
  RETURN novo;
END $$;

REVOKE ALL ON FUNCTION roar_e_plataforma(uuid), roar_listar_organizacoes(uuid), roar_listar_pedidos_de_organizacao(uuid),
  roar_pedir_organizacao(uuid, text, text, text), roar_pedir_remocao_de_organizacao(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_e_plataforma(uuid), roar_listar_organizacoes(uuid), roar_listar_pedidos_de_organizacao(uuid),
  roar_pedir_organizacao(uuid, text, text, text), roar_pedir_remocao_de_organizacao(uuid, uuid, text) TO roar_api;
