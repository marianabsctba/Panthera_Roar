-- Base do Roar. Isolamento por cliente com RLS, valendo também para o dono das tabelas.
-- O papel roar_admin é superusuário só para migrações; a aplicação nunca o usa.

CREATE ROLE roar_ingestao LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE roar_api LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- Sem cliente definido na transação, devolve NULL e nenhuma linha passa.
CREATE FUNCTION roar_cliente_atual() RETURNS uuid
  LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('roar.cliente', true), '')::uuid $$;

CREATE TABLE clientes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nome text NOT NULL UNIQUE,
  criado_em timestamptz NOT NULL DEFAULT now()
);

-- Cada cliente tem o seu gerenciador do Wazuh, com índice e credenciais próprios.
-- O dono de um alerta é o gerenciador em cujo índice ele está, nunca o conteúdo do alerta.
CREATE TABLE gerenciadores (
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9]{6,32}$'),
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  porta_base integer NOT NULL UNIQUE,
  criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON gerenciadores (cliente_id);

CREATE TABLE grupos_alerta (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  chave text NOT NULL,
  dia date NOT NULL,
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  agente_id text NOT NULL,
  ip_origem inet,
  nivel smallint NOT NULL,
  severidade text NOT NULL CHECK (severidade IN ('baixa', 'media', 'alta', 'critica')),
  regras text[] NOT NULL,
  total bigint NOT NULL DEFAULT 1,
  primeira_em timestamptz NOT NULL,
  ultima_em timestamptz NOT NULL,
  UNIQUE (cliente_id, chave),
  UNIQUE (cliente_id, id)
);
CREATE INDEX ON grupos_alerta (cliente_id, ultima_em DESC);

CREATE TABLE eventos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  grupo_id bigint,
  origem text NOT NULL,
  origem_id text NOT NULL,
  ocorrido_em timestamptz NOT NULL,
  recebido_em timestamptz NOT NULL DEFAULT now(),
  nivel smallint NOT NULL,
  severidade text NOT NULL CHECK (severidade IN ('baixa', 'media', 'alta', 'critica')),
  regra_id text NOT NULL,
  regra_descricao text,
  regra_grupos text[] NOT NULL DEFAULT '{}',
  mitre text[] NOT NULL DEFAULT '{}',
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  agente_id text NOT NULL,
  agente_nome text,
  ip_origem inet,
  usuario text,
  bruto jsonb NOT NULL,
  UNIQUE (cliente_id, origem, origem_id),
  -- O grupo precisa ser do mesmo cliente do evento.
  FOREIGN KEY (cliente_id, grupo_id) REFERENCES grupos_alerta (cliente_id, id)
);
CREATE INDEX ON eventos (cliente_id, ocorrido_em DESC);
CREATE INDEX ON eventos (cliente_id, usuario, ocorrido_em DESC);
CREATE INDEX ON eventos (cliente_id, grupo_id);

-- O que não pode virar evento de cliente nunca entra em cliente nenhum.
CREATE TABLE quarentena (
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  origem text NOT NULL,
  origem_id text NOT NULL,
  motivo text NOT NULL,
  agente_id text,
  recebido_em timestamptz NOT NULL DEFAULT now(),
  bruto jsonb NOT NULL,
  PRIMARY KEY (gerenciador_id, origem, origem_id)
);
CREATE INDEX ON quarentena (motivo);

CREATE TABLE checkpoints (
  fonte text PRIMARY KEY,
  ocorrido_em timestamptz NOT NULL,
  atualizado_em timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE clientes ENABLE ROW LEVEL SECURITY;
ALTER TABLE clientes FORCE ROW LEVEL SECURITY;
ALTER TABLE gerenciadores ENABLE ROW LEVEL SECURITY;
ALTER TABLE gerenciadores FORCE ROW LEVEL SECURITY;
ALTER TABLE grupos_alerta ENABLE ROW LEVEL SECURITY;
ALTER TABLE grupos_alerta FORCE ROW LEVEL SECURITY;
ALTER TABLE eventos ENABLE ROW LEVEL SECURITY;
ALTER TABLE eventos FORCE ROW LEVEL SECURITY;

CREATE POLICY isolamento ON clientes TO roar_api USING (id = roar_cliente_atual());

CREATE POLICY isolamento ON gerenciadores TO roar_api USING (cliente_id = roar_cliente_atual());
-- A ingestão percorre todos os gerenciadores, só para leitura.
CREATE POLICY percurso ON gerenciadores FOR SELECT TO roar_ingestao USING (true);

CREATE POLICY isolamento ON grupos_alerta TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());

CREATE POLICY isolamento ON eventos TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());

GRANT SELECT ON gerenciadores TO roar_ingestao;
GRANT SELECT, INSERT, UPDATE ON grupos_alerta TO roar_ingestao;
GRANT SELECT, INSERT ON eventos TO roar_ingestao;
GRANT UPDATE (grupo_id) ON eventos TO roar_ingestao;
GRANT SELECT, INSERT ON quarentena TO roar_ingestao;
GRANT UPDATE (motivo) ON quarentena TO roar_ingestao;
GRANT SELECT, INSERT, UPDATE ON checkpoints TO roar_ingestao;

GRANT SELECT ON clientes, gerenciadores, grupos_alerta, eventos TO roar_api;
