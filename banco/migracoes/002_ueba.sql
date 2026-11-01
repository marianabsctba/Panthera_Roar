-- UEBA: entidades, o que cada uma costuma fazer, sinais de desvio e alertas de risco.

CREATE ROLE roar_ueba LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- O horário "normal" de uma pessoa depende do fuso do cliente, não do servidor.
ALTER TABLE clientes ADD COLUMN fuso text NOT NULL DEFAULT 'America/Sao_Paulo';

CREATE TABLE entidades (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  tipo text NOT NULL CHECK (tipo IN ('usuario', 'ativo')),
  chave text NOT NULL,
  nome text,
  primeira_vista timestamptz NOT NULL,
  ultima_vista timestamptz NOT NULL,
  sucessos bigint NOT NULL DEFAULT 0,
  risco double precision NOT NULL DEFAULT 0,
  risco_em timestamptz,
  ultima_lat double precision,
  ultima_lon double precision,
  ultima_geo_em timestamptz,
  UNIQUE (cliente_id, tipo, chave),
  UNIQUE (cliente_id, id)
);

-- Hosts, IPs e privilégios já vistos para cada usuário.
CREATE TABLE vistos (
  cliente_id uuid NOT NULL,
  entidade_id bigint NOT NULL,
  dimensao text NOT NULL CHECK (dimensao IN ('host', 'ip', 'privilegio')),
  valor text NOT NULL,
  primeira_vez timestamptz NOT NULL,
  contagem bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (cliente_id, entidade_id, dimensao, valor),
  FOREIGN KEY (cliente_id, entidade_id) REFERENCES entidades (cliente_id, id)
);
CREATE INDEX ON vistos (cliente_id, dimensao, valor);

CREATE TABLE horas (
  cliente_id uuid NOT NULL,
  entidade_id bigint NOT NULL,
  hora smallint NOT NULL CHECK (hora BETWEEN 0 AND 23),
  contagem bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (cliente_id, entidade_id, hora),
  FOREIGN KEY (cliente_id, entidade_id) REFERENCES entidades (cliente_id, id)
);

CREATE TABLE falhas_por_hora (
  cliente_id uuid NOT NULL,
  entidade_id bigint NOT NULL,
  inicio timestamptz NOT NULL,
  contagem bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (cliente_id, entidade_id, inicio),
  FOREIGN KEY (cliente_id, entidade_id) REFERENCES entidades (cliente_id, id)
);

-- Um mesmo sinal, com o mesmo valor, conta uma vez por dia: repetição não infla o risco.
CREATE TABLE sinais (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  entidade_id bigint NOT NULL,
  tipo text NOT NULL,
  valor text NOT NULL,
  dia date NOT NULL,
  peso double precision NOT NULL,
  ocorrido_em timestamptz NOT NULL,
  evento_id bigint NOT NULL REFERENCES eventos (id),
  detalhes jsonb NOT NULL DEFAULT '{}',
  UNIQUE (cliente_id, entidade_id, tipo, valor, dia),
  FOREIGN KEY (cliente_id, entidade_id) REFERENCES entidades (cliente_id, id)
);
CREATE INDEX ON sinais (cliente_id, entidade_id, ocorrido_em DESC);

CREATE TABLE alertas_risco (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  entidade_id bigint NOT NULL,
  estado text NOT NULL DEFAULT 'aberto' CHECK (estado IN ('aberto', 'encerrado')),
  severidade text NOT NULL CHECK (severidade IN ('alta', 'critica')),
  risco_maximo double precision NOT NULL,
  aberto_em timestamptz NOT NULL,
  encerrado_em timestamptz,
  FOREIGN KEY (cliente_id, entidade_id) REFERENCES entidades (cliente_id, id)
);
-- No máximo um alerta aberto por entidade.
CREATE UNIQUE INDEX ON alertas_risco (cliente_id, entidade_id) WHERE estado = 'aberto';

CREATE TABLE ueba_cursor (
  cliente_id uuid PRIMARY KEY REFERENCES clientes (id),
  ultimo_evento_id bigint NOT NULL DEFAULT 0
);

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['entidades', 'vistos', 'horas', 'falhas_por_hora', 'sinais', 'alertas_risco', 'ueba_cursor'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ueba
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON %I TO roar_ueba', tabela);
    EXECUTE format('GRANT SELECT ON %I TO roar_api', tabela);
  END LOOP;
END $$;

CREATE POLICY leitura_ueba ON eventos FOR SELECT TO roar_ueba
  USING (cliente_id = roar_cliente_atual());
GRANT SELECT ON eventos TO roar_ueba;

-- O serviço percorre os clientes, sem acesso ao nome de nenhum deles.
CREATE POLICY percurso ON clientes FOR SELECT TO roar_ueba USING (true);
GRANT SELECT (id, fuso) ON clientes TO roar_ueba;
