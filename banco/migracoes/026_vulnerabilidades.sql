-- Gestão contínua de vulnerabilidades. Quem varre são ferramentas prontas; aqui fica o que serve para todas:
-- alvos, modelos, agenda, achados por ativo, peso, e a história de cada achado.
CREATE TABLE vuln_modelos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  nome text NOT NULL,
  ferramenta text NOT NULL CHECK (ferramenta IN ('rede', 'web', 'conteiner', 'nuvem')),
  intrusiva boolean NOT NULL DEFAULT false,
  todas_portas boolean NOT NULL DEFAULT false,
  ativo boolean NOT NULL DEFAULT true,
  criado_por uuid NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cliente_id, nome)
);

CREATE TABLE vuln_alvos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  nome text NOT NULL,
  hosts text[] NOT NULL CHECK (cardinality(hosts) BETWEEN 1 AND 256),
  modelo_id bigint NOT NULL REFERENCES vuln_modelos (id),
  credencial_tipo text CHECK (credencial_tipo IN ('ssh', 'smb', 'snmp')),
  credencial_usuario text,
  -- Nome em segredos: o valor fica cifrado no cofre e a API nunca o lê de volta.
  credencial_segredo text,
  a_cada_dias integer NOT NULL DEFAULT 30 CHECK (a_cada_dias = 0 OR a_cada_dias BETWEEN 1 AND 365),
  proxima_em timestamptz,
  ativo boolean NOT NULL DEFAULT true,
  criado_por uuid NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cliente_id, nome)
);

CREATE TABLE vuln_varreduras (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  alvo_id bigint NOT NULL REFERENCES vuln_alvos (id),
  modelo_id bigint NOT NULL REFERENCES vuln_modelos (id),
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'em_andamento', 'concluida', 'falhou')),
  -- Vazio quando foi a agenda que disparou.
  pedida_por uuid,
  pedida_em timestamptz NOT NULL DEFAULT now(),
  iniciada_em timestamptz,
  terminada_em timestamptz,
  autenticada boolean,
  hosts_respondendo integer,
  novos integer,
  corrigidos integer,
  mensagem text,
  id_externo text
);
CREATE INDEX ON vuln_varreduras (cliente_id, pedida_em DESC);
CREATE UNIQUE INDEX ON vuln_varreduras (alvo_id) WHERE estado IN ('pendente', 'em_andamento');

CREATE TABLE vuln_ativos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  host text NOT NULL,
  nome text,
  sistema text,
  peso smallint NOT NULL DEFAULT 3 CHECK (peso BETWEEN 1 AND 5),
  peso_definido_por uuid,
  monitorado boolean NOT NULL DEFAULT true,
  primeira_vez timestamptz NOT NULL DEFAULT now(),
  ultima_varredura timestamptz,
  UNIQUE (cliente_id, host)
);

CREATE TABLE vuln_achados (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  ativo_id bigint NOT NULL REFERENCES vuln_ativos (id),
  chave text NOT NULL,
  fonte text NOT NULL,
  titulo text NOT NULL,
  cves text[] NOT NULL DEFAULT '{}',
  cvss real,
  severidade text NOT NULL CHECK (severidade IN ('critica', 'alta', 'media', 'baixa', 'informativa')),
  porta text,
  evidencia text,
  solucao text,
  estado text NOT NULL DEFAULT 'aberto' CHECK (estado IN ('aberto', 'corrigido', 'aceito', 'falso_positivo')),
  autenticada boolean NOT NULL DEFAULT false,
  intrusiva boolean NOT NULL DEFAULT false,
  todas_portas boolean NOT NULL DEFAULT false,
  primeira_vez timestamptz NOT NULL DEFAULT now(),
  ultima_vez timestamptz NOT NULL DEFAULT now(),
  corrigido_em timestamptz,
  ultima_varredura bigint REFERENCES vuln_varreduras (id),
  UNIQUE (ativo_id, chave)
);
CREATE INDEX ON vuln_achados (cliente_id, estado, severidade);
CREATE INDEX ON vuln_achados USING gin (cves);

-- A história não muda: é ela que mostra a evolução das correções e quem aceitou um risco.
CREATE TABLE vuln_historico (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  achado_id bigint NOT NULL REFERENCES vuln_achados (id),
  quando timestamptz NOT NULL DEFAULT now(),
  de text,
  para text NOT NULL,
  por uuid,
  varredura_id bigint REFERENCES vuln_varreduras (id),
  motivo text
);
CREATE INDEX ON vuln_historico (achado_id, quando);
CREATE INDEX ON vuln_historico (cliente_id, quando DESC);

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['vuln_modelos', 'vuln_alvos', 'vuln_varreduras', 'vuln_ativos', 'vuln_achados', 'vuln_historico'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ingestao
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

GRANT SELECT, INSERT ON vuln_modelos, vuln_alvos, vuln_varreduras, vuln_historico TO roar_api;
GRANT UPDATE (ativo) ON vuln_modelos TO roar_api;
GRANT UPDATE (ativo, proxima_em) ON vuln_alvos TO roar_api;
GRANT SELECT ON vuln_ativos, vuln_achados TO roar_api;
GRANT UPDATE (peso, peso_definido_por, monitorado) ON vuln_ativos TO roar_api;
GRANT UPDATE (estado) ON vuln_achados TO roar_api;

GRANT SELECT ON vuln_modelos, vuln_alvos TO roar_ingestao;
GRANT UPDATE (proxima_em) ON vuln_alvos TO roar_ingestao;
GRANT SELECT, INSERT, UPDATE ON vuln_varreduras, vuln_ativos, vuln_achados TO roar_ingestao;
GRANT SELECT, INSERT ON vuln_historico TO roar_ingestao;
