-- FIM: o que cada cliente monitora, pedidos de varredura e a base de arquivos de cada ativo.
-- Quem coleta e compara é o módulo do agente; aqui fica só a configuração e o que a tela mostra.
CREATE TABLE fim_caminhos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  caminho text NOT NULL,
  sistema text NOT NULL CHECK (sistema IN ('linux', 'windows')),
  modo text NOT NULL CHECK (modo IN ('agendado', 'tempo_real', 'quem_alterou')),
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'ativo', 'recusado', 'desativado')),
  mensagem text,
  criado_por uuid NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ON fim_caminhos (gerenciador_id, sistema, caminho) WHERE estado <> 'desativado';

CREATE TABLE fim_varreduras (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  agente_id text NOT NULL CHECK (agente_id ~ '^[0-9]{3,8}$'),
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'enviada', 'falhou')),
  pedida_por uuid NOT NULL,
  pedida_em timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE fim_base (
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  agente_id text NOT NULL,
  caminho text NOT NULL,
  tipo text,
  tamanho bigint,
  modificado_em timestamptz,
  sha256 text,
  dono text,
  permissao text,
  atualizado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gerenciador_id, agente_id, caminho)
);
CREATE INDEX ON fim_base (cliente_id, agente_id);

ALTER TABLE ativos ADD COLUMN fim_inicio timestamptz;
ALTER TABLE ativos ADD COLUMN fim_fim timestamptz;

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['fim_caminhos', 'fim_varreduras', 'fim_base'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ingestao
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

GRANT SELECT, INSERT ON fim_caminhos, fim_varreduras TO roar_api;
GRANT UPDATE (estado) ON fim_caminhos TO roar_api;
GRANT SELECT ON fim_base TO roar_api;
GRANT SELECT ON fim_caminhos, fim_varreduras TO roar_ingestao;
GRANT UPDATE (estado, mensagem) ON fim_caminhos TO roar_ingestao;
GRANT UPDATE (estado) ON fim_varreduras TO roar_ingestao;
GRANT SELECT, INSERT, UPDATE, DELETE ON fim_base TO roar_ingestao;
GRANT UPDATE (fim_inicio, fim_fim) ON ativos TO roar_ingestao;
