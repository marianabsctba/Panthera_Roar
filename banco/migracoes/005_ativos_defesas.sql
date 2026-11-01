-- O que o Wazuh sabe sobre cada ativo, copiado para a tela não falar com o gerenciador.
CREATE TABLE ativos (
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  agente_id text NOT NULL,
  nome text,
  ip text,
  sistema text,
  versao text,
  estado text,
  grupos text[] NOT NULL DEFAULT '{}',
  ultima_conexao timestamptz,
  sca_politica text,
  sca_nota smallint,
  sca_aprovados integer,
  sca_reprovados integer,
  atualizado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gerenciador_id, agente_id)
);
CREATE INDEX ON ativos (cliente_id);

ALTER TABLE ativos ENABLE ROW LEVEL SECURITY;
ALTER TABLE ativos FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON ativos TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT ON ativos TO roar_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ativos TO roar_ingestao;

-- Base pública do MITRE D3FEND: não pertence a nenhum cliente.
CREATE TABLE tecnicas_defesa (
  tecnica text NOT NULL,
  defesa_id text NOT NULL,
  defesa_nome text NOT NULL,
  tatica_defesa text,
  atualizado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tecnica, defesa_id)
);
-- Lembra as técnicas já consultadas, mesmo as que o D3FEND não cobre.
CREATE TABLE tecnicas_consultadas (
  tecnica text PRIMARY KEY,
  consultada_em timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON tecnicas_defesa TO roar_api;
GRANT SELECT, INSERT, UPDATE ON tecnicas_defesa, tecnicas_consultadas TO roar_ingestao;
