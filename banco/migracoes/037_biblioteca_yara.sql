-- Biblioteca de regras YARA da comunidade. Pacote e catálogo são públicos: não pertencem a nenhum cliente.
-- Cada organização escolhe usar ou não, se atualiza sozinha e quais regras não quer.
CREATE TABLE yara_pacotes (
  versao text PRIMARY KEY,
  conteudo text NOT NULL,
  regras integer NOT NULL,
  sha256 text NOT NULL,
  publicado_em timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE yara_biblioteca (
  nome text PRIMARY KEY,
  privada boolean NOT NULL,
  descricao text,
  autor text,
  repositorio text,
  licenca text,
  endereco text,
  pontuacao integer,
  conteudo text NOT NULL
);

-- De onde veio cada biblioteca e como foi a última tentativa de atualizar.
CREATE TABLE bibliotecas_estado (
  nome text PRIMARY KEY CHECK (nome IN ('sigma', 'yara')),
  versao text,
  atualizada_em timestamptz,
  tentativa_em timestamptz,
  erro text
);

CREATE TABLE yara_assinatura (
  cliente_id uuid PRIMARY KEY REFERENCES clientes (id) ON DELETE CASCADE,
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id) ON DELETE CASCADE,
  ativa boolean NOT NULL DEFAULT false,
  automatica boolean NOT NULL DEFAULT true,
  versao text,
  excluidas text[] NOT NULL DEFAULT '{}',
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'aplicada', 'recusada')),
  mensagem text,
  atualizada_em timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE yara_assinatura ENABLE ROW LEVEL SECURITY;
ALTER TABLE yara_assinatura FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON yara_assinatura TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());

GRANT SELECT ON yara_pacotes, yara_biblioteca, bibliotecas_estado TO roar_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON yara_pacotes, yara_biblioteca, bibliotecas_estado TO roar_ingestao;
GRANT SELECT, INSERT, UPDATE ON yara_assinatura TO roar_api;
GRANT SELECT ON yara_assinatura TO roar_ingestao;
GRANT UPDATE (versao, estado, mensagem) ON yara_assinatura TO roar_ingestao;
