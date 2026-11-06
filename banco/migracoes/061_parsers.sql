-- Parsers próprios: ensinam o gerenciador a ler um formato de log que ele não conhece.
-- O guiado guarda a definição e o XML gerado dela; o escrito à mão guarda só o XML. Ver api/roar_api/parsers.py.
CREATE TABLE parsers (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id) ON DELETE CASCADE,
  -- Vai no nome do decodificador: não muda depois de criado.
  nome text NOT NULL CHECK (nome ~ '^[a-z0-9][a-z0-9_]{0,40}$'),
  titulo text NOT NULL,
  modo text NOT NULL CHECK (modo IN ('guiado', 'xml')),
  definicao jsonb,
  xml text NOT NULL,
  exemplo text NOT NULL DEFAULT '',
  ativo boolean NOT NULL DEFAULT true,
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'aplicado', 'recusado')),
  mensagem text,
  criado_por uuid,
  criado_em timestamptz NOT NULL DEFAULT now(),
  alterado_em timestamptz NOT NULL DEFAULT now(),
  aplicado_em timestamptz,
  UNIQUE (cliente_id, nome)
);

-- Pedido de teste: a console grava, o serviço de parsers roda o log no gerenciador e devolve o resultado.
CREATE TABLE parser_testes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id) ON DELETE CASCADE,
  gerenciador_id text NOT NULL,
  log text NOT NULL CHECK (length(log) BETWEEN 1 AND 8000),
  xml text,
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'pronto', 'erro')),
  resultado jsonb,
  criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON parser_testes (gerenciador_id, id) WHERE estado = 'pendente';

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['parsers', 'parser_testes'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ingestao
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

GRANT SELECT, INSERT, DELETE ON parsers TO roar_api;
GRANT UPDATE (titulo, modo, definicao, xml, exemplo, ativo, estado, mensagem, alterado_em) ON parsers TO roar_api;
GRANT SELECT, INSERT ON parser_testes TO roar_api;
GRANT SELECT ON parsers TO roar_ingestao;
GRANT UPDATE (estado, mensagem, aplicado_em) ON parsers TO roar_ingestao;
GRANT SELECT, UPDATE, DELETE ON parser_testes TO roar_ingestao;
