-- Caso: junta alertas, riscos e eventos de um mesmo incidente, com responsável, prazo e histórico.
CREATE TABLE casos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  titulo text NOT NULL CHECK (length(titulo) BETWEEN 1 AND 200),
  severidade text NOT NULL CHECK (severidade IN ('baixa', 'media', 'alta', 'critica')),
  estado text NOT NULL DEFAULT 'aberto' CHECK (estado IN ('aberto', 'investigando', 'encerrado')),
  desfecho text CHECK (desfecho IN ('incidente', 'falso_positivo', 'sem_acao')),
  responsavel_id uuid,
  responsavel_nome text,
  criado_por uuid NOT NULL,
  criado_por_nome text NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  atualizado_em timestamptz NOT NULL DEFAULT now(),
  prazo timestamptz NOT NULL,
  encerrado_em timestamptz,
  -- Encerrado sempre diz como terminou; aberto nunca tem desfecho.
  CHECK ((estado = 'encerrado') = (desfecho IS NOT NULL AND encerrado_em IS NOT NULL)),
  UNIQUE (cliente_id, id)
);
CREATE INDEX ON casos (cliente_id, estado, prazo);

CREATE TABLE casos_itens (
  cliente_id uuid NOT NULL,
  caso_id bigint NOT NULL,
  tipo text NOT NULL CHECK (tipo IN ('grupo', 'risco', 'evento')),
  item_id bigint NOT NULL,
  adicionado_por_nome text NOT NULL,
  adicionado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (caso_id, tipo, item_id),
  FOREIGN KEY (cliente_id, caso_id) REFERENCES casos (cliente_id, id) ON DELETE CASCADE
);
CREATE INDEX ON casos_itens (cliente_id, tipo, item_id);

-- O histórico só cresce: nota escrita não muda nem some.
CREATE TABLE casos_notas (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  caso_id bigint NOT NULL,
  autor_id uuid,
  autor_nome text NOT NULL,
  -- Mudança de estado, responsável ou itens vira nota automática.
  automatica boolean NOT NULL DEFAULT false,
  texto text NOT NULL CHECK (length(texto) BETWEEN 1 AND 4000),
  criado_em timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (cliente_id, caso_id) REFERENCES casos (cliente_id, id) ON DELETE CASCADE
);
CREATE INDEX ON casos_notas (caso_id, criado_em);

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['casos', 'casos_itens', 'casos_notas'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

GRANT SELECT, INSERT ON casos, casos_itens, casos_notas TO roar_api;
GRANT UPDATE (titulo, severidade, estado, desfecho, responsavel_id, responsavel_nome, atualizado_em, prazo, encerrado_em) ON casos TO roar_api;
GRANT DELETE ON casos_itens TO roar_api;
