-- Buscas salvas, que podem rodar sozinhas e avisar, e painéis montados com blocos de busca.
-- O texto é o da linguagem de consulta (api/roar_api/consulta.py); quem roda as agendadas é ingestao/roar_ingestao/buscas.py.
CREATE TABLE buscas_salvas (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id) ON DELETE CASCADE,
  nome text NOT NULL,
  texto text NOT NULL CHECK (length(texto) <= 2000),
  janela_minutos integer NOT NULL,
  -- Sem intervalo, é só uma busca guardada. Com intervalo, roda sozinha e avisa quando a condição vale.
  a_cada_minutos integer CHECK (a_cada_minutos BETWEEN 5 AND 10080),
  condicao text NOT NULL DEFAULT 'qualquer' CHECK (condicao IN ('qualquer', 'mais_de', 'nenhum')),
  limite integer NOT NULL DEFAULT 0 CHECK (limite >= 0),
  ativa boolean NOT NULL DEFAULT true,
  proxima_em timestamptz,
  ultima_em timestamptz,
  ultimo_total bigint,
  ultimo_erro text,
  criada_por uuid,
  criada_em timestamptz NOT NULL DEFAULT now(),
  alterada_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cliente_id, nome),
  UNIQUE (cliente_id, id)
);
CREATE INDEX ON buscas_salvas (proxima_em) WHERE ativa AND a_cada_minutos IS NOT NULL;

CREATE TABLE buscas_execucoes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  busca_id bigint NOT NULL,
  em timestamptz NOT NULL DEFAULT now(),
  total bigint,
  disparou boolean NOT NULL DEFAULT false,
  erro text,
  FOREIGN KEY (cliente_id, busca_id) REFERENCES buscas_salvas (cliente_id, id) ON DELETE CASCADE
);
CREATE INDEX ON buscas_execucoes (busca_id, em DESC);

CREATE TABLE paineis (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id) ON DELETE CASCADE,
  nome text NOT NULL,
  -- [{"titulo", "tipo", "texto", "minutos", "campo", "tamanho", "largura"}]: conferido pela API.
  blocos jsonb NOT NULL DEFAULT '[]',
  criado_por uuid,
  criado_em timestamptz NOT NULL DEFAULT now(),
  alterado_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cliente_id, nome)
);

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['buscas_salvas', 'buscas_execucoes', 'paineis'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ingestao
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

GRANT SELECT, INSERT, DELETE ON buscas_salvas, paineis TO roar_api;
GRANT UPDATE (nome, texto, janela_minutos, a_cada_minutos, condicao, limite, ativa, proxima_em, alterada_em) ON buscas_salvas TO roar_api;
GRANT UPDATE (nome, blocos, alterado_em) ON paineis TO roar_api;
GRANT SELECT ON buscas_execucoes TO roar_api;
GRANT SELECT ON buscas_salvas TO roar_ingestao;
GRANT UPDATE (proxima_em, ultima_em, ultimo_total, ultimo_erro) ON buscas_salvas TO roar_ingestao;
GRANT SELECT, INSERT, DELETE ON buscas_execucoes TO roar_ingestao;
-- O aviso no sino vem da função da migração 057, que só ela grava em notificações.
GRANT EXECUTE ON FUNCTION roar_avisar(uuid, text, text) TO roar_ingestao;
