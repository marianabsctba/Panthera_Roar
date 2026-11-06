-- Listas de observação: IPs, usuários, domínios ou hashes que as regras consultam. Cada lista vira um arquivo
-- no gerenciador da organização (ingestao/roar_ingestao/listas.py), que as regras em XML citam pelo nome.
CREATE TABLE listas (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id) ON DELETE CASCADE,
  -- Vai no caminho do arquivo e na regra: não muda depois de criada.
  nome text NOT NULL CHECK (nome ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
  titulo text NOT NULL,
  descricao text NOT NULL DEFAULT '',
  tipo text NOT NULL CHECK (tipo IN ('ip', 'usuario', 'dominio', 'hash', 'texto')),
  criada_por uuid,
  criada_em timestamptz NOT NULL DEFAULT now(),
  alterada_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cliente_id, nome),
  UNIQUE (cliente_id, id)
);

CREATE TABLE listas_itens (
  cliente_id uuid NOT NULL,
  lista_id bigint NOT NULL,
  valor text NOT NULL CHECK (length(valor) BETWEEN 1 AND 255 AND valor !~ '[\r\n]'),
  nota text NOT NULL DEFAULT '' CHECK (length(nota) <= 200 AND nota !~ '[\r\n]'),
  adicionado_por uuid,
  adicionado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (lista_id, valor),
  FOREIGN KEY (cliente_id, lista_id) REFERENCES listas (cliente_id, id) ON DELETE CASCADE
);

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['listas', 'listas_itens'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ingestao
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

GRANT SELECT, INSERT, DELETE ON listas, listas_itens TO roar_api;
GRANT UPDATE (titulo, descricao, alterada_em) ON listas TO roar_api;
GRANT UPDATE (nota) ON listas_itens TO roar_api;
GRANT SELECT ON listas, listas_itens TO roar_ingestao;
