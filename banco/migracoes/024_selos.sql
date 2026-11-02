-- Selos de integridade: cada janela de eventos vira uma raiz de Merkle encadeada à anterior e assinada.
-- Só aceita acréscimo. Quem quiser reescrever a história precisa desligar o gatilho, e ainda assim
-- não consegue assinar: a chave privada fica fora do banco.
-- Sem chave estrangeira para cliente: encerrar um cliente não pode reescrever a história nem travar.
-- Só resumos e identificadores ficam para trás, nenhum conteúdo de log.
CREATE TABLE selos (
  gerenciador_id text NOT NULL,
  n bigint NOT NULL CHECK (n >= 1),
  cliente_id uuid NOT NULL,
  fonte text NOT NULL CHECK (fonte IN ('alertas', 'logs')),
  inicio timestamptz NOT NULL,
  fim timestamptz NOT NULL CHECK (fim > inicio),
  total bigint NOT NULL CHECK (total >= 0),
  tardio boolean NOT NULL DEFAULT false,
  raiz text NOT NULL,
  anterior text NOT NULL,
  hash text NOT NULL UNIQUE,
  assinatura text NOT NULL,
  chave text NOT NULL,
  selado_em timestamptz NOT NULL,
  PRIMARY KEY (gerenciador_id, n)
);
CREATE INDEX ON selos (cliente_id, fonte, fim DESC);
CREATE INDEX ON selos (gerenciador_id, fonte, inicio);

-- O que permite apontar qual evento mudou e montar a prova de um só. Separado do selo porque ocupa
-- espaço, e porque o sal de cada folha não pode sair daqui: é ele que protege os eventos vizinhos.
CREATE TABLE selo_folhas (
  gerenciador_id text NOT NULL,
  n bigint NOT NULL,
  cliente_id uuid NOT NULL,
  segredo bytea NOT NULL,
  folhas bytea NOT NULL,
  PRIMARY KEY (gerenciador_id, n),
  FOREIGN KEY (gerenciador_id, n) REFERENCES selos (gerenciador_id, n)
);

CREATE TABLE selo_verificacoes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  gerenciador_id text NOT NULL,
  quando timestamptz NOT NULL DEFAULT now(),
  completa boolean NOT NULL,
  selos_conferidos bigint NOT NULL,
  eventos_conferidos bigint NOT NULL,
  estado text NOT NULL CHECK (estado IN ('integra', 'violada')),
  achados jsonb NOT NULL DEFAULT '[]'
);
CREATE INDEX ON selo_verificacoes (cliente_id, quando DESC);

-- Âncora pública: o resumo da cadeia registrado fora do nosso controle. Só o resumo sai daqui.
CREATE TABLE selo_ancoras (
  gerenciador_id text NOT NULL,
  n bigint NOT NULL,
  cliente_id uuid NOT NULL,
  hash text NOT NULL,
  calendario text NOT NULL,
  recibo bytea NOT NULL,
  criada_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gerenciador_id, n, calendario),
  FOREIGN KEY (gerenciador_id, n) REFERENCES selos (gerenciador_id, n)
);

CREATE FUNCTION roar_selo_so_acrescenta() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'selos de integridade não podem ser alterados nem apagados';
END $$;

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['selos', 'selo_folhas', 'selo_verificacoes', 'selo_ancoras'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ingestao
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
    EXECUTE format('CREATE TRIGGER so_acrescenta BEFORE UPDATE OR DELETE ON %I
                    FOR EACH ROW EXECUTE FUNCTION roar_selo_so_acrescenta()', tabela);
    EXECUTE format('CREATE TRIGGER nao_truncar BEFORE TRUNCATE ON %I
                    FOR EACH STATEMENT EXECUTE FUNCTION roar_selo_so_acrescenta()', tabela);
  END LOOP;
END $$;

GRANT SELECT, INSERT ON selos, selo_folhas, selo_verificacoes, selo_ancoras TO roar_ingestao;
-- A API gera a prova de um evento, então lê as folhas; nunca escreve em nada disto.
GRANT SELECT ON selos, selo_folhas, selo_verificacoes, selo_ancoras TO roar_api;
