-- Regras escritas à mão em XML, biblioteca pública de regras e XML original das regras do Wazuh.
-- As duas últimas são públicas: não pertencem a nenhum cliente.
ALTER TABLE regras_proprias DROP CONSTRAINT regras_proprias_formato_check;
ALTER TABLE regras_proprias ADD CONSTRAINT regras_proprias_formato_check
  CHECK (formato IN ('sigma', 'guiada', 'xml', 'biblioteca'));

CREATE TABLE biblioteca_regras (
  id text PRIMARY KEY,
  titulo text NOT NULL,
  descricao text,
  autor text,
  nivel text,
  origem text,
  tecnicas text[] NOT NULL DEFAULT '{}',
  endereco text,
  conteudo text NOT NULL,
  convertivel boolean NOT NULL,
  motivo text,
  versao text NOT NULL
);
CREATE INDEX ON biblioteca_regras (convertivel);

CREATE TABLE arquivos_de_regras (
  arquivo text PRIMARY KEY,
  conteudo text NOT NULL,
  atualizado_em timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON biblioteca_regras, arquivos_de_regras TO roar_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON biblioteca_regras, arquivos_de_regras TO roar_ingestao;
