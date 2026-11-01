-- Matriz completa do MITRE ATT&CK: base pública, não pertence a nenhum cliente.
CREATE TABLE taticas_attack (
  tatica text PRIMARY KEY,
  nome text NOT NULL,
  ordem smallint NOT NULL
);
CREATE TABLE tecnicas_attack (
  tecnica text PRIMARY KEY,
  nome text NOT NULL,
  taticas text[] NOT NULL,
  pai text,
  endereco text,
  versao text NOT NULL
);
CREATE INDEX ON tecnicas_attack (pai);
GRANT SELECT ON taticas_attack, tecnicas_attack TO roar_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON taticas_attack, tecnicas_attack TO roar_ingestao;
