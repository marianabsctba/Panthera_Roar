-- Listas públicas que dão contexto a um alerta. Ficam aqui para consultar sem contar a ninguém o que se está olhando.
-- Não pertencem a nenhum cliente.
CREATE TABLE contexto_redes (
  lista text NOT NULL,
  rotulo text NOT NULL,
  rede cidr NOT NULL
);
CREATE INDEX contexto_redes_rede ON contexto_redes USING gist (rede inet_ops);
CREATE INDEX ON contexto_redes (lista);

CREATE TABLE contexto_itens (
  lista text NOT NULL,
  chave text NOT NULL,
  rotulo text NOT NULL,
  detalhe text,
  endereco text,
  PRIMARY KEY (lista, chave)
);

ALTER TABLE bibliotecas_estado DROP CONSTRAINT bibliotecas_estado_nome_check;

GRANT SELECT ON contexto_redes, contexto_itens TO roar_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON contexto_redes, contexto_itens TO roar_ingestao;
