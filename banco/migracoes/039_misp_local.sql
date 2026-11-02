-- A fonte que já vem com a instalação. O endereço e a chave ficam no serviço, nunca no banco nem na tela.
ALTER TABLE intel_fontes ADD COLUMN interna boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX ON intel_fontes (cliente_id) WHERE interna;

GRANT INSERT ON intel_fontes TO roar_ingestao;
GRANT UPDATE (ativa, proxima_em) ON intel_fontes TO roar_api;
