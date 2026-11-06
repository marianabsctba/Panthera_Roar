-- O e-mail do domínio (SPF, DKIM e DMARC), conferido junto com o nome do próprio domínio: o que foi achado, para a tela.
ALTER TABLE superficie_hosts ADD COLUMN email jsonb;
