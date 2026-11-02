-- Busca periódica em um sistema sem módulo pronto. Guarda o que já entregou para não repetir.
ALTER TABLE fontes DROP CONSTRAINT fontes_tipo_check;
ALTER TABLE fontes ADD CONSTRAINT fontes_tipo_check CHECK (tipo IN ('syslog', 'github', 'office365', 'webhook', 'api'));
ALTER TABLE fontes ADD COLUMN proxima_busca timestamptz;
ALTER TABLE fontes ADD COLUMN vistos text[] NOT NULL DEFAULT '{}';

GRANT UPDATE (proxima_busca, vistos, ultimo_dado_em) ON fontes TO roar_ingestao;
