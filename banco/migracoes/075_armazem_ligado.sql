-- O armazém de eventos passa a ser o padrão (docs/clickhouse.md, etapa 5): toda organização lê dele. A que ainda não
-- tem banco no armazém continua lendo do indexador, pela API, até ter.
ALTER TABLE clientes ALTER COLUMN ler_do_armazem SET DEFAULT true;
UPDATE clientes SET ler_do_armazem = true;
