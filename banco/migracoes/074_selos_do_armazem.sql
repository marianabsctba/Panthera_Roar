-- De onde vieram os eventos de cada selo (docs/clickhouse.md, etapa 4). Os selos antigos são do indexador e continuam
-- conferindo contra ele; os novos podem ser do armazém de eventos. A origem entra no cabeçalho assinado só quando é o
-- armazém, então nenhum selo antigo muda de hash.
ALTER TABLE selos ADD COLUMN origem text NOT NULL DEFAULT 'indexador' CHECK (origem IN ('indexador', 'armazem'));
