-- Trazer de volta da cópia fria do armazém de eventos (roar_ingestao.copia_do_armazem). A cópia de cada dia fica numa pasta
-- só do root: o serviço que copia registra aqui os dias guardados de cada organização, para a tela mostrar o que dá para
-- trazer. E cada pedido de recuperação diz de onde o dia volta.
CREATE TABLE copias_do_armazem (
  cliente_id uuid NOT NULL REFERENCES clientes (id) ON DELETE CASCADE,
  dia date NOT NULL,
  PRIMARY KEY (cliente_id, dia)
);
ALTER TABLE copias_do_armazem ENABLE ROW LEVEL SECURITY;
ALTER TABLE copias_do_armazem FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON copias_do_armazem TO roar_api USING (cliente_id = roar_cliente_atual());
GRANT SELECT ON copias_do_armazem TO roar_api;

-- O pedido do indexador traz índices; o do armazém, dias (os nomes ficam em indices, como "logs:20261101").
ALTER TABLE recuperacoes ADD COLUMN origem text NOT NULL DEFAULT 'indexador' CHECK (origem IN ('indexador', 'armazem'));
GRANT INSERT (origem) ON recuperacoes TO roar_api;
