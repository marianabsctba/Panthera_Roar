-- Quem instala só vulnerabilidades tem cliente sem gerenciador, e o serviço de varredura precisa encontrá-lo.
CREATE POLICY percurso_ingestao ON clientes FOR SELECT TO roar_ingestao USING (true);
GRANT SELECT (id) ON clientes TO roar_ingestao;
