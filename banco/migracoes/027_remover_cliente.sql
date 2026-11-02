-- Os cursores são estado dos serviços, e com eles rodando todo cliente tem um: sem isto, nenhum cliente poderia ser removido.
ALTER TABLE ueba_cursor DROP CONSTRAINT ueba_cursor_cliente_id_fkey;
ALTER TABLE ueba_cursor ADD CONSTRAINT ueba_cursor_cliente_id_fkey FOREIGN KEY (cliente_id) REFERENCES clientes (id) ON DELETE CASCADE;
ALTER TABLE soar_cursor DROP CONSTRAINT IF EXISTS soar_cursor_cliente_id_fkey;
ALTER TABLE soar_cursor ADD CONSTRAINT soar_cursor_cliente_id_fkey FOREIGN KEY (cliente_id) REFERENCES clientes (id) ON DELETE CASCADE;
