-- O PDF de um painel entra no mesmo histórico dos relatórios. A coluna norma guarda o nome do painel.
ALTER TABLE relatorios_gerados DROP CONSTRAINT relatorios_gerados_tipo_check;
ALTER TABLE relatorios_gerados ADD CONSTRAINT relatorios_gerados_tipo_check CHECK (tipo IN ('completo', 'executivo', 'norma', 'painel'));
