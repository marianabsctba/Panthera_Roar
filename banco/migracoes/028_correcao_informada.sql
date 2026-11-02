-- Quem corrigiu diz que corrigiu; quem confirma é a varredura. Até lá, o risco continua contando.
ALTER TABLE vuln_achados DROP CONSTRAINT vuln_achados_estado_check;
ALTER TABLE vuln_achados ADD CONSTRAINT vuln_achados_estado_check CHECK (estado IN ('aberto', 'correcao_informada', 'corrigido', 'aceito', 'falso_positivo'));
