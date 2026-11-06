-- A API só faz consultas curtas, para a tela. Nelas, compilar o plano custa mais que rodar: a aba Correção levava
-- um segundo compilando e 90 ms sem compilar. Consultas longas de relatório continuam rápidas sem isso.
ALTER ROLE roar_api SET jit = off;
