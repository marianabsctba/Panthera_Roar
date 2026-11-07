-- Selo em blocos (roar_ingestao.selo_em_blocos): para janelas grandes do armazém de eventos, as folhas são calculadas no
-- próprio armazém e juntadas em blocos, e o Postgres guarda só o resumo de cada bloco (em selo_folhas). Os selos de antes
-- ficam na versão 1, com o mesmo cabeçalho e o mesmo hash de sempre.
ALTER TABLE selos ADD COLUMN versao smallint NOT NULL DEFAULT 1 CHECK (versao IN (1, 2));
-- Quantos blocos a janela usou, e quantos tinham evento (as folhas da árvore de cima).
ALTER TABLE selos ADD COLUMN blocos integer CHECK (blocos >= 1);
ALTER TABLE selos ADD COLUMN folhas_superiores integer CHECK (folhas_superiores >= 0);
-- Que eventos o selo cobre pela hora de chegada ao armazém: o que chegar depois entra num selo tardio.
ALTER TABLE selos ADD COLUMN recebido_de timestamptz;
ALTER TABLE selos ADD COLUMN recebido_ate timestamptz;
ALTER TABLE selos ADD CONSTRAINT selo_em_blocos_completo
  CHECK (versao = 1 OR (blocos IS NOT NULL AND folhas_superiores IS NOT NULL AND recebido_ate IS NOT NULL AND origem = 'armazem'));
