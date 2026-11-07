-- Pareceres da IA local sobre um alerta (roar_api.parecer). A IA lê só o pacote da investigação, e o Roar guarda o que
-- sobrou depois de conferir as citações: cada motivo aponta perguntas e alertas que estavam no pacote.
CREATE TABLE pareceres (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  evento_id bigint NOT NULL,
  modelo text NOT NULL,
  veredito text NOT NULL CHECK (veredito IN ('ataque', 'suspeito', 'benigno', 'inconclusivo')),
  confianca text NOT NULL CHECK (confianca IN ('baixa', 'media', 'alta')),
  resumo text NOT NULL,
  motivos jsonb NOT NULL DEFAULT '[]',
  proximos_passos jsonb NOT NULL DEFAULT '[]',
  -- O que o Roar tirou ou corrigiu na resposta: citação inventada, veredito sem prova, contradição com as perguntas.
  avisos jsonb NOT NULL DEFAULT '[]',
  segundos real NOT NULL,
  pedido_por uuid,
  -- Guardado na hora, como nos riscos: a API não lê a tabela de usuários.
  pedido_por_nome text,
  criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON pareceres (cliente_id, evento_id, criado_em DESC);

ALTER TABLE pareceres ENABLE ROW LEVEL SECURITY;
ALTER TABLE pareceres FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON pareceres TO roar_api
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());

GRANT SELECT, INSERT ON pareceres TO roar_api;
