-- Casos, parte 2: fato e hipótese separados, passagem de plantão e evidências guardadas no caso.

-- A nota ganha um tipo. O texto continua sem mudar; só a situação da hipótese muda, e cada mudança vira nota automática.
ALTER TABLE casos_notas ADD COLUMN tipo text NOT NULL DEFAULT 'nota' CHECK (tipo IN ('nota', 'fato', 'hipotese', 'passagem'));
ALTER TABLE casos_notas ADD COLUMN situacao text CHECK (situacao IN ('aberta', 'confirmada', 'descartada'));
ALTER TABLE casos_notas ADD CONSTRAINT casos_notas_hipotese_tem_situacao CHECK ((tipo = 'hipotese') = (situacao IS NOT NULL));
GRANT UPDATE (situacao) ON casos_notas TO roar_api;

-- Evidência guardada no caso: o pacote de prova dos eventos do caso, ou um arquivo anexado, como um print.
-- Não se apaga nem se troca: o resumo de cada uma fica no histórico do caso, que é a cadeia de custódia.
CREATE TABLE casos_evidencias (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  caso_id bigint NOT NULL,
  tipo text NOT NULL CHECK (tipo IN ('pacote', 'arquivo')),
  nome text NOT NULL CHECK (length(nome) BETWEEN 1 AND 200),
  tipo_midia text NOT NULL,
  descricao text NOT NULL DEFAULT '' CHECK (length(descricao) <= 1000),
  conteudo bytea NOT NULL,
  tamanho integer NOT NULL,
  sha256 text NOT NULL,
  adicionado_por uuid NOT NULL,
  adicionado_por_nome text NOT NULL,
  adicionado_em timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (cliente_id, caso_id) REFERENCES casos (cliente_id, id) ON DELETE CASCADE
);
CREATE INDEX ON casos_evidencias (caso_id, adicionado_em);
ALTER TABLE casos_evidencias ENABLE ROW LEVEL SECURITY;
ALTER TABLE casos_evidencias FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON casos_evidencias TO roar_api
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT, INSERT ON casos_evidencias TO roar_api;
