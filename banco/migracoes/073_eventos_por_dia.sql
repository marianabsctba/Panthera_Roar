-- Alertas no Postgres só os recentes, divididos por dia (docs/clickhouse.md, etapa 3). O histórico inteiro fica no
-- armazém de eventos. Dia vencido sai inteiro, sem apagar linha por linha: é o que aguenta milhões de alertas por dia.
--
-- A tabela é recriada como particionada com as mesmas colunas, índices, políticas e permissões, e os dados vêm junto.
-- A chave primária e a de "não repetir" passam a levar ocorrido_em, que é como o Postgres divide a tabela: o mesmo
-- alerta reprocessado tem o mesmo ocorrido_em e continua não repetindo.

ALTER TABLE eventos RENAME TO eventos_antigos;
ALTER INDEX eventos_pais RENAME TO eventos_antigos_pais;
ALTER INDEX eventos_cidade RENAME TO eventos_antigos_cidade;
ALTER INDEX eventos_operadora RENAME TO eventos_antigos_operadora;

-- Sinal do UEBA aponta para o evento que o gerou; com o dia descartado, o sinal fica e o evento some, como acontece
-- com o que vence no índice. A referência deixa de ser chave estrangeira.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT conname, conrelid::regclass AS tabela FROM pg_constraint WHERE confrelid = 'eventos_antigos'::regclass LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', r.tabela, r.conname);
  END LOOP;
END $$;

CREATE TABLE eventos (
  id bigint GENERATED ALWAYS AS IDENTITY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  grupo_id bigint,
  origem text NOT NULL,
  origem_id text NOT NULL,
  ocorrido_em timestamptz NOT NULL,
  recebido_em timestamptz NOT NULL DEFAULT now(),
  nivel smallint NOT NULL,
  severidade text NOT NULL CHECK (severidade IN ('baixa', 'media', 'alta', 'critica')),
  regra_id text NOT NULL,
  regra_descricao text,
  regra_grupos text[] NOT NULL DEFAULT '{}',
  mitre text[] NOT NULL DEFAULT '{}',
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  agente_id text NOT NULL,
  agente_nome text,
  ip_origem inet,
  usuario text,
  bruto jsonb NOT NULL,
  pais text GENERATED ALWAYS AS (bruto #>> '{GeoLocation,country_name}') STORED,
  cidade text GENERATED ALWAYS AS (bruto #>> '{GeoLocation,city_name}') STORED,
  regiao text GENERATED ALWAYS AS (bruto #>> '{GeoLocation,region_name}') STORED,
  operadora text GENERATED ALWAYS AS (bruto #>> '{Operadora,organization_name}') STORED,
  asn text GENERATED ALWAYS AS (bruto #>> '{Operadora,asn}') STORED,
  PRIMARY KEY (id, ocorrido_em),
  UNIQUE (cliente_id, origem, origem_id, ocorrido_em),
  -- O grupo precisa ser do mesmo cliente do evento.
  FOREIGN KEY (cliente_id, grupo_id) REFERENCES grupos_alerta (cliente_id, id)
) PARTITION BY RANGE (ocorrido_em);

-- O que cai fora dos dias criados (data muito antiga ou no futuro) fica aqui, e a manutenção apaga quando vence.
CREATE TABLE eventos_fora_dos_dias PARTITION OF eventos DEFAULT;

CREATE INDEX ON eventos (cliente_id, ocorrido_em DESC);
CREATE INDEX ON eventos (cliente_id, usuario, ocorrido_em DESC);
CREATE INDEX ON eventos (cliente_id, grupo_id);
CREATE INDEX ON eventos (cliente_id, regra_id, ocorrido_em DESC);
CREATE INDEX eventos_pais ON eventos (cliente_id, pais) WHERE pais IS NOT NULL;
CREATE INDEX eventos_cidade ON eventos (cliente_id, pais, cidade) WHERE pais IS NOT NULL;
CREATE INDEX eventos_operadora ON eventos (cliente_id, operadora) WHERE operadora IS NOT NULL;
-- Leitores com cursor (UEBA, SOAR, inteligência) andam por id.
CREATE INDEX ON eventos (id);

ALTER TABLE eventos ENABLE ROW LEVEL SECURITY;
ALTER TABLE eventos FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON eventos TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
CREATE POLICY leitura_ueba ON eventos FOR SELECT TO roar_ueba USING (cliente_id = roar_cliente_atual());
CREATE POLICY leitura_soar ON eventos FOR SELECT TO roar_soar USING (cliente_id = roar_cliente_atual());

GRANT SELECT, INSERT ON eventos TO roar_ingestao;
GRANT UPDATE (grupo_id) ON eventos TO roar_ingestao;
GRANT SELECT ON eventos TO roar_api, roar_ueba;
GRANT SELECT (id, cliente_id, regra_id, regra_descricao, nivel, severidade, ip_origem, agente_id, gerenciador_id, ocorrido_em, recebido_em, usuario, pais)
  ON eventos TO roar_soar;

-- Cria os dias de amanhã em diante e descarta os que passaram do prazo. Roda pela ingestão, uma vez por hora.
CREATE FUNCTION roar_manter_dias_de_eventos(p_dias_guardados integer, p_dias_a_frente integer DEFAULT 3) RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE
  dia date;
  nome text;
  descartados integer := 0;
  r record;
BEGIN
  IF p_dias_guardados < 7 THEN
    RAISE EXCEPTION 'guardar menos de 7 dias de alertas no Postgres não é permitido';
  END IF;
  FOR dia IN SELECT generate_series(current_date - 1, current_date + p_dias_a_frente, interval '1 day')::date LOOP
    nome := format('eventos_%s', to_char(dia, 'YYYYMMDD'));
    IF to_regclass(nome) IS NULL THEN
      -- Dia que já tem linhas no "fora dos dias" não pode virar partição sem tirá-las antes: ficam lá até vencer.
      IF NOT EXISTS (SELECT 1 FROM eventos_fora_dos_dias WHERE ocorrido_em >= dia AND ocorrido_em < dia + 1) THEN
        EXECUTE format('CREATE TABLE %I PARTITION OF eventos FOR VALUES FROM (%L) TO (%L)', nome, dia, dia + 1);
      END IF;
    END IF;
  END LOOP;
  FOR r IN SELECT c.relname, (regexp_match(c.relname, '^eventos_(\d{8})$'))[1] AS dia
           FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
           WHERE i.inhparent = 'eventos'::regclass AND c.relname ~ '^eventos_\d{8}$' LOOP
    IF to_date(r.dia, 'YYYYMMDD') < current_date - p_dias_guardados THEN
      EXECUTE format('DROP TABLE %I', r.relname);
      descartados := descartados + 1;
    END IF;
  END LOOP;
  DELETE FROM eventos_fora_dos_dias WHERE ocorrido_em < current_date - p_dias_guardados;
  RETURN descartados;
END $$;
REVOKE ALL ON FUNCTION roar_manter_dias_de_eventos(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_manter_dias_de_eventos(integer, integer) TO roar_ingestao;

-- Os dias dos dados que já existem (até 90 para trás) ganham a própria partição; o resto vai para o "fora dos dias".
DO $$
DECLARE dia date;
BEGIN
  FOR dia IN SELECT generate_series(greatest(coalesce((SELECT min(ocorrido_em)::date FROM eventos_antigos), current_date), current_date - 90),
                                    current_date + 3, interval '1 day')::date LOOP
    EXECUTE format('CREATE TABLE %I PARTITION OF eventos FOR VALUES FROM (%L) TO (%L)', format('eventos_%s', to_char(dia, 'YYYYMMDD')), dia, dia + 1);
  END LOOP;
END $$;

INSERT INTO eventos (id, cliente_id, grupo_id, origem, origem_id, ocorrido_em, recebido_em, nivel, severidade, regra_id, regra_descricao,
                     regra_grupos, mitre, gerenciador_id, agente_id, agente_nome, ip_origem, usuario, bruto)
  OVERRIDING SYSTEM VALUE
  SELECT id, cliente_id, grupo_id, origem, origem_id, ocorrido_em, recebido_em, nivel, severidade, regra_id, regra_descricao,
         regra_grupos, mitre, gerenciador_id, agente_id, agente_nome, ip_origem, usuario, bruto
  FROM eventos_antigos;
SELECT setval(pg_get_serial_sequence('eventos', 'id'), greatest((SELECT coalesce(max(id), 0) FROM eventos_antigos), 1));

DROP TABLE eventos_antigos;

-- O leitor do armazém anda por (recebido_em, id), sem casar com a hora do evento.
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS posicao text;
