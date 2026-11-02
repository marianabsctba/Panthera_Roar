-- Inteligência de ameaças opcional, por cliente. Os indicadores vêm para cá, para o evento não depender de consulta externa.
-- Nada volta para a fonte: dizer "vi este indicador" revelaria o que o cliente tem.
CREATE TABLE intel_fontes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  nome text NOT NULL,
  tipo text NOT NULL CHECK (tipo IN ('misp', 'taxii')),
  endereco text NOT NULL,
  colecao text,
  segredo text,
  ativa boolean NOT NULL DEFAULT true,
  a_cada_minutos integer NOT NULL DEFAULT 60 CHECK (a_cada_minutos BETWEEN 5 AND 10080),
  proxima_em timestamptz NOT NULL DEFAULT now(),
  ultima_em timestamptz,
  ultimo_erro text,
  criado_por uuid NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cliente_id, nome)
);

CREATE TABLE intel_indicadores (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  fonte_id bigint NOT NULL REFERENCES intel_fontes (id),
  tipo text NOT NULL CHECK (tipo IN ('ip', 'dominio', 'url', 'md5', 'sha1', 'sha256')),
  valor text NOT NULL,
  descricao text,
  primeira_vez timestamptz NOT NULL DEFAULT now(),
  ultima_vez timestamptz NOT NULL DEFAULT now(),
  UNIQUE (fonte_id, tipo, valor)
);
CREATE INDEX ON intel_indicadores (cliente_id, tipo, valor);

CREATE TABLE intel_ocorrencias (
  indicador_id bigint NOT NULL REFERENCES intel_indicadores (id) ON DELETE CASCADE,
  evento_id bigint NOT NULL,
  cliente_id uuid NOT NULL,
  ocorrido_em timestamptz NOT NULL,
  encontrada_em timestamptz NOT NULL DEFAULT now(),
  -- Encontrada olhando para trás: o indicador chegou depois do evento.
  no_passado boolean NOT NULL DEFAULT false,
  PRIMARY KEY (indicador_id, evento_id)
);
CREATE INDEX ON intel_ocorrencias (cliente_id, ocorrido_em DESC);

CREATE TABLE intel_cursor (
  cliente_id uuid PRIMARY KEY,
  ultimo_evento bigint NOT NULL DEFAULT 0
);

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['intel_fontes', 'intel_indicadores', 'intel_ocorrencias', 'intel_cursor'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ingestao
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

GRANT SELECT, INSERT ON intel_fontes TO roar_api;
GRANT UPDATE (ativa, proxima_em) ON intel_fontes TO roar_api;
GRANT SELECT ON intel_indicadores, intel_ocorrencias TO roar_api;

GRANT SELECT ON intel_fontes TO roar_ingestao;
GRANT UPDATE (proxima_em, ultima_em, ultimo_erro) ON intel_fontes TO roar_ingestao;
GRANT SELECT, INSERT, UPDATE ON intel_indicadores TO roar_ingestao;
GRANT SELECT, INSERT ON intel_ocorrencias TO roar_ingestao;
GRANT SELECT, INSERT, UPDATE ON intel_cursor TO roar_ingestao;
GRANT SELECT ON eventos TO roar_ingestao;

-- Evento encontrado em inteligência avisa quem acompanha, somando no mesmo aviso.
CREATE FUNCTION roar_avisar_inteligencia(p_cliente uuid, p_valor text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  UPDATE notificacoes SET contagem = contagem + 1, atualizada_em = now()
    WHERE cliente_id = p_cliente AND tipo = 'indicador_encontrado' AND alvo = left(p_valor, 300) AND lida_em IS NULL;
  IF NOT FOUND THEN
    INSERT INTO notificacoes (cliente_id, tipo, alvo) VALUES (p_cliente, 'indicador_encontrado', left(p_valor, 300));
  END IF;
END $$;
REVOKE ALL ON FUNCTION roar_avisar_inteligencia(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_avisar_inteligencia(uuid, text) TO roar_ingestao;
