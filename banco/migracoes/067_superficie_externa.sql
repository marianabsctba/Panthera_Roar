-- Superfície externa: os domínios que a organização declara como seus, e o que deles aparece na internet.
-- Quem trabalha é ingestao/roar_ingestao/superficie.py, aos poucos e sem parar: a descoberta lista os nomes de um domínio
-- por vez, e cada nome entra numa fila com hora marcada para ser conferido. Os achados vão para Vulnerabilidades (fonte 'externa').
CREATE TABLE superficie_dominios (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id) ON DELETE CASCADE,
  dominio text NOT NULL CHECK (dominio ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$'),
  -- Varrer o que é de terceiros não é permitido: quem cadastra declara ser dono ou ter autorização, e fica registrado.
  autorizado_por uuid NOT NULL,
  autorizado_por_nome text NOT NULL,
  autorizado_em timestamptz NOT NULL DEFAULT now(),
  ativo boolean NOT NULL DEFAULT true,
  -- De quanto em quanto tempo procura nomes novos, e de quanto em quanto tempo confere cada nome.
  descobrir_a_cada_horas integer NOT NULL DEFAULT 24 CHECK (descobrir_a_cada_horas BETWEEN 6 AND 720),
  conferir_a_cada_horas integer NOT NULL DEFAULT 6 CHECK (conferir_a_cada_horas BETWEEN 1 AND 168),
  proxima_descoberta timestamptz,
  ultima_descoberta timestamptz,
  ultimo_erro text,
  UNIQUE (cliente_id, dominio)
);

CREATE TABLE superficie_hosts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  dominio_id bigint NOT NULL REFERENCES superficie_dominios (id) ON DELETE CASCADE,
  nome text NOT NULL,
  ips text[] NOT NULL DEFAULT '{}',
  -- De onde o nome veio: registro público de certificados, nome comum testado no DNS, ou o próprio domínio.
  origem text NOT NULL CHECK (origem IN ('certificados', 'dns', 'dominio')),
  interno boolean NOT NULL DEFAULT false,
  -- Saiu do DNS na última descoberta: os achados dele fecham, e o nome some da tela em 30 dias.
  sumiu boolean NOT NULL DEFAULT false,
  portas integer[] NOT NULL DEFAULT '{}',
  tls_vence timestamptz,
  tls_emissor text,
  tls_problema text,
  -- A fila: cada nome tem a hora da próxima conferência, e quem está sendo conferido agora fica marcado.
  proxima_conferencia timestamptz NOT NULL DEFAULT now(),
  conferindo_desde timestamptz,
  conferido_em timestamptz,
  primeira_vez timestamptz NOT NULL DEFAULT now(),
  ultima_vez timestamptz NOT NULL DEFAULT now(),
  UNIQUE (dominio_id, nome)
);
CREATE INDEX ON superficie_hosts (proxima_conferencia) WHERE NOT sumiu;

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['superficie_dominios', 'superficie_hosts'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_ingestao
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

GRANT SELECT, INSERT, DELETE ON superficie_dominios TO roar_api;
GRANT UPDATE (ativo, descobrir_a_cada_horas, conferir_a_cada_horas, proxima_descoberta) ON superficie_dominios TO roar_api;
GRANT SELECT ON superficie_hosts TO roar_api;
GRANT UPDATE (proxima_conferencia) ON superficie_hosts TO roar_api;
GRANT SELECT ON superficie_dominios TO roar_ingestao;
GRANT UPDATE (proxima_descoberta, ultima_descoberta, ultimo_erro) ON superficie_dominios TO roar_ingestao;
GRANT SELECT, INSERT, UPDATE, DELETE ON superficie_hosts TO roar_ingestao;

-- A fila é de todas as organizações, mas o serviço só enxerga uma por vez (RLS). Estas duas funções dizem, sem mostrar
-- nada de dentro, qual organização tem trabalho vencido: o próximo da fila sai pela hora, não pela organização.
CREATE FUNCTION roar_superficie_proxima_descoberta() RETURNS TABLE (cliente_id uuid, dominio_id bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT cliente_id, id FROM superficie_dominios WHERE ativo AND (proxima_descoberta IS NULL OR proxima_descoberta <= now())
        ORDER BY proxima_descoberta NULLS FIRST LIMIT 1 $$;
CREATE FUNCTION roar_superficie_proximos_nomes(p_quantos integer) RETURNS TABLE (cliente_id uuid, host_id bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT h.cliente_id, h.id FROM superficie_hosts h JOIN superficie_dominios d ON d.id = h.dominio_id
        WHERE d.ativo AND NOT h.sumiu AND h.proxima_conferencia <= now() ORDER BY h.proxima_conferencia LIMIT least(p_quantos, 20) $$;
REVOKE ALL ON FUNCTION roar_superficie_proxima_descoberta(), roar_superficie_proximos_nomes(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_superficie_proxima_descoberta(), roar_superficie_proximos_nomes(integer) TO roar_ingestao;
