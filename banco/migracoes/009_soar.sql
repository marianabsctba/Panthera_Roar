-- Automação: playbooks em blocos, cada execução e cada aprovação pedida no meio de uma execução.

CREATE ROLE roar_soar LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

CREATE TABLE playbooks (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  nome text NOT NULL,
  ativo boolean NOT NULL DEFAULT true,
  -- Quando, se e blocos. O formato está em motor/roar_motor/blocos.py.
  definicao jsonb NOT NULL,
  -- Não repete a resposta para o mesmo alvo dentro deste intervalo.
  intervalo_minutos integer NOT NULL DEFAULT 60 CHECK (intervalo_minutos BETWEEN 0 AND 10080),
  criado_por uuid NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  alterado_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cliente_id, id)
);

CREATE TABLE execucoes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  playbook_id bigint NOT NULL,
  gerenciador_id text NOT NULL REFERENCES gerenciadores (id),
  origem_tipo text NOT NULL CHECK (origem_tipo IN ('risco', 'evento')),
  origem_id bigint NOT NULL,
  alvo text,
  agente_id text,
  titulo text,
  -- Cópia do que foi disparado: editar o playbook depois não muda uma execução em andamento.
  definicao jsonb NOT NULL,
  contexto jsonb NOT NULL,
  estado text NOT NULL DEFAULT 'nova' CHECK (estado IN ('nova', 'executando', 'aguardando_aprovacao', 'concluida', 'falhou', 'recusada')),
  resultado jsonb,
  criada_em timestamptz NOT NULL DEFAULT now(),
  concluida_em timestamptz,
  UNIQUE (cliente_id, playbook_id, origem_tipo, origem_id),
  UNIQUE (cliente_id, id),
  FOREIGN KEY (cliente_id, playbook_id) REFERENCES playbooks (cliente_id, id)
);
CREATE INDEX ON execucoes (cliente_id, criada_em DESC);
CREATE INDEX ON execucoes (cliente_id, playbook_id, alvo, criada_em DESC);

CREATE TABLE aprovacoes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL,
  execucao_id bigint NOT NULL,
  -- Posição do bloco no playbook; a mesma aprovação não é pedida duas vezes.
  chave text NOT NULL,
  descricao text NOT NULL,
  estado text NOT NULL DEFAULT 'pendente' CHECK (estado IN ('pendente', 'aprovada', 'recusada', 'expirada')),
  decidida_por uuid,
  decidida_em timestamptz,
  motivo text,
  avisada boolean NOT NULL DEFAULT false,
  criada_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cliente_id, execucao_id, chave),
  FOREIGN KEY (cliente_id, execucao_id) REFERENCES execucoes (cliente_id, id)
);
CREATE INDEX ON aprovacoes (cliente_id, estado);

-- Só eventos usam cursor. Risco é relido enquanto estiver aberto, porque pode subir de alta para crítica.
CREATE TABLE soar_cursor (
  cliente_id uuid PRIMARY KEY REFERENCES clientes (id),
  ultimo_evento bigint NOT NULL DEFAULT 0
);

DO $$
DECLARE tabela text;
BEGIN
  FOREACH tabela IN ARRAY ARRAY['playbooks', 'execucoes', 'aprovacoes', 'soar_cursor'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tabela);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tabela);
    EXECUTE format('CREATE POLICY isolamento ON %I TO roar_api, roar_soar
                    USING (cliente_id = roar_cliente_atual())
                    WITH CHECK (cliente_id = roar_cliente_atual())', tabela);
  END LOOP;
END $$;

-- A API não lê a tabela de usuários, que guarda o hash da senha: só o nome de quem decidiu.
CREATE FUNCTION roar_nome_do_usuario(p_id uuid) RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
  AS $$ SELECT nome FROM usuarios WHERE id = p_id AND cliente_id = roar_cliente_atual() $$;
REVOKE ALL ON FUNCTION roar_nome_do_usuario(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_nome_do_usuario(uuid) TO roar_api;

GRANT SELECT, INSERT ON playbooks TO roar_api;
GRANT UPDATE (nome, ativo, definicao, intervalo_minutos, alterado_em) ON playbooks TO roar_api;
GRANT SELECT ON execucoes TO roar_api;
-- A pessoa só decide. Quem executa é o motor.
GRANT SELECT ON aprovacoes TO roar_api;
GRANT UPDATE (estado, decidida_por, decidida_em, motivo) ON aprovacoes TO roar_api;

GRANT SELECT ON playbooks TO roar_soar;
GRANT SELECT, INSERT ON execucoes TO roar_soar;
GRANT UPDATE (estado, resultado, concluida_em) ON execucoes TO roar_soar;
GRANT SELECT, INSERT ON aprovacoes TO roar_soar;
GRANT UPDATE (estado, avisada) ON aprovacoes TO roar_soar;
GRANT SELECT, INSERT, UPDATE ON soar_cursor TO roar_soar;

-- Só leitura do que dispara, e o percurso pelos clientes sem acesso ao nome deles.
CREATE POLICY leitura_soar ON eventos FOR SELECT TO roar_soar USING (cliente_id = roar_cliente_atual());
CREATE POLICY leitura_soar ON alertas_risco FOR SELECT TO roar_soar USING (cliente_id = roar_cliente_atual());
CREATE POLICY leitura_soar ON sinais FOR SELECT TO roar_soar USING (cliente_id = roar_cliente_atual());
CREATE POLICY leitura_soar ON entidades FOR SELECT TO roar_soar USING (cliente_id = roar_cliente_atual());
CREATE POLICY percurso_soar ON clientes FOR SELECT TO roar_soar USING (true);
CREATE POLICY percurso_soar ON gerenciadores FOR SELECT TO roar_soar USING (cliente_id = roar_cliente_atual());
GRANT SELECT ON alertas_risco, sinais, entidades, gerenciadores TO roar_soar;
-- O conteúdo bruto do alerta não é necessário para disparar.
GRANT SELECT (id, cliente_id, regra_id, regra_descricao, nivel, severidade, ip_origem, agente_id, gerenciador_id, ocorrido_em, recebido_em) ON eventos TO roar_soar;
GRANT SELECT (id) ON clientes TO roar_soar;
