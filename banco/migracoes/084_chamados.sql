-- Chamados em ferramentas de ITSM (roar_ingestao.chamados): ServiceNow, Jira Service Management e GLPI, cadastrados como
-- fontes. A tela pede o chamado de um caso; o serviço de fontes, que abre o cofre, cria na ferramenta e acompanha o
-- andamento. Quando a ferramenta resolve, entra uma nota automática no caso.
ALTER TABLE fontes DROP CONSTRAINT fontes_tipo_check;
ALTER TABLE fontes ADD CONSTRAINT fontes_tipo_check CHECK (tipo IN (
  'syslog', 'fluxo', 'webhook', 'api', 'github', 'office365', 'msgraph', 'aws', 'azure', 'gcp', 'okta', 'workspace',
  'servicenow', 'jira', 'glpi', 'slack', 'pagerduty', 'virustotal', 'maltiverse'));

CREATE TABLE chamados (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cliente_id uuid NOT NULL REFERENCES clientes (id),
  caso_id bigint NOT NULL,
  fonte_id bigint NOT NULL REFERENCES fontes (id),
  -- pedido: a tela pediu e o serviço ainda não criou; aberto: existe na ferramenta; resolvido: a ferramenta resolveu ou
  -- fechou; falhou: a ferramenta recusou depois de algumas tentativas, e o motivo fica em mensagem.
  estado text NOT NULL DEFAULT 'pedido' CHECK (estado IN ('pedido', 'aberto', 'resolvido', 'falhou')),
  -- O número que a pessoa vê (INC0010023, SOC-12, 345) e o identificador que a API da ferramenta usa.
  numero text,
  id_externo text,
  endereco text,
  situacao_externa text,
  mensagem text,
  tentativas smallint NOT NULL DEFAULT 0,
  pedido_por_nome text NOT NULL,
  pedido_em timestamptz NOT NULL DEFAULT now(),
  aberto_em timestamptz,
  resolvido_em timestamptz,
  conferido_em timestamptz,
  -- Um chamado por caso: pedir de novo depois de uma falha reaproveita a linha.
  UNIQUE (cliente_id, caso_id),
  FOREIGN KEY (cliente_id, caso_id) REFERENCES casos (cliente_id, id) ON DELETE CASCADE
);
CREATE INDEX ON chamados (estado, conferido_em);

ALTER TABLE chamados ENABLE ROW LEVEL SECURITY;
ALTER TABLE chamados FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON chamados TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT, INSERT, UPDATE (estado, fonte_id, mensagem, tentativas, pedido_por_nome, pedido_em) ON chamados TO roar_api;
GRANT SELECT, UPDATE (estado, numero, id_externo, endereco, situacao_externa, mensagem, tentativas, aberto_em, resolvido_em, conferido_em)
  ON chamados TO roar_ingestao;

-- O serviço lê do caso só o que vai no chamado, e escreve no histórico dele a abertura e a resolução.
CREATE POLICY isolamento_ingestao ON casos TO roar_ingestao USING (cliente_id = roar_cliente_atual());
GRANT SELECT (id, cliente_id, titulo, severidade, estado, prazo, criado_em) ON casos TO roar_ingestao;
CREATE POLICY isolamento_ingestao ON casos_notas TO roar_ingestao
  USING (cliente_id = roar_cliente_atual()) WITH CHECK (cliente_id = roar_cliente_atual());
GRANT INSERT (cliente_id, caso_id, autor_nome, automatica, texto) ON casos_notas TO roar_ingestao;
GRANT SELECT (id) ON casos_notas TO roar_ingestao;
