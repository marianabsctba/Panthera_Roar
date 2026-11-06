-- Avisos do sino também por e-mail, pelo servidor de e-mail da própria organização.
-- A senha fica no cofre (segredos, nome "email-senha"): a API fecha e não abre; quem abre é o serviço de avisos.
CREATE TABLE email_config (
  cliente_id uuid PRIMARY KEY REFERENCES clientes (id) ON DELETE CASCADE,
  servidor text NOT NULL CHECK (servidor ~ '^[A-Za-z0-9.-]{1,253}$'),
  porta integer NOT NULL CHECK (porta IN (25, 465, 587, 2525)),
  seguranca text NOT NULL CHECK (seguranca IN ('starttls', 'ssl')),
  usuario text NOT NULL DEFAULT '',
  remetente text NOT NULL,
  destinatarios text[] NOT NULL CHECK (cardinality(destinatarios) BETWEEN 1 AND 20),
  -- Vazio: todos os avisos do sino.
  tipos text[] NOT NULL DEFAULT '{}',
  ativo boolean NOT NULL DEFAULT true,
  -- O último aviso já mandado. Ao ligar, começa do aviso mais novo: não manda o passado inteiro.
  ultima_notificacao bigint NOT NULL DEFAULT 0,
  ultimo_envio timestamptz,
  ultimo_erro text,
  teste_pedido_em timestamptz,
  teste_resultado text,
  teste_em timestamptz,
  atualizado_por uuid,
  atualizado_em timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE email_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_config FORCE ROW LEVEL SECURITY;
CREATE POLICY isolamento ON email_config TO roar_api, roar_ingestao
  USING (cliente_id = roar_cliente_atual())
  WITH CHECK (cliente_id = roar_cliente_atual());
GRANT SELECT, INSERT, DELETE ON email_config TO roar_api;
GRANT UPDATE (servidor, porta, seguranca, usuario, remetente, destinatarios, tipos, ativo, ultima_notificacao, teste_pedido_em, teste_resultado,
              atualizado_por, atualizado_em) ON email_config TO roar_api;
GRANT SELECT ON email_config TO roar_ingestao;
GRANT UPDATE (ultima_notificacao, ultimo_envio, ultimo_erro, teste_pedido_em, teste_resultado, teste_em) ON email_config TO roar_ingestao;

-- O serviço de avisos lê o sino da organização para mandar por e-mail.
CREATE POLICY leitura_dos_avisos ON notificacoes FOR SELECT TO roar_ingestao USING (cliente_id = roar_cliente_atual());
GRANT SELECT ON notificacoes TO roar_ingestao;
-- O nome da organização vai no assunto do e-mail.
GRANT SELECT (nome) ON clientes TO roar_ingestao;
