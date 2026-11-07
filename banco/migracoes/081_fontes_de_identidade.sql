-- Fontes de identidade (roar_ingestao.identidade): o log do sistema do Okta e os relatórios de auditoria do Google
-- Workspace, buscados de tempos em tempos e entregues ao gerenciador. Cada fonte guarda de onde a próxima busca recomeça.
ALTER TABLE fontes DROP CONSTRAINT fontes_tipo_check;
ALTER TABLE fontes ADD CONSTRAINT fontes_tipo_check CHECK (tipo IN (
  'syslog', 'fluxo', 'webhook', 'api', 'github', 'office365', 'msgraph', 'aws', 'azure', 'gcp', 'okta', 'workspace',
  'slack', 'pagerduty', 'virustotal', 'maltiverse'));
ALTER TABLE fontes ADD COLUMN posicao jsonb;
GRANT UPDATE (posicao) ON fontes TO roar_ingestao;
