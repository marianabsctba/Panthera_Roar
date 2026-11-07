-- Fluxos de rede (NetFlow, IPFIX e sFlow; roar_ingestao.fluxos): a fonte diz quais equipamentos exportam fluxos para a
-- organização, e os fluxos vão direto ao armazém de eventos, sem passar pelo gerenciador.
ALTER TABLE fontes DROP CONSTRAINT fontes_tipo_check;
ALTER TABLE fontes ADD CONSTRAINT fontes_tipo_check CHECK (tipo IN (
  'syslog', 'fluxo', 'webhook', 'api', 'github', 'office365', 'msgraph', 'aws', 'azure', 'gcp', 'slack', 'pagerduty', 'virustotal', 'maltiverse'));
