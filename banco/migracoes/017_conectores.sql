-- Mais conectores do Wazuh como fonte ou aviso, e o usuário do alerta disponível para as respostas.
ALTER TABLE fontes DROP CONSTRAINT fontes_tipo_check;
ALTER TABLE fontes ADD CONSTRAINT fontes_tipo_check CHECK (tipo IN (
  'syslog', 'webhook', 'api', 'github', 'office365', 'msgraph', 'aws', 'azure', 'gcp', 'slack', 'pagerduty', 'virustotal', 'maltiverse'));

GRANT SELECT (usuario) ON eventos TO roar_soar;
