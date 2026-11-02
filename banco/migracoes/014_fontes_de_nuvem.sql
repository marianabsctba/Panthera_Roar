-- Fontes que buscam em nuvem. A credencial fica em segredos; config só guarda o nome dela.
ALTER TABLE fontes DROP CONSTRAINT fontes_tipo_check;
ALTER TABLE fontes ADD CONSTRAINT fontes_tipo_check CHECK (tipo IN ('syslog', 'github', 'office365'));
