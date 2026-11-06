-- Login único também por SAML 2.0. Para SAML, emissor guarda o endereço de login do provedor (onde a pessoa é mandada),
-- e client_id guarda o identificador do Roar (o que o provedor espera no público da resposta).
ALTER TABLE sso DROP CONSTRAINT sso_provedor_check;
ALTER TABLE sso ADD CONSTRAINT sso_provedor_check CHECK (provedor IN ('google', 'microsoft', 'outro', 'saml'));
-- O identificador do provedor (Issuer da resposta) e o certificado com que ele assina, em PEM.
ALTER TABLE sso ADD COLUMN saml_entidade text CHECK (length(saml_entidade) <= 500);
ALTER TABLE sso ADD COLUMN saml_certificado text CHECK (length(saml_certificado) <= 20000);
ALTER TABLE sso ADD CONSTRAINT sso_saml_completo CHECK (provedor <> 'saml' OR (saml_entidade IS NOT NULL AND saml_certificado IS NOT NULL));

DROP FUNCTION roar_sso_da_organizacao(uuid);
CREATE FUNCTION roar_sso_da_organizacao(p_cliente uuid)
  RETURNS TABLE (emissor text, client_id text, segredo bytea, dominios text[], provedor text, saml_entidade text, saml_certificado text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$ SELECT emissor, client_id, segredo, dominios, provedor, saml_entidade, saml_certificado FROM sso WHERE cliente_id = p_cliente AND ativo $$;
REVOKE ALL ON FUNCTION roar_sso_da_organizacao(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_sso_da_organizacao(uuid) TO roar_api;
