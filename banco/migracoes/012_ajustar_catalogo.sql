-- Editar ou desligar uma regra do catálogo sem tocar no arquivo original: a versão do cliente
-- entra com o mesmo número e passa a valer no lugar dela. Restaurar é só tirar essa versão.
ALTER TABLE regras_proprias ADD COLUMN substitui text;
ALTER TABLE regras_proprias ADD COLUMN desligada boolean NOT NULL DEFAULT false;

ALTER TABLE regras_proprias DROP CONSTRAINT regras_proprias_formato_check;
ALTER TABLE regras_proprias ADD CONSTRAINT regras_proprias_formato_check
  CHECK (formato IN ('sigma', 'guiada', 'xml', 'biblioteca', 'substituicao'));

-- No máximo uma versão em uso por regra do catálogo em cada gerenciador.
CREATE UNIQUE INDEX regras_proprias_uma_substituicao ON regras_proprias (gerenciador_id, substitui)
  WHERE substitui IS NOT NULL AND estado <> 'desativada';

GRANT UPDATE (desligada) ON regras_proprias TO roar_api;
