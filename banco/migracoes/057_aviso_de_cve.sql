-- Aviso no sino quando uma falha urgente aparece no inventário: a que já é explorada por atacantes (catálogo KEV).
-- Dois caminhos: um ativo ganhou uma falha assim, ou uma falha que já estava aberta entrou no catálogo.

CREATE FUNCTION roar_avisar(p_cliente uuid, p_tipo text, p_alvo text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  UPDATE notificacoes SET contagem = contagem + 1, atualizada_em = now()
    WHERE cliente_id = p_cliente AND tipo = p_tipo AND alvo = left(p_alvo, 300) AND lida_em IS NULL;
  IF NOT FOUND THEN
    INSERT INTO notificacoes (cliente_id, tipo, alvo) VALUES (p_cliente, p_tipo, left(p_alvo, 300));
  END IF;
END $$;
REVOKE ALL ON FUNCTION roar_avisar(uuid, text, text) FROM PUBLIC;

-- Um aviso por ativo, somando: o primeiro inventário de um servidor velho traz dezenas de uma vez.
CREATE FUNCTION roar_avisar_falha_urgente() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  IF NEW.estado = 'aberto' AND EXISTS (SELECT 1 FROM cves c WHERE c.cve = ANY(NEW.cves) AND c.kev_desde IS NOT NULL) THEN
    PERFORM roar_avisar(NEW.cliente_id, 'falha_explorada_no_ativo',
                        (SELECT coalesce(t.nome, t.host) FROM vuln_ativos t WHERE t.id = NEW.ativo_id));
  END IF;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION roar_avisar_falha_urgente() FROM PUBLIC;
CREATE TRIGGER avisar_falha_urgente AFTER INSERT ON vuln_achados FOR EACH ROW EXECUTE FUNCTION roar_avisar_falha_urgente();

-- Chamada pela carga da base de CVEs com as que acabaram de entrar no catálogo: um aviso por CVE, em cada
-- organização que tem a falha aberta, contando os ativos.
CREATE FUNCTION roar_avisar_cves_exploradas(p_cves text[]) RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE
  l record;
  n integer := 0;
BEGIN
  FOR l IN SELECT a.cliente_id, u.cve, count(DISTINCT a.ativo_id) AS ativos
           FROM vuln_achados a, unnest(a.cves) AS u(cve)
           WHERE u.cve = ANY(p_cves) AND a.estado IN ('aberto', 'correcao_informada') GROUP BY 1, 2 LOOP
    PERFORM roar_avisar(l.cliente_id, 'cve_passou_a_ser_explorada', l.cve);
    UPDATE notificacoes SET contagem = l.ativos
      WHERE cliente_id = l.cliente_id AND tipo = 'cve_passou_a_ser_explorada' AND alvo = l.cve AND lida_em IS NULL;
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;
REVOKE ALL ON FUNCTION roar_avisar_cves_exploradas(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION roar_avisar_cves_exploradas(text[]) TO roar_ingestao;
