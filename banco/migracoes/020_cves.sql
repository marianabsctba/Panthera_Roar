-- Base pública de CVEs, igual para todos os clientes: não tem nada de nenhum deles.
CREATE TABLE cves (
  cve text PRIMARY KEY CHECK (cve ~ '^CVE-[0-9]{4}-[0-9]+$'),
  publicado_em timestamptz,
  rejeitado boolean NOT NULL DEFAULT false,
  titulo text,
  descricao text,
  produto text,
  cvss real,
  vetor text,
  kev_desde date,
  kev_ransomware boolean NOT NULL DEFAULT false,
  kev_prazo date,
  epss real,
  epss_percentil real,
  prioridade text NOT NULL CHECK (prioridade IN ('agora', 'alta', 'media', 'baixa', 'sem_dados')),
  busca tsvector GENERATED ALWAYS AS (to_tsvector('simple', coalesce(titulo, '') || ' ' || coalesce(produto, '') || ' ' || coalesce(descricao, ''))) STORED
);
CREATE INDEX ON cves USING gin (busca);
CREATE INDEX ON cves (prioridade, epss DESC NULLS LAST);
CREATE INDEX ON cves (kev_desde) WHERE kev_desde IS NOT NULL;

-- De onde veio e quando: a tela mostra a idade da base, porque base velha engana.
CREATE TABLE cves_carga (
  id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  total integer NOT NULL,
  versao text,
  epss_data date,
  carregada_em timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON cves, cves_carga TO roar_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON cves, cves_carga TO roar_ingestao;
