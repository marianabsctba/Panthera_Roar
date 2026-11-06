-- O que o OSV disse do pacote que um serviço anuncia (OpenSSH_8.2p1 Ubuntu-4ubuntu0.5): de qual versão da distribuição
-- ele é e quais CVEs ainda pegam aquela versão exata. Guardado por um dia, igual para todos: não tem nada de nenhum cliente.
CREATE TABLE distro_consultas (
  distribuicao text NOT NULL CHECK (distribuicao IN ('ubuntu', 'debian')),
  pacote text NOT NULL,
  versao text NOT NULL,
  -- Nulos quando não deu para saber de qual versão da distribuição o pacote é.
  versao_com_epoca text,
  ecossistemas text[],
  cves text[],
  consultado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (distribuicao, pacote, versao)
);
GRANT SELECT ON distro_consultas TO roar_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON distro_consultas TO roar_ingestao;
