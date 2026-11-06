-- Faixas de versão afetadas por CVE, tiradas da NVD, só dos produtos que a superfície externa reconhece pela resposta
-- do servidor (SSH, FTP, servidor web, banco). Igual para todos os clientes: não tem nada de nenhum deles.
CREATE TABLE cves_versoes (
  cve text NOT NULL,
  -- fornecedor:produto, como no CPE: openbsd:openssh, apache:http_server.
  produto text NOT NULL,
  -- Versão exata, ou faixa: desde (incluída ou não) até (incluída ou não). Sem nada, todas as versões.
  exata text,
  desde text,
  desde_incluida boolean NOT NULL DEFAULT true,
  ate text,
  ate_incluida boolean NOT NULL DEFAULT false
);
CREATE INDEX ON cves_versoes (produto);
GRANT SELECT ON cves_versoes TO roar_api;
GRANT SELECT, INSERT, DELETE ON cves_versoes TO roar_ingestao;

-- O que respondeu em cada porta aberta: [{"porta", "produto", "nome", "versao", "resposta"}].
ALTER TABLE superficie_hosts ADD COLUMN servicos jsonb NOT NULL DEFAULT '[]';
