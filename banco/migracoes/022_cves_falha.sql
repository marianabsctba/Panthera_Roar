-- A última tentativa que falhou: a tela avisa, porque a base anterior continua valendo e fica velha.
ALTER TABLE cves_carga ADD COLUMN falha text;
ALTER TABLE cves_carga ADD COLUMN falha_em timestamptz;
