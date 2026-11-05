-- O UEBA soma o risco das regras que disparam e conta as táticas do ATT&CK de cada entidade.
GRANT SELECT (tecnica, taticas) ON tecnicas_attack TO roar_ueba;
