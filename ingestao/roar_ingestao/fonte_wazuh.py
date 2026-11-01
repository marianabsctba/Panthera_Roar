"""Lê os alertas do indexer do Wazuh, em ordem, com verificação de TLS."""

import requests
from requests.adapters import HTTPAdapter


class _NomeDoCertificado(HTTPAdapter):
    """Conecta em um endereço e valida o certificado pelo nome do serviço."""

    def __init__(self, nome, **kwargs):
        self._nome = nome
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_hostname"] = self._nome
        super().init_poolmanager(*args, **kwargs)


class Indexer:
    def __init__(self, url, usuario, senha, ca, nome_certificado="wazuh.indexer"):
        self.url = url.rstrip("/")
        self.sessao = requests.Session()
        self.sessao.auth = (usuario, senha)
        self.sessao.verify = ca
        self.sessao.mount("https://", _NomeDoCertificado(nome_certificado))

    def alertas_desde(self, padrao, inicio, tamanho=500):
        """Devolve lotes de (id do documento, alerta), do mais antigo ao mais novo."""
        consulta = {
            "size": tamanho,
            "sort": [{"timestamp": "asc"}, {"id": "asc"}],
            "query": {"range": {"timestamp": {"gte": inicio.isoformat()}}},
        }
        while True:
            r = self.sessao.post(f"{self.url}/{padrao}/_search", json=consulta, timeout=60)
            r.raise_for_status()
            documentos = r.json()["hits"]["hits"]
            if not documentos:
                return
            yield [(d["_id"], d["_source"]) for d in documentos]
            consulta["search_after"] = documentos[-1]["sort"]
