-- De onde veio a nota: o registro oficial ou, quando ele não traz, a NVD.
ALTER TABLE cves ADD COLUMN cvss_fonte text CHECK (cvss_fonte IN ('registro', 'nvd'));
