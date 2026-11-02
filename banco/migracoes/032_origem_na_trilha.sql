-- Toda ação de uma pessoa leva o endereço de quem fez, sem depender de cada rota lembrar.
-- A API define a origem na transação. O que vem de um serviço, como um ativo novo, continua sem origem.
CREATE FUNCTION roar_origem_na_trilha() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.origem IS NULL THEN
    NEW.origem := left(nullif(current_setting('roar.origem', true), ''), 64);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER origem_na_trilha BEFORE INSERT ON auditoria FOR EACH ROW EXECUTE FUNCTION roar_origem_na_trilha();
