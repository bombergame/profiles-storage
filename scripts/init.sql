CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION encrypt_password(_password_ TEXT)
  RETURNS TEXT
AS $$
SELECT crypt(_password_, gen_salt('md5'));
$$
LANGUAGE SQL;

CREATE OR REPLACE FUNCTION check_password(
  _password_ TEXT, _encoded_ TEXT)
  RETURNS BOOLEAN
AS $$
SELECT _encoded_ = crypt(_password_, _encoded_);
$$
LANGUAGE SQL;

CREATE TABLE IF NOT EXISTS profile (
  "id"       BIGSERIAL
    CONSTRAINT "profile_id_primary_key" PRIMARY KEY,

  "username" TEXT
    CONSTRAINT "profile_username_not_null" NOT NULL
    CONSTRAINT "profile_username_unique" UNIQUE
    CONSTRAINT "profile_username_check" CHECK ("username" ~ '^\w+$'),

  "password" TEXT
    CONSTRAINT "profile_password_not_null" NOT NULL,

  "email"    TEXT
    CONSTRAINT "profile_email_not_null" NOT NULL
    CONSTRAINT "profile_email_unique" UNIQUE
    CONSTRAINT "profile_email_check" CHECK (email ~ '^.+@.+$'),

  "score"    INTEGER
    DEFAULT 0
    CONSTRAINT "profile_score_not_null" NOT NULL
    CONSTRAINT "profile_score_check" CHECK ("score" >= 0),

  "active"   BOOLEAN
    DEFAULT TRUE
    CONSTRAINT "profile_active_not_null" NOT NULL
);

CREATE OR REPLACE PROCEDURE create_profile(
  _username_ TEXT, _password_ TEXT, _email_ TEXT)
AS $$
BEGIN
  INSERT INTO "profile" ("username", "password", "email")
  VALUES (_username_, encrypt_password(_password_), _email_);
END;
$$
LANGUAGE PLPGSQL;

CREATE OR REPLACE PROCEDURE update_profile(_profile_id_ BIGINT,
                                           _username_   TEXT,
                                           _password_   TEXT,
                                           _email_      TEXT)
AS $$
DECLARE _profile_ "profile";
BEGIN
  SELECT p.* FROM "profile" p WHERE p."id" = _profile_id_
                                AND p."active"
      INTO _profile_;

  IF _profile_ IS NULL
  THEN
    RAISE 'profile not found';
  END IF;

  IF _username_ != ''
  THEN
    _profile_."username" := _username_;
  END IF;
  IF _password_ != ''
  THEN
    _profile_."password" := encrypt_password(_password_);
  END IF;
  IF _email_ != ''
  THEN
    _profile_."email" := _email_;
  END IF;

  UPDATE "profile"
  SET "username" = _profile_."username",
      "password" = _profile_."password",
      "email"    = _profile_."email"
  WHERE "id" = _profile_id_;
END;
$$
LANGUAGE PLPGSQL;

CREATE OR REPLACE PROCEDURE delete_profile(_profile_id_ BIGINT)
AS $$
BEGIN
  IF NOT EXISTS(
      SELECT * FROM "profile" p WHERE p."id" = _profile_id_
                                  AND p."active")
  THEN
    RAISE 'profile not found';
  END IF;

  UPDATE "profile" SET "active" = FALSE WHERE "id" = _profile_id_;
END;
$$
LANGUAGE PLPGSQL;

CREATE OR REPLACE FUNCTION get_profile(IN  _profile_id_ BIGINT,
                                       OUT _username_   TEXT, OUT _email_ TEXT, OUT _score_ INTEGER)
  RETURNS RECORD
AS $$
DECLARE _id_ INTEGER;
BEGIN
  SELECT p."id", p."username", p."email", p."score"
  FROM "profile" p
  WHERE "id" = _profile_id_
    AND p."active"
      INTO _id_, _username_, _email_, _score_;

  IF _id_ IS NULL
  THEN
    RAISE EXCEPTION 'profile not found';
  END IF;
END;
$$
LANGUAGE PLPGSQL;

CREATE OR REPLACE FUNCTION get_profile_id(
  _username_ TEXT, _password_ TEXT)
  RETURNS BIGINT
AS $$
DECLARE _profile_id_ BIGINT;
BEGIN
  SELECT p."id", p."password"
  FROM "profile" p
  WHERE p."username" = _username_
    AND p."active"
    AND check_password(_password_, p."password")
      INTO _profile_id_;

  IF _profile_id_ IS NULL
  THEN
    RAISE 'profile not found';
  END IF;

  RETURN _profile_id_;
END;
$$
LANGUAGE PLPGSQL;

CREATE OR REPLACE FUNCTION get_all_profiles(
  _page_index_ INTEGER, _page_size_ INTEGER)
  RETURNS TABLE(
    "id" BIGINT, "username" TEXT, "email" TEXT, "score" INTEGER
  )
AS $$
SELECT p."id", p."username", p."email", p."score"
FROM "profile" p
WHERE p."active"
ORDER BY p."score", p."username"
LIMIT _page_size_
OFFSET _page_index_;
$$
LANGUAGE SQL;
