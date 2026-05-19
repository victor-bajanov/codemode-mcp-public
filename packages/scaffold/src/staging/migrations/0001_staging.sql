-- packages/scaffold/src/staging/migrations/0001_staging.sql
CREATE TABLE IF NOT EXISTS staging (
  token_hash         BLOB    PRIMARY KEY,
  file_handle        TEXT    NOT NULL UNIQUE,
  state              TEXT    NOT NULL CHECK (state IN ('pending','claimed','corrupt')),
  r2_key             TEXT,
  iv                 BLOB,
  content_type_hint  TEXT,
  content_type       TEXT,
  expected_byte_len  INTEGER,
  byte_len           INTEGER,
  filename           TEXT,
  created_at         INTEGER NOT NULL,
  claimed_at         INTEGER,
  expires_at         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_staging_expires_at ON staging (expires_at);
CREATE INDEX IF NOT EXISTS idx_staging_file_handle ON staging (file_handle);
