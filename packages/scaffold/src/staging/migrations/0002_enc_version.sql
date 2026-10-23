-- packages/scaffold/src/staging/migrations/0002_enc_version.sql
-- At-rest format version: 1 = one-shot AES-GCM (retired; refused with 410), 2 = blockwise
-- AES-GCM (1 MiB blocks, position-bound AAD). Existing rows are v1.
ALTER TABLE staging ADD COLUMN enc_version INTEGER NOT NULL DEFAULT 1;
