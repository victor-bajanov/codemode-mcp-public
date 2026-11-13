-- packages/scaffold/src/staging/migrations/0003_owner.sql
-- E-1 (2026-11 review): every staged file belongs to the principal that created it, and the
-- public /staging/fetch download is counted against STAGING_FETCH_MAX_USES (default 5) within
-- the fetch TTL. Rows written before this migration have no owner and are refused by every
-- reader (no shim); they expire within their TTL.
ALTER TABLE staging ADD COLUMN owner TEXT;
ALTER TABLE staging ADD COLUMN fetch_count INTEGER NOT NULL DEFAULT 0;
