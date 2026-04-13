pub const SCHEMA_SQL: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS name_record (
    namehash          BLOB    NOT NULL PRIMARY KEY,
    content_uri       BLOB    NOT NULL,
    expires_at_block  INTEGER NOT NULL,
    verified_against  BLOB    NOT NULL,
    cached_at_unix    INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_name_record_expires_at
    ON name_record (expires_at_block);

CREATE TABLE IF NOT EXISTS nxdomain_cache (
    namehash                 BLOB    NOT NULL PRIMARY KEY,
    verified_absent_against  BLOB    NOT NULL,
    cached_at_unix           INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS header_anchor (
    block_number      INTEGER NOT NULL PRIMARY KEY,
    block_hash        BLOB    NOT NULL,
    state_root        BLOB    NOT NULL,
    parent_hash       BLOB    NOT NULL,
    finalized         INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_header_anchor_hash
    ON header_anchor (block_hash);
"#;
