CREATE TABLE recovery_codes (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);
INSERT INTO schema_migrations VALUES(6);
