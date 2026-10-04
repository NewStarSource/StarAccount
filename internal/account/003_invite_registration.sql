ALTER TABLE users ADD COLUMN username TEXT;
CREATE UNIQUE INDEX users_username_unique ON users(username) WHERE username IS NOT NULL;
CREATE TABLE invite_codes (
 code_hash TEXT PRIMARY KEY,
 created_at INTEGER NOT NULL,
 used_at INTEGER,
 used_by TEXT REFERENCES users(id)
);
CREATE INDEX invite_codes_available ON invite_codes(used_at, created_at);
INSERT INTO schema_migrations VALUES(3);
