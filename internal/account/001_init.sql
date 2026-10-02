CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, subject_id TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
 alias TEXT NOT NULL, password_hash TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0,1)),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','deactivated','recovery_pending','deleted')),
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
 hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 kind TEXT NOT NULL CHECK(kind IN ('verify','reset')), candidate_hash TEXT NOT NULL DEFAULT '',
 expires_at INTEGER NOT NULL, used_at INTEGER
);
CREATE INDEX IF NOT EXISTS tokens_user ON tokens(user_id,kind);
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL REFERENCES users(id),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS mail_jobs (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE REFERENCES tokens(hash),
 payload BLOB NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','sent','permanent_failure')),
 attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 completed_at INTEGER, error_code TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS mail_due ON mail_jobs(status,next_at);
CREATE TABLE IF NOT EXISTS limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS security_events (id TEXT PRIMARY KEY, event TEXT NOT NULL, created_at INTEGER NOT NULL);
INSERT OR IGNORE INTO schema_migrations(version) VALUES(1);
