ALTER TABLE users ADD COLUMN status_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN recovery_until INTEGER;
ALTER TABLE sessions ADD COLUMN reauthenticated_at INTEGER NOT NULL DEFAULT 0;
CREATE TABLE identity_events (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
 account_id TEXT NOT NULL, sid TEXT, event_type TEXT NOT NULL,
 status TEXT NOT NULL, status_version INTEGER NOT NULL, occurred_at INTEGER NOT NULL
);
CREATE TRIGGER session_revoked_event AFTER UPDATE OF revoked_at ON sessions
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN
 INSERT INTO identity_events(event_id,account_id,sid,event_type,status,status_version,occurred_at)
 SELECT lower(hex(randomblob(16))),NEW.user_id,NEW.id,'session_revoked',status,status_version,NEW.revoked_at FROM users WHERE id=NEW.user_id;
END;
CREATE TRIGGER account_status_event AFTER UPDATE OF status ON users WHEN OLD.status<>NEW.status
BEGIN
 UPDATE users SET status_version=OLD.status_version+1 WHERE id=NEW.id;
 UPDATE sessions SET revoked_at=unixepoch() WHERE user_id=NEW.id AND revoked_at IS NULL;
 INSERT INTO identity_events(event_id,account_id,event_type,status,status_version,occurred_at)
 VALUES(lower(hex(randomblob(16))),NEW.id,'status_changed',NEW.status,OLD.status_version+1,unixepoch());
END;
CREATE TABLE oidc_requests (
 id TEXT PRIMARY KEY, body BLOB NOT NULL, binding_hash TEXT NOT NULL,
 code_hash TEXT UNIQUE, expires_at INTEGER NOT NULL, exchanged INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE oidc_tokens (
 hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), sid TEXT NOT NULL,
 expires_at INTEGER NOT NULL
);
INSERT INTO schema_migrations VALUES(2);
