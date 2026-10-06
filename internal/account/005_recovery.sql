CREATE TRIGGER credentials_changed_event AFTER UPDATE OF password_hash ON users
WHEN OLD.password_hash<>NEW.password_hash AND OLD.password_hash<>'' AND NEW.password_hash<>''
BEGIN
 INSERT INTO identity_events(event_id,account_id,event_type,status,status_version,occurred_at)
 VALUES(lower(hex(randomblob(16))),NEW.id,'credentials_changed',NEW.status,NEW.status_version,unixepoch());
END;
INSERT INTO schema_migrations VALUES(5);
