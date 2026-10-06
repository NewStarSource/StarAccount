package account

// Opening an old database directly still cannot bypass later security withdrawals.
func (app *App) replaySecurityEvents() error {
	records, err := app.readSecurityJournal()
	if err != nil {
		return err
	}
	var high int64
	if err = app.db.QueryRow("SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='identity_events'),0)").Scan(&high); err != nil {
		return err
	}
	if len(records) == 0 || records[len(records)-1].Event.Sequence <= high {
		return nil
	}
	tx, err := app.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var trigger, sessionTrigger string
	if err = tx.QueryRow("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='account_status_event'").Scan(&trigger); err != nil {
		return err
	}
	if err = tx.QueryRow("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='session_revoked_event'").Scan(&sessionTrigger); err != nil {
		return err
	}
	if _, err = tx.Exec("DROP TRIGGER account_status_event; DROP TRIGGER session_revoked_event;"); err != nil {
		return err
	}
	for _, record := range records {
		e := record.Event
		if e.Sequence <= high {
			continue
		}
		if e.Type == "status_changed" {
			if _, err = tx.Exec("UPDATE users SET status=?,status_version=?,recovery_until=? WHERE id=? AND status_version<?", e.Status, e.Version, e.OccurredAt+30*86400, e.AccountID, e.Version); err != nil {
				return err
			}
		}
		if e.Type == "session_revoked" {
			if _, err = tx.Exec("UPDATE sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL", e.OccurredAt, e.SID); err != nil {
				return err
			}
		}
		if _, err = tx.Exec("INSERT OR IGNORE INTO identity_events VALUES(?,?,?,?,?,?,?,?)", e.Sequence, e.ID, e.AccountID, e.SID, e.Type, e.Status, e.Version, e.OccurredAt); err != nil {
			return err
		}
	}
	for _, record := range records {
		e := record.Event
		if e.Sequence > high && e.Type == "credentials_changed" {
			if _, err = tx.Exec("UPDATE users SET status='recovery_pending',password_hash='' WHERE id=? AND status NOT IN ('deleted','deactivated')", e.AccountID); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec("UPDATE sessions SET revoked_at=unixepoch() WHERE revoked_at IS NULL; DELETE FROM oidc_requests; DELETE FROM oidc_tokens; DELETE FROM mail_jobs; DELETE FROM tokens;"); err != nil {
		return err
	}
	if _, err = tx.Exec(sessionTrigger); err != nil {
		return err
	}
	if _, err = tx.Exec(trigger); err != nil {
		return err
	}
	return tx.Commit()
}
