package account

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func (app *App) scrubBackups() error {
	unlock, err := app.securityLock()
	if err != nil {
		return err
	}
	defer unlock()
	records, err := app.readSecurityJournal()
	if err != nil {
		return err
	}
	var sequence int64
	if len(records) > 0 {
		sequence = records[len(records)-1].Event.Sequence
	}
	manifests, invalid := app.validBackups()
	if invalid > 0 {
		return errors.New("account backup integrity failure")
	}
	if len(manifests) == 0 {
		return nil
	}
	rows, err := app.db.Query("SELECT id FROM users WHERE status='deleted'")
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	key, err := os.ReadFile(app.config.BackupKeyFile)
	if err != nil {
		return err
	}
	for _, m := range manifests {
		if m.ScrubbedSequence >= sequence {
			continue
		}
		path := filepath.Join(app.config.BackupDirectory, m.Archive)
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		raw, err = decrypt(key, raw)
		if err != nil {
			return err
		}
		dir, err := os.MkdirTemp(filepath.Dir(app.config.Database), "account-scrub-")
		if err != nil {
			return err
		}
		err = func() error {
			defer os.RemoveAll(dir)
			if err := restrictPath(dir, true); err != nil {
				return err
			}
			snapshot := filepath.Join(dir, "snapshot.db")
			if err := accountExclusiveFile(snapshot, raw); err != nil {
				return err
			}
			db, err := sql.Open("sqlite", snapshot)
			if err != nil {
				return err
			}
			defer db.Close()
			for _, id := range ids {
				if _, err = db.Exec("UPDATE users SET password_hash='',email='deleted:'||id,username='deleted:'||id,display_name='',bio='',location='',website='' WHERE id=?", id); err != nil {
					return err
				}
			}
			if _, err = db.Exec("VACUUM"); err != nil {
				return err
			}
			if err = db.Close(); err != nil {
				return err
			}
			raw, err := os.ReadFile(snapshot)
			if err != nil {
				return err
			}
			raw, err = encrypt(key, raw)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(raw)
			m.Hash = hex.EncodeToString(sum[:])
			m.ScrubbedSequence = sequence
			if err = accountExclusiveFile(path+".rewrite", raw); err != nil {
				return err
			}
			if err = os.Rename(path+".rewrite", path); err != nil {
				return err
			}
			meta, _ := json.MarshalIndent(m, "", "  ")
			if err = accountExclusiveFile(path+".json.rewrite", meta); err != nil {
				return err
			}
			return os.Rename(path+".json.rewrite", path+".json")
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
