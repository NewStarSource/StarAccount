package account

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type securityRecord struct {
	Event    identityEvent `json:"event"`
	Previous string        `json:"previous"`
	MAC      string        `json:"mac"`
}

func (app *App) securityMAC(record securityRecord) string {
	record.MAC = ""
	raw, _ := json.Marshal(record)
	mac := hmac.New(sha256.New, app.keys[64:96])
	mac.Write([]byte("staraccount-security-journal-v1:"))
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}
func (app *App) initSecurityJournal() error {
	if app.config.SecurityJournalFile == "" {
		app.config.SecurityJournalFile = app.config.Database + ".security.jsonl"
	}
	if app.config.BackupDirectory == "" {
		app.config.BackupDirectory = app.config.Database + ".backups"
	}
	if app.config.BackupKeyFile == "" {
		app.config.BackupKeyFile = app.config.Database + ".backup.key"
	}
	path := app.config.SecurityJournalFile
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Existing events are imported once. Later loss is detected by the permanent marker.
		if _, err = os.Stat(path + ".initialized"); err == nil {
			return errors.New("security journal missing")
		}
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err = accountExclusiveFile(path, nil); err != nil {
			return err
		}
		if err = os.MkdirAll(path+".anchors", 0700); err != nil {
			return err
		}
		if err = accountExclusiveFile(path+".initialized", []byte("security-journal-v1")); err != nil {
			return err
		}
	}
	if err := app.replaySecurityEvents(); err != nil {
		return err
	}
	return app.mirrorSecurityEvents()
}
func accountExclusiveFile(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = restrictPath(path, false); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func (app *App) readSecurityJournal() ([]securityRecord, error) {
	f, err := os.Open(app.config.SecurityJournalFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 65536)
	var records []securityRecord
	previous := ""
	var seq int64
	for scan.Scan() {
		var record securityRecord
		if json.Unmarshal(scan.Bytes(), &record) != nil || record.Event.Sequence <= seq || record.Previous != previous || !hmac.Equal([]byte(record.MAC), []byte(app.securityMAC(record))) {
			return nil, errors.New("security journal integrity failure")
		}
		anchor, err := os.ReadFile(filepath.Join(app.config.SecurityJournalFile+".anchors", fmt.Sprintf("%020d", record.Event.Sequence)))
		if err != nil || string(anchor) != record.MAC {
			return nil, errors.New("security journal anchor mismatch")
		}
		records = append(records, record)
		seq = record.Event.Sequence
		previous = record.MAC
	}
	if err = scan.Err(); err != nil {
		return nil, err
	}
	anchors, err := os.ReadDir(app.config.SecurityJournalFile + ".anchors")
	if err != nil || len(anchors) != len(records) {
		return nil, errors.New("security journal truncated")
	}
	return records, nil
}
func (app *App) securityLock() (func(), error) {
	path := app.config.SecurityJournalFile + ".lock"
	deadline := time.Now().Add(2 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			fmt.Fprintf(f, "%d", os.Getpid())
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !os.IsExist(err) || time.Now().After(deadline) {
			return nil, errors.New("security journal busy")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func (app *App) mirrorSecurityEvents() error {
	unlock, err := app.securityLock()
	if err != nil {
		return err
	}
	defer unlock()
	records, err := app.readSecurityJournal()
	if err != nil {
		return err
	}
	var after int64
	previous := ""
	if len(records) > 0 {
		last := records[len(records)-1]
		after = last.Event.Sequence
		previous = last.MAC
	}
	rows, err := app.db.Query("SELECT seq,event_id,account_id,COALESCE(sid,''),event_type,status,status_version,occurred_at FROM identity_events WHERE seq>? ORDER BY seq", after)
	if err != nil {
		return err
	}
	var events []identityEvent
	for rows.Next() {
		var e identityEvent
		if err = rows.Scan(&e.Sequence, &e.ID, &e.AccountID, &e.SID, &e.Type, &e.Status, &e.Version, &e.OccurredAt); err != nil {
			rows.Close()
			return err
		}
		events = append(events, e)
	}
	rows.Close()
	for _, event := range events {
		record := securityRecord{Event: event, Previous: previous}
		record.MAC = app.securityMAC(record)
		raw, _ := json.Marshal(record)
		f, err := os.OpenFile(app.config.SecurityJournalFile, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(append(raw, '\n'))
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return err
		}
		if err = accountExclusiveFile(filepath.Join(app.config.SecurityJournalFile+".anchors", fmt.Sprintf("%020d", event.Sequence)), []byte(record.MAC)); err != nil {
			return err
		}
		previous = record.MAC
	}
	return nil
}

type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}
func (b *bufferedResponse) Write(raw []byte) (int, error) {
	if b.status == 0 {
		b.status = 200
	}
	return b.body.Write(raw)
}
func (app *App) protectJournal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			next.ServeHTTP(w, r)
			return
		}
		app.operationsMu.Lock()
		defer app.operationsMu.Unlock()
		if _, err := app.readSecurityJournal(); err != nil {
			writeJSON(w, 503, map[string]string{"code": "SECURITY_JOURNAL_UNAVAILABLE"})
			return
		}
		response := &bufferedResponse{header: make(http.Header)}
		next.ServeHTTP(response, r)
		if err := app.mirrorSecurityEvents(); err != nil {
			app.audit("security_journal_failed")
			writeJSON(w, 503, map[string]string{"code": "SECURITY_JOURNAL_UNAVAILABLE"})
			return
		}
		for name, values := range response.header {
			w.Header()[name] = values
		}
		if response.status == 0 {
			response.status = 200
		}
		w.WriteHeader(response.status)
		w.Write(response.body.Bytes())
	})
}

type AccountBackup struct {
	CreatedAt        int64  `json:"created_at"`
	Schema           int    `json:"schema"`
	Archive          string `json:"archive"`
	Hash             string `json:"sha256"`
	JournalSequence  int64  `json:"journal_sequence"`
	JournalMAC       string `json:"journal_mac"`
	Tier             string `json:"tier"`
	ScrubbedSequence int64  `json:"scrubbed_sequence"`
}

func (app *App) Backup() (AccountBackup, error) {
	app.operationsMu.Lock()
	defer app.operationsMu.Unlock()
	var result AccountBackup
	if err := app.mirrorSecurityEvents(); err != nil {
		return result, err
	}
	unlock, err := app.securityLock()
	if err != nil {
		return result, err
	}
	defer unlock()
	records, err := app.readSecurityJournal()
	if err != nil {
		return result, err
	}
	if len(records) > 0 {
		last := records[len(records)-1]
		result.JournalSequence = last.Event.Sequence
		result.JournalMAC = last.MAC
	}
	key, err := os.ReadFile(app.config.BackupKeyFile)
	if os.IsNotExist(err) {
		key = randomBytes(32)
		err = accountExclusiveFile(app.config.BackupKeyFile, key)
	}
	if err != nil || len(key) != 32 {
		return result, errors.New("backup key unavailable")
	}
	dir, err := os.MkdirTemp(filepath.Dir(app.config.Database), "account-backup-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(dir)
	if err = restrictPath(dir, true); err != nil {
		return result, err
	}
	snapshot := filepath.Join(dir, "snapshot.db")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err = app.db.ExecContext(ctx, "VACUUM INTO ?", snapshot); err != nil {
		return result, err
	}
	db, err := sql.Open("sqlite", snapshot)
	if err != nil {
		return result, err
	}
	_, err = db.Exec("DELETE FROM mail_jobs; DELETE FROM tokens; DELETE FROM sessions; DELETE FROM oidc_requests; DELETE FROM oidc_tokens; DELETE FROM limits; DELETE FROM security_events; VACUUM;")
	db.Close()
	if err != nil {
		return result, err
	}
	raw, err := os.ReadFile(snapshot)
	if err != nil {
		return result, err
	}
	raw, err = encrypt(key, raw)
	if err != nil {
		return result, err
	}
	result.CreatedAt = app.now().Unix()
	result.Tier = "hourly"
	result.ScrubbedSequence = result.JournalSequence
	result.Schema = 5
	result.Archive = fmt.Sprintf("%d-%s.backup", time.Now().UnixNano(), opaqueID())
	sum := sha256.Sum256(raw)
	result.Hash = hex.EncodeToString(sum[:])
	if err = os.MkdirAll(app.config.BackupDirectory, 0700); err != nil {
		return result, err
	}
	if err = accountExclusiveFile(filepath.Join(app.config.BackupDirectory, result.Archive), raw); err != nil {
		return result, err
	}
	meta, _ := json.MarshalIndent(result, "", "  ")
	err = accountExclusiveFile(filepath.Join(app.config.BackupDirectory, result.Archive+".json"), meta)
	if err != nil {
		return result, err
	}
	err = app.rotateBackups(result, raw)
	return result, err
}
func RestoreAccountBackup(config Config, keys []byte, archive, destination string) error {
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		return errors.New("restore destination must not exist")
	}
	if config.SecurityJournalFile == "" {
		config.SecurityJournalFile = config.Database + ".security.jsonl"
	}
	if config.BackupKeyFile == "" {
		config.BackupKeyFile = config.Database + ".backup.key"
	}
	app := &App{config: config, keys: keys}
	records, err := app.readSecurityJournal()
	if err != nil {
		return err
	}
	meta, err := os.ReadFile(archive + ".json")
	if err != nil {
		return err
	}
	var manifest AccountBackup
	if json.Unmarshal(meta, &manifest) != nil || manifest.Schema != 5 {
		return errors.New("invalid account backup manifest")
	}
	match := manifest.JournalSequence == 0
	for _, r := range records {
		if r.Event.Sequence == manifest.JournalSequence && r.MAC == manifest.JournalMAC {
			match = true
		}
	}
	if !match {
		return errors.New("stale security journal")
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != manifest.Hash {
		return errors.New("account backup hash mismatch")
	}
	key, err := os.ReadFile(config.BackupKeyFile)
	if err != nil {
		return err
	}
	raw, err = decrypt(key, raw)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	if err = accountExclusiveFile(destination, raw); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", destination)
	if err != nil {
		return err
	}
	defer db.Close()
	var trigger string
	if err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='account_status_event'").Scan(&trigger); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DROP TRIGGER account_status_event; DELETE FROM sessions; DELETE FROM oidc_requests; DELETE FROM oidc_tokens; DELETE FROM mail_jobs; DELETE FROM tokens;"); err != nil {
		return err
	}
	for _, record := range records {
		e := record.Event
		if e.Type == "credentials_changed" && e.Sequence > manifest.JournalSequence {
			if _, err = tx.Exec("UPDATE users SET status='recovery_pending',password_hash='' WHERE id=? AND status<>'deleted'", e.AccountID); err != nil {
				return err
			}
		}
		if e.Type == "status_changed" {
			if _, err = tx.Exec("UPDATE users SET status=?,status_version=?,recovery_until=? WHERE id=? AND status_version<?", e.Status, e.Version, e.OccurredAt+30*86400, e.AccountID, e.Version); err != nil {
				return err
			}
		}
		if _, err = tx.Exec("INSERT OR IGNORE INTO identity_events VALUES(?,?,?,?,?,?,?,?)", e.Sequence, e.ID, e.AccountID, e.SID, e.Type, e.Status, e.Version, e.OccurredAt); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("UPDATE users SET status='deleted',password_hash='',email='deleted:'||id,username='deleted:'||id,display_name='',bio='',location='',website='' WHERE status='deleted' OR (status='deactivated' AND recovery_until<=unixepoch())"); err != nil {
		return err
	}
	for _, record := range records {
		if record.Event.Type == "credentials_changed" && record.Event.Sequence > manifest.JournalSequence {
			if _, err = tx.Exec("UPDATE users SET status='recovery_pending',password_hash='' WHERE id=? AND status NOT IN ('deleted','deactivated')", record.Event.AccountID); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec(trigger); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	var integrity string
	if err = db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("account restore integrity failed")
	}
	return nil
}
func (app *App) Diagnostics() (map[string]any, error) {
	result := map[string]any{}
	var check string
	if err := app.db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil {
		return nil, err
	}
	result["integrity"] = check
	_, err := app.readSecurityJournal()
	result["journal_valid"] = err == nil
	entries, _ := os.ReadDir(app.config.BackupDirectory)
	var latest int64
	invalid := 0
	key, _ := os.ReadFile(app.config.BackupKeyFile)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".backup.json") {
			continue
		}
		raw, e := os.ReadFile(filepath.Join(app.config.BackupDirectory, entry.Name()))
		var m AccountBackup
		if e != nil || json.Unmarshal(raw, &m) != nil || filepath.Base(m.Archive) != m.Archive {
			invalid++
			continue
		}
		raw, e = os.ReadFile(filepath.Join(app.config.BackupDirectory, m.Archive))
		sum := sha256.Sum256(raw)
		if e != nil || hex.EncodeToString(sum[:]) != m.Hash {
			invalid++
			continue
		}
		if _, e = decrypt(key, raw); e != nil {
			invalid++
			continue
		}
		if m.CreatedAt > latest {
			latest = m.CreatedAt
		}
	}
	result["latest_backup_at"] = latest
	result["backup_stale"] = latest == 0 || app.now().Unix()-latest > 3600
	result["invalid_backups"] = invalid
	return result, nil
}
