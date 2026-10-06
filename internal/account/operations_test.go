package account

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAccountBackupRestoreStateRevocationAndKeySeparation(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	backup, err := app.Backup()
	if err != nil {
		t.Fatal(err)
	}
	records, invalid := app.validBackups()
	if len(records) != 3 || invalid != 0 {
		t.Fatal("backup tiers", len(records), invalid)
	}
	requireStatus(t, securityCall(client, "reauthenticate", url.Values{"password": {testPassword}}), 200)
	requireStatus(t, securityCall(client, "deactivate", url.Values{"confirm": {"deactivate"}}), 200)
	destination := filepath.Join(t.TempDir(), "restored.db")
	archive := filepath.Join(app.config.BackupDirectory, backup.Archive)
	if err = RestoreAccountBackup(app.config, app.keys, archive, destination); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var status string
	var count int
	if err = db.QueryRow("SELECT status FROM users WHERE username='testuser'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "deactivated" {
		t.Fatal("restored account state", status)
	}
	if err = db.QueryRow("SELECT count(*) FROM sessions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("restored sessions")
	}
	if err = RestoreAccountBackup(app.config, app.keys, archive, destination); err == nil {
		t.Fatal("overwrote restore destination")
	}
	raw, _ := os.ReadFile(archive)
	if strings.Contains(string(raw), "testuser") {
		t.Fatal("unencrypted account backup")
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(archive, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = RestoreAccountBackup(app.config, app.keys, archive, filepath.Join(t.TempDir(), "bad.db")); err == nil {
		t.Fatal("tampered backup accepted")
	}
}
func TestAccountRestoreOldCredentialsRemainDisabled(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	backup, err := app.Backup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.db.Exec("UPDATE users SET password_hash='newer-hash' WHERE username='testuser'"); err != nil {
		t.Fatal(err)
	}
	if err = app.mirrorSecurityEvents(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "restored.db")
	if err = RestoreAccountBackup(app.config, app.keys, filepath.Join(app.config.BackupDirectory, backup.Archive), destination); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var status, password string
	if err = db.QueryRow("SELECT status,password_hash FROM users WHERE username='testuser'").Scan(&status, &password); err != nil {
		t.Fatal(err)
	}
	if status != "recovery_pending" || password != "" {
		t.Fatal("old credentials revived", status)
	}
}
func TestAccountRecoveryWindowCleanupAndJournalTruncation(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	backup, err := app.Backup()
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, securityCall(client, "reauthenticate", url.Values{"password": {testPassword}}), 200)
	requireStatus(t, securityCall(client, "deactivate", url.Values{"confirm": {"deactivate"}}), 200)
	future := time.Now().Add(31 * 24 * time.Hour)
	app.now = func() time.Time { return future }
	if err = app.Cleanup(); err != nil {
		t.Fatal(err)
	}
	var status, password string
	if err = app.db.QueryRow("SELECT status,password_hash FROM users LIMIT 1").Scan(&status, &password); err != nil {
		t.Fatal(err)
	}
	if status != "deleted" || password != "" {
		t.Fatal("expired recovery window kept credentials")
	}
	if err = app.restore(context.Background(), "testuser", testPassword); err == nil {
		t.Fatal("expired account recovered")
	}
	raw, err := os.ReadFile(filepath.Join(app.config.BackupDirectory, backup.Archive))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(app.config.BackupKeyFile)
	plain, err := decrypt(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "$2a$") {
		t.Fatal("expired password hash remained in older ordinary backup")
	}
	if err = os.WriteFile(app.config.SecurityJournalFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = app.readSecurityJournal(); err == nil {
		t.Fatal("truncated security journal accepted")
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 503)
}
