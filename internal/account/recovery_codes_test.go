package account

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecoveryCodeResetRotationAndRevocation(t *testing.T) {
	app, c, _ := fixture(t)
	invite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	response := c.call("POST", "/api/v1/auth/register", input{Username: "recoveruser", Password: testPassword, InviteCode: invite})
	requireStatus(t, response, 201)
	var data struct {
		RecoveryCode string `json:"recovery_code"`
	}
	if json.Unmarshal(response.Body.Bytes(), &data) != nil || len(data.RecoveryCode) != 43 {
		t.Fatal("registration recovery code missing")
	}
	var stored string
	app.db.QueryRow("SELECT code_hash FROM recovery_codes").Scan(&stored)
	if stored == data.RecoveryCode || stored != hash(data.RecoveryCode) {
		t.Fatal("plaintext recovery secret")
	}
	response = securityCall(c, "recovery-code", url.Values{"password": {testPassword}})
	requireStatus(t, response, 200)
	var rotated struct {
		RecoveryCode string `json:"recovery_code"`
	}
	json.Unmarshal(response.Body.Bytes(), &rotated)
	if err = app.consumeRecoveryCode("recoveruser", data.RecoveryCode, "replacement password 123"); err != errCredential {
		t.Fatal("old code accepted", err)
	}
	if err = app.consumeRecoveryCode("recoveruser", rotated.RecoveryCode, "replacement password 123"); err != nil {
		t.Fatal(err)
	}
	if err = app.mirrorSecurityEvents(); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, c.call("GET", "/api/v1/auth/session", nil), 200)
	if i, err := app.identity(httptest.NewRequest("GET", "http://test/", nil)); err != nil || i != nil {
		t.Fatal(err)
	}
	var active int
	app.db.QueryRow("SELECT count(*) FROM sessions WHERE revoked_at IS NULL").Scan(&active)
	if active != 0 {
		t.Fatal("session survived reset")
	}
	if _, err = app.login("recoveruser", testPassword, ""); err != errCredential {
		t.Fatal("old password accepted")
	}
	if _, err = app.login("recoveruser", "replacement password 123", ""); err != nil {
		t.Fatal(err)
	}
	if err = app.consumeRecoveryCode("recoveruser", rotated.RecoveryCode, "third password 123"); err != errCredential {
		t.Fatal("code replay", err)
	}
}
func TestRecoveryCodesExcludedFromBackupAndPendingOperatorFlow(t *testing.T) {
	app, c, _ := fixture(t)
	registerVerified(t, app, c)
	requireStatus(t, c.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	requireStatus(t, securityCall(c, "recovery-code", url.Values{"password": {testPassword}}), 200)
	backup, err := app.Backup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.db.Exec("UPDATE users SET password_hash='changed' WHERE username='testuser'"); err != nil {
		t.Fatal(err)
	}
	if err = app.mirrorSecurityEvents(); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored.db")
	if err = RestoreAccountBackup(app.config, app.keys, filepath.Join(app.config.BackupDirectory, backup.Archive), dest); err != nil {
		t.Fatal(err)
	}
	config := app.config
	config.Database = dest
	restored, err := New(config, app.keys, app.logger)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var count int
	restored.db.QueryRow("SELECT count(*) FROM recovery_codes").Scan(&count)
	if count != 0 {
		t.Fatal("backup revived recovery code")
	}
	raw, err := restored.IssueRecovery("testuser")
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.consumeRecoveryCode("testuser", raw, "recovered new password 123"); err != nil {
		t.Fatal(err)
	}
	if _, err = restored.login("testuser", "recovered new password 123", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = restored.IssueRecovery("testuser"); err == nil {
		t.Fatal("operator bypassed active account")
	}
}
func TestRecoveryCodeExpirySuspensionAndConcurrentUse(t *testing.T) {
	app, c, _ := fixture(t)
	registerVerified(t, app, c)
	var id string
	app.db.QueryRow("SELECT id FROM users WHERE username='testuser'").Scan(&id)
	raw := randomToken()
	app.db.Exec("INSERT INTO recovery_codes VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at", id, hash(raw), app.now().Unix(), app.now().Add(time.Minute).Unix())
	app.db.Exec("UPDATE users SET status='suspended' WHERE id=?", id)
	if err := app.consumeRecoveryCode("testuser", raw, "new password 123"); err != errCredential {
		t.Fatal("suspended account recovered", err)
	}
	app.db.Exec("UPDATE users SET status='active' WHERE id=?", id)
	app.db.Exec("UPDATE recovery_codes SET expires_at=?", app.now().Add(-time.Minute).Unix())
	if err := app.consumeRecoveryCode("testuser", raw, "new password 123"); err != errCredential {
		t.Fatal("expired code accepted")
	}
	app.db.Exec("UPDATE recovery_codes SET expires_at=?", app.now().Add(time.Hour).Unix())
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- app.consumeRecoveryCode("testuser", raw, "new password 123") }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if err != errCredential {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("double use", success)
	}
}
func TestProductionCookiesCrossSiteNavigationAndCSRF(t *testing.T) {
	app, _, _ := fixture(t)
	app.config.Mode = "production"
	app.config.Origin = "https://account.example.test"
	app.config.TrustedProxies = []string{"127.0.0.1/32"}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, app.config.Origin+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1000"
		r.Header.Set("X-Forwarded-For", "198.51.100.8")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/login", "")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if !c.Secure || !c.HttpOnly {
			t.Fatal("unsafe csrf cookie")
		}
	}
	if w = request("POST", "/api/v1/auth/recover-password", ""); w.Code != 403 {
		t.Fatal("cross site mutation allowed", w.Code)
	}
}

func TestFullBundleIsolationClearsSnapshotCredentials(t *testing.T) {
	app, c, _ := fixture(t)
	registerVerified(t, app, c)
	requireStatus(t, c.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	backup, err := app.Backup()
	if err != nil {
		t.Fatal(err)
	}
	if err = app.IsolateRestoredCopy(); err != nil {
		t.Fatal(err)
	}
	if _, err = app.login("testuser", testPassword, ""); err != errCredential {
		t.Fatal("snapshot password accepted")
	}
	var n int
	app.db.QueryRow("SELECT count(*) FROM sessions").Scan(&n)
	if n != 0 {
		t.Fatal("snapshot sessions survived")
	}
	dest := filepath.Join(t.TempDir(), "before-isolation.db")
	if err = RestoreAccountBackup(app.config, app.keys, filepath.Join(app.config.BackupDirectory, backup.Archive), dest); err != nil {
		t.Fatal(err)
	}
	config := app.config
	config.Database = dest
	restored, err := New(config, app.keys, app.logger)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err = restored.login("testuser", testPassword, ""); err != errCredential {
		t.Fatal("isolation rolled back")
	}
	raw, err := restored.IssueRecovery("testuser")
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.consumeRecoveryCode("testuser", raw, "verified recovered password 123"); err != nil {
		t.Fatal(err)
	}
}
