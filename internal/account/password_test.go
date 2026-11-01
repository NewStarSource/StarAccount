package account

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const changedPassword = "new synthetic password 456"

func passwordValues() url.Values {
	return url.Values{"current_password": {testPassword}, "password": {changedPassword}, "password_confirmation": {changedPassword}}
}
func passwordLogin(t *testing.T, app *App, c *browser) *Identity {
	t.Helper()
	registerVerified(t, app, c)
	requireStatus(t, c.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	r := httptest.NewRequest("GET", app.config.Origin+"/", nil)
	for _, cookie := range c.cookies {
		r.AddCookie(cookie)
	}
	i, err := app.identity(r)
	if err != nil || i == nil {
		t.Fatal("identity", err)
	}
	return i
}

func TestPasswordChangeRevocationAndRecovery(t *testing.T) {
	app, c, logs := fixture(t)
	i := passwordLogin(t, app, c)
	if _, err := app.login("testuser", testPassword, ""); err != nil {
		t.Fatal(err)
	}
	otherID := opaqueID()
	if _, err := app.db.Exec("INSERT INTO users(id,subject_id,email,username,alias,password_hash,verified,status,created_at) SELECT ?,?,'password-other@account.invalid','passwordother','passwordother',password_hash,1,'active',created_at FROM users WHERE id=?", otherID, opaqueID(), i.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.login("passwordother", testPassword, ""); err != nil {
		t.Fatal(err)
	}
	response := securityCall(c, "recovery-code", url.Values{"password": {testPassword}})
	requireStatus(t, response, 200)
	var recovery struct {
		Code string `json:"recovery_code"`
	}
	json.Unmarshal(response.Body.Bytes(), &recovery)
	backup, err := app.Backup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.db.Exec("INSERT INTO oidc_tokens VALUES(?,?,?,?)", hash(randomToken()), i.ID, i.SessionID, app.now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	page := c.call("GET", "/security/password", nil)
	requireStatus(t, page, 200)
	if !strings.Contains(page.Body.String(), `autocomplete="current-password"`) || !strings.Contains(c.call("GET", "/security", nil).Body.String(), `href="/security/password"`) {
		t.Fatal("password form/entry missing")
	}
	response = securityCall(c, "change-password", passwordValues())
	requireStatus(t, response, 200)
	if !strings.Contains(response.Body.String(), "PASSWORD_CHANGED") {
		t.Fatal("missing success result")
	}
	for _, query := range []string{"SELECT count(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL", "SELECT count(*) FROM oidc_tokens WHERE user_id=?", "SELECT count(*) FROM recovery_codes WHERE user_id=?"} {
		var n int
		if err = app.db.QueryRow(query, i.ID).Scan(&n); err != nil || n != 0 {
			t.Fatal("credentials survived", query, n, err)
		}
	}
	if _, err = app.login("testuser", testPassword, ""); err != errCredential {
		t.Fatal("old password accepted", err)
	}
	if _, err = app.login("testuser", changedPassword, ""); err != nil {
		t.Fatal(err)
	}
	var otherActive int
	if err = app.db.QueryRow("SELECT count(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL", otherID).Scan(&otherActive); err != nil || otherActive != 1 {
		t.Fatal("other account session affected", err)
	}
	if _, err = app.login("passwordother", testPassword, ""); err != nil {
		t.Fatal("other account password affected", err)
	}
	if err = app.consumeRecoveryCode("testuser", recovery.Code, "third password 789"); err != errCredential {
		t.Fatal("old recovery code accepted", err)
	}
	if strings.Contains(logs.String(), testPassword) || strings.Contains(logs.String(), changedPassword) {
		t.Fatal("secret in logs")
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
	if _, err = restored.login("testuser", testPassword, ""); err != errCredential {
		t.Fatal("backup revived old password", err)
	}
}

func TestPasswordChangeInputAndAuthorization(t *testing.T) {
	for _, scenario := range []string{"wrong-current", "mismatch", "short", "same", "utf8-bytes", "csrf", "revoked", "suspended", "expired", "anonymous"} {
		t.Run(scenario, func(t *testing.T) {
			app, c, _ := fixture(t)
			i := passwordLogin(t, app, c)
			v := passwordValues()
			want := 400
			switch scenario {
			case "wrong-current":
				v.Set("current_password", "wrong current password")
				want = 401
			case "mismatch":
				v.Set("password_confirmation", "other password 789")
			case "short":
				v.Set("password", "short")
			case "same":
				v.Set("password", testPassword)
				v.Set("password_confirmation", testPassword)
			case "utf8-bytes":
				v.Set("password", strings.Repeat("密", 25))
				v.Set("password_confirmation", strings.Repeat("密", 25))
			case "csrf":
				c.csrf = "invalid"
				want = 403
			case "revoked":
				app.db.Exec("UPDATE sessions SET revoked_at=unixepoch() WHERE id=?", i.SessionID)
				want = 401
			case "suspended":
				app.db.Exec("UPDATE users SET status='suspended' WHERE id=?", i.ID)
				want = 401
			case "expired":
				app.db.Exec("UPDATE sessions SET expires_at=unixepoch()-1 WHERE id=?", i.SessionID)
				want = 401
			case "anonymous":
				delete(c.cookies, "star_account_session")
				want = 401
			}
			requireStatus(t, securityCall(c, "change-password", v), want)
			var stored string
			if err := app.db.QueryRow("SELECT password_hash FROM users WHERE id=?", i.ID).Scan(&stored); err != nil || bcrypt.CompareHashAndPassword([]byte(stored), []byte(testPassword)) != nil {
				t.Fatal("failed operation changed password", err)
			}
		})
	}
}

func TestPasswordChangeStaleSessionAndAtomicity(t *testing.T) {
	app, c, _ := fixture(t)
	i := passwordLogin(t, app, c)
	var old string
	app.db.QueryRow("SELECT password_hash FROM users WHERE id=?", i.ID).Scan(&old)
	newHash, _ := bcrypt.GenerateFromPassword([]byte(changedPassword), bcrypt.DefaultCost)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- app.commitPasswordChange(context.Background(), i, old, string(newHash))
		}()
	}
	wg.Wait()
	close(results)
	success, stale := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if err == errCredential {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || stale != 1 {
		t.Fatal("concurrent update", success, stale)
	}
	if err := app.commitPasswordChange(context.Background(), i, string(newHash), old); err != errCredential {
		t.Fatal("revoked session wrote new credentials", err)
	}
}

func TestPasswordChangeRollbackAndHTML(t *testing.T) {
	app, c, _ := fixture(t)
	i := passwordLogin(t, app, c)
	if _, err := app.db.Exec(`CREATE TRIGGER fail_password_cleanup BEFORE DELETE ON recovery_codes BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, securityCall(c, "change-password", passwordValues()), 503)
	if _, err := app.login("testuser", testPassword, ""); err != nil {
		t.Fatal("failed transaction changed credentials", err)
	}
	var n int
	app.db.QueryRow("SELECT count(*) FROM identity_events WHERE event_type='credentials_changed' AND account_id=?", i.ID).Scan(&n)
	if n != 0 {
		t.Fatal("failed change left event")
	}
	app.db.Exec("DROP TRIGGER fail_password_cleanup")
	v := passwordValues()
	v.Set("password_confirmation", "mismatch")
	v.Set("gorilla.csrf.Token", c.csrf)
	r := httptest.NewRequest("POST", app.config.Origin+"/api/v1/security/change-password", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", app.config.Origin)
	r.Header.Set("Accept", "text/html")
	for _, cookie := range c.cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	requireStatus(t, w, 400)
	if !strings.Contains(w.Body.String(), `role="alert"`) || !strings.Contains(w.Body.String(), `action="/api/v1/security/change-password"`) || strings.Contains(w.Body.String(), changedPassword) {
		t.Fatal("unsafe or unusable HTML failure")
	}
}

func TestPasswordChangeRateLimit(t *testing.T) {
	app, c, _ := fixture(t)
	passwordLogin(t, app, c)
	v := passwordValues()
	v.Set("current_password", "incorrect password 123")
	for n := 0; n < 5; n++ {
		requireStatus(t, securityCall(c, "change-password", v), 401)
	}
	requireStatus(t, securityCall(c, "change-password", passwordValues()), 429)
}
