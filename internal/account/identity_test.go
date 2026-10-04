package account

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func securityCall(client *browser, action string, values url.Values) *httptest.ResponseRecorder {
	values.Set("gorilla.csrf.Token", client.csrf)
	request := httptest.NewRequest("POST", client.app.config.Origin+"/api/v1/security/"+action, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Origin", client.app.config.Origin)
	request.RemoteAddr = "127.0.0.1:9999"
	for _, cookie := range client.cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	client.app.Handler().ServeHTTP(response, request)
	return response
}
func TestSecurityOwnershipReauthenticationAndRecovery(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	requireStatus(t, securityCall(client, "revoke-all", url.Values{}), 403)
	requireStatus(t, securityCall(client, "reauthenticate", url.Values{"password": {"wrong password 123"}}), 401)
	requireStatus(t, securityCall(client, "reauthenticate", url.Values{"password": {testPassword}}), 200)
	requireStatus(t, securityCall(client, "revoke", url.Values{"session_id": {"not-owned"}}), 404)
	otherID := opaqueID()
	if _, err := app.db.Exec("INSERT INTO users(id,subject_id,email,username,alias,password_hash,verified,status,created_at) SELECT ?,?,'other@account.invalid','otheruser','otheruser',password_hash,1,'active',created_at FROM users WHERE username='testuser'", otherID, opaqueID()); err != nil {
		t.Fatal(err)
	}
	otherToken, err := app.login("otheruser", testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	var otherSID string
	if err = app.db.QueryRow("SELECT id FROM sessions WHERE hash=?", hash(otherToken)).Scan(&otherSID); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, securityCall(client, "revoke", url.Values{"session_id": {otherSID}}), 404)
	var stillActive int
	if err = app.db.QueryRow("SELECT count(*) FROM sessions WHERE id=? AND revoked_at IS NULL", otherSID).Scan(&stillActive); err != nil || stillActive != 1 {
		t.Fatal("another account session revoked")
	}
	sessions := client.call("GET", "/api/v1/auth/sessions", nil)
	requireStatus(t, sessions, 200)
	if strings.Contains(sessions.Body.String(), "token") || strings.Contains(sessions.Body.String(), "subject_id") {
		t.Fatal("private credential in session view")
	}
	requireStatus(t, securityCall(client, "deactivate", url.Values{"confirm": {"deactivate"}}), 200)
	if strings.Contains(client.call("GET", "/api/v1/auth/session", nil).Body.String(), `"authenticated":true`) {
		t.Fatal("deactivated session accepted")
	}
	var events int
	if err := app.db.QueryRow("SELECT count(*) FROM identity_events").Scan(&events); err != nil || events < 2 {
		t.Fatal("revocation and status event missing")
	}
	requireStatus(t, securityCall(client, "restore", url.Values{"username": {"testuser"}, "password": {"wrong password 123"}}), 400)
	requireStatus(t, securityCall(client, "restore", url.Values{"username": {"testuser"}, "password": {testPassword}}), 200)
	if strings.Contains(client.call("GET", "/api/v1/auth/session", nil).Body.String(), `"authenticated":true`) {
		t.Fatal("restore resurrected session")
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	if _, err := app.db.Exec("UPDATE users SET status='suspended'"); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, securityCall(client, "restore", url.Values{"username": {"testuser"}, "password": {testPassword}}), 400)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 401)
}
func TestRecoveryExpiryAndReauthTimeout(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	requireStatus(t, securityCall(client, "reauthenticate", url.Values{"password": {testPassword}}), 200)
	timestamp := time.Now().Add(6 * time.Minute)
	app.now = func() time.Time { return timestamp }
	requireStatus(t, securityCall(client, "deactivate", url.Values{"confirm": {"deactivate"}}), 403)
	requireStatus(t, securityCall(client, "reauthenticate", url.Values{"password": {testPassword}}), 200)
	requireStatus(t, securityCall(client, "deactivate", url.Values{"confirm": {"deactivate"}}), 200)
	timestamp = timestamp.Add(31 * 24 * time.Hour)
	requireStatus(t, securityCall(client, "restore", url.Values{"username": {"testuser"}, "password": {testPassword}}), 400)
}
func TestRevocationEventsTransactionalAndAuthenticated(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	var initialCount int
	if err := app.db.QueryRow("SELECT count(*) FROM identity_events").Scan(&initialCount); err != nil {
		t.Fatal(err)
	}
	transaction, err := app.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transaction.Exec("UPDATE sessions SET revoked_at=1"); err != nil {
		t.Fatal(err)
	}
	transaction.Rollback()
	var count int
	if err = app.db.QueryRow("SELECT count(*) FROM identity_events").Scan(&count); err != nil || count != initialCount {
		t.Fatalf("event escaped rolled-back transaction: initial=%d current=%d", initialCount, count)
	}
	app.oidcStore = &oidcStore{app: app, secret: randomToken()}
	request := httptest.NewRequest("GET", app.config.Origin+"/internal/identity/events?after=0", nil)
	response := httptest.NewRecorder()
	app.identityAPI(response, request)
	requireStatus(t, response, 401)
	request.SetBasicAuth("star-atlas", app.oidcStore.secret)
	requireStatus(t, client.call("POST", "/api/v1/auth/logout", input{}), 200)
	response = httptest.NewRecorder()
	app.identityAPI(response, request)
	requireStatus(t, response, 200)
	var body struct {
		Events []identityEvent `json:"events"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Events) < 1 {
		t.Fatal("missing committed event")
	}
	if err = app.restore(context.Background(), "testuser", testPassword); err == nil {
		t.Fatal("active account restored")
	}
}

func TestIdentityMigrationPreservesExistingAccounts(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec("INSERT INTO users(id,subject_id,email,alias,password_hash,verified,status,created_at) VALUES('legacy','subject','legacy@example.com','旧化名','hash',1,'active',1)"); err != nil {
		t.Fatal(err)
	}
	legacy.Close()
	upgraded, err := openDatabase(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	var alias string
	var version int
	if err = upgraded.QueryRow("SELECT alias,status_version FROM users WHERE id='legacy'").Scan(&alias, &version); err != nil || alias != "旧化名" || version != 1 {
		t.Fatal("migration lost identity")
	}
	if _, err = upgraded.Exec("UPDATE users SET status='suspended' WHERE id='legacy'"); err != nil {
		t.Fatal(err)
	}
	if err = upgraded.QueryRow("SELECT status_version FROM users WHERE id='legacy'").Scan(&version); err != nil || version != 2 {
		t.Fatal("state version missing")
	}
}

func TestProtocolLogsExcludeCredentials(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(ProtocolLogHandler(&output)).With("redirect_uri", "http://bad.invalid?token=sensitive")
	logger.Warn("untrusted sensitive message", "client_secret", "secret-material", "code", "private-code")
	if strings.Contains(output.String(), "sensitive") || strings.Contains(output.String(), "secret-material") || strings.Contains(output.String(), "private-code") || !strings.Contains(output.String(), "oidc_protocol_event") {
		t.Fatal("unsafe protocol logging")
	}
}

func TestOIDCCodeAtomicConsumptionAndExpiry(t *testing.T) {
	app, _, _ := fixture(t)
	store := &oidcStore{app: app}
	raw := randomToken()
	auth := authorization{ID: opaqueID(), Complete: true}
	body, err := json.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.db.Exec("INSERT INTO oidc_requests(id,body,binding_hash,code_hash,expires_at) VALUES(?,?,?,?,?)", auth.ID, body, hash("browser"), hash(raw), app.now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 8)
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := store.AuthRequestByCode(context.Background(), raw)
			results <- err
		}()
	}
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("authorization code consumed %d times", successes)
	}
	if _, err = app.db.Exec("UPDATE oidc_requests SET exchanged=0,expires_at=0"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AuthRequestByCode(context.Background(), raw); err == nil {
		t.Fatal("expired code accepted")
	}
}
