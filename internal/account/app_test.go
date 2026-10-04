package account

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type browser struct {
	app     *App
	cookies map[string]*http.Cookie
	csrf    string
}

func fixture(t *testing.T) (*App, *browser, *bytes.Buffer) {
	t.Helper()
	config := Config{Mode: "test", Address: "127.0.0.1:4100", Origin: "http://127.0.0.1:4100", Database: filepath.Join(t.TempDir(), "account.db"), KeyFile: "test-only", MailMode: "synthetic"}
	logs := &bytes.Buffer{}
	app, err := New(config, randomBytes(96), log.New(logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	client := &browser{app: app, cookies: map[string]*http.Cookie{}}
	response := client.call("GET", "/api/v1/csrf", nil)
	var body map[string]string
	if err = json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	client.csrf = body["csrf_token"]
	return app, client, logs
}
func (client *browser) call(method, path string, values any) *httptest.ResponseRecorder {
	var payload io.Reader
	if values != nil {
		content, _ := json.Marshal(values)
		payload = bytes.NewReader(content)
	}
	request := httptest.NewRequest(method, client.app.config.Origin+path, payload)
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("Accept", "application/json")
	if method == "POST" {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", client.app.config.Origin)
		request.Header.Set("X-CSRF-Token", client.csrf)
	}
	for _, cookie := range client.cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	client.app.Handler().ServeHTTP(response, request)
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(client.cookies, cookie.Name)
		} else {
			client.cookies[cookie.Name] = cookie
		}
	}
	return response
}
func requireStatus(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d expected=%d response=%s", response.Code, status, response.Body.String())
	}
}
func mailToken(t *testing.T, app *App, kind string) string {
	t.Helper()
	if err := app.ProcessMail(context.Background()); err != nil {
		t.Fatal(err)
	}
	messages, err := app.Mailbox()
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		if message.Kind == kind {
			link, _ := url.Parse(message.Link)
			return link.Query().Get("token")
		}
	}
	t.Fatal("mail missing")
	return ""
}

const testPassword = "synthetic password 123"

func registerVerified(t *testing.T, app *App, client *browser) string {
	t.Helper()
	invite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Username: "testuser", Password: testPassword, InviteCode: invite}), 201)
	client.call("POST", "/api/v1/auth/logout", nil)
	return invite
}

func TestInviteRegistrationSingleUse(t *testing.T) {
	app, client, _ := fixture(t)
	invite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	password := "invite password 123"
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Username: "inviteuser", Password: password, InviteCode: invite}), 201)
	if client.cookies["star_account_session"] == nil {
		t.Fatal("registration did not create session")
	}
	client.call("POST", "/api/v1/auth/logout", nil)
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Username: "seconduser", Password: password, InviteCode: invite}), 400)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "inviteuser", Password: password}), 200)
	badInvite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Username: "thirduser", Password: password, InviteCode: badInvite + "x"}), 400)
}

func TestRegisterVerifyLoginLogout(t *testing.T) {
	app, client, logs := fixture(t)
	invite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Username: "testuser", Password: testPassword, InviteCode: invite}), 201)
	cookie := client.cookies["star_account_session"]
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge > 30*86400 {
		t.Fatal("invalid cookie attributes")
	}
	if !strings.Contains(client.call("GET", "/api/v1/auth/session", nil).Body.String(), `"authenticated":true`) {
		t.Fatal("session missing")
	}
	var stored string
	if err := app.db.QueryRow("SELECT hash FROM sessions").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == cookie.Value || stored != hash(cookie.Value) {
		t.Fatal("raw session stored")
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/logout", struct{}{}), 200)
	client.cookies["star_account_session"] = cookie
	if !strings.Contains(client.call("GET", "/api/v1/auth/session", nil).Body.String(), `"authenticated":false`) {
		t.Fatal("revoked session accepted")
	}
	for _, secret := range []string{testPassword, invite, cookie.Value, "testuser"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("sensitive log content")
		}
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Email: "old@example.com", Password: testPassword}), 400)
}
func TestRecoveryAndExpiry(t *testing.T) {
	app, client, _ := fixture(t)
	invite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Username: "resetuser", Password: testPassword, InviteCode: invite}), 201)
	oldCookie := client.cookies["star_account_session"]
	var email string
	if err := app.db.QueryRow("SELECT email FROM users WHERE username='resetuser'").Scan(&email); err != nil {
		t.Fatal(err)
	}
	existing := client.call("POST", "/api/v1/auth/request-reset", input{Email: email})
	missing := client.call("POST", "/api/v1/auth/request-reset", input{Email: "missing@example.com"})
	if existing.Code != missing.Code || existing.Body.String() != missing.Body.String() {
		t.Fatal("recovery enumerates accounts")
	}
	token := mailToken(t, app, "reset")
	requireStatus(t, client.call("POST", "/api/v1/auth/reset-password", input{Token: token, Password: "short"}), 400)
	requireStatus(t, client.call("POST", "/api/v1/auth/reset-password", input{Token: token, Password: "replacement password 456"}), 200)
	requireStatus(t, client.call("POST", "/api/v1/auth/reset-password", input{Token: token, Password: testPassword}), 400)
	client.cookies["star_account_session"] = oldCookie
	if strings.Contains(client.call("GET", "/api/v1/auth/session", nil).Body.String(), `"authenticated":true`) {
		t.Fatal("reset did not revoke sessions")
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "resetuser", Password: testPassword}), 401)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "resetuser", Password: "replacement password 456"}), 200)
	requireStatus(t, client.call("POST", "/api/v1/auth/request-reset", input{Email: email}), 202)
	expired := mailToken(t, app, "reset")
	timestamp := time.Now().Add(2 * time.Hour)
	app.now = func() time.Time { return timestamp }
	requireStatus(t, client.call("POST", "/api/v1/auth/reset-password", input{Token: expired, Password: testPassword}), 400)
}
func TestVerificationExpiryAndPreRegistration(t *testing.T) {
	app, client, _ := fixture(t)
	invite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Username: "expireuser", Password: testPassword, InviteCode: invite}), 201)
	var email string
	if err := app.db.QueryRow("SELECT email FROM users WHERE username='expireuser'").Scan(&email); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/request-reset", input{Email: email}), 202)
	token := mailToken(t, app, "reset")
	timestamp := time.Now().Add(2 * time.Hour)
	app.now = func() time.Time { return timestamp }
	requireStatus(t, client.call("POST", "/api/v1/auth/reset-password", input{Token: token, Password: testPassword}), 400)
}
func TestConcurrentConsumption(t *testing.T) {
	app, client, _ := fixture(t)
	invite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Username: "concurrentuser", Password: testPassword, InviteCode: invite}), 201)
	var email string
	if err := app.db.QueryRow("SELECT email FROM users WHERE username='concurrentuser'").Scan(&email); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/request-reset", input{Email: email}), 202)
	token := mailToken(t, app, "reset")
	var group sync.WaitGroup
	results := make(chan error, 8)
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() { defer group.Done(); results <- app.consume(token, "reset", "new password 789") }()
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, errCredential) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("token consumed %d times", success)
	}
}
func TestCSRFOriginLimitsAndUnknownPassword(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	wrong := client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: "incorrect password 123"})
	missing := client.call("POST", "/api/v1/auth/login", input{Username: "absentuser", Password: testPassword})
	if wrong.Code != 401 || missing.Body.String() != wrong.Body.String() {
		t.Fatal("login enumeration")
	}
	token := client.csrf
	client.csrf = ""
	requireStatus(t, client.call("POST", "/api/v1/auth/logout", struct{}{}), 403)
	client.csrf = token
	request := httptest.NewRequest("POST", app.config.Origin+"/api/v1/auth/logout", strings.NewReader("{}"))
	request.Header.Set("Origin", "http://evil.test")
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	requireStatus(t, response, 403)
	for index := 0; index < 4; index++ {
		client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: "incorrect password 123"})
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 429)
	for index := 0; index < 30; index++ {
		client.call("POST", "/api/v1/auth/request-reset", input{Email: "absent@example.com"})
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/request-reset", input{Email: "absent@example.com"}), 429)
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Email: "someone@gmail.com", Password: testPassword}), 400)
}
func TestPersistenceStatusAndMigration(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(app.config, app.keys, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	client.app = reopened
	if !strings.Contains(client.call("GET", "/api/v1/auth/session", nil).Body.String(), `"authenticated":true`) {
		t.Fatal("session lost on restart")
	}
	if _, err = reopened.db.Exec("UPDATE users SET status='suspended'"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(client.call("GET", "/api/v1/auth/session", nil).Body.String(), `"authenticated":true`) {
		t.Fatal("suspended user authenticated")
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 401)
	var version int
	if err = reopened.db.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 3 {
		t.Fatal("migration failed")
	}
}

type failSender struct{}

func (failSender) Send(context.Context, Mail) error {
	return errors.New("provider secret should never be logged")
}
func TestMailFailureEncryptionRetryAndCleanup(t *testing.T) {
	app, client, _ := fixture(t)
	invite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/register", input{Username: "mailuser", Password: testPassword, InviteCode: invite}), 201)
	var email string
	if err := app.db.QueryRow("SELECT email FROM users WHERE username='mailuser'").Scan(&email); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, client.call("POST", "/api/v1/auth/request-reset", input{Email: email}), 202)
	var payload []byte
	if err := app.db.QueryRow("SELECT payload FROM mail_jobs").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(email)) {
		t.Fatal("unencrypted outbox")
	}
	app.config.MailMode = "smtp"
	app.sender = failSender{}
	timestamp := time.Now()
	app.now = func() time.Time { return timestamp }
	for index := 0; index < 3; index++ {
		if err := app.ProcessMail(context.Background()); err != nil {
			t.Fatal(err)
		}
		timestamp = timestamp.Add(10 * time.Minute)
	}
	var status, code string
	var attempts int
	if err := app.db.QueryRow("SELECT status,attempts,error_code FROM mail_jobs").Scan(&status, &attempts, &code); err != nil {
		t.Fatal(err)
	}
	if status != "permanent_failure" || attempts != 3 || code != "MAIL_DELIVERY_FAILED" {
		t.Fatal("mail failure not recorded")
	}
	logs := &bytes.Buffer{}
	app.logger = log.New(logs, "", 0)
	if err := app.ProcessMail(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "provider secret") {
		t.Fatal("mail error leaked")
	}
	app.config.MailMode = "synthetic"
	timestamp = timestamp.Add(32 * 24 * time.Hour)
	if err := app.Cleanup(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := app.db.QueryRow("SELECT count(*) FROM mail_jobs").Scan(&count); err != nil || count != 0 {
		t.Fatal("outbox not cleaned")
	}
}
func TestInvalidConfigAndCorruptDatabase(t *testing.T) {
	app, _, _ := fixture(t)
	for _, mutate := range []func(*Config){func(config *Config) { config.Mode = "production" }, func(config *Config) { config.Address = "0.0.0.0:4100" }, func(config *Config) { config.Origin = "http://evil.test" }, func(config *Config) { config.Database = "" }, func(config *Config) { config.MailMode = "" }} {
		config := app.config
		mutate(&config)
		if config.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	if _, _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing config accepted")
	}
	filename := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(filename, []byte("not a sqlite database"), 0600); err != nil {
		t.Fatal(err)
	}
	config := app.config
	config.Database = filename
	if opened, err := New(config, app.keys, log.New(io.Discard, "", 0)); err == nil {
		opened.Close()
		t.Fatal("corrupt database accepted")
	}
}

func TestFormsHeadersAndIsolation(t *testing.T) {
	app, client, _ := fixture(t)
	response := client.call("GET", "/register", nil)
	if response.Header().Get("Referrer-Policy") != "strict-origin" {
		t.Fatal("form origin must be retained without path/query")
	}
	invite, err := app.GenerateInvite()
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"username": {"formuser"}, "password": {testPassword}, "invite_code": {invite}, "gorilla.csrf.Token": {client.csrf}}
	request := httptest.NewRequest("POST", app.config.Origin+"/api/v1/auth/register", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", app.config.Origin)
	request.Header.Set("Referer", app.config.Origin+"/")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, cookie := range client.cookies {
		request.AddCookie(cookie)
	}
	response = httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	requireStatus(t, response, 201)
	if !strings.Contains(response.Body.String(), "注册成功") {
		t.Fatal("SSR result missing")
	}
	for _, origin := range []string{"null", "http://evil.test", "http://127.0.0.1:4200"} {
		request := httptest.NewRequest("POST", app.config.Origin+"/api/v1/auth/logout", strings.NewReader("{}"))
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", client.csrf)
		for _, cookie := range client.cookies {
			request.AddCookie(cookie)
		}
		response = httptest.NewRecorder()
		app.Handler().ServeHTTP(response, request)
		requireStatus(t, response, 403)
	}
	request = httptest.NewRequest("POST", app.config.Origin+"/api/v1/auth/logout", nil)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	response = httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	requireStatus(t, response, 403)
	request = httptest.NewRequest("GET", "http://evil.test/dev/mailbox", nil)
	response = httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	requireStatus(t, response, 400)
	app.config.MailMode = "smtp"
	requireStatus(t, client.call("GET", "/dev/mailbox", nil), 404)
	app.config.MailMode = "synthetic"
	invite2, _ := app.GenerateInvite()
	response = client.call("POST", "/api/v1/auth/register", input{Username: "sizeuser", Password: strings.Repeat("x", 9000), InviteCode: invite2})
	if response.Code != 400 && response.Code != 403 {
		t.Fatal("oversized request accepted")
	}
}

func TestSessionRotationAndExpiry(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	old := client.cookies["star_account_session"]
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	current := client.cookies["star_account_session"]
	if current.Value == old.Value {
		t.Fatal("session not rotated")
	}
	client.cookies["star_account_session"] = old
	if strings.Contains(client.call("GET", "/api/v1/auth/session", nil).Body.String(), `"authenticated":true`) {
		t.Fatal("old session still accepted")
	}
	client.cookies["star_account_session"] = current
	timestamp := time.Now().Add(8 * 24 * time.Hour)
	app.now = func() time.Time { return timestamp }
	if strings.Contains(client.call("GET", "/api/v1/auth/session", nil).Body.String(), `"authenticated":true`) {
		t.Fatal("expired session accepted")
	}
}

func TestMigrationFailureRollsBack(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "migration.db")
	database, err := sql.Open("sqlite", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec("CREATE TABLE tokens(hash TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	database.Close()
	opened, err := openDatabase(filename)
	if err == nil {
		opened.Close()
		t.Fatal("incompatible schema accepted")
	}
	database, err = sql.Open("sqlite", filename)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err = database.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='users'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("partial migration was not rolled back")
	}
}
