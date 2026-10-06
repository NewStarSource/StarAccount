package account

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestProfileUnicodeRefillAndUnsafeWebsite(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	values := url.Values{"display_name": {strings.Repeat("汉", 100)}, "bio": {"资料简介"}, "location": {"测试所在地"}, "website": {"https://example.invalid/profile"}}
	requireStatus(t, securityCall(client, "update-profile", values), 200)
	page := client.call("GET", "/profile", nil)
	requireStatus(t, page, 200)
	if !strings.Contains(page.Body.String(), "资料简介") || !strings.Contains(page.Body.String(), "测试所在地") || !strings.Contains(page.Body.String(), `value="https://example.invalid/profile"`) {
		t.Fatal("profile not refilled")
	}
	for _, website := range []string{"javascript:alert(1)", "https://user:password@example.invalid/", "//example.invalid/"} {
		values.Set("website", website)
		requireStatus(t, securityCall(client, "update-profile", values), 400)
	}
	values.Set("website", "")
	values.Set("display_name", strings.Repeat("汉", 101))
	requireStatus(t, securityCall(client, "update-profile", values), 400)
	var name string
	if err := app.db.QueryRow("SELECT display_name FROM users WHERE username='testuser'").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if len([]rune(name)) != 100 {
		t.Fatal("invalid request modified stored profile")
	}
}
func TestInternalProfileWhitelistAndRecentDeactivation(t *testing.T) {
	app, client, _ := fixture(t)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	app.oidcStore = &oidcStore{app: app, secret: randomToken()}
	var account, sid string
	if err := app.db.QueryRow("SELECT id FROM users WHERE username='testuser'").Scan(&account); err != nil {
		t.Fatal(err)
	}
	if err := app.db.QueryRow("SELECT id FROM sessions WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1", account).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, form url.Values, authenticated bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, app.config.Origin+path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if authenticated {
			request.SetBasicAuth("star-atlas", app.oidcStore.secret)
		}
		response := httptest.NewRecorder()
		app.identityAPI(response, request)
		return response
	}
	requireStatus(t, call("GET", "/internal/identity/profile?account_id="+account, nil, false), 401)
	response := call("GET", "/internal/identity/profile?account_id="+account, nil, true)
	requireStatus(t, response, 200)
	for _, key := range []string{"password", "email", "username", "subject_id", account, sid} {
		if strings.Contains(response.Body.String(), key) {
			t.Fatal("private field exposed in profile", key)
		}
	}
	form := url.Values{"account_id": {account}, "sid": {sid}}
	requireStatus(t, call("POST", "/internal/identity/deactivate", form, false), 401)
	form.Set("sid", "not-owned")
	requireStatus(t, call("POST", "/internal/identity/deactivate", form, true), 403)
	form.Set("sid", sid)
	if _, err := app.db.Exec("UPDATE sessions SET created_at=?,reauthenticated_at=0 WHERE id=?", app.now().Add(-6*time.Minute).Unix(), sid); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, call("POST", "/internal/identity/deactivate", form, true), 403)
	if _, err := app.db.Exec("UPDATE sessions SET reauthenticated_at=? WHERE id=?", app.now().Unix(), sid); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, call("POST", "/internal/identity/deactivate", form, true), 200)
	requireStatus(t, call("GET", "/internal/identity/profile?account_id="+account, nil, true), 404)
	var revoked int
	if err := app.db.QueryRow("SELECT count(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL", account).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != 0 {
		t.Fatal("deactivation left sessions active")
	}
}
