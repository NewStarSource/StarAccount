package account

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Submit the native form without the JavaScript fetch/JSON path.
func nativeSecurityForm(c *browser, action string, values url.Values) *httptest.ResponseRecorder {
	values.Set("gorilla.csrf.Token", c.csrf)
	r := httptest.NewRequest("POST", c.app.config.Origin+"/api/v1/security/"+action, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Origin", c.app.config.Origin)
	r.RemoteAddr = "127.0.0.1:9999"
	for _, cookie := range c.cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	c.app.Handler().ServeHTTP(w, r)
	for _, cookie := range w.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(c.cookies, cookie.Name)
		} else {
			c.cookies[cookie.Name] = cookie
		}
	}
	return w
}

func TestRecoveryStatusLifecycleAndPrivacy(t *testing.T) {
	app, c, logs := fixture(t)
	i := passwordLogin(t, app, c)
	check := func(state string, secrets ...string) {
		t.Helper()
		for _, path := range []string{"/security", "/security/recovery"} {
			w := c.call("GET", path, nil)
			requireStatus(t, w, 200)
			if !strings.Contains(w.Body.String(), state) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("status or cache protection missing", path)
			}
			for _, secret := range secrets {
				if strings.Contains(w.Body.String(), secret) || strings.Contains(logs.String(), secret) {
					t.Fatal("recovery secret exposed in status or logs", path)
				}
			}
		}
	}
	// Registration creates a code; accounts without one must also render correctly.
	check("可用")
	if _, err := app.db.Exec("DELETE FROM recovery_codes WHERE user_id=?", i.ID); err != nil {
		t.Fatal(err)
	}
	check("未设置")
	create := func() string {
		t.Helper()
		w := securityCall(c, "recovery-code", url.Values{"password": {testPassword}})
		requireStatus(t, w, 200)
		var data struct {
			Code string `json:"recovery_code"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || len(data.Code) != 43 {
			t.Fatal("one-time code missing")
		}
		return data.Code
	}
	first := create()
	check("可用", first, hash(first))
	var created, expires int64
	if err := app.db.QueryRow("SELECT created_at,expires_at FROM recovery_codes WHERE user_id=?", i.ID).Scan(&created, &expires); err != nil {
		t.Fatal(err)
	}
	w := c.call("GET", "/security/recovery", nil)
	if !strings.Contains(html.UnescapeString(w.Body.String()), securityTime(created)) || !strings.Contains(html.UnescapeString(w.Body.String()), securityTime(expires)) {
		t.Fatal("metadata does not match stored validity")
	}
	second := create()
	check("可用", first, hash(first), second, hash(second))
	if err := app.consumeRecoveryCode("testuser", first, changedPassword); err != errCredential {
		t.Fatal("replaced code accepted", err)
	}
	if _, err := app.db.Exec("UPDATE recovery_codes SET expires_at=? WHERE user_id=?", app.now().Unix(), i.ID); err != nil {
		t.Fatal(err)
	}
	check("已过期", second, hash(second))
	if err := app.consumeRecoveryCode("testuser", second, changedPassword); err != errCredential {
		t.Fatal("code accepted at expiry boundary", err)
	}
	third := create()
	if err := app.consumeRecoveryCode("testuser", third, changedPassword); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, c.call("GET", "/security/recovery", nil), 303)
	requireStatus(t, c.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: changedPassword}), 200)
	check("未设置", third, hash(third))
}

func TestSecuritySessionVisibilityAndLimit(t *testing.T) {
	app, c, _ := fixture(t)
	i := passwordLogin(t, app, c)
	if _, err := app.db.Exec("DELETE FROM recovery_codes WHERE user_id=?", i.ID); err != nil {
		t.Fatal(err)
	}
	// The current session is older than the display limit, and must still be visible.
	if _, err := app.db.Exec("UPDATE sessions SET created_at=? WHERE id=?", app.now().Add(-time.Hour).Unix(), i.SessionID); err != nil {
		t.Fatal(err)
	}
	var otherSID string
	for n := range 102 {
		sid := opaqueID()
		if n == 0 {
			otherSID = sid
		}
		if _, err := app.db.Exec("INSERT INTO sessions(id,hash,user_id,created_at,expires_at) VALUES(?,?,?,?,?)", sid, hash(randomToken()), i.ID, app.now().Unix(), app.now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	for _, sid := range []string{"expired-session", "revoked-session"} {
		var revoked any
		expires := app.now().Unix()
		if sid == "revoked-session" {
			revoked = app.now().Unix()
			expires = app.now().Add(time.Hour).Unix()
		}
		if _, err := app.db.Exec("INSERT INTO sessions(id,hash,user_id,created_at,expires_at,revoked_at) VALUES(?,?,?,?,?,?)", sid, hash(randomToken()), i.ID, app.now().Unix(), expires, revoked); err != nil {
			t.Fatal(err)
		}
	}
	other := opaqueID()
	if _, err := app.db.Exec("INSERT INTO users(id,subject_id,email,username,alias,password_hash,verified,status,created_at) SELECT ?,?,'view-other@account.invalid','viewother','viewother',password_hash,1,'active',created_at FROM users WHERE id=?", other, opaqueID(), i.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.db.Exec("INSERT INTO sessions(id,hash,user_id,created_at,expires_at) VALUES('foreign-session',?,?,?,?)", hash(randomToken()), other, app.now().Unix(), app.now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	foreignCode := randomToken()
	if _, err := app.db.Exec("INSERT INTO recovery_codes VALUES(?,?,?,?)", other, hash(foreignCode), app.now().Unix(), app.now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	w := c.call("GET", "/api/v1/auth/sessions", nil)
	var data struct {
		Sessions []SessionView `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || len(data.Sessions) != 100 || !data.Sessions[0].Current || data.Sessions[0].ID != i.SessionID || data.Sessions[0].Expires == "" {
		t.Fatal("current session or validity omitted at display limit", err)
	}
	for _, path := range []string{"/security", "/api/v1/auth/sessions", "/security/recovery"} {
		w = c.call("GET", path, nil)
		requireStatus(t, w, 200)
		for _, hidden := range []string{"expired-session", "revoked-session", "foreign-session", foreignCode, hash(foreignCode)} {
			if strings.Contains(w.Body.String(), hidden) {
				t.Fatal("hidden or foreign data exposed", path)
			}
		}
	}
	if !strings.Contains(c.call("GET", "/security", nil).Body.String(), "共 100 条") || !strings.Contains(c.call("GET", "/security/recovery", nil).Body.String(), "未设置") {
		t.Fatal("truncation or own recovery state missing")
	}
	requireStatus(t, securityCall(c, "reauthenticate", url.Values{"password": {testPassword}}), 200)
	requireStatus(t, securityCall(c, "revoke", url.Values{"session_id": {"foreign-session"}}), 404)
	requireStatus(t, securityCall(c, "revoke", url.Values{"session_id": {"expired-session"}}), 404)
	requireStatus(t, securityCall(c, "revoke", url.Values{"session_id": {"revoked-session"}}), 404)
	requireStatus(t, securityCall(c, "revoke", url.Values{"session_id": {otherSID}}), 200)
	requireStatus(t, securityCall(c, "revoke-all", url.Values{}), 200)
	var count int
	if err := app.db.QueryRow("SELECT count(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at>?", i.ID, app.now().Unix()).Scan(&count); err != nil || count != 0 {
		t.Fatal("unlisted sessions survived revoke-all", err)
	}
	if err := app.db.QueryRow("SELECT count(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL", other).Scan(&count); err != nil || count != 1 {
		t.Fatal("other user's session affected", err)
	}
}

func TestNativeSecurityForms(t *testing.T) {
	app, c, _ := fixture(t)
	i := passwordLogin(t, app, c)
	w := nativeSecurityForm(c, "recovery-code", url.Values{"password": {"wrong password 123"}})
	requireStatus(t, w, 401)
	if !strings.Contains(w.Body.String(), `role="alert"`) || !strings.Contains(w.Body.String(), `action="/api/v1/security/recovery-code"`) || strings.Contains(w.Body.String(), "wrong password 123") {
		t.Fatal("native error loses form or echoes password")
	}
	w = nativeSecurityForm(c, "recovery-code", url.Values{"password": {testPassword}})
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "仅显示一次") || !strings.Contains(w.Body.String(), "<pre>") {
		t.Fatal("native one-time code presentation missing")
	}
	w = nativeSecurityForm(c, "reauthenticate", url.Values{"password": {testPassword}})
	requireStatus(t, w, http.StatusSeeOther)
	if w.Header().Get("Location") != "/security" || !strings.Contains(c.call("GET", "/security", nil).Body.String(), "确认有效至") {
		t.Fatal("native confirmation did not return to usable controls")
	}
	token, err := app.login("testuser", testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	var sid string
	if err = app.db.QueryRow("SELECT id FROM sessions WHERE hash=?", hash(token)).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	w = nativeSecurityForm(c, "revoke", url.Values{"session_id": {sid}})
	requireStatus(t, w, http.StatusSeeOther)
	if w.Header().Get("Location") != "/security" || strings.Contains(c.call("GET", "/security", nil).Body.String(), sid) {
		t.Fatal("revoked session still listed")
	}
	future := app.now().Add(5 * time.Minute)
	app.now = func() time.Time { return future }
	if strings.Contains(c.call("GET", "/security", nil).Body.String(), "确认有效至") {
		t.Fatal("expired confirmation displayed as valid")
	}
	requireStatus(t, nativeSecurityForm(c, "revoke", url.Values{"session_id": {i.SessionID}}), 403)
	requireStatus(t, nativeSecurityForm(c, "reauthenticate", url.Values{"password": {testPassword}}), 303)
	w = nativeSecurityForm(c, "revoke", url.Values{"session_id": {i.SessionID}})
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "该会话及其星图登录已退出") {
		t.Fatal("current-session result unclear")
	}
	requireStatus(t, c.call("GET", "/security", nil), 303)
}

func TestSecurityPagesRequireActiveSession(t *testing.T) {
	for _, state := range []string{"anonymous", "expired", "revoked", "suspended"} {
		t.Run(state, func(t *testing.T) {
			app, c, _ := fixture(t)
			if state != "anonymous" {
				i := passwordLogin(t, app, c)
				var err error
				switch state {
				case "expired":
					_, err = app.db.Exec("UPDATE sessions SET expires_at=? WHERE id=?", app.now().Unix(), i.SessionID)
				case "revoked":
					_, err = app.db.Exec("UPDATE sessions SET revoked_at=? WHERE id=?", app.now().Unix(), i.SessionID)
				case "suspended":
					_, err = app.db.Exec("UPDATE users SET status='suspended' WHERE id=?", i.ID)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, path := range []string{"/security", "/security/recovery"} {
				w := c.call("GET", path, nil)
				requireStatus(t, w, 303)
				if w.Header().Get("Location") != "/login" {
					t.Fatal("invalid session reached metadata")
				}
			}
			requireStatus(t, c.call("GET", "/api/v1/auth/sessions", nil), 401)
			requireStatus(t, nativeSecurityForm(c, "recovery-code", url.Values{"password": {testPassword}}), 401)
		})
	}
}

func TestNativeRecoveryRateLimit(t *testing.T) {
	app, c, _ := fixture(t)
	passwordLogin(t, app, c)
	for range 5 {
		requireStatus(t, nativeSecurityForm(c, "recovery-code", url.Values{"password": {"short"}}), 400)
	}
	w := nativeSecurityForm(c, "recovery-code", url.Values{"password": {testPassword}})
	requireStatus(t, w, 429)
	if !strings.Contains(w.Body.String(), "尝试过于频繁") || !strings.Contains(w.Body.String(), `action="/api/v1/security/recovery-code"`) || strings.Contains(w.Body.String(), testPassword) {
		t.Fatal("native throttling loses safe retry form")
	}
}
