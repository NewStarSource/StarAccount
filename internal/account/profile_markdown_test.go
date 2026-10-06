package account

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProfileMarkdownPreviewAndPersistence(t *testing.T) {
	app, client, _ := fixture(t)
	preview := func(bio string, withCSRF bool) *httptest.ResponseRecorder {
		form := url.Values{"bio": {bio}}
		if withCSRF {
			form.Set("gorilla.csrf.Token", client.csrf)
		}
		request := httptest.NewRequest("POST", app.config.Origin+"/api/v1/profile/preview", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Accept", "text/html")
		request.Header.Set("Origin", app.config.Origin)
		for _, cookie := range client.cookies {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		app.Handler().ServeHTTP(response, request)
		return response
	}

	requireStatus(t, preview("**测试**", true), 401)
	registerVerified(t, app, client)
	requireStatus(t, client.call("POST", "/api/v1/auth/login", input{Username: "testuser", Password: testPassword}), 200)
	bio := "## 关于我\n\n**创作**与[项目](https://example.invalid/)\n\n- 阅读\n- 编程\n\n<script>alert(1)</script>\n\n[危险](javascript:alert(1))\n\n![外站](https://example.invalid/tracker.png)"
	requireStatus(t, preview(bio, false), 403)
	response := preview(bio, true)
	requireStatus(t, response, 200)
	assertSafeProfileMarkdown(t, response.Body.String())
	var stored, accountID string
	if err := app.db.QueryRow("SELECT id,bio FROM users WHERE username='testuser'").Scan(&accountID, &stored); err != nil || stored != "" {
		t.Fatal("preview changed the stored profile", err)
	}

	// Percent-encoded Chinese reaches more than 8 KiB at the existing 2000-character limit.
	fullBio := strings.Repeat("汉", 2000)
	requireStatus(t, preview(fullBio, true), 200)
	requireStatus(t, preview(fullBio+"汉", true), 400)
	requireStatus(t, securityCall(client, "update-profile", url.Values{"bio": {fullBio}}), 200)
	requireStatus(t, securityCall(client, "update-profile", url.Values{"bio": {fullBio + "汉"}}), 400)
	requireStatus(t, securityCall(client, "update-profile", url.Values{"bio": {bio}}), 200)
	if err := app.db.QueryRow("SELECT bio FROM users WHERE id=?", accountID).Scan(&stored); err != nil || stored != bio {
		t.Fatal("Markdown source was not preserved", err)
	}
	edit := client.call("GET", "/profile", nil)
	requireStatus(t, edit, 200)
	if !strings.Contains(edit.Body.String(), "**创作**") || !strings.Contains(edit.Body.String(), "&lt;script&gt;") {
		t.Fatal("editor failed to refill escaped Markdown source")
	}
	view := client.call("GET", "/profile/"+accountID, nil)
	requireStatus(t, view, 200)
	assertSafeProfileMarkdown(t, view.Body.String())
}

func assertSafeProfileMarkdown(t *testing.T, output string) {
	t.Helper()
	for _, expected := range []string{"<h2>关于我</h2>", "<strong>创作</strong>", "<ul>", `href="https://example.invalid/"`} {
		if !strings.Contains(output, expected) {
			t.Fatal("Markdown formatting missing", expected)
		}
	}
	for _, unsafe := range []string{"<script>", "javascript:", "<img", "tracker.png"} {
		if strings.Contains(output, unsafe) {
			t.Fatal("unsafe profile output", unsafe)
		}
	}
}
