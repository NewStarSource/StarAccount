package account

import (
	"database/sql"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

func (app *App) showRecoveryCode(w http.ResponseWriter, r *http.Request, status int, code string) {
	message := "恢复码已更新。请立即离线保存，仅显示这一次，一年内有效。"
	codeName := "RECOVERY_CODE_CREATED"
	if status == 201 {
		message = "注册成功。请立即离线保存恢复码，仅显示这一次，一年内有效。"
		codeName = "REGISTERED"
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeJSON(w, status, map[string]any{"ok": true, "code": codeName, "message": message, "recovery_code": code})
		return
	}
	app.render(w, r, status, page{Name: "recovery_code", RecoveryCode: code, Message: message})
}
func (app *App) recoveryRoutes(router chi.Router) {
	router.Get("/security/recovery", func(w http.ResponseWriter, r *http.Request) {
		i, err := app.identity(r)
		if err != nil {
			app.internal(w, r)
			return
		}
		if i == nil {
			http.Redirect(w, r, "/login", 303)
			return
		}
		app.render(w, r, 200, page{Name: "recovery_settings", Identity: i})
	})
	router.Post("/api/v1/security/recovery-code", app.createRecoveryCode)
	router.Post("/api/v1/auth/recover-password", app.recoverPassword)
}
func recordRecoveryChange(tx *sql.Tx, id string, now int64) error {
	_, err := tx.Exec("INSERT INTO identity_events(event_id,account_id,event_type,status,status_version,occurred_at) SELECT ?,id,'recovery_changed',status,status_version,? FROM users WHERE id=?", opaqueID(), now, id)
	return err
}
func (app *App) createRecoveryCode(w http.ResponseWriter, r *http.Request) {
	i, err := app.identity(r)
	if err != nil {
		app.internal(w, r)
		return
	}
	if i == nil {
		app.respond(w, r, 401, "SESSION_REQUIRED", "请先登录")
		return
	}
	if !app.allow("recovery-code:"+i.ID, 5, 15*time.Minute) {
		app.respond(w, r, 429, "RATE_LIMITED", "尝试过于频繁，请稍后重试")
		return
	}
	if r.ParseForm() != nil || !validPassword(r.PostForm.Get("password")) {
		app.respond(w, r, 400, "INPUT_INVALID", "请填写有效密码")
		return
	}
	select {
	case app.expensive <- struct{}{}:
		defer func() { <-app.expensive }()
	default:
		app.respond(w, r, 503, "BUSY", "请稍后重试")
		return
	}
	var old string
	if err = app.db.QueryRow("SELECT password_hash FROM users WHERE id=? AND status='active'", i.ID).Scan(&old); err != nil {
		app.internal(w, r)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(old), []byte(r.PostForm.Get("password"))) != nil {
		app.respond(w, r, 401, "INVALID_CREDENTIALS", "凭据无效")
		return
	}
	tx, err := app.db.Begin()
	if err != nil {
		app.internal(w, r)
		return
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow("SELECT count(*) FROM users JOIN sessions ON sessions.user_id=users.id WHERE users.id=? AND users.password_hash=? AND users.status='active' AND sessions.id=? AND sessions.revoked_at IS NULL AND sessions.expires_at>?", i.ID, old, i.SessionID, app.now().Unix()).Scan(&n); err != nil || n != 1 {
		app.respond(w, r, 401, "INVALID_CREDENTIALS", "凭据无效")
		return
	}
	raw := randomToken()
	if _, err = tx.Exec("INSERT INTO recovery_codes VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,created_at=excluded.created_at,expires_at=excluded.expires_at", i.ID, hash(raw), app.now().Unix(), app.now().Add(365*24*time.Hour).Unix()); err == nil {
		err = recordRecoveryChange(tx, i.ID, app.now().Unix())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		app.internal(w, r)
		return
	}
	app.showRecoveryCode(w, r, 200, raw)
}
func (app *App) recoverPassword(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !app.allow("recover-password-ip:"+host, 10, 15*time.Minute) {
		app.respond(w, r, 429, "RATE_LIMITED", "尝试过于频繁，请稍后重试")
		return
	}
	if r.ParseForm() != nil {
		app.respond(w, r, 400, "INPUT_INVALID", "输入无效")
		return
	}
	username, err := normalizeUsername(r.PostForm.Get("username"))
	code := r.PostForm.Get("recovery_code")
	password := r.PostForm.Get("password")
	if err != nil || len(code) != 43 || !validPassword(password) {
		app.respond(w, r, 400, "RECOVERY_INVALID", "恢复信息无效或已过期")
		return
	}
	if !app.allow("recover-password-user:"+username, 5, 15*time.Minute) {
		app.respond(w, r, 429, "RATE_LIMITED", "尝试过于频繁，请稍后重试")
		return
	}
	select {
	case app.expensive <- struct{}{}:
		defer func() { <-app.expensive }()
	default:
		app.respond(w, r, 503, "BUSY", "请稍后重试")
		return
	}
	if err = app.consumeRecoveryCode(username, code, password); err != nil {
		if errors.Is(err, errCredential) {
			app.respond(w, r, 400, "RECOVERY_INVALID", "恢复信息无效或已过期")
		} else {
			app.internal(w, r)
		}
		return
	}
	setSession(w, "", app.config.secure())
	app.respond(w, r, 200, "PASSWORD_RECOVERED", "密码已重置，恢复码和原有会话已失效。请重新登录并生成新恢复码。")
}
func (app *App) consumeRecoveryCode(username, code, password string) error {
	if !validPassword(password) || len(code) != 43 {
		return errCredential
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tx, err := app.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id, old, status string
	err = tx.QueryRow("SELECT u.id,u.password_hash,u.status FROM users u JOIN recovery_codes c ON c.user_id=u.id WHERE u.username=? AND c.code_hash=? AND c.expires_at>? AND u.verified=1 AND u.status IN ('active','recovery_pending')", username, hash(code), app.now().Unix()).Scan(&id, &old, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return errCredential
	}
	if err != nil {
		return err
	}
	for _, q := range []string{"DELETE FROM recovery_codes WHERE user_id=?", "UPDATE sessions SET revoked_at=unixepoch() WHERE user_id=? AND revoked_at IS NULL", "DELETE FROM mail_jobs WHERE token_hash IN (SELECT hash FROM tokens WHERE user_id=?)", "DELETE FROM tokens WHERE user_id=?", "DELETE FROM oidc_tokens WHERE user_id=?"} {
		if _, err = tx.Exec(q, id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("UPDATE users SET password_hash=?,status='active' WHERE id=?", string(newHash), id); err != nil {
		return err
	}
	if old == "" {
		if _, err = tx.Exec("INSERT INTO identity_events(event_id,account_id,event_type,status,status_version,occurred_at) SELECT ?,id,'credentials_changed',status,status_version,? FROM users WHERE id=?", opaqueID(), app.now().Unix(), id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// IssueRecovery is a local operator action, restricted to recovery_pending users.
// Operators must verify the account owner through an independent channel first.
func (app *App) IssueRecovery(username string) (string, error) {
	app.operationsMu.Lock()
	defer app.operationsMu.Unlock()
	if _, err := app.readSecurityJournal(); err != nil {
		return "", err
	}
	tx, err := app.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id string
	if err = tx.QueryRow("SELECT id FROM users WHERE username=? AND status='recovery_pending' AND verified=1", username).Scan(&id); err != nil {
		return "", err
	}
	raw := randomToken()
	if _, err = tx.Exec("INSERT INTO recovery_codes VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,created_at=excluded.created_at,expires_at=excluded.expires_at", id, hash(raw), app.now().Unix(), app.now().Add(15*time.Minute).Unix()); err != nil {
		return "", err
	}
	if err = recordRecoveryChange(tx, id, app.now().Unix()); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	if err = app.mirrorSecurityEvents(); err != nil {
		return "", err
	}
	return raw, nil
}

// IsolateRestoredCopy must be run on an offline, isolated full-bundle restore.
// Snapshot credentials cannot establish ownership after a disaster rollback.
func (app *App) IsolateRestoredCopy() error {
	app.operationsMu.Lock()
	defer app.operationsMu.Unlock()
	if _, err := app.readSecurityJournal(); err != nil {
		return err
	}
	tx, err := app.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, query := range []string{
		"DELETE FROM recovery_codes",
		"UPDATE sessions SET revoked_at=unixepoch() WHERE revoked_at IS NULL",
		"DELETE FROM sessions;DELETE FROM oidc_requests;DELETE FROM oidc_tokens;DELETE FROM mail_jobs;DELETE FROM tokens",
		"UPDATE users SET password_hash='',status=CASE WHEN status='active' THEN 'recovery_pending' ELSE status END WHERE status<>'deleted'",
		"INSERT INTO identity_events(event_id,account_id,event_type,status,status_version,occurred_at) SELECT lower(hex(randomblob(16))),id,'recovery_isolated',status,status_version,unixepoch() FROM users WHERE status<>'deleted'",
	} {
		if _, err = tx.Exec(query); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return app.mirrorSecurityEvents()
}
