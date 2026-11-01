package account

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

func (app *App) passwordRoutes(router chi.Router) {
	router.Get("/security/password", func(w http.ResponseWriter, r *http.Request) {
		i, err := app.identity(r)
		if err != nil {
			app.internal(w, r)
			return
		}
		if i == nil {
			http.Redirect(w, r, "/login", 303)
			return
		}
		app.render(w, r, 200, page{Name: "change_password", Identity: i})
	})
	router.Post("/api/v1/security/change-password", app.changePassword)
}

func (app *App) passwordError(w http.ResponseWriter, r *http.Request, status int, code, message string, i *Identity) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		app.respond(w, r, status, code, message)
		return
	}
	app.render(w, r, status, page{Name: "change_password", Identity: i, Message: message})
}

func (app *App) changePassword(w http.ResponseWriter, r *http.Request) {
	i, err := app.identity(r)
	if err != nil {
		app.internal(w, r)
		return
	}
	if i == nil {
		app.respond(w, r, 401, "SESSION_REQUIRED", "请重新登录")
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !app.allow("change-password-ip:"+host, 10, 15*time.Minute) || !app.allow("change-password-user:"+i.ID, 5, 15*time.Minute) {
		app.passwordError(w, r, 429, "RATE_LIMITED", "尝试过于频繁，请稍后重试", i)
		return
	}
	if r.ParseForm() != nil {
		app.passwordError(w, r, 400, "INPUT_INVALID", "请检查密码输入", i)
		return
	}
	current, next, confirmation := r.PostForm.Get("current_password"), r.PostForm.Get("password"), r.PostForm.Get("password_confirmation")
	if !validPassword(current) {
		app.passwordError(w, r, 401, "INVALID_CREDENTIALS", "当前密码不正确", i)
		return
	}
	if !validPassword(next) {
		app.passwordError(w, r, 400, "INPUT_INVALID", "新密码至少 12 个字符，不超过 72 个 UTF-8 字节", i)
		return
	}
	if next != confirmation {
		app.passwordError(w, r, 400, "INPUT_INVALID", "两次输入的新密码不一致", i)
		return
	}
	if next == current {
		app.passwordError(w, r, 400, "INPUT_INVALID", "新密码需要与当前密码不同", i)
		return
	}
	select {
	case app.expensive <- struct{}{}:
		defer func() { <-app.expensive }()
	default:
		app.passwordError(w, r, 503, "BUSY", "请稍后重试", i)
		return
	}
	var old string
	if err = app.db.QueryRowContext(r.Context(), "SELECT password_hash FROM users WHERE id=? AND status='active' AND verified=1", i.ID).Scan(&old); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			app.respond(w, r, 401, "SESSION_REQUIRED", "请重新登录")
		} else {
			app.internal(w, r)
		}
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(old), []byte(current)) != nil {
		app.passwordError(w, r, 401, "INVALID_CREDENTIALS", "当前密码不正确", i)
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		app.internal(w, r)
		return
	}
	if err = app.commitPasswordChange(r.Context(), i, old, string(newHash)); err != nil {
		if errors.Is(err, errCredential) {
			app.passwordError(w, r, 409, "CREDENTIALS_CHANGED", "账户凭据或会话已变化，请重新登录后再试", i)
		} else {
			app.internal(w, r)
		}
		return
	}
	setSession(w, "", app.config.secure())
	app.audit("password_changed")
	app.respond(w, r, 200, "PASSWORD_CHANGED", "密码已修改，全部旧会话与恢复码已失效。请重新登录，并生成新的恢复码。")
}

// Recheck the exact hash and initiating session inside the write transaction.
// A concurrent reset, revocation or status change cannot be overwritten.
func (app *App) commitPasswordChange(ctx context.Context, i *Identity, old, newHash string) error {
	tx, err := app.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=? AND password_hash=? AND status='active' AND verified=1 AND EXISTS(SELECT 1 FROM sessions WHERE id=? AND user_id=users.id AND revoked_at IS NULL AND expires_at>?)`, newHash, i.ID, old, i.SessionID, app.now().Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errCredential
	}
	for _, query := range []string{
		"DELETE FROM recovery_codes WHERE user_id=?",
		"UPDATE sessions SET revoked_at=unixepoch() WHERE user_id=? AND revoked_at IS NULL",
		"DELETE FROM mail_jobs WHERE token_hash IN (SELECT hash FROM tokens WHERE user_id=?)",
		"DELETE FROM tokens WHERE user_id=?",
		"DELETE FROM oidc_tokens WHERE user_id=?",
	} {
		if _, err = tx.ExecContext(ctx, query, i.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
