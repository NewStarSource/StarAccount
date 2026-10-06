package account

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

type SessionView struct {
	ID      string `json:"id"`
	Created string `json:"created_at"`
	Current bool   `json:"current"`
}
type identityEvent struct {
	Sequence   int64  `json:"sequence"`
	ID         string `json:"event_id"`
	AccountID  string `json:"account_id"`
	SID        string `json:"sid,omitempty"`
	Type       string `json:"event_type"`
	Status     string `json:"status"`
	Version    int64  `json:"status_version"`
	OccurredAt int64  `json:"occurred_at"`
}

func (app *App) identityRoutes(router chi.Router) {
	router.Get("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
		profileID := chi.URLParam(request, "id")
		identity, err := app.identity(request)
		if err != nil {
			app.internal(writer, request)
			return
		}

		// Query user profile
		var username, displayName, bio, location, website string
		var createdAt int64
		err = app.db.QueryRowContext(request.Context(),
			"SELECT username, display_name, bio, location, website, created_at FROM users WHERE id=? AND verified=1 AND status='active'",
			profileID).Scan(&username, &displayName, &bio, &location, &website, &createdAt)

		if errors.Is(err, sql.ErrNoRows) {
			app.respond(writer, request, 404, "NOT_FOUND", "用户不存在")
			return
		}
		if err != nil {
			app.internal(writer, request)
			return
		}

		app.render(writer, request, 200, page{Name: "profile_view", Identity: identity, Token: username, Profile: publicProfile{displayName, bio, location, website}})
	})

	router.Get("/profile", func(writer http.ResponseWriter, request *http.Request) {
		identity, err := app.identity(request)
		if err != nil {
			app.internal(writer, request)
			return
		}
		if identity == nil {
			http.Redirect(writer, request, "/login", 303)
			return
		}

		// Query current user's profile
		var displayName, bio, location, website string
		err = app.db.QueryRowContext(request.Context(),
			"SELECT display_name, bio, location, website FROM users WHERE id=?",
			identity.ID).Scan(&displayName, &bio, &location, &website)

		if err != nil {
			app.internal(writer, request)
			return
		}

		app.render(writer, request, 200, page{Name: "profile_edit", Identity: identity, Profile: publicProfile{displayName, bio, location, website}})
	})

	router.Get("/security", func(writer http.ResponseWriter, request *http.Request) {
		identity, err := app.identity(request)
		if err != nil {
			app.internal(writer, request)
			return
		}
		if identity == nil {
			http.Redirect(writer, request, "/login", 303)
			return
		}
		sessions, err := app.sessionViews(request.Context(), identity)
		if err != nil {
			app.internal(writer, request)
			return
		}
		app.render(writer, request, 200, page{Name: "security", Identity: identity, Sessions: sessions})
	})
	router.Get("/recover", func(writer http.ResponseWriter, request *http.Request) {
		app.render(writer, request, 200, page{Name: "recover"})
	})
	router.Get("/api/v1/auth/sessions", func(writer http.ResponseWriter, request *http.Request) {
		identity, err := app.identity(request)
		if err != nil {
			app.internal(writer, request)
			return
		}
		if identity == nil {
			app.respond(writer, request, 401, "SESSION_REQUIRED", "请先登录")
			return
		}
		sessions, err := app.sessionViews(request.Context(), identity)
		if err != nil {
			app.internal(writer, request)
			return
		}
		writeJSON(writer, 200, map[string]any{"sessions": sessions})
	})
	for _, action := range []string{"reauthenticate", "revoke", "revoke-all", "deactivate", "restore", "update-profile"} {
		router.Post("/api/v1/security/"+action, app.securityAction(action))
	}
}
func (app *App) sessionViews(ctx context.Context, identity *Identity) ([]SessionView, error) {
	rows, err := app.db.QueryContext(ctx, "SELECT id,created_at FROM sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at>? ORDER BY created_at DESC,id LIMIT 100", identity.ID, app.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := []SessionView{}
	for rows.Next() {
		var session SessionView
		var created int64
		if err = rows.Scan(&session.ID, &created); err != nil {
			return nil, err
		}
		session.Created = time.Unix(created, 0).In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01-02 15:04:05 +08:00")
		session.Current = session.ID == identity.SessionID
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}
func (app *App) securityAction(action string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		host, _, _ := net.SplitHostPort(request.RemoteAddr)
		if !app.allow("security:"+action+":"+host, 10, 15*time.Minute) {
			app.respond(writer, request, 429, "RATE_LIMITED", "请稍后重试")
			return
		}
		if err := request.ParseForm(); err != nil {
			app.respond(writer, request, 400, "INPUT_INVALID", "表单无效")
			return
		}
		if action == "restore" {
			identifier := request.PostForm.Get("username")
			if identifier == "" {
				identifier = request.PostForm.Get("email")
			}
			address, err := normalizeIdentifier(identifier)
			secret := request.PostForm.Get("password")
			if err != nil || !validPassword(secret) || !app.allow("restore:"+address, 5, 15*time.Minute) {
				app.respond(writer, request, 400, "RECOVERY_FAILED", "无法恢复，请检查凭据、账户状态和恢复期限")
				return
			}
			select {
			case app.expensive <- struct{}{}:
				defer func() { <-app.expensive }()
			default:
				app.respond(writer, request, 503, "BUSY", "请稍后重试")
				return
			}
			if err = app.restore(request.Context(), address, secret); err != nil {
				app.respond(writer, request, 400, "RECOVERY_FAILED", "无法恢复，请检查凭据、账户状态和恢复期限")
				return
			}
			setSession(writer, "", false)
			app.audit("account_restored")
			app.respond(writer, request, 200, "RESTORED", "已恢复。请重新登录；原有会话不会恢复。")
			return
		}
		if action == "update-profile" {
			identity, err := app.identity(request)
			if err != nil {
				app.internal(writer, request)
				return
			}
			if identity == nil {
				app.respond(writer, request, 401, "SESSION_REQUIRED", "请先登录")
				return
			}

			displayName := strings.TrimSpace(request.PostForm.Get("display_name"))
			bio := strings.TrimSpace(request.PostForm.Get("bio"))
			location := strings.TrimSpace(request.PostForm.Get("location"))
			website := strings.TrimSpace(request.PostForm.Get("website"))

			// Validate inputs
			if !utf8.ValidString(displayName) || utf8.RuneCountInString(displayName) > 100 {
				app.respond(writer, request, 400, "INPUT_INVALID", "显示名称不能超过 100 个字符")
				return
			}
			if !validProfileBio(bio) {
				app.respond(writer, request, 400, "INPUT_INVALID", "个人简介不能超过 2000 个字符")
				return
			}
			if !utf8.ValidString(location) || utf8.RuneCountInString(location) > 100 {
				app.respond(writer, request, 400, "INPUT_INVALID", "所在地不能超过 100 个字符")
				return
			}
			if !utf8.ValidString(website) || utf8.RuneCountInString(website) > 200 {
				app.respond(writer, request, 400, "INPUT_INVALID", "网站地址不能超过 200 个字符")
				return
			}

			if website != "" {
				u, e := url.Parse(website)
				if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
					app.respond(writer, request, 400, "INPUT_INVALID", "网站地址必须使用 http 或 https")
					return
				}
			}
			// Update profile
			_, err = app.db.ExecContext(request.Context(),
				"UPDATE users SET display_name=?, bio=?, location=?, website=? WHERE id=?",
				displayName, bio, location, website, identity.ID)

			if err != nil {
				app.internal(writer, request)
				return
			}

			app.audit("profile_updated")
			app.respond(writer, request, 200, "UPDATED", "个人资料已更新")
			return
		}
		identity, err := app.identity(request)
		if err != nil {
			app.internal(writer, request)
			return
		}
		if identity == nil {
			app.respond(writer, request, 401, "SESSION_REQUIRED", "请先登录")
			return
		}
		if action == "reauthenticate" {
			secret := request.PostForm.Get("password")
			if !validPassword(secret) {
				app.respond(writer, request, 401, "INVALID_CREDENTIALS", "凭据无效")
				return
			}
			select {
			case app.expensive <- struct{}{}:
				defer func() { <-app.expensive }()
			default:
				app.respond(writer, request, 503, "BUSY", "请稍后重试")
				return
			}
			var passwordHash string
			if err = app.db.QueryRowContext(request.Context(), "SELECT password_hash FROM users WHERE id=?", identity.ID).Scan(&passwordHash); err != nil {
				app.internal(writer, request)
				return
			}
			if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(secret)) != nil {
				app.respond(writer, request, 401, "INVALID_CREDENTIALS", "凭据无效")
				return
			}
			result, err := app.db.ExecContext(request.Context(), "UPDATE sessions SET reauthenticated_at=? WHERE id=? AND revoked_at IS NULL AND expires_at>? AND user_id IN (SELECT id FROM users WHERE id=? AND password_hash=? AND status='active')", app.now().Unix(), identity.SessionID, app.now().Unix(), identity.ID, passwordHash)
			if err != nil {
				app.internal(writer, request)
				return
			}
			count, _ := result.RowsAffected()
			if count != 1 {
				app.respond(writer, request, 401, "SESSION_REQUIRED", "请重新登录")
				return
			}
			app.audit("reauthenticated")
			app.respond(writer, request, 200, "REAUTHENTICATED", "身份已重新确认，五分钟内可以执行安全操作。")
			return
		}
		transaction, err := app.db.BeginTx(request.Context(), nil)
		if err != nil {
			app.internal(writer, request)
			return
		}
		defer transaction.Rollback()
		var recent int64
		err = transaction.QueryRow("SELECT reauthenticated_at FROM sessions WHERE id=? AND user_id=? AND revoked_at IS NULL AND expires_at>?", identity.SessionID, identity.ID, app.now().Unix()).Scan(&recent)
		if err != nil || recent <= app.now().Add(-5*time.Minute).Unix() {
			app.respond(writer, request, 403, "REAUTH_REQUIRED", "请先在安全设置页重新输入密码确认身份")
			return
		}
		switch action {
		case "revoke":
			result, updateErr := transaction.Exec("UPDATE sessions SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL", app.now().Unix(), request.PostForm.Get("session_id"), identity.ID)
			if updateErr != nil {
				app.internal(writer, request)
				return
			}
			count, _ := result.RowsAffected()
			if count != 1 {
				app.respond(writer, request, 404, "SESSION_NOT_FOUND", "会话不存在或不属于当前账户")
				return
			}
		case "revoke-all":
			_, err = transaction.Exec("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", app.now().Unix(), identity.ID)
		case "deactivate":
			if request.PostForm.Get("confirm") != "deactivate" {
				app.respond(writer, request, 400, "CONFIRM_REQUIRED", "请确认进入注销恢复期")
				return
			}
			_, err = transaction.Exec("UPDATE users SET status='deactivated',recovery_until=? WHERE id=? AND status='active'", app.now().Add(30*24*time.Hour).Unix(), identity.ID)
		}
		if err != nil {
			app.internal(writer, request)
			return
		}
		if err = transaction.Commit(); err != nil {
			app.internal(writer, request)
			return
		}
		if action != "revoke" || request.PostForm.Get("session_id") == identity.SessionID {
			setSession(writer, "", false)
		}
		app.audit("security_" + action)
		app.respond(writer, request, 200, "UPDATED", "操作完成，受影响会话已撤销。注销恢复期为 30 天；恢复必须重新验证。")
	}
}

func (app *App) restore(ctx context.Context, address, password string) error {
	var userID, passwordHash string
	err := app.db.QueryRowContext(ctx, "SELECT id,password_hash FROM users WHERE (email=? OR username=?) AND verified=1 AND status='deactivated' AND recovery_until>?", address, address, app.now().Unix()).Scan(&userID, &passwordHash)
	candidate := passwordHash
	if candidate == "" {
		candidate = app.dummyHash
	}
	matched := bcrypt.CompareHashAndPassword([]byte(candidate), []byte(password)) == nil
	if err != nil || !matched {
		return errCredential
	}
	transaction, err := app.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	result, err := transaction.Exec("UPDATE users SET status='active',recovery_until=NULL WHERE id=? AND password_hash=? AND status='deactivated' AND recovery_until>?", userID, passwordHash, app.now().Unix())
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return errCredential
	}
	if _, err = transaction.Exec("UPDATE tokens SET used_at=?,candidate_hash='' WHERE user_id=?", app.now().Unix(), userID); err != nil {
		return err
	}
	if _, err = transaction.Exec("DELETE FROM oidc_requests WHERE json_extract(body,'$.Subject')=?", userID); err != nil {
		return err
	}
	return transaction.Commit()
}

func (app *App) SetSyntheticStatus(accountID, status string) error {
	if app.config.MailMode != "synthetic" || (status != "active" && status != "suspended") {
		return errors.New("仅支持合成环境 active/suspended 状态演练")
	}
	result, err := app.db.Exec("UPDATE users SET status=? WHERE id=? AND verified=1 AND status IN ('active','suspended')", status, accountID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return errors.New("合成账户不存在或不能变更此状态")
	}
	app.audit("synthetic_status_changed")
	return nil
}

func (app *App) identityAPI(writer http.ResponseWriter, request *http.Request) {
	client, secret, ok := request.BasicAuth()
	if (request.Method != "GET" && !(request.URL.Path == "/internal/identity/deactivate" && request.Method == "POST")) || !ok || app.oidcStore.AuthorizeClientIDSecret(request.Context(), client, secret) != nil {
		writeJSON(writer, 401, map[string]string{"code": "INVALID_CLIENT"})
		return
	}
	if request.URL.Path == "/internal/identity/profile" {
		app.internalProfile(writer, request)
		return
	}
	if request.URL.Path == "/internal/identity/deactivate" {
		app.internalDeactivate(writer, request)
		return
	}
	if request.URL.Path == "/internal/identity/session" {
		var status string
		var version, expiry int64
		err := app.db.QueryRowContext(request.Context(), "SELECT users.status,users.status_version,sessions.expires_at FROM users JOIN sessions ON sessions.user_id=users.id WHERE users.id=? AND sessions.id=? AND sessions.revoked_at IS NULL AND sessions.expires_at>?", request.URL.Query().Get("account_id"), request.URL.Query().Get("sid"), app.now().Unix()).Scan(&status, &version, &expiry)
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(writer, 200, map[string]any{"active": false})
			return
		}
		if err != nil {
			app.internal(writer, request)
			return
		}
		writeJSON(writer, 200, map[string]any{"active": status == "active", "status": status, "status_version": version, "expires_at": expiry})
		return
	}
	after, err := strconv.ParseInt(request.URL.Query().Get("after"), 10, 64)
	if err != nil || after < 0 {
		writeJSON(writer, 400, map[string]string{"code": "INVALID_CURSOR"})
		return
	}
	rows, err := app.db.QueryContext(request.Context(), "SELECT seq,event_id,account_id,COALESCE(sid,''),event_type,status,status_version,occurred_at FROM identity_events WHERE seq>? AND event_type IN ('status_changed','session_revoked') ORDER BY seq LIMIT 200", after)
	if err != nil {
		app.internal(writer, request)
		return
	}
	defer rows.Close()
	events := []identityEvent{}
	for rows.Next() {
		var event identityEvent
		if err = rows.Scan(&event.Sequence, &event.ID, &event.AccountID, &event.SID, &event.Type, &event.Status, &event.Version, &event.OccurredAt); err != nil {
			app.internal(writer, request)
			return
		}
		events = append(events, event)
	}
	if rows.Err() != nil {
		app.internal(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"events": events, "schema_version": 1})
}
