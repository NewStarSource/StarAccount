package account

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/bcrypt"
)

//go:embed page.html
var pageHTML string

//go:embed profile.js
var profileJS string

type App struct {
	config       Config
	db           *sql.DB
	keys         []byte
	dummyHash    string
	now          func() time.Time
	logger       *log.Logger
	sender       Sender
	mailMu       sync.Mutex
	operationsMu sync.Mutex
	lastBackup   int64
	expensive    chan struct{}
	pages        *template.Template
	provider     *op.Provider
	oidcStore    *oidcStore
}
type page struct {
	Name      string
	Title     string
	Message   string
	CSRF      template.HTML
	Identity  *Identity
	Token     string
	Messages  []Mail
	Synthetic bool
	Failed    int
	Force     bool
	Sessions  []SessionView
	Profile   publicProfile
}
type input struct {
	Username   string `json:"username"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	InviteCode string `json:"invite_code"`
	Token      string `json:"token"`
}

func New(config Config, keys []byte, logger *log.Logger) (*App, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if len(keys) != 96 {
		return nil, errors.New("invalid keys")
	}
	database, err := openDatabase(config.Database)
	if err != nil {
		return nil, err
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte(randomToken()), bcrypt.DefaultCost)
	if err != nil {
		database.Close()
		return nil, err
	}
	pages, err := template.New("page").Funcs(template.FuncMap{"profileMarkdown": renderProfileMarkdown}).Parse(pageHTML)
	if err != nil {
		database.Close()
		return nil, err
	}
	app := &App{config: config, db: database, keys: keys, dummyHash: string(dummy), now: time.Now, logger: logger, sender: smtpSender{config}, expensive: make(chan struct{}, 2), pages: pages}
	if err = app.initSecurityJournal(); err != nil {
		database.Close()
		return nil, err
	}
	if err = app.Cleanup(); err != nil {
		database.Close()
		return nil, err
	}
	if err = app.initOIDC(); err != nil {
		database.Close()
		return nil, err
	}
	return app, nil
}
func (app *App) Close() error { return app.db.Close() }

func (app *App) Handler() http.Handler { return app.protectJournal(app.baseHandler()) }
func (app *App) baseHandler() http.Handler {
	router := chi.NewRouter()
	app.identityRoutes(router)
	app.profileMarkdownRoutes(router)
	router.Get("/oidc/login", app.oidcLogin)
	router.Post("/oidc/login", app.oidcLogin)
	router.Get("/health", func(writer http.ResponseWriter, request *http.Request) {
		if err := app.db.PingContext(request.Context()); err != nil {
			app.respond(writer, request, 503, "DEPENDENCY_UNAVAILABLE", "服务暂时不可用，请稍后重试")
			return
		}
		writeJSON(writer, 200, map[string]any{"ok": true, "service": "star-account", "stage": "S03", "oidc_configured": app.provider != nil, "integration": "本地合成；真实环境未联调", "real_users": false})
	})
	router.Get("/robots.txt", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(writer, "User-agent: *\nDisallow: /\n")
	})
	router.Get("/api/v1/config", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, 200, map[string]any{"service": "star-account", "mail_mode": app.config.MailMode, "password_owner": "star-account", "oidc_configured": app.provider != nil, "real_users": false})
	})
	router.Get("/api/v1/csrf", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, 200, map[string]string{"csrf_token": csrf.Token(request)})
	})
	router.Get("/api/v1/auth/session", func(writer http.ResponseWriter, request *http.Request) {
		identity, err := app.identity(request)
		if err != nil {
			app.internal(writer, request)
			return
		}
		writeJSON(writer, 200, map[string]any{"authenticated": identity != nil, "user": identity})
	})
	for route, name := range map[string]string{"/": "home", "/register": "register", "/login": "login", "/forgot": "forgot", "/reset": "reset", "/config": "config"} {
		router.Get(route, func(writer http.ResponseWriter, request *http.Request) {
			identity, err := app.identity(request)
			if err != nil {
				app.internal(writer, request)
				return
			}
			token := request.URL.Query().Get("token")
			if len(token) > 128 {
				token = ""
			}
			app.render(writer, request, 200, page{Name: name, Identity: identity, Token: token})
		})
	}
	if app.config.MailMode == "synthetic" {
		router.Get("/dev/mailbox", func(writer http.ResponseWriter, request *http.Request) {
			messages, err := app.Mailbox()
			if err != nil {
				app.internal(writer, request)
				return
			}
			var failed int
			if err = app.db.QueryRow("SELECT count(*) FROM mail_jobs WHERE status='permanent_failure'").Scan(&failed); err != nil {
				app.internal(writer, request)
				return
			}
			app.render(writer, request, 200, page{Name: "mailbox", Messages: messages, Failed: failed})
		})
	}
	for _, action := range []string{"register", "request-reset", "reset-password", "login", "logout"} {
		router.Post("/api/v1/auth/"+action, app.action(action))
	}
	router.NotFound(func(writer http.ResponseWriter, request *http.Request) {
		app.respond(writer, request, 404, "NOT_FOUND", "页面不存在")
	})
	protected := csrf.Protect(app.keys[:32], csrf.Secure(false), csrf.HttpOnly(true), csrf.SameSite(csrf.SameSiteLaxMode), csrf.Path("/"), csrf.CookieName("star_account_csrf"), csrf.ErrorHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		app.audit("csrf_rejected")
		app.respond(writer, request, 403, "CSRF_INVALID", "页面已失效，请刷新后重试")
	})))(router)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Referrer-Policy", "strict-origin")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("X-Robots-Tag", "noindex, nofollow")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if request.Host != app.config.Address {
			app.respond(writer, request, 400, "HOST_INVALID", "请求地址无效")
			return
		}
		if origin := request.Header.Get("Origin"); origin != "" && origin != app.config.Origin {
			app.respond(writer, request, 403, "ORIGIN_INVALID", "请在账户网站内完成操作")
			return
		}
		if request.Header.Get("Sec-Fetch-Site") == "cross-site" {
			app.respond(writer, request, 403, "ORIGIN_INVALID", "请在账户网站内完成操作")
			return
		}
		bodyLimit := int64(8192)
		if request.URL.Path == "/api/v1/security/update-profile" || request.URL.Path == "/api/v1/profile/preview" {
			// Percent-encoded Unicode in the bounded profile fields needs more than 8 KiB.
			bodyLimit = 32768
		}
		request.Body = http.MaxBytesReader(writer, request.Body, bodyLimit)
		if app.provider != nil {
			switch request.URL.Path {
			case "/.well-known/openid-configuration", "/keys", "/authorize", "/authorize/callback", "/oauth/token", "/userinfo":
				method := "GET"
				if request.URL.Path == "/oauth/token" {
					method = "POST"
				}
				if request.Method != method {
					app.respond(writer, request, 405, "METHOD_NOT_ALLOWED", "请求方式无效")
					return
				}
				host, _, _ := net.SplitHostPort(request.RemoteAddr)
				if !app.allow("protocol:"+request.URL.Path+":"+host, 120, time.Minute) {
					app.respond(writer, request, 429, "RATE_LIMITED", "请求过于频繁")
					return
				}
				if request.URL.Path == "/authorize" {
					binding := randomToken()
					http.SetCookie(writer, &http.Cookie{Name: "star_oidc_flow", Value: binding, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
					request = request.WithContext(context.WithValue(request.Context(), oidcBindingKey{}, binding))
				}
				if request.URL.Path == "/authorize/callback" {
					if _, err := app.boundAuthorization(request, request.URL.Query().Get("id")); err != nil {
						app.respond(writer, request, 400, "AUTH_REQUEST_INVALID", "登录请求失效")
						return
					}
				}
				app.provider.ServeHTTP(writer, request)
				return
			case "/internal/identity/events", "/internal/identity/session", "/internal/identity/profile", "/internal/identity/deactivate":
				app.identityAPI(writer, request)
				return
			}
		}
		protected.ServeHTTP(writer, csrf.PlaintextHTTPRequest(request))
	})
}

func (app *App) action(action string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		address, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil {
			address = "unknown"
		}
		if !app.allow("ip:"+action+":"+address, 30, 15*time.Minute) {
			writer.Header().Set("Retry-After", "900")
			app.respond(writer, request, 429, "RATE_LIMITED", "尝试过于频繁，请在 15 分钟后重试")
			return
		}
		if action == "logout" {
			if _, err = io.Copy(io.Discard, request.Body); err != nil {
				app.respond(writer, request, 400, "INPUT_INVALID", "请求无效")
				return
			}
			if err = app.logout(request.Context(), request); err != nil {
				app.internal(writer, request)
				return
			}
			setSession(writer, "", false)
			app.audit("logout")
			app.respond(writer, request, 200, "SIGNED_OUT", "已退出。旧会话已失效。")
			return
		}
		var values input
		contentType, _, _ := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if contentType == "application/json" {
			decoder := json.NewDecoder(request.Body)
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&values)
			if err == nil {
				var extra any
				if decoder.Decode(&extra) != io.EOF {
					err = errors.New("extra json")
				}
			}
		} else if contentType == "application/x-www-form-urlencoded" {
			err = request.ParseForm()
			values = input{Username: request.PostForm.Get("username"), Email: request.PostForm.Get("email"), Password: request.PostForm.Get("password"), InviteCode: request.PostForm.Get("invite_code"), Token: request.PostForm.Get("token")}
		} else {
			app.respond(writer, request, 415, "CONTENT_TYPE_INVALID", "请使用页面表单或 JSON 提交")
			return
		}
		if err != nil {
			app.respond(writer, request, 400, "INPUT_INVALID", "输入无效或内容过长，请检查后重试")
			return
		}
		select {
		case app.expensive <- struct{}{}:
			defer func() { <-app.expensive }()
		default:
			app.respond(writer, request, 503, "BUSY", "服务繁忙，请稍后重试")
			return
		}
		if action == "register" {
			values.Username, err = normalizeUsername(values.Username)
			if err != nil || !validPassword(values.Password) || len(values.InviteCode) < 20 || len(values.InviteCode) > 128 {
				app.respond(writer, request, 400, "INVITE_REQUIRED", "当前阶段只接受邀请码注册。请输入有效用户名、密码和邀请码。")
				return
			}
			if !app.allow("invite-register:"+values.Username, 5, 15*time.Minute) {
				app.respond(writer, request, 429, "RATE_LIMITED", "尝试过于频繁，请稍后重试")
				return
			}
			if err = app.registerInvite(values.Username, values.Password, values.InviteCode); errors.Is(err, errInvite) {
				app.respond(writer, request, 400, "INVITE_INVALID", "邀请码无效、已使用或用户名已存在")
				return
			} else if err != nil {
				app.internal(writer, request)
				return
			}
			raw, loginErr := app.login(values.Username, values.Password, "")
			if loginErr != nil {
				app.internal(writer, request)
				return
			}
			setSession(writer, raw, false)
			app.audit("invite_registration_succeeded")
			app.respond(writer, request, 201, "REGISTERED", "注册成功，已登录新星账户。")
			return
		}
		if action == "request-reset" || action == "login" {
			if action == "login" && values.Username != "" {
				values.Username, err = normalizeUsername(values.Username)
				if err != nil {
					app.respond(writer, request, 400, "INPUT_INVALID", "请输入有效用户名")
					return
				}
			} else {
				values.Email, err = normalizeEmail(values.Email)
				if err != nil {
					app.respond(writer, request, 400, "INPUT_INVALID", "请输入有效邮箱")
					return
				}
			}
			if action == "login" && !validPassword(values.Password) {
				app.respond(writer, request, 400, "INPUT_INVALID", "密码需至少 12 个字符，且不超过 72 个 UTF-8 字节")
				return
			}
			if values.Username == "" && app.config.MailMode == "synthetic" && !syntheticEmail(values.Email) {
				app.respond(writer, request, 400, "SYNTHETIC_ONLY", "当前仅供合成测试，请使用 example.com 或 .test 邮箱")
				return
			}
			identifier := values.Email
			if values.Username != "" {
				identifier = values.Username
			}
			allowed := app.allow("login:"+action+":"+identifier, 5, 15*time.Minute)
			if !allowed {
				if action == "login" {
					writer.Header().Set("Retry-After", "900")
					app.respond(writer, request, 429, "RATE_LIMITED", "尝试过于频繁，请在 15 分钟后重试")
				} else {
					app.accepted(writer, request)
				}
				return
			}
		}
		switch action {
		case "request-reset":
			if err = app.requestMail(values.Email, values.Password, "reset"); err != nil {
				app.internal(writer, request)
				return
			}
			app.audit("mail_request_accepted")
			app.accepted(writer, request)
		case "reset-password":
			if !validPassword(values.Password) {
				app.respond(writer, request, 400, "INPUT_INVALID", "密码需至少 12 个字符，且不超过 72 个 UTF-8 字节")
				return
			}
			if err = app.consume(values.Token, "reset", values.Password); errors.Is(err, errCredential) {
				app.respond(writer, request, 400, "LINK_INVALID", "链接已过期、已使用或不适用于当前账户。请重新申请找回。")
				return
			} else if err != nil {
				app.internal(writer, request)
				return
			}
			setSession(writer, "", false)
			app.audit("credential_confirmed")
			app.respond(writer, request, 200, "CONFIRMED", "密码已重置，请用新密码登录。原有会话已失效。")
		case "login":
			old := ""
			if cookie, cookieErr := request.Cookie("star_account_session"); cookieErr == nil {
				old = cookie.Value
			}
			identifier := values.Email
			if values.Username != "" {
				identifier = values.Username
			}
			raw, loginErr := app.login(identifier, values.Password, old)
			if errors.Is(loginErr, errCredential) {
				app.audit("login_failed")
				app.respond(writer, request, 401, "INVALID_CREDENTIALS", "无法登录，请检查邮箱、密码和验证邮件，或申请找回。")
				return
			} else if loginErr != nil {
				app.internal(writer, request)
				return
			}
			setSession(writer, raw, false)
			app.audit("login_succeeded")
			app.respond(writer, request, 200, "SIGNED_IN", "已登录新星账户。可以返回首页查看会话并退出。")
		}
	}
}

func (app *App) accepted(writer http.ResponseWriter, request *http.Request) {
	app.respond(writer, request, 202, "REQUEST_ACCEPTED", "请求已受理。如地址适用，将收到邮件；请稍候并检查收件箱。未收到时可稍后重新申请。")
}
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
func (app *App) respond(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	if strings.Contains(request.Header.Get("Accept"), "application/json") || strings.HasPrefix(request.Header.Get("Content-Type"), "application/json") {
		writeJSON(writer, status, map[string]any{"ok": status < 400, "code": code, "message": message})
		return
	}
	app.render(writer, request, status, page{Name: "result", Message: message})
}
func (app *App) internal(writer http.ResponseWriter, request *http.Request) {
	app.logger.Print("request_dependency_failed")
	app.respond(writer, request, 503, "DEPENDENCY_UNAVAILABLE", "服务暂时不可用，请稍后重试")
}
func (app *App) render(writer http.ResponseWriter, request *http.Request, status int, value page) {
	value.CSRF = csrf.TemplateField(request)
	value.Synthetic = app.config.MailMode == "synthetic"
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)
	if err := app.pages.Execute(writer, value); err != nil {
		app.logger.Print("page_render_failed")
	}
}
