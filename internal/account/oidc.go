package account

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type oidcBindingKey struct{}
type oidcStore struct {
	app    *App
	secret string
	key    signingKey
}
type signingKey struct {
	private *rsa.PrivateKey
	id      string
}

func (key signingKey) ID() string                                  { return key.id }
func (key signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (key signingKey) Key() any                                    { return key.private }

type publicKey struct{ signingKey }

func (key publicKey) Key() any                           { return &key.private.PublicKey }
func (key publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (key publicKey) Use() string                        { return "sig" }

type authorization struct {
	ID       string
	Request  oidc.AuthRequest
	Subject  string
	SID      string
	AuthTime time.Time
	Complete bool
}

func (auth *authorization) GetID() string          { return auth.ID }
func (auth *authorization) GetACR() string         { return "urn:staraccount:pwd" }
func (auth *authorization) GetAMR() []string       { return []string{"pwd"} }
func (auth *authorization) GetAudience() []string  { return []string{"star-atlas"} }
func (auth *authorization) GetAuthTime() time.Time { return auth.AuthTime }
func (auth *authorization) GetClientID() string    { return auth.Request.ClientID }
func (auth *authorization) GetCodeChallenge() *oidc.CodeChallenge {
	return &oidc.CodeChallenge{Challenge: auth.Request.CodeChallenge, Method: oidc.CodeChallengeMethodS256}
}
func (auth *authorization) GetNonce() string                   { return auth.Request.Nonce }
func (auth *authorization) GetRedirectURI() string             { return auth.Request.RedirectURI }
func (auth *authorization) GetResponseType() oidc.ResponseType { return oidc.ResponseTypeCode }
func (auth *authorization) GetResponseMode() oidc.ResponseMode { return oidc.ResponseModeQuery }
func (auth *authorization) GetScopes() []string                { return auth.Request.Scopes }
func (auth *authorization) GetState() string                   { return auth.Request.State }
func (auth *authorization) GetSubject() string                 { return auth.Subject }
func (auth *authorization) Done() bool                         { return auth.Complete }

type atlasClient struct{ origin string }

func (client atlasClient) GetID() string                       { return "star-atlas" }
func (client atlasClient) RedirectURIs() []string              { return []string{client.origin + "/auth/callback"} }
func (client atlasClient) PostLogoutRedirectURIs() []string    { return nil }
func (client atlasClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (client atlasClient) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodBasic }
func (client atlasClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (client atlasClient) GrantTypes() []oidc.GrantType        { return []oidc.GrantType{oidc.GrantTypeCode} }
func (client atlasClient) LoginURL(id string) string           { return "/oidc/login?id=" + url.QueryEscape(id) }
func (client atlasClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }
func (client atlasClient) IDTokenLifetime() time.Duration      { return 5 * time.Minute }
func (client atlasClient) DevMode() bool                       { return true }
func (client atlasClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (client atlasClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (client atlasClient) IsScopeAllowed(scope string) bool     { return scope == "atlas_identity" }
func (client atlasClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (client atlasClient) ClockSkew() time.Duration             { return 0 }

func (app *App) initOIDC() error {
	if app.config.OIDCSecretFile == "" {
		return nil
	}
	secret, err := os.ReadFile(app.config.OIDCSecretFile)
	if err != nil || len(secret) != 43 {
		return errors.New("invalid OIDC client secret")
	}
	encoded, err := os.ReadFile(app.config.SigningKeyFile)
	if err != nil {
		return errors.New("signing key unavailable")
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		return errors.New("invalid signing key")
	}
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return errors.New("invalid signing key")
	}
	rsaKey, ok := private.(*rsa.PrivateKey)
	if !ok || rsaKey.N.BitLen() < 2048 {
		return errors.New("invalid RSA signing key")
	}
	fingerprint := sha256.Sum256(x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey))
	store := &oidcStore{app: app, secret: string(secret), key: signingKey{rsaKey, hex.EncodeToString(fingerprint[:16])}}
	var encryptionKey [32]byte
	copy(encryptionKey[:], app.keys[32:64])
	provider, err := op.NewProvider(&op.Config{CryptoKey: encryptionKey, CryptoKeyId: "account-v1", CodeMethodS256: true, DefaultLogoutRedirectURI: "/", SupportedScopes: []string{"openid", "atlas_identity"}}, store, op.StaticIssuer(app.config.Origin), op.WithAllowInsecure())
	if err != nil {
		return err
	}
	app.provider = provider
	app.oidcStore = store
	return nil
}
func (store *oidcStore) CreateAuthRequest(ctx context.Context, request *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	if request.ClientID != "star-atlas" || request.RedirectURI != store.app.config.AtlasOrigin+"/auth/callback" || request.ResponseType != oidc.ResponseTypeCode || request.CodeChallengeMethod != oidc.CodeChallengeMethodS256 || len(request.CodeChallenge) != 43 || len(request.State) < 32 || len(request.Nonce) < 32 || !slices.Contains(request.Scopes, "openid") || !slices.Contains(request.Scopes, "atlas_identity") {
		return nil, oidc.ErrInvalidRequest()
	}
	if request.ResponseMode != "" && request.ResponseMode != oidc.ResponseModeQuery {
		return nil, oidc.ErrInvalidRequest()
	}
	for _, scope := range request.Scopes {
		if scope != "openid" && scope != "atlas_identity" {
			return nil, oidc.ErrInvalidScope()
		}
	}
	binding, _ := ctx.Value(oidcBindingKey{}).(string)
	if binding == "" {
		return nil, oidc.ErrInvalidRequest()
	}
	auth := &authorization{ID: opaqueID(), Request: *request}
	data, err := json.Marshal(auth)
	if err != nil {
		return nil, err
	}
	_, err = store.app.db.ExecContext(ctx, "INSERT INTO oidc_requests(id,body,binding_hash,expires_at) VALUES(?,?,?,?)", auth.ID, data, hash(binding), store.app.now().Add(5*time.Minute).Unix())
	return auth, err
}
func (store *oidcStore) load(ctx context.Context, query string, args ...any) (*authorization, error) {
	var data []byte
	if err := store.app.db.QueryRowContext(ctx, query, args...).Scan(&data); err != nil {
		return nil, oidc.ErrInvalidGrant()
	}
	var auth authorization
	if err := json.Unmarshal(data, &auth); err != nil {
		return nil, err
	}
	return &auth, nil
}
func (store *oidcStore) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return store.load(ctx, "SELECT body FROM oidc_requests WHERE id=? AND expires_at>? AND exchanged=0", id, store.app.now().Unix())
}
func (store *oidcStore) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	return store.load(ctx, "UPDATE oidc_requests SET exchanged=1 WHERE code_hash=? AND exchanged=0 AND expires_at>? RETURNING body", hash(code), store.app.now().Unix())
}
func (store *oidcStore) SaveAuthCode(ctx context.Context, id, code string) error {
	result, err := store.app.db.ExecContext(ctx, "UPDATE oidc_requests SET code_hash=? WHERE id=? AND code_hash IS NULL AND exchanged=0 AND expires_at>?", hash(code), id, store.app.now().Unix())
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return oidc.ErrInvalidGrant()
	}
	return nil
}
func (store *oidcStore) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := store.app.db.ExecContext(ctx, "DELETE FROM oidc_requests WHERE id=?", id)
	return err
}
func (store *oidcStore) active(ctx context.Context, subject, sid string) bool {
	var count int
	err := store.app.db.QueryRowContext(ctx, "SELECT count(*) FROM sessions JOIN users ON users.id=sessions.user_id WHERE users.id=? AND users.status='active' AND users.verified=1 AND sessions.id=? AND revoked_at IS NULL AND expires_at>?", subject, sid, store.app.now().Unix()).Scan(&count)
	return err == nil && count == 1
}
func (store *oidcStore) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	auth, ok := request.(*authorization)
	if !ok || !auth.Complete || !store.active(ctx, auth.Subject, auth.SID) {
		return "", time.Time{}, oidc.ErrInvalidGrant()
	}
	raw := randomToken()
	expiry := store.app.now().Add(5 * time.Minute)
	_, err := store.app.db.ExecContext(ctx, "INSERT INTO oidc_tokens(hash,user_id,sid,expires_at) VALUES(?,?,?,?)", hash(raw), auth.Subject, auth.SID, expiry.Unix())
	return raw, expiry, err
}
func (store *oidcStore) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	if id != "star-atlas" {
		return nil, oidc.ErrInvalidClient()
	}
	return atlasClient{store.app.config.AtlasOrigin}, nil
}
func (store *oidcStore) AuthorizeClientIDSecret(_ context.Context, id, secret string) error {
	if id != "star-atlas" || subtle.ConstantTimeCompare([]byte(hash(secret)), []byte(hash(store.secret))) != 1 {
		return oidc.ErrInvalidClient()
	}
	return nil
}
func (store *oidcStore) SigningKey(context.Context) (op.SigningKey, error) { return store.key, nil }
func (store *oidcStore) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}
func (store *oidcStore) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{publicKey{store.key}}, nil
}
func (store *oidcStore) Health(ctx context.Context) error { return store.app.db.PingContext(ctx) }
func (store *oidcStore) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}
func (store *oidcStore) claims(ctx context.Context, info *oidc.UserInfo, subject, sid string) error {
	if !store.active(ctx, subject, sid) {
		return oidc.ErrInvalidGrant()
	}
	var linked, alias, status string
	var version int64
	if err := store.app.db.QueryRowContext(ctx, "SELECT subject_id,alias,status,status_version FROM users WHERE id=?", subject).Scan(&linked, &alias, &status, &version); err != nil {
		return err
	}
	info.Subject = subject
	info.AppendClaims("subject_id", linked)
	info.AppendClaims("alias", alias)
	info.AppendClaims("status", status)
	info.AppendClaims("status_version", version)
	info.AppendClaims("sid", sid)
	info.AppendClaims("email_verified", true)
	return nil
}
func (store *oidcStore) SetUserinfoFromRequest(ctx context.Context, info *oidc.UserInfo, request op.IDTokenRequest, _ []string) error {
	auth, ok := request.(*authorization)
	if !ok {
		return oidc.ErrInvalidGrant()
	}
	return store.claims(ctx, info, auth.Subject, auth.SID)
}
func (store *oidcStore) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, token, subject, origin string) error {
	var sid string
	if origin != "" {
		return oidc.ErrAccessDenied()
	}
	if err := store.app.db.QueryRowContext(ctx, "SELECT sid FROM oidc_tokens WHERE hash=? AND user_id=? AND expires_at>?", hash(token), subject, store.app.now().Unix()).Scan(&sid); err != nil {
		return oidc.ErrInvalidGrant()
	}
	return store.claims(ctx, info, subject, sid)
}
func (store *oidcStore) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}
func (store *oidcStore) CreateAccessAndRefreshTokens(context.Context, op.TokenRequest, string) (string, string, time.Time, error) {
	return "", "", time.Time{}, oidc.ErrUnsupportedGrantType()
}
func (store *oidcStore) TokenRequestByRefreshToken(context.Context, string) (op.RefreshTokenRequest, error) {
	return nil, op.ErrInvalidRefreshToken
}
func (store *oidcStore) TerminateSession(context.Context, string, string) error {
	return oidc.ErrAccessDenied()
}
func (store *oidcStore) RevokeToken(context.Context, string, string, string) *oidc.Error {
	return oidc.ErrAccessDenied()
}
func (store *oidcStore) GetRefreshTokenInfo(context.Context, string, string) (string, string, error) {
	return "", "", op.ErrInvalidRefreshToken
}
func (store *oidcStore) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return oidc.ErrAccessDenied()
}
func (store *oidcStore) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, oidc.ErrAccessDenied()
}
func (store *oidcStore) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, oidc.ErrAccessDenied()
}

func (app *App) boundAuthorization(request *http.Request, id string) (*authorization, error) {
	cookie, err := request.Cookie("star_oidc_flow")
	if err != nil {
		return nil, err
	}
	var binding string
	if err = app.db.QueryRowContext(request.Context(), "SELECT binding_hash FROM oidc_requests WHERE id=? AND exchanged=0 AND expires_at>?", id, app.now().Unix()).Scan(&binding); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(binding), []byte(hash(cookie.Value))) != 1 {
		return nil, errCredential
	}
	auth, err := app.oidcStore.AuthRequestByID(request.Context(), id)
	if err != nil {
		return nil, err
	}
	return auth.(*authorization), nil
}
func (app *App) oidcLogin(writer http.ResponseWriter, request *http.Request) {
	if app.provider == nil {
		app.respond(writer, request, 503, "AUTH_NOT_CONFIGURED", "登录服务未配置")
		return
	}
	id := request.URL.Query().Get("id")
	if request.Method == "POST" {
		if request.ParseForm() != nil {
			app.respond(writer, request, 400, "INPUT_INVALID", "请求无效")
			return
		}
		id = request.PostForm.Get("id")
	}
	auth, err := app.boundAuthorization(request, id)
	if err != nil {
		app.respond(writer, request, 400, "AUTH_REQUEST_INVALID", "登录请求已失效，请回星图重新发起登录")
		return
	}
	identity, err := app.identity(request)
	if err != nil {
		app.internal(writer, request)
		return
	}
	force := slices.Contains(auth.Request.Prompt, "login") || auth.Request.MaxAge != nil
	if request.Method == "GET" {
		app.render(writer, request, 200, page{Name: "oidc", Token: id, Identity: identity, Force: force})
		return
	}
	host, _, _ := net.SplitHostPort(request.RemoteAddr)
	if !app.allow("oidc:"+host, 20, 15*time.Minute) {
		app.respond(writer, request, 429, "RATE_LIMITED", "请稍后再试")
		return
	}
	if identity == nil || force {
		username, err := normalizeUsername(request.PostForm.Get("username"))
		password := request.PostForm.Get("password")
		if err != nil || !validPassword(password) || !app.allow("oidc-username:"+username, 5, 15*time.Minute) {
			app.respond(writer, request, 401, "INVALID_CREDENTIALS", "无法登录，请检查邮箱和密码")
			return
		}
		select {
		case app.expensive <- struct{}{}:
			defer func() { <-app.expensive }()
		default:
			app.respond(writer, request, 503, "BUSY", "请稍后重试")
			return
		}
		raw, err := app.login(username, password, "")
		if err != nil {
			app.respond(writer, request, 401, "INVALID_CREDENTIALS", "无法登录，请检查邮箱、密码和账户状态")
			return
		}
		setSession(writer, raw, false)
		clone := request.Clone(request.Context())
		clone.Header = clone.Header.Clone()
		clone.Header.Del("Cookie")
		clone.AddCookie(&http.Cookie{Name: "star_account_session", Value: raw})
		identity, err = app.identity(clone)
		if err != nil || identity == nil {
			app.internal(writer, request)
			return
		}
	}
	var created int64
	if err = app.db.QueryRowContext(request.Context(), "SELECT created_at FROM sessions WHERE id=?", identity.SessionID).Scan(&created); err != nil {
		app.internal(writer, request)
		return
	}
	auth.Subject = identity.ID
	auth.SID = identity.SessionID
	auth.AuthTime = time.Unix(created, 0)
	auth.Complete = true
	body, err := json.Marshal(auth)
	if err == nil {
		_, err = app.db.ExecContext(request.Context(), "UPDATE oidc_requests SET body=? WHERE id=? AND code_hash IS NULL AND exchanged=0", body, id)
	}
	if err != nil {
		app.internal(writer, request)
		return
	}
	app.render(writer, request, 200, page{Name: "oidc-continue", Token: id})
}

var _ op.Storage = (*oidcStore)(nil)
