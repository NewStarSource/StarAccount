package account

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

var errCredential = errors.New("invalid credential")

type Identity struct {
	ID        string `json:"id"`
	Alias     string `json:"alias"`
	Status    string `json:"status"`
	SessionID string `json:"-"`
}

func normalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || len(value) > 254 || !strings.Contains(strings.SplitN(value, "@", 2)[1], ".") {
		return "", errors.New("invalid email")
	}
	return value, nil
}
func validPassword(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= 12 && len(value) <= 72
}
func syntheticEmail(address string) bool {
	domain := strings.SplitN(address, "@", 2)[1]
	return domain == "example.com" || domain == "example.net" || domain == "example.org" || strings.HasSuffix(domain, ".test") || strings.HasSuffix(domain, ".invalid")
}

func (app *App) requestMail(address, password, kind string) error {
	var candidate []byte
	var err error
	if kind == "verify" {
		candidate, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
	}
	transaction, err := app.db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var userID, status string
	var verified int
	err = transaction.QueryRow("SELECT id,verified,status FROM users WHERE email=?", address).Scan(&userID, &verified, &status)
	if errors.Is(err, sql.ErrNoRows) && kind == "verify" {
		userID = opaqueID()
		status = "active"
		_, err = transaction.Exec("INSERT INTO users(id,subject_id,email,alias,password_hash,created_at) VALUES(?,?,?,?,?,?)", userID, opaqueID(), address, "新星用户", "", app.now().Unix())
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status != "active" || (kind == "verify" && verified == 1) || (kind == "reset" && verified != 1) {
		return nil
	}
	if kind == "verify" {
		if _, err = transaction.Exec("UPDATE tokens SET used_at=?,candidate_hash='' WHERE user_id=? AND kind='verify' AND used_at IS NULL", app.now().Unix(), userID); err != nil {
			return err
		}
		if _, err = transaction.Exec("DELETE FROM mail_jobs WHERE token_hash IN (SELECT hash FROM tokens WHERE user_id=? AND kind='verify')", userID); err != nil {
			return err
		}
	}
	raw := randomToken()
	expiry := app.now().Add(time.Hour).Unix()
	_, err = transaction.Exec("INSERT INTO tokens(hash,user_id,kind,candidate_hash,expires_at) VALUES(?,?,?,?,?)", hash(raw), userID, kind, string(candidate), expiry)
	if err != nil {
		return err
	}
	jobID := opaqueID()
	payload, err := json.Marshal(Mail{ID: jobID, To: address, Kind: kind, Token: raw})
	if err != nil {
		return err
	}
	sealed, err := encrypt(app.keys[32:64], payload)
	if err != nil {
		return err
	}
	_, err = transaction.Exec("INSERT INTO mail_jobs(id,token_hash,payload,status,next_at,expires_at) VALUES(?,?,?,'pending',?,?)", jobID, hash(raw), sealed, app.now().Unix(), expiry)
	if err != nil {
		return err
	}
	return transaction.Commit()
}

func (app *App) consume(raw, kind, password string) error {
	if len(raw) != 43 {
		return errCredential
	}
	var newPassword []byte
	var err error
	if kind == "reset" {
		if !validPassword(password) {
			return errCredential
		}
		newPassword, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
	}
	transaction, err := app.db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var userID, candidate string
	err = transaction.QueryRow(`UPDATE tokens SET used_at=? WHERE hash=? AND kind=? AND used_at IS NULL AND expires_at>? AND user_id IN (SELECT id FROM users WHERE status='active') RETURNING user_id,candidate_hash`, app.now().Unix(), hash(raw), kind, app.now().Unix()).Scan(&userID, &candidate)
	if errors.Is(err, sql.ErrNoRows) {
		return errCredential
	}
	if err != nil {
		return err
	}
	if kind == "verify" {
		_, err = transaction.Exec("UPDATE users SET verified=1,password_hash=? WHERE id=? AND verified=0", candidate, userID)
	} else {
		_, err = transaction.Exec("UPDATE users SET password_hash=? WHERE id=? AND verified=1", string(newPassword), userID)
	}
	if err != nil {
		return err
	}
	if _, err = transaction.Exec("UPDATE tokens SET used_at=?,candidate_hash='' WHERE user_id=? AND used_at IS NULL", app.now().Unix(), userID); err != nil {
		return err
	}
	if _, err = transaction.Exec("UPDATE tokens SET candidate_hash='' WHERE user_id=?", userID); err != nil {
		return err
	}
	if _, err = transaction.Exec("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", app.now().Unix(), userID); err != nil {
		return err
	}
	if _, err = transaction.Exec("DELETE FROM mail_jobs WHERE token_hash IN (SELECT hash FROM tokens WHERE user_id=?)", userID); err != nil {
		return err
	}
	return transaction.Commit()
}

func (app *App) login(address, password, oldToken string) (string, error) {
	var userID, passwordHash, status string
	var verified int
	err := app.db.QueryRow("SELECT id,password_hash,verified,status FROM users WHERE email=?", address).Scan(&userID, &passwordHash, &verified, &status)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	comparison := passwordHash
	if comparison == "" {
		comparison = app.dummyHash
	}
	matched := bcrypt.CompareHashAndPassword([]byte(comparison), []byte(password)) == nil
	if !matched || userID == "" || verified != 1 || status != "active" {
		return "", errCredential
	}
	transaction, err := app.db.Begin()
	if err != nil {
		return "", err
	}
	defer transaction.Rollback()
	var currentHash, currentStatus string
	if err = transaction.QueryRow("SELECT password_hash,status FROM users WHERE id=?", userID).Scan(&currentHash, &currentStatus); err != nil {
		return "", err
	}
	if currentHash != passwordHash || currentStatus != "active" {
		return "", errCredential
	}
	raw := randomToken()
	if _, err = transaction.Exec("INSERT INTO sessions(id,hash,user_id,created_at,expires_at) VALUES(?,?,?,?,?)", opaqueID(), hash(raw), userID, app.now().Unix(), app.now().Add(7*24*time.Hour).Unix()); err != nil {
		return "", err
	}
	if oldToken != "" {
		if _, err = transaction.Exec("UPDATE sessions SET revoked_at=? WHERE hash=? AND revoked_at IS NULL", app.now().Unix(), hash(oldToken)); err != nil {
			return "", err
		}
	}
	if err = transaction.Commit(); err != nil {
		return "", err
	}
	return raw, nil
}

func (app *App) identity(request *http.Request) (*Identity, error) {
	cookie, err := request.Cookie("star_account_session")
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	identity := &Identity{}
	err = app.db.QueryRowContext(request.Context(), `SELECT users.id,users.alias,users.status,sessions.id FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.hash=? AND sessions.revoked_at IS NULL AND sessions.expires_at>? AND users.status='active' AND users.verified=1`, hash(cookie.Value), app.now().Unix()).Scan(&identity.ID, &identity.Alias, &identity.Status, &identity.SessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return identity, err
}
func (app *App) logout(ctx context.Context, request *http.Request) error {
	cookie, err := request.Cookie("star_account_session")
	if errors.Is(err, http.ErrNoCookie) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = app.db.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE hash=? AND revoked_at IS NULL", app.now().Unix(), hash(cookie.Value))
	return err
}
func setSession(writer http.ResponseWriter, value string, secure bool) {
	maxAge := 7 * 86400
	if value == "" {
		maxAge = -1
	}
	http.SetCookie(writer, &http.Cookie{Name: "star_account_session", Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}
