package account

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

//go:embed 001_init.sql
var schema string

func randomBytes(size int) []byte {
	output := make([]byte, size)
	if _, err := rand.Read(output); err != nil {
		panic("secure random unavailable")
	}
	return output
}
func randomToken() string { return base64.RawURLEncoding.EncodeToString(randomBytes(32)) }
func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func opaqueID() string { return uuid.NewString() }

func openDatabase(filename string) (*sql.DB, error) {
	if strings.ContainsAny(filename, "?\x00") {
		return nil, errors.New("invalid database path")
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return nil, err
	}
	database, err := sql.Open("sqlite", filename+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(2000)&_pragma=synchronous(FULL)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	transaction, err := database.Begin()
	if err != nil {
		database.Close()
		return nil, err
	}
	if _, err = transaction.Exec(schema); err != nil {
		transaction.Rollback()
		database.Close()
		return nil, err
	}
	var version int
	if err = transaction.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 1 {
		transaction.Rollback()
		database.Close()
		return nil, errors.New("unsupported schema version")
	}
	if err = transaction.Commit(); err != nil {
		database.Close()
		return nil, err
	}
	var foreignKeys, synchronous, busy int
	var journal string
	for query, target := range map[string]any{"PRAGMA foreign_keys": &foreignKeys, "PRAGMA synchronous": &synchronous, "PRAGMA busy_timeout": &busy, "PRAGMA journal_mode": &journal} {
		if err = database.QueryRow(query).Scan(target); err != nil {
			database.Close()
			return nil, err
		}
	}
	if foreignKeys != 1 || synchronous != 2 || busy != 2000 || journal != "wal" {
		database.Close()
		return nil, errors.New("sqlite safety settings unavailable")
	}
	if err = os.Chmod(filename, 0600); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, []byte("staraccount-mail-v1")), nil
}
func decrypt(key, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(payload) < gcm.NonceSize() {
		return nil, errors.New("invalid payload")
	}
	return gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], []byte("staraccount-mail-v1"))
}
func (app *App) limiterKey(value string) string {
	mac := hmac.New(sha256.New, app.keys[64:])
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
func (app *App) allow(value string, maximum int, window time.Duration) bool {
	timestamp := app.now().Unix()
	var count int
	err := app.db.QueryRow(`INSERT INTO limits(key,count,reset_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN limits.reset_at<=? THEN 1 ELSE limits.count+1 END, reset_at=CASE WHEN limits.reset_at<=? THEN excluded.reset_at ELSE limits.reset_at END RETURNING count`, app.limiterKey(value), timestamp+int64(window.Seconds()), timestamp, timestamp).Scan(&count)
	return err == nil && count <= maximum
}
func (app *App) audit(event string) {
	_, err := app.db.Exec("INSERT INTO security_events VALUES(?,?,?)", opaqueID(), event, app.now().Unix())
	if err != nil {
		app.logger.Print("security_event_write_failed")
	}
}

func (app *App) Cleanup() error {
	timestamp := app.now().Unix()
	transaction, err := app.db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	statements := []struct {
		query  string
		cutoff int64
	}{
		{"DELETE FROM limits WHERE reset_at <= ?", timestamp},
		{"DELETE FROM security_events WHERE created_at < ?", timestamp - 30*86400},
		{"DELETE FROM sessions WHERE COALESCE(revoked_at,expires_at) < ?", timestamp - 30*86400},
		{"DELETE FROM mail_jobs WHERE expires_at <= ?", timestamp},
		{"DELETE FROM tokens WHERE expires_at <= ?", timestamp},
		{"DELETE FROM users WHERE verified=0 AND created_at < ? AND id NOT IN (SELECT user_id FROM tokens)", timestamp - 86400},
	}
	for _, statement := range statements {
		if _, err = transaction.Exec(statement.query, statement.cutoff); err != nil {
			return err
		}
	}
	return transaction.Commit()
}
