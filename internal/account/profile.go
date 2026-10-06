package account

import (
	"database/sql"
	"net/http"
	"time"
)

type publicProfile struct {
	DisplayName string `json:"display_name"`
	Bio         string `json:"bio"`
	Location    string `json:"location"`
	Website     string `json:"website"`
}

func (app *App) internalProfile(w http.ResponseWriter, r *http.Request) {
	var p publicProfile
	err := app.db.QueryRowContext(r.Context(), "SELECT display_name,bio,location,website FROM users WHERE id=? AND verified=1 AND status='active'", r.URL.Query().Get("account_id")).Scan(&p.DisplayName, &p.Bio, &p.Location, &p.Website)
	if err == sql.ErrNoRows {
		writeJSON(w, 404, map[string]string{"code": "NOT_FOUND"})
		return
	}
	if err != nil {
		app.internal(w, r)
		return
	}
	writeJSON(w, 200, p)
}
func (app *App) internalDeactivate(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() != nil {
		writeJSON(w, 400, map[string]string{"code": "INPUT_INVALID"})
		return
	}
	account, sid := r.PostForm.Get("account_id"), r.PostForm.Get("sid")
	tx, err := app.db.BeginTx(r.Context(), nil)
	if err != nil {
		app.internal(w, r)
		return
	}
	defer tx.Rollback()
	var recent int64
	err = tx.QueryRow("SELECT max(s.created_at,s.reauthenticated_at) FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND u.id=? AND u.verified=1 AND u.status='active' AND s.revoked_at IS NULL AND s.expires_at>?", sid, account, app.now().Unix()).Scan(&recent)
	if err != nil || recent < app.now().Add(-5*time.Minute).Unix() {
		writeJSON(w, 403, map[string]string{"code": "REAUTH_REQUIRED"})
		return
	}
	result, err := tx.Exec("UPDATE users SET status='deactivated',recovery_until=? WHERE id=? AND status='active'", app.now().Add(30*24*time.Hour).Unix(), account)
	if err != nil {
		app.internal(w, r)
		return
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		writeJSON(w, 409, map[string]string{"code": "STATE_CONFLICT"})
		return
	}
	if _, err = tx.Exec("DELETE FROM oidc_requests WHERE json_extract(body,'$.Subject')=?", account); err != nil {
		app.internal(w, r)
		return
	}
	if err = tx.Commit(); err != nil {
		app.internal(w, r)
		return
	}
	app.audit("account_deactivated_by_client")
	writeJSON(w, 200, map[string]string{"code": "DEACTIVATED"})
}
