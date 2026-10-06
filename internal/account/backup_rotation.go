package account

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (app *App) validBackups() ([]AccountBackup, int) {
	entries, err := os.ReadDir(app.config.BackupDirectory)
	if err != nil {
		return nil, 0
	}
	key, err := os.ReadFile(app.config.BackupKeyFile)
	if err != nil {
		return nil, len(entries)
	}
	var manifests []AccountBackup
	invalid := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".backup.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(app.config.BackupDirectory, entry.Name()))
		var m AccountBackup
		if err != nil || json.Unmarshal(raw, &m) != nil || filepath.Base(m.Archive) != m.Archive || entry.Name() != m.Archive+".json" || m.Schema != 5 {
			invalid++
			continue
		}
		encrypted, err := os.ReadFile(filepath.Join(app.config.BackupDirectory, m.Archive))
		sum := sha256.Sum256(encrypted)
		if err != nil || hex.EncodeToString(sum[:]) != m.Hash || m.CreatedAt > time.Now().Unix()+60 {
			invalid++
			continue
		}
		if _, err = decrypt(key, encrypted); err != nil {
			invalid++
			continue
		}
		manifests = append(manifests, m)
	}
	return manifests, invalid
}
func (app *App) rotateBackups(current AccountBackup, encrypted []byte) error {
	manifests, _ := app.validBackups()
	now := time.Unix(current.CreatedAt, 0).UTC()
	for _, tier := range []string{"daily", "monthly"} {
		exists := false
		for _, m := range manifests {
			at := time.Unix(m.CreatedAt, 0).UTC()
			same := at.Format("2006-01-02") == now.Format("2006-01-02")
			if tier == "monthly" {
				same = at.Format("2006-01") == now.Format("2006-01")
			}
			if m.Tier == tier && same {
				exists = true
				break
			}
		}
		if !exists {
			copy := current
			copy.Tier = tier
			copy.Archive = tier + "-" + current.Archive
			if err := accountExclusiveFile(filepath.Join(app.config.BackupDirectory, copy.Archive), encrypted); err != nil {
				return err
			}
			raw, _ := json.MarshalIndent(copy, "", "  ")
			if err := accountExclusiveFile(filepath.Join(app.config.BackupDirectory, copy.Archive+".json"), raw); err != nil {
				return err
			}
		}
	}
	for _, m := range manifests {
		cutoff := now.Add(-48 * time.Hour)
		if m.Tier == "daily" {
			cutoff = now.Add(-30 * 24 * time.Hour)
		}
		if m.Tier == "monthly" {
			cutoff = now.AddDate(-1, 0, 0)
		}
		if time.Unix(m.CreatedAt, 0).Before(cutoff) {
			// Each name has been checked to stay inside the configured backup directory.
			if err := os.Remove(filepath.Join(app.config.BackupDirectory, m.Archive)); err != nil {
				return err
			}
			if err := os.Remove(filepath.Join(app.config.BackupDirectory, m.Archive+".json")); err != nil {
				return err
			}
		}
	}
	return nil
}
