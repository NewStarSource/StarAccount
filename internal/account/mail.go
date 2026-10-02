package account

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	gomail "github.com/wneessen/go-mail"
)

type Mail struct {
	ID    string
	To    string
	Kind  string
	Token string
	Link  string
}
type Sender interface {
	Send(context.Context, Mail) error
}
type smtpSender struct{ config Config }

func (sender smtpSender) Send(ctx context.Context, message Mail) error {
	client, err := gomail.NewClient(sender.config.SMTPHost, gomail.WithPort(sender.config.SMTPPort), gomail.WithSMTPAuth(gomail.SMTPAuthPlain), gomail.WithUsername(os.Getenv("STARACCOUNT_SMTP_USER")), gomail.WithPassword(os.Getenv("STARACCOUNT_SMTP_PASSWORD")), gomail.WithTLSPolicy(gomail.TLSMandatory))
	if err != nil {
		return err
	}
	letter := gomail.NewMsg()
	if err = letter.From(sender.config.MailFrom); err != nil {
		return err
	}
	if err = letter.To(message.To); err != nil {
		return err
	}
	subject := "验证你的新星账户"
	if message.Kind == "reset" {
		subject = "找回新星账户访问权限"
	}
	letter.Subject(subject)
	letter.SetMessageIDWithValue(message.ID + "@staraccount.local")
	letter.SetBodyString(gomail.TypeTextPlain, fmt.Sprintf("%s\n\n请打开以下链接并确认操作。链接一小时内有效且只能使用一次。\n%s\n\n如果不是你发起的请求，请忽略这封邮件。", subject, message.Link))
	return client.DialAndSendWithContext(ctx, letter)
}

func (app *App) mailLink(message Mail) string {
	route := "verify"
	if message.Kind == "reset" {
		route = "reset"
	}
	return app.config.Origin + "/" + route + "?token=" + url.QueryEscape(message.Token)
}

func (app *App) ProcessMail(ctx context.Context) error {
	app.mailMu.Lock()
	defer app.mailMu.Unlock()
	var jobID string
	var payload []byte
	var attempts int
	err := app.db.QueryRowContext(ctx, "SELECT id,payload,attempts FROM mail_jobs WHERE status='pending' AND next_at<=? AND expires_at>? ORDER BY next_at,id LIMIT 1", app.now().Unix(), app.now().Unix()).Scan(&jobID, &payload, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	plaintext, err := decrypt(app.keys[32:64], payload)
	var message Mail
	if err == nil {
		err = json.Unmarshal(plaintext, &message)
	}
	if err == nil {
		message.Link = app.mailLink(message)
		if app.config.MailMode == "smtp" {
			err = app.sender.Send(ctx, message)
		}
	}
	if err != nil {
		attempts++
		status := "pending"
		if attempts >= 3 {
			status = "permanent_failure"
		}
		_, updateErr := app.db.ExecContext(ctx, "UPDATE mail_jobs SET attempts=?,status=?,next_at=?,error_code='MAIL_DELIVERY_FAILED' WHERE id=?", attempts, status, app.now().Add(time.Duration(1<<attempts)*time.Minute).Unix(), jobID)
		app.logger.Print("mail_delivery_failed")
		app.audit("mail_delivery_failed")
		return updateErr
	}
	if app.config.MailMode == "synthetic" {
		_, err = app.db.ExecContext(ctx, "UPDATE mail_jobs SET status='sent',attempts=attempts+1,completed_at=? WHERE id=?", app.now().Unix(), jobID)
	} else {
		_, err = app.db.ExecContext(ctx, "UPDATE mail_jobs SET status='sent',payload=X'',attempts=attempts+1,completed_at=? WHERE id=?", app.now().Unix(), jobID)
	}
	return err
}

func (app *App) Mailbox() ([]Mail, error) {
	if app.config.MailMode != "synthetic" {
		return nil, errors.New("synthetic mailbox disabled")
	}
	rows, err := app.db.Query("SELECT payload FROM mail_jobs WHERE status='sent' AND expires_at>? ORDER BY completed_at DESC LIMIT 30", app.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	messages := []Mail{}
	for rows.Next() {
		var payload []byte
		if err = rows.Scan(&payload); err != nil {
			return nil, err
		}
		plaintext, err := decrypt(app.keys[32:64], payload)
		if err != nil {
			return nil, err
		}
		var message Mail
		if err = json.Unmarshal(plaintext, &message); err != nil {
			return nil, err
		}
		message.Link = app.mailLink(message)
		message.Token = ""
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

func (app *App) Worker(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	cleanup := time.NewTicker(time.Minute)
	defer cleanup.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			delivery, cancel := context.WithTimeout(ctx, 15*time.Second)
			if err := app.ProcessMail(delivery); err != nil {
				app.logger.Print("mail_worker_unavailable")
			}
			cancel()
		case <-cleanup.C:
			if err := app.Cleanup(); err != nil {
				app.logger.Print("cleanup_failed")
			}
		}
	}
}
