package mailer

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"net"
	"net/smtp"
	"time"
)

// SMTPMailer sends transactional emails via a plain SMTP server.
// It supports both plain SMTP (port 25/587 with STARTTLS) and
// implicit TLS (port 465).
type SMTPMailer struct {
	host     string
	port     int
	username string
	password string
	from     string // "Display Name <addr@example.com>"
	useTLS   bool   // true = implicit TLS (port 465), false = STARTTLS
}

// SMTPConfig holds the settings needed to construct an SMTPMailer.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	UseTLS   bool // set true for port 465 (implicit TLS), false for 587 (STARTTLS)
}

// NewSMTPMailer creates an SMTPMailer from the given config.
func NewSMTPMailer(cfg SMTPConfig) *SMTPMailer {
	return &SMTPMailer{
		host:     cfg.Host,
		port:     cfg.Port,
		username: cfg.Username,
		password: cfg.Password,
		from:     cfg.From,
		useTLS:   cfg.UseTLS,
	}
}

// ── Mailer interface ──────────────────────────────────────────────────────────

func (m *SMTPMailer) SendVerificationEmail(_ context.Context, to, verifyURL string) error {
	subject := "Verify your email address"
	body, err := renderTemplate(verificationTmpl, map[string]string{
		"VerifyURL": verifyURL,
		"Year":      fmt.Sprintf("%d", time.Now().Year()),
	})
	if err != nil {
		return fmt.Errorf("render verification email: %w", err)
	}
	return m.send(to, subject, body)
}

func (m *SMTPMailer) SendPasswordResetEmail(_ context.Context, to, resetURL string) error {
	subject := "Reset your password"
	body, err := renderTemplate(passwordResetTmpl, map[string]string{
		"ResetURL": resetURL,
		"Year":     fmt.Sprintf("%d", time.Now().Year()),
	})
	if err != nil {
		return fmt.Errorf("render password reset email: %w", err)
	}
	return m.send(to, subject, body)
}

// ── internal send ─────────────────────────────────────────────────────────────

func (m *SMTPMailer) send(to, subject, htmlBody string) error {
	msg := buildMIMEMessage(m.from, to, subject, htmlBody)
	addr := fmt.Sprintf("%s:%d", m.host, m.port)
	auth := smtp.PlainAuth("", m.username, m.password, m.host)

	if m.useTLS {
		return m.sendImplicitTLS(addr, auth, to, msg)
	}
	return m.sendSTARTTLS(addr, auth, to, msg)
}

// sendSTARTTLS connects on port 587 and upgrades with STARTTLS.
func (m *SMTPMailer) sendSTARTTLS(addr string, auth smtp.Auth, to string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}

	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(addressOnly(m.from)); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		return fmt.Errorf("smtp write body: %w", err)
	}
	return wc.Close()
}

// sendImplicitTLS connects directly over TLS (port 465).
func (m *SMTPMailer) sendImplicitTLS(addr string, auth smtp.Auth, to string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}

	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Close()

	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(addressOnly(m.from)); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		return fmt.Errorf("smtp write body: %w", err)
	}
	return wc.Close()
}

// ── helpers ───────────────────────────────────────────────────────────────────

// buildMIMEMessage constructs a minimal MIME email with an HTML body.
func buildMIMEMessage(from, to, subject, htmlBody string) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", to)
	fmt.Fprintf(&buf, "Subject: %s\r\n", subject)
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: text/html; charset=UTF-8\r\n")
	fmt.Fprintf(&buf, "\r\n")
	buf.WriteString(htmlBody)
	return buf.Bytes()
}

// addressOnly extracts the bare email address from "Name <addr>" or "addr".
func addressOnly(from string) string {
	start := bytes.IndexByte([]byte(from), '<')
	end := bytes.IndexByte([]byte(from), '>')
	if start >= 0 && end > start {
		return from[start+1 : end]
	}
	// Check if it's a valid host:port — if not, treat as plain address.
	if _, _, err := net.SplitHostPort(from); err != nil {
		return from
	}
	return from
}

// renderTemplate executes a text/template and returns the rendered string.
func renderTemplate(tmpl *template.Template, data any) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
