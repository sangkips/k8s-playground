// Package mailer defines the Mailer interface used by auth handlers to send
// transactional emails (verification, password reset).
// Swap in a real implementation (SMTP, SendGrid, etc.) by satisfying the interface.
package mailer

import "context"

// Mailer sends transactional emails.
type Mailer interface {
	SendVerificationEmail(ctx context.Context, to, verifyURL string) error
	SendPasswordResetEmail(ctx context.Context, to, resetURL string) error
}

// NoOp is a Mailer that logs nothing and does nothing.
// Useful in tests and local development before a real mailer is wired up.
type NoOp struct{}

func (NoOp) SendVerificationEmail(_ context.Context, to, url string) error {
	return nil
}

func (NoOp) SendPasswordResetEmail(_ context.Context, to, url string) error {
	return nil
}
