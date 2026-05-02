package mailer

import "html/template"

var verificationTmpl = template.Must(template.New("verify").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify your email</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f4f4f5; margin: 0; padding: 0; }
    .wrapper { max-width: 560px; margin: 40px auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
    .header  { background: #18181b; padding: 32px 40px; }
    .header h1 { color: #ffffff; font-size: 20px; margin: 0; }
    .body    { padding: 32px 40px; color: #3f3f46; font-size: 15px; line-height: 1.6; }
    .btn     { display: inline-block; margin: 24px 0; padding: 12px 28px; background: #2563eb; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 15px; }
    .footer  { padding: 16px 40px; background: #f4f4f5; color: #a1a1aa; font-size: 12px; }
    .url     { word-break: break-all; color: #6b7280; font-size: 13px; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header"><h1>K8s Learning Platform</h1></div>
    <div class="body">
      <p>Hi there,</p>
      <p>Thanks for signing up. Click the button below to verify your email address. The link expires in <strong>24 hours</strong>.</p>
      <a class="btn" href="{{.VerifyURL}}">Verify email address</a>
      <p>If the button doesn't work, copy and paste this URL into your browser:</p>
      <p class="url">{{.VerifyURL}}</p>
      <p>If you didn't create an account, you can safely ignore this email.</p>
    </div>
    <div class="footer">&copy; {{.Year}} K8s Learning Platform. All rights reserved.</div>
  </div>
</body>
</html>`))

var passwordResetTmpl = template.Must(template.New("reset").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset your password</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f4f4f5; margin: 0; padding: 0; }
    .wrapper { max-width: 560px; margin: 40px auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
    .header  { background: #18181b; padding: 32px 40px; }
    .header h1 { color: #ffffff; font-size: 20px; margin: 0; }
    .body    { padding: 32px 40px; color: #3f3f46; font-size: 15px; line-height: 1.6; }
    .btn     { display: inline-block; margin: 24px 0; padding: 12px 28px; background: #dc2626; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 15px; }
    .footer  { padding: 16px 40px; background: #f4f4f5; color: #a1a1aa; font-size: 12px; }
    .url     { word-break: break-all; color: #6b7280; font-size: 13px; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header"><h1>K8s Learning Platform</h1></div>
    <div class="body">
      <p>Hi there,</p>
      <p>We received a request to reset your password. Click the button below to choose a new one. The link expires in <strong>1 hour</strong>.</p>
      <a class="btn" href="{{.ResetURL}}">Reset password</a>
      <p>If the button doesn't work, copy and paste this URL into your browser:</p>
      <p class="url">{{.ResetURL}}</p>
      <p>If you didn't request a password reset, you can safely ignore this email — your password won't change.</p>
    </div>
    <div class="footer">&copy; {{.Year}} K8s Learning Platform. All rights reserved.</div>
  </div>
</body>
</html>`))
