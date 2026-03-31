package proof

import (
	"context"
	"net/url"
)

// Emails provides access to the emails API.
type Emails struct {
	http *httpClient
}

// List lists all emails for the authenticated user.
func (e *Emails) List(ctx context.Context) ([]UserEmail, error) {
	return getAs[[]UserEmail](e.http, ctx, "/api/v1/me/emails", nil)
}

// Remove removes an email by ID.
func (e *Emails) Remove(ctx context.Context, emailID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](e.http, ctx, "/api/v1/me/emails/"+url.PathEscape(emailID))
}

// SetPrimary sets an email as the primary email.
func (e *Emails) SetPrimary(ctx context.Context, emailID string) (UserEmail, error) {
	return putAs[UserEmail](e.http, ctx, "/api/v1/me/emails/"+url.PathEscape(emailID)+"/primary", nil)
}

// StartAdd starts adding a new email.
func (e *Emails) StartAdd(ctx context.Context, params map[string]any) (map[string]any, error) {
	return e.http.post(ctx, "/api/v1/me/emails/add", params)
}

// GetAddStatus gets the status of an email add session.
func (e *Emails) GetAddStatus(ctx context.Context, sessionID string) (map[string]any, error) {
	return e.http.get(ctx, "/api/v1/me/emails/add/"+url.PathEscape(sessionID), nil)
}

// VerifyOTP verifies an email using an OTP code.
func (e *Emails) VerifyOTP(ctx context.Context, sessionID string, params map[string]any) (UserEmail, error) {
	return postAs[UserEmail](e.http, ctx, "/api/v1/me/emails/add/"+url.PathEscape(sessionID)+"/verify", params)
}

// ResendOTP resends the email OTP.
func (e *Emails) ResendOTP(ctx context.Context, sessionID string) (SuccessResponse, error) {
	return postAs[SuccessResponse](e.http, ctx, "/api/v1/me/emails/add/"+url.PathEscape(sessionID)+"/resend", nil)
}
