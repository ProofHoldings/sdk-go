package proof

import (
	"context"
	"net/url"
)

// TwoFA provides access to the 2FA API.
type TwoFA struct {
	http *httpClient
}

// Start starts a 2FA session. Params must include action_type and channel.
func (t *TwoFA) Start(ctx context.Context, params map[string]any) (map[string]any, error) {
	return t.http.post(ctx, "/api/v1/me/2fa/start", params)
}

// GetStatus polls the 2FA session status.
func (t *TwoFA) GetStatus(ctx context.Context, sessionID string) (map[string]any, error) {
	return t.http.get(ctx, "/api/v1/me/2fa/"+url.PathEscape(sessionID), nil)
}

// Verify verifies a 2FA code.
func (t *TwoFA) Verify(ctx context.Context, sessionID string, params map[string]any) (SuccessResponse, error) {
	return postAs[SuccessResponse](t.http, ctx, "/api/v1/me/2fa/"+url.PathEscape(sessionID)+"/verify", params)
}

// VerifyMagicLink verifies 2FA via magic link.
func (t *TwoFA) VerifyMagicLink(ctx context.Context, token string) (SuccessResponse, error) {
	return postAs[SuccessResponse](t.http, ctx, "/api/v1/me/2fa/magic/"+url.PathEscape(token), map[string]any{})
}
