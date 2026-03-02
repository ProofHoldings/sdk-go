package proof

import (
	"context"
	"net/url"
)

// Auth provides access to the auth API.
type Auth struct {
	http *httpClient
}

// GetMe gets the current authenticated user.
func (a *Auth) GetMe(ctx context.Context) (AuthUser, error) {
	return getAs[AuthUser](a.http, ctx, "/api/v1/auth/me", nil)
}

// ListSessions lists all active sessions for the current user.
func (a *Auth) ListSessions(ctx context.Context) (ListSessionsResponse, error) {
	return getAs[ListSessionsResponse](a.http, ctx, "/api/v1/auth/sessions", nil)
}

// RevokeSession revokes a specific session.
func (a *Auth) RevokeSession(ctx context.Context, sessionID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](a.http, ctx, "/api/v1/auth/sessions/"+url.PathEscape(sessionID))
}
