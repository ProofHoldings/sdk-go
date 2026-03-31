package proof

import (
	"context"
	"net/http"
	"net/url"
)

// Account provides access to the account deletion API.
type Account struct {
	http *httpClient
}

// InitiateDeletion starts the account deletion flow.
func (a *Account) InitiateDeletion(ctx context.Context) (SuccessResponse, error) {
	return postAs[SuccessResponse](a.http, ctx, "/api/v1/me/account/delete", map[string]any{})
}

// DeletionStatus gets the account deletion session status.
func (a *Account) DeletionStatus(ctx context.Context, sessionID string) (map[string]any, error) {
	return a.http.get(ctx, "/api/v1/me/account/delete/"+url.PathEscape(sessionID), nil)
}

// VerifyDeletion verifies account deletion via email code.
func (a *Account) VerifyDeletion(ctx context.Context, sessionID string, params map[string]any) (SuccessResponse, error) {
	return postAs[SuccessResponse](a.http, ctx, "/api/v1/me/account/delete/"+url.PathEscape(sessionID)+"/verify", params)
}

// VerifyDeletionMagicLink verifies account deletion via magic link.
func (a *Account) VerifyDeletionMagicLink(ctx context.Context, token string) (SuccessResponse, error) {
	return postAs[SuccessResponse](a.http, ctx, "/api/v1/me/account/delete/magic/"+url.PathEscape(token), map[string]any{})
}

// Delete finalizes the account deletion (requires confirmed session_id).
func (a *Account) Delete(ctx context.Context, params map[string]any) (SuccessResponse, error) {
	return requestAs[SuccessResponse](a.http, ctx, http.MethodDelete, "/api/v1/me/account", params, nil)
}
