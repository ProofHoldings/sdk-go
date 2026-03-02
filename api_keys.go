package proof

import (
	"context"
	"net/url"
)

// APIKeys provides access to the API keys management API.
type APIKeys struct {
	http *httpClient
}

// List returns all API keys for the authenticated user.
func (a *APIKeys) List(ctx context.Context) ([]APIKeyResponse, error) {
	return getAs[[]APIKeyResponse](a.http, ctx, "/api/v1/me/api-keys", nil)
}

// Create creates a new API key. All params are optional; nil is
// coerced to an empty map so the POST always sends a JSON body.
func (a *APIKeys) Create(ctx context.Context, params map[string]any) (APIKeyResponse, error) {
	if params == nil {
		params = map[string]any{}
	}
	return postAs[APIKeyResponse](a.http, ctx, "/api/v1/me/api-keys", params)
}

// Revoke revokes an API key.
func (a *APIKeys) Revoke(ctx context.Context, keyID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](a.http, ctx, "/api/v1/me/api-keys/"+url.PathEscape(keyID))
}

// Regenerate regenerates an API key.
func (a *APIKeys) Regenerate(ctx context.Context, keyID string) (APIKeyResponse, error) {
	return postAs[APIKeyResponse](a.http, ctx, "/api/v1/me/api-keys/"+url.PathEscape(keyID)+"/regenerate", nil)
}
