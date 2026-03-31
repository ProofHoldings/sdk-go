package proof

import (
	"context"
	"net/url"
)

// Authorizations provides access to the authorizations API.
type Authorizations struct {
	http *httpClient
}

// Create creates a new authorization request.
func (a *Authorizations) Create(ctx context.Context, params map[string]any) (CreateAuthorizationResponse, error) {
	return postAs[CreateAuthorizationResponse](a.http, ctx, "/api/v1/authorizations", params)
}

// Retrieve gets an authorization by ID.
func (a *Authorizations) Retrieve(ctx context.Context, id string) (Authorization, error) {
	return getAs[Authorization](a.http, ctx, "/api/v1/authorizations/"+url.PathEscape(id), nil)
}

// List lists authorizations with optional filters.
func (a *Authorizations) List(ctx context.Context, params map[string]string) (AuthorizationListResponse, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return getAs[AuthorizationListResponse](a.http, ctx, "/api/v1/authorizations", q)
}

// Revoke revokes an authorization.
func (a *Authorizations) Revoke(ctx context.Context, id string, params map[string]any) (Authorization, error) {
	return delWithBodyAs[Authorization](a.http, ctx, "/api/v1/authorizations/"+url.PathEscape(id), params)
}

// Export exports authorizations. Pass format:"csv" for CSV or format:"json" for JSON.
// Note: CSV responses return raw text; the result map will contain a "data" key with the CSV string.
func (a *Authorizations) Export(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return getAs[map[string]any](a.http, ctx, "/api/v1/authorizations/export", q)
}
