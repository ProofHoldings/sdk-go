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
func (a *Authorizations) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return a.http.post(ctx, "/api/v1/authorizations", params)
}

// Retrieve gets an authorization by ID.
func (a *Authorizations) Retrieve(ctx context.Context, id string) (map[string]any, error) {
	return a.http.get(ctx, "/api/v1/authorizations/"+url.PathEscape(id), nil)
}

// List lists authorizations with optional filters.
func (a *Authorizations) List(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return a.http.get(ctx, "/api/v1/authorizations", q)
}

// Revoke revokes an authorization. Body is sent as DELETE with JSON body.
func (a *Authorizations) Revoke(ctx context.Context, id string, params map[string]any) (map[string]any, error) {
	return a.http.requestWithBody(ctx, "DELETE", "/api/v1/authorizations/"+url.PathEscape(id), params)
}

// Export exports authorizations. Pass format:"csv" for CSV or format:"json" for JSON.
// CSV responses are served as text/csv and come back through the http layer's
// non-JSON envelope: the result map contains "data" ([]byte, the raw CSV) and
// "content_type" (string).
func (a *Authorizations) Export(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return a.http.get(ctx, "/api/v1/authorizations/export", q)
}
