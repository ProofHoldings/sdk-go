package proof

import (
	"context"
	"net/url"
)

// Confirmations provides access to the confirmations API.
type Confirmations struct {
	http *httpClient
}

// Create creates a new confirmation request.
func (c *Confirmations) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return c.http.post(ctx, "/api/v1/confirmations", params)
}

// Retrieve gets a confirmation by ID.
func (c *Confirmations) Retrieve(ctx context.Context, id string) (map[string]any, error) {
	return c.http.get(ctx, "/api/v1/confirmations/"+url.PathEscape(id), nil)
}

// List lists confirmations with optional filters.
func (c *Confirmations) List(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return c.http.get(ctx, "/api/v1/confirmations", q)
}

// ApprovalLink generates a fresh HMAC approval link for a pending confirmation.
func (c *Confirmations) ApprovalLink(ctx context.Context, id string) (map[string]any, error) {
	return c.http.post(ctx, "/api/v1/confirmations/"+url.PathEscape(id)+"/approval-link", nil)
}
