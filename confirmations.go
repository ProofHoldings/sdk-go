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
func (c *Confirmations) Create(ctx context.Context, params map[string]any) (Confirmation, error) {
	return postAs[Confirmation](c.http, ctx, "/api/v1/confirmations", params)
}

// Retrieve gets a confirmation by ID.
func (c *Confirmations) Retrieve(ctx context.Context, id string) (Confirmation, error) {
	return getAs[Confirmation](c.http, ctx, "/api/v1/confirmations/"+url.PathEscape(id), nil)
}

// List lists confirmations with optional filters.
func (c *Confirmations) List(ctx context.Context, params map[string]string) (ConfirmationListResponse, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return getAs[ConfirmationListResponse](c.http, ctx, "/api/v1/confirmations", q)
}
