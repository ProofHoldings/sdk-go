package proof

import (
	"context"
	"net/url"
)

// Phones provides access to the phones API.
type Phones struct {
	http *httpClient
}

// List lists all phones for the authenticated user.
func (p *Phones) List(ctx context.Context) ([]UserPhone, error) {
	return getAs[[]UserPhone](p.http, ctx, "/api/v1/me/phones", nil)
}

// Remove removes a phone by ID.
func (p *Phones) Remove(ctx context.Context, phoneID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](p.http, ctx, "/api/v1/me/phones/"+url.PathEscape(phoneID))
}

// SetPrimary sets a phone as the primary phone.
func (p *Phones) SetPrimary(ctx context.Context, phoneID string) (UserPhone, error) {
	return putAs[UserPhone](p.http, ctx, "/api/v1/me/phones/"+url.PathEscape(phoneID)+"/primary", nil)
}

// StartAdd starts adding a new phone.
func (p *Phones) StartAdd(ctx context.Context, params map[string]any) (map[string]any, error) {
	return p.http.post(ctx, "/api/v1/me/phones/add", params)
}

// GetAddStatus gets the status of a phone add session.
func (p *Phones) GetAddStatus(ctx context.Context, sessionID string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/me/phones/add/"+url.PathEscape(sessionID), nil)
}
