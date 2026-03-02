package proof

import (
	"context"
	"net/url"
)

// DNSCredentials provides access to the DNS credentials API.
type DNSCredentials struct {
	http *httpClient
}

// List returns all DNS credentials for the authenticated user.
func (d *DNSCredentials) List(ctx context.Context) (map[string]any, error) {
	return d.http.get(ctx, "/api/v1/me/dns-credentials", nil)
}

// Create creates a new DNS credential.
func (d *DNSCredentials) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return d.http.post(ctx, "/api/v1/me/dns-credentials", params)
}

// Delete deletes a DNS credential.
func (d *DNSCredentials) Delete(ctx context.Context, credentialID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](d.http, ctx, "/api/v1/me/dns-credentials/"+url.PathEscape(credentialID))
}
