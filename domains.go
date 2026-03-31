package proof

import (
	"context"
	"net/url"
)

// Domains provides access to the domain management API.
type Domains struct {
	http *httpClient
}

// List lists all domains.
func (d *Domains) List(ctx context.Context) ([]Domain, error) {
	return getAs[[]Domain](d.http, ctx, "/api/v1/me/domains", nil)
}

// Add adds a domain.
func (d *Domains) Add(ctx context.Context, params map[string]any) (Domain, error) {
	return postAs[Domain](d.http, ctx, "/api/v1/me/domains", params)
}

// Get gets a domain by ID.
func (d *Domains) Get(ctx context.Context, domainID string) (Domain, error) {
	return getAs[Domain](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID), nil)
}

// Delete deletes a domain.
func (d *Domains) Delete(ctx context.Context, domainID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID))
}

// OAuthURL gets the OAuth URL for DNS provider authorization.
func (d *Domains) OAuthURL(ctx context.Context, domainID string) (map[string]any, error) {
	return d.http.post(ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/oauth-url", map[string]any{})
}

// Verify verifies domain ownership.
func (d *Domains) Verify(ctx context.Context, domainID string) (DomainCheckResponse, error) {
	return postAs[DomainCheckResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/verify", map[string]any{})
}

// ConnectCloudflare connects Cloudflare to a domain.
func (d *Domains) ConnectCloudflare(ctx context.Context, domainID string, params map[string]any) (SuccessResponse, error) {
	return postAs[SuccessResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/connect/cloudflare", params)
}

// ConnectGoDaddy connects GoDaddy to a domain.
func (d *Domains) ConnectGoDaddy(ctx context.Context, domainID string, params map[string]any) (SuccessResponse, error) {
	return postAs[SuccessResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/connect/godaddy", params)
}

// ConnectProvider connects a DNS provider to a domain.
func (d *Domains) ConnectProvider(ctx context.Context, domainID, provider string, params map[string]any) (SuccessResponse, error) {
	return postAs[SuccessResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/connect/"+url.PathEscape(provider), params)
}

// AddProvider adds an additional verification provider to an already-verified domain.
func (d *Domains) AddProvider(ctx context.Context, domainID, provider string, params map[string]any) (SuccessResponse, error) {
	return postAs[SuccessResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/add-provider/"+url.PathEscape(provider), params)
}

// GetProviders gets metadata for all supported DNS providers.
func (d *Domains) GetProviders(ctx context.Context) (map[string]any, error) {
	return d.http.get(ctx, "/api/v1/me/dns-providers", nil)
}

// VerifyWithCredentials verifies a domain with existing credentials.
func (d *Domains) VerifyWithCredentials(ctx context.Context, domainID string) (DomainCheckResponse, error) {
	return postAs[DomainCheckResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/verify-with-credentials", map[string]any{})
}

// CheckCredentials checks if credentials have access to a domain.
func (d *Domains) CheckCredentials(ctx context.Context, domainID string) (map[string]any, error) {
	return d.http.get(ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/check-credentials", nil)
}

// StartEmailVerification starts email verification for a domain.
func (d *Domains) StartEmailVerification(ctx context.Context, domainID string, params map[string]any) (SuccessResponse, error) {
	return postAs[SuccessResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/verify-email", params)
}

// ConfirmEmailCode confirms email verification code.
func (d *Domains) ConfirmEmailCode(ctx context.Context, domainID string, params map[string]any) (DomainCheckResponse, error) {
	return postAs[DomainCheckResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/verify-email/confirm", params)
}

// ResendEmail resends email verification.
func (d *Domains) ResendEmail(ctx context.Context, domainID string, params map[string]any) (SuccessResponse, error) {
	return postAs[SuccessResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/verify-email/resend", params)
}

// EmailSetup sets up email sending for a domain.
func (d *Domains) EmailSetup(ctx context.Context, domainID string, params map[string]any) (SuccessResponse, error) {
	return postAs[SuccessResponse](d.http, ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/email-setup", params)
}

// EmailStatus checks email sending status for a domain.
func (d *Domains) EmailStatus(ctx context.Context, domainID string) (map[string]any, error) {
	return d.http.get(ctx, "/api/v1/me/domains/"+url.PathEscape(domainID)+"/email-status", nil)
}
