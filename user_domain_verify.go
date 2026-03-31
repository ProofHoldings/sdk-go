package proof

import (
	"context"
	"net/url"
)

// UserDomainVerify provides access to self-service domain verification endpoints.
type UserDomainVerify struct {
	http *httpClient
}

// Start initiates domain verification.
func (d *UserDomainVerify) Start(ctx context.Context, params map[string]any) (DomainVerificationResponse, error) {
	return postAs[DomainVerificationResponse](d.http, ctx, "/api/v1/me/verify/domain", params)
}

// Status polls domain verification status.
func (d *UserDomainVerify) Status(ctx context.Context, sessionID string) (DomainCheckResponse, error) {
	return getAs[DomainCheckResponse](d.http, ctx, "/api/v1/me/verify/domain/"+url.PathEscape(sessionID), nil)
}

// Check checks domain verification.
func (d *UserDomainVerify) Check(ctx context.Context, sessionID string) (DomainCheckResponse, error) {
	return postAs[DomainCheckResponse](d.http, ctx, "/api/v1/me/verify/domain/"+url.PathEscape(sessionID)+"/check", nil)
}
