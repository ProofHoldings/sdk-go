package proof

import (
	"context"
	"net/url"
)

// UserRequests provides access to user verification request endpoints.
type UserRequests struct {
	http *httpClient
}

// List returns the user's verification requests.
func (r *UserRequests) List(ctx context.Context) (VerificationRequestListResponse, error) {
	return getAs[VerificationRequestListResponse](r.http, ctx, "/api/v1/me/verification-requests", nil)
}

// ListIncoming returns incoming verification requests.
func (r *UserRequests) ListIncoming(ctx context.Context) (VerificationRequestListResponse, error) {
	return getAs[VerificationRequestListResponse](r.http, ctx, "/api/v1/me/verification-requests/incoming", nil)
}

// Create creates a new verification request.
func (r *UserRequests) Create(ctx context.Context, params map[string]any) (VerificationRequest, error) {
	return postAs[VerificationRequest](r.http, ctx, "/api/v1/me/verification-requests", params)
}

// Claim claims assets from a verification request.
func (r *UserRequests) Claim(ctx context.Context, requestID string) (SuccessResponse, error) {
	return postAs[SuccessResponse](r.http, ctx, "/api/v1/me/verification-requests/"+url.PathEscape(requestID)+"/claim", nil)
}

// Cancel cancels a verification request.
func (r *UserRequests) Cancel(ctx context.Context, requestID string) (CancelRequestResponse, error) {
	return delAs[CancelRequestResponse](r.http, ctx, "/api/v1/me/verification-requests/"+url.PathEscape(requestID))
}

// Extend extends a verification request.
func (r *UserRequests) Extend(ctx context.Context, requestID string) (VerificationRequest, error) {
	return postAs[VerificationRequest](r.http, ctx, "/api/v1/me/verification-requests/"+url.PathEscape(requestID)+"/extend", nil)
}

// ShareEmail shares a verification request via email.
func (r *UserRequests) ShareEmail(ctx context.Context, requestID string) (SuccessResponse, error) {
	return postAs[SuccessResponse](r.http, ctx, "/api/v1/me/verification-requests/"+url.PathEscape(requestID)+"/share-email", nil)
}
