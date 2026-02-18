package proof

import (
	"context"
	"net/url"
)

// VerificationRequests provides access to the verification requests API.
type VerificationRequests struct {
	http *httpClient
}

// Create creates a multi-asset verification request.
func (vr *VerificationRequests) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return vr.http.post(ctx, "/api/v1/verification-requests", params)
}

// Retrieve gets a verification request by ID.
func (vr *VerificationRequests) Retrieve(ctx context.Context, id string) (map[string]any, error) {
	return vr.http.get(ctx, "/api/v1/verification-requests/"+url.PathEscape(id), nil)
}

// List lists verification requests with optional filters.
func (vr *VerificationRequests) List(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return vr.http.get(ctx, "/api/v1/verification-requests", q)
}

// GetByReference gets a verification request by its reference ID.
func (vr *VerificationRequests) GetByReference(ctx context.Context, referenceID string) (map[string]any, error) {
	return vr.http.get(ctx, "/api/v1/verification-requests/by-reference/"+url.PathEscape(referenceID), nil)
}

// Cancel cancels a pending verification request.
func (vr *VerificationRequests) Cancel(ctx context.Context, id string) (map[string]any, error) {
	return vr.http.del(ctx, "/api/v1/verification-requests/"+url.PathEscape(id))
}

// WaitForCompletion polls until request reaches a terminal state.
func (vr *VerificationRequests) WaitForCompletion(ctx context.Context, id string, opts *WaitOptions) (map[string]any, error) {
	return pollUntilComplete(
		ctx,
		func(c context.Context) (map[string]any, error) { return vr.Retrieve(c, id) },
		isTerminalRequestStatus,
		"Verification request "+id,
		opts,
	)
}

func isTerminalRequestStatus(s string) bool {
	return s == "completed" || s == "expired" || s == "cancelled"
}
