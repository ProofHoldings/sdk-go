package proof

import (
	"context"
	"net/url"
)

// Verifications provides access to the verifications API.
type Verifications struct {
	http *httpClient
}

// Create creates a new verification.
func (v *Verifications) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return v.http.post(ctx, "/api/v1/verifications", params)
}

// Retrieve gets a verification by ID.
func (v *Verifications) Retrieve(ctx context.Context, id string) (map[string]any, error) {
	return v.http.get(ctx, "/api/v1/verifications/"+url.PathEscape(id), nil)
}

// List lists verifications with optional filters.
func (v *Verifications) List(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return v.http.get(ctx, "/api/v1/verifications", q)
}

// Verify triggers a DNS/HTTP verification check.
func (v *Verifications) Verify(ctx context.Context, id string) (map[string]any, error) {
	return v.http.post(ctx, "/api/v1/verifications/"+url.PathEscape(id)+"/verify", nil)
}

// Submit submits an OTP/challenge code.
func (v *Verifications) Submit(ctx context.Context, id, code string) (map[string]any, error) {
	return v.http.post(ctx, "/api/v1/verifications/"+url.PathEscape(id)+"/submit", map[string]string{"code": code})
}

// Resend resends a verification email (email channel only).
func (v *Verifications) Resend(ctx context.Context, id string) (map[string]any, error) {
	return v.http.post(ctx, "/api/v1/verifications/"+url.PathEscape(id)+"/resend", nil)
}

// TestVerify auto-completes a verification in test mode (pk_test_* API keys only).
func (v *Verifications) TestVerify(ctx context.Context, id string) (map[string]any, error) {
	return v.http.post(ctx, "/api/v1/verifications/"+url.PathEscape(id)+"/test-verify", nil)
}

// ListVerifiedUsers lists verified users grouped by external_user_id.
func (v *Verifications) ListVerifiedUsers(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return v.http.get(ctx, "/api/v1/verifications/users", q)
}

// GetVerifiedUser gets a single verified user's verifications by external user ID.
func (v *Verifications) GetVerifiedUser(ctx context.Context, externalUserID string) (map[string]any, error) {
	return v.http.get(ctx, "/api/v1/verifications/users/"+url.PathEscape(externalUserID), nil)
}

// StartDomainVerification starts a B2B domain verification.
func (v *Verifications) StartDomainVerification(ctx context.Context, params map[string]any) (map[string]any, error) {
	return v.http.post(ctx, "/api/v1/verifications/domain", params)
}

// CheckDomainVerification checks a pending domain verification (DNS/HTTP file).
func (v *Verifications) CheckDomainVerification(ctx context.Context, id string) (map[string]any, error) {
	return v.http.post(ctx, "/api/v1/verifications/domain/"+url.PathEscape(id)+"/check", nil)
}

// WaitForCompletion polls until verification reaches a terminal state.
func (v *Verifications) WaitForCompletion(ctx context.Context, id string, opts *WaitOptions) (map[string]any, error) {
	return pollUntilComplete(
		ctx,
		func(c context.Context) (map[string]any, error) { return v.Retrieve(c, id) },
		isTerminalVerificationStatus,
		"Verification "+id,
		opts,
	)
}

func isTerminalVerificationStatus(s string) bool {
	return s == "verified" || s == "failed" || s == "expired" || s == "revoked"
}
