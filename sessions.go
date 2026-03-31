package proof

import (
	"context"
	"net/url"
)

// Sessions provides access to the sessions API.
type Sessions struct {
	http *httpClient
}

// Create creates a new phone verification session.
func (s *Sessions) Create(ctx context.Context, params map[string]any) (Session, error) {
	return postAs[Session](s.http, ctx, "/api/v1/sessions", params)
}

// Retrieve gets session status by ID.
func (s *Sessions) Retrieve(ctx context.Context, id string) (Session, error) {
	return getAs[Session](s.http, ctx, "/api/v1/sessions/"+url.PathEscape(id), nil)
}

// WaitForCompletion polls until session reaches a terminal state.
func (s *Sessions) WaitForCompletion(ctx context.Context, id string, opts *WaitOptions) (Session, error) {
	return pollUntilCompleteAs[Session](
		ctx,
		func(c context.Context) (Session, error) { return s.Retrieve(c, id) },
		isTerminalSessionStatus,
		"Session "+id,
		opts,
	)
}

// Sessions cannot be revoked (unlike verifications); terminal states are a strict subset.
func isTerminalSessionStatus(s string) bool {
	return s == "verified" || s == "failed" || s == "expired"
}
