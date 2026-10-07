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
func (s *Sessions) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return s.http.post(ctx, "/api/v1/sessions", params)
}

// Retrieve gets session status by ID.
func (s *Sessions) Retrieve(ctx context.Context, id string) (map[string]any, error) {
	return s.http.get(ctx, "/api/v1/sessions/"+url.PathEscape(id), nil)
}

// WaitForCompletion polls until session reaches a terminal state.
func (s *Sessions) WaitForCompletion(ctx context.Context, id string, opts *WaitOptions) (map[string]any, error) {
	return pollUntilComplete(
		ctx,
		func(c context.Context) (map[string]any, error) { return s.Retrieve(c, id) },
		isTerminalSessionStatus,
		"Session "+id,
		opts,
	)
}

func isTerminalSessionStatus(s string) bool {
	return s == "verified" || s == "failed" || s == "expired"
}
