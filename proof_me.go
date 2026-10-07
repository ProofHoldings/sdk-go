package proof

import (
	"context"
	"net/url"
)

// ProofMe provides access to the Proof-Me anti-impersonation API: cross-channel
// identity challenges against an enrolled Circle member. Member enrollment and
// drills live on the Circles resource (the Circle people-primitive).
type ProofMe struct {
	http *httpClient
}

// CreateIdentityChallenge creates a cross-channel identity challenge (CONFIRM) for
// an enrolled Circle member. params must include "circle_id" and "member_id".
func (p *ProofMe) CreateIdentityChallenge(ctx context.Context, params map[string]any) (map[string]any, error) {
	return p.http.post(ctx, "/api/v1/identity-challenges", params)
}

// GetIdentityChallenge gets an identity challenge by ID (poll for resolution).
func (p *ProofMe) GetIdentityChallenge(ctx context.Context, id string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/identity-challenges/"+url.PathEscape(id), nil)
}
