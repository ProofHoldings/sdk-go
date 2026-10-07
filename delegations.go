package proof

import (
	"context"
	"net/url"
)

// Delegations provides access to the Proof of Delegation API: a control-proven
// domain authorizes a typed url/purl artifact for a set of capability scopes.
// The attestation is that the domain's controller authorized the artifact —
// nothing more.
type Delegations struct {
	http *httpClient
}

// Create creates a delegation from your active domain control proof.
// Each mint is a billable proof; a requested lifetime longer than the control
// proof's remainder is rejected (400), never truncated. The result carries the
// publishable token AND the derived effective_status/is_valid the reads carry —
// the shape of a delegation does not depend on which verb produced it.
func (d *Delegations) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return d.http.post(ctx, "/api/v1/delegations", params)
}

// Retrieve gets a delegation by Mongo id or ph_dlg_* handle; the response
// carries the stored token plus the derived effective_status/is_valid.
func (d *Delegations) Retrieve(ctx context.Context, id string) (map[string]any, error) {
	return d.http.get(ctx, "/api/v1/delegations/"+url.PathEscape(id), nil)
}

// List lists your own delegations (tokens are not included in the list).
// Each item carries the derived effective_status/is_valid beside its stored
// status — render the derived one, since status records only whether you
// revoked the delegation yourself. The status param filters the stored record.
func (d *Delegations) List(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return d.http.get(ctx, "/api/v1/delegations", q)
}

// Revoke revokes ONE delegation — the domain proof and sibling delegations stay
// valid. Idempotent: a repeat revoke answers 200 with the same body, here and on
// POST /proofs/{handle}/revoke. (A PROOF differs deliberately — that one answers
// 400 already_revoked.) The result carries the derived effective_status/is_valid.
func (d *Delegations) Revoke(ctx context.Context, id string, params map[string]any) (map[string]any, error) {
	// A typed-nil map forwarded as `any` is a non-nil interface and would
	// marshal to the body `null`, which the server's strict JSON parser rejects.
	if params == nil {
		return d.http.post(ctx, "/api/v1/delegations/"+url.PathEscape(id)+"/revoke", nil)
	}
	return d.http.post(ctx, "/api/v1/delegations/"+url.PathEscape(id)+"/revoke", params)
}
