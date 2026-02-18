package proof

import (
	"context"
	"net/url"
)

// Proofs provides access to the proofs API.
type Proofs struct {
	http    *httpClient
	jwksURL string
}

// Validate validates a proof token online (checks revocation status).
func (p *Proofs) Validate(ctx context.Context, proofToken string, identifier string) (map[string]any, error) {
	body := map[string]string{"proof_token": proofToken}
	if identifier != "" {
		body["identifier"] = identifier
	}
	return p.http.post(ctx, "/api/v1/proofs/validate", body)
}

// Revoke revokes a proof by verification ID.
func (p *Proofs) Revoke(ctx context.Context, id string, reason string) (map[string]any, error) {
	var body map[string]string
	if reason != "" {
		body = map[string]string{"reason": reason}
	}
	return p.http.post(ctx, "/api/v1/proofs/"+url.PathEscape(id)+"/revoke", body)
}

// Status gets the status of a proof by verification ID.
func (p *Proofs) Status(ctx context.Context, id string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/proofs/"+url.PathEscape(id)+"/status", nil)
}

// ListRevoked gets the revocation list.
func (p *Proofs) ListRevoked(ctx context.Context) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/proofs/revoked", nil)
}
