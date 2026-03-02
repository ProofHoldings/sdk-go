package proof

import (
	"context"
	"net/url"
)

// Proofs provides access to the proofs API.
type Proofs struct {
	http      *httpClient
	jwksCache *jwksCache
}

// Validate validates a proof token online (checks revocation status).
func (p *Proofs) Validate(ctx context.Context, proofToken string) (ValidateProofResponse, error) {
	body := map[string]string{"proof_token": proofToken}
	return postAs[ValidateProofResponse](p.http, ctx, "/api/v1/proofs/validate", body)
}

// Revoke revokes a proof by verification ID.
func (p *Proofs) Revoke(ctx context.Context, id string, reason string) (RevokeProofResponse, error) {
	var body map[string]string
	if reason != "" {
		body = map[string]string{"reason": reason}
	}
	return postAs[RevokeProofResponse](p.http, ctx, "/api/v1/proofs/"+url.PathEscape(id)+"/revoke", body)
}

// Status gets the status of a proof by verification ID.
func (p *Proofs) Status(ctx context.Context, id string) (ProofStatusResponse, error) {
	return getAs[ProofStatusResponse](p.http, ctx, "/api/v1/proofs/"+url.PathEscape(id)+"/status", nil)
}

// ListRevoked gets the revocation list.
func (p *Proofs) ListRevoked(ctx context.Context) (RevocationList, error) {
	return getAs[RevocationList](p.http, ctx, "/api/v1/proofs/revoked", nil)
}

// VerifyOffline verifies a proof token offline using JWKS public keys.
// The JWKS is fetched once and cached. Call RefreshJWKS to invalidate the cache.
// No API call is made to the proofs endpoint -- verification is done locally.
func (p *Proofs) VerifyOffline(token string) (map[string]any, error) {
	claims, err := verifyJWT(p.jwksCache, token, "proof.holdings")
	if err != nil {
		return map[string]any{
			"valid": false,
			"error": err.Error(),
		}, nil
	}

	// Expose a stable subset of claims; new JWT fields require explicit addition here
	return map[string]any{
		"valid": true,
		"payload": map[string]any{
			"iss":             claims["iss"],
			"sub":             claims["sub"],
			"iat":             claims["iat"],
			"exp":             claims["exp"],
			"type":            claims["type"],
			"channel":         claims["channel"],
			"identifier_hash": claims["identifier_hash"],
			"verified_at":     claims["verified_at"],
			"user_id":         claims["user_id"],
		},
	}, nil
}

// RefreshJWKS clears the cached JWKS keys, forcing a re-fetch on the next VerifyOffline call.
func (p *Proofs) RefreshJWKS() {
	if p.jwksCache != nil {
		p.jwksCache.clear()
	}
}
