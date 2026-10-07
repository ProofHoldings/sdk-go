package proof

import (
	"context"
	"net/url"
)

// Me provides access to the authenticated account's dashboard/agent data
// surface. The Me struct itself (and its SSE streaming helpers) is declared in
// streaming.go; these dual-auth (JWT or API key) data methods live here.

// Summary returns a one-call account snapshot: quota with end-of-month
// projection, request health, per-channel completion rates, HITL counts, and
// active API key count. Optional params: environment (production|test).
//
// GET /api/v1/me/summary
func (m *Me) Summary(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	return m.http.get(ctx, "/api/v1/me/summary", q)
}

// Search runs a prefix-anchored global account search across six resource
// buckets. Params: q (required), type, environment, limit.
//
// GET /api/v1/me/search
func (m *Me) Search(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	return m.http.get(ctx, "/api/v1/me/search", q)
}

// ApiKeySelf returns the calling API key's own redacted metadata (agent
// self-inspection). The backend returns 400 api_key_required for a JWT caller,
// but SDK callers always authenticate with an API key.
//
// GET /api/v1/me/api-key
func (m *Me) ApiKeySelf(ctx context.Context) (map[string]any, error) {
	return m.http.get(ctx, "/api/v1/me/api-key", nil)
}

// ApiKeyUsage returns per-API-key usage counts (verifications, requests,
// confirmations, authorizations) plus attribution context for the key id.
// Optional params: environment (production|test).
//
// GET /api/v1/me/api-keys/:id/usage
func (m *Me) ApiKeyUsage(ctx context.Context, id string, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	return m.http.get(ctx, "/api/v1/me/api-keys/"+url.PathEscape(id)+"/usage", q)
}
