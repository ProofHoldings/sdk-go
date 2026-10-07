package proof

import (
	"context"
	"net/url"
)

// HitlKeys provides access to the HITL encryption key management API.
type HitlKeys struct {
	http *httpClient
}

// GetKeys retrieves the encryption keypair for a HITL config.
func (h *HitlKeys) GetKeys(ctx context.Context, hitlID string) (map[string]any, error) {
	return h.http.get(ctx, "/api/v1/hitl/"+url.PathEscape(hitlID)+"/keys", nil)
}

// UploadKeys uploads an encryption keypair for a HITL config.
func (h *HitlKeys) UploadKeys(ctx context.Context, hitlID string, params map[string]any) (map[string]any, error) {
	return h.http.put(ctx, "/api/v1/hitl/"+url.PathEscape(hitlID)+"/keys", params)
}

// DeleteKeys deletes the encryption keypair from a HITL config.
func (h *HitlKeys) DeleteKeys(ctx context.Context, hitlID string) (map[string]any, error) {
	return h.http.del(ctx, "/api/v1/hitl/"+url.PathEscape(hitlID)+"/keys")
}
