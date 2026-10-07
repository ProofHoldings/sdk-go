package proof

import (
	"context"
	"net/url"
)

// HITL config CRUD. Configs are created in "pending" status; upload an
// encryption keypair (see HitlKeys) and call Finalize to activate. The HITL
// struct itself is declared in streaming.go (chat-id discovery streaming).

// Create creates a new HITL configuration (starts in "pending" status).
func (h *HITL) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return h.http.post(ctx, "/api/v1/hitl", params)
}

// List lists HITL configurations with optional filters.
func (h *HITL) List(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return h.http.get(ctx, "/api/v1/hitl", q)
}

// Get gets a HITL configuration by ID.
func (h *HITL) Get(ctx context.Context, id string) (map[string]any, error) {
	return h.http.get(ctx, "/api/v1/hitl/"+url.PathEscape(id), nil)
}

// Update updates a HITL configuration's name, channels, or timeout.
func (h *HITL) Update(ctx context.Context, id string, params map[string]any) (map[string]any, error) {
	return h.http.requestWithBody(ctx, "PATCH", "/api/v1/hitl/"+url.PathEscape(id), params)
}

// Archive archives a HITL configuration (soft delete; returns the archived config).
func (h *HITL) Archive(ctx context.Context, id string) (map[string]any, error) {
	return h.http.del(ctx, "/api/v1/hitl/"+url.PathEscape(id))
}

// Finalize finalizes a pending HITL configuration (pending → active).
// Requires an uploaded encryption keypair; dispatches authorization consent
// messages to configured channels.
func (h *HITL) Finalize(ctx context.Context, id string) (map[string]any, error) {
	return h.http.post(ctx, "/api/v1/hitl/"+url.PathEscape(id)+"/finalize", nil)
}

// RequestAuthorization requests authorization consent for channels in an
// active HITL config that don't have one yet.
func (h *HITL) RequestAuthorization(ctx context.Context, id string) (map[string]any, error) {
	return h.http.post(ctx, "/api/v1/hitl/"+url.PathEscape(id)+"/authorize", nil)
}

// CreateChatIDDiscovery creates a chat-ID discovery token (Telegram deeplink + QR code).
func (h *HITL) CreateChatIDDiscovery(ctx context.Context) (map[string]any, error) {
	return h.http.post(ctx, "/api/v1/hitl/chat-id-discovery", nil)
}

// GetApproverKeys lists enrolled approver public keys for a config. Feed these
// into EncryptMessageV2 to wrap a confirmation message for every approver.
func (h *HITL) GetApproverKeys(ctx context.Context, id string) (map[string]any, error) {
	return h.http.get(ctx, "/api/v1/hitl/"+url.PathEscape(id)+"/approver-keys", nil)
}
