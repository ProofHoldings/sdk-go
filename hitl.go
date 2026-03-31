package proof

import (
	"context"
	"net/url"
)

// HitlConfigs provides access to the HITL configs API.
type HitlConfigs struct {
	http *httpClient
}

// Create creates a new HITL config.
func (h *HitlConfigs) Create(ctx context.Context, params map[string]any) (Hitl, error) {
	return postAs[Hitl](h.http, ctx, "/api/v1/hitl", params)
}

// Retrieve gets a HITL config by ID.
func (h *HitlConfigs) Retrieve(ctx context.Context, id string) (Hitl, error) {
	return getAs[Hitl](h.http, ctx, "/api/v1/hitl/"+url.PathEscape(id), nil)
}

// List lists HITL configs with optional filters.
func (h *HitlConfigs) List(ctx context.Context, params map[string]string) (HitlListResponse, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return getAs[HitlListResponse](h.http, ctx, "/api/v1/hitl", q)
}

// Update updates a HITL config.
func (h *HitlConfigs) Update(ctx context.Context, id string, params map[string]any) (Hitl, error) {
	return patchAs[Hitl](h.http, ctx, "/api/v1/hitl/"+url.PathEscape(id), params)
}

// Delete archives a HITL config.
func (h *HitlConfigs) Delete(ctx context.Context, id string) (Hitl, error) {
	return delAs[Hitl](h.http, ctx, "/api/v1/hitl/"+url.PathEscape(id))
}

// RequestAuthorization sends authorization consent requests to all configured channels.
func (h *HitlConfigs) RequestAuthorization(ctx context.Context, id string) (HitlAuthorizationResponse, error) {
	return postAs[HitlAuthorizationResponse](h.http, ctx, "/api/v1/hitl/"+url.PathEscape(id)+"/authorize", map[string]any{})
}

// CreateChatIdDiscovery creates a Telegram chat ID discovery token with deep link and QR code.
func (h *HitlConfigs) CreateChatIdDiscovery(ctx context.Context) (ChatIdDiscoveryResponse, error) {
	return postAs[ChatIdDiscoveryResponse](h.http, ctx, "/api/v1/hitl/chat-id-discovery", map[string]any{})
}

// PollChatIdDiscovery polls a chat ID discovery token for the result.
func (h *HitlConfigs) PollChatIdDiscovery(ctx context.Context, token string) (ChatIdDiscoveryPollResponse, error) {
	return getAs[ChatIdDiscoveryPollResponse](h.http, ctx, "/api/v1/hitl/chat-id-discovery/"+url.PathEscape(token), nil)
}
