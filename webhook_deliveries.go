package proof

import (
	"context"
	"net/url"
)

// WebhookDeliveries provides access to the webhook deliveries API.
type WebhookDeliveries struct {
	http *httpClient
}

// List lists webhook deliveries with optional filters.
func (w *WebhookDeliveries) List(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return w.http.get(ctx, "/api/v1/webhook-deliveries", q)
}

// Retrieve gets a webhook delivery by ID.
func (w *WebhookDeliveries) Retrieve(ctx context.Context, id string) (map[string]any, error) {
	return w.http.get(ctx, "/api/v1/webhook-deliveries/"+url.PathEscape(id), nil)
}

// Retry retries a failed webhook delivery.
func (w *WebhookDeliveries) Retry(ctx context.Context, id string) (map[string]any, error) {
	return w.http.post(ctx, "/api/v1/webhook-deliveries/"+url.PathEscape(id)+"/retry", nil)
}
