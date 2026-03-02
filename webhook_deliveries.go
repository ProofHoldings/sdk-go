package proof

import (
	"context"
	"net/url"
)

// WebhookDeliveries provides access to the webhook deliveries API.
type WebhookDeliveries struct {
	http *httpClient
}

// Stats gets webhook delivery statistics (totals, rates, recent failures).
func (w *WebhookDeliveries) Stats(ctx context.Context) (WebhookDeliveryStats, error) {
	return getAs[WebhookDeliveryStats](w.http, ctx, "/api/v1/webhook-deliveries/stats", nil)
}

// List lists webhook deliveries with optional filters.
func (w *WebhookDeliveries) List(ctx context.Context, params map[string]string) (WebhookDeliveryListResponse, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return getAs[WebhookDeliveryListResponse](w.http, ctx, "/api/v1/webhook-deliveries", q)
}

// Retrieve gets a webhook delivery by ID.
func (w *WebhookDeliveries) Retrieve(ctx context.Context, id string) (WebhookDelivery, error) {
	return getAs[WebhookDelivery](w.http, ctx, "/api/v1/webhook-deliveries/"+url.PathEscape(id), nil)
}

// Retry retries a failed webhook delivery.
func (w *WebhookDeliveries) Retry(ctx context.Context, id string) (RetryDeliveryResponse, error) {
	return postAs[RetryDeliveryResponse](w.http, ctx, "/api/v1/webhook-deliveries/"+url.PathEscape(id)+"/retry", nil)
}
