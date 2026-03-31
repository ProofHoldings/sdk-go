package proof

import "context"

// Billing provides access to the billing API.
type Billing struct {
	http *httpClient
}

// Subscription gets the current subscription details.
func (b *Billing) Subscription(ctx context.Context) (map[string]any, error) {
	return b.http.get(ctx, "/api/v1/billing/subscription", nil)
}

// Checkout creates a Stripe checkout session for plan upgrade.
func (b *Billing) Checkout(ctx context.Context, params map[string]any) (CheckoutResponse, error) {
	return postAs[CheckoutResponse](b.http, ctx, "/api/v1/billing/checkout", params)
}

// Portal creates a Stripe customer portal session.
func (b *Billing) Portal(ctx context.Context, params map[string]any) (PortalResponse, error) {
	return postAs[PortalResponse](b.http, ctx, "/api/v1/billing/portal", params)
}
