package proof

import (
	"context"
	"net/url"
)

// Templates provides access to the templates API.
type Templates struct {
	http *httpClient
}

// List lists all custom templates for the authenticated tenant.
func (t *Templates) List(ctx context.Context) ([]Template, error) {
	return getAs[[]Template](t.http, ctx, "/api/v1/templates", nil)
}

// GetDefaults gets all default templates.
func (t *Templates) GetDefaults(ctx context.Context) ([]Template, error) {
	return getAs[[]Template](t.http, ctx, "/api/v1/templates/defaults", nil)
}

// Retrieve gets a specific template (custom or default) by channel and message type.
func (t *Templates) Retrieve(ctx context.Context, channel, messageType string) (Template, error) {
	return getAs[Template](t.http, ctx, "/api/v1/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType), nil)
}

// Upsert creates or updates a custom template.
func (t *Templates) Upsert(ctx context.Context, channel, messageType string, params map[string]any) (Template, error) {
	return putAs[Template](t.http, ctx, "/api/v1/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType), params)
}

// Delete deletes a custom template (resets to default).
func (t *Templates) Delete(ctx context.Context, channel, messageType string) (SuccessResponse, error) {
	return delAs[SuccessResponse](t.http, ctx, "/api/v1/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType))
}

// Preview previews a template with sample data.
func (t *Templates) Preview(ctx context.Context, params map[string]any) (map[string]any, error) {
	return t.http.post(ctx, "/api/v1/templates/preview", params)
}

// Render renders a template with provided variables.
func (t *Templates) Render(ctx context.Context, params map[string]any) (map[string]any, error) {
	return t.http.post(ctx, "/api/v1/templates/render", params)
}
