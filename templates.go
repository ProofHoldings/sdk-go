package proof

import (
	"context"
	"net/url"
)

// Templates is the message templates resource: custom notification
// templates per channel/message type, plus preview and render helpers.
type Templates struct {
	http *httpClient
}

// List lists custom templates plus available channels, message types, and variables.
func (t *Templates) List(ctx context.Context) (map[string]any, error) {
	return t.http.get(ctx, "/api/v1/templates", nil)
}

// GetDefaults gets all default templates (for reference).
func (t *Templates) GetDefaults(ctx context.Context) (map[string]any, error) {
	return t.http.get(ctx, "/api/v1/templates/defaults", nil)
}

// Get gets a specific template (custom if set, default otherwise).
func (t *Templates) Get(ctx context.Context, channel, messageType string) (map[string]any, error) {
	return t.http.get(ctx, "/api/v1/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType), nil)
}

// Upsert creates or updates a custom template.
func (t *Templates) Upsert(ctx context.Context, channel, messageType string, content map[string]any) (map[string]any, error) {
	return t.http.put(ctx, "/api/v1/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType), content)
}

// Delete deletes a custom template (resets to default; 404 if no custom template exists).
func (t *Templates) Delete(ctx context.Context, channel, messageType string) (map[string]any, error) {
	return t.http.del(ctx, "/api/v1/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType))
}

// Preview previews a template with sample data.
func (t *Templates) Preview(ctx context.Context, params map[string]any) (map[string]any, error) {
	return t.http.post(ctx, "/api/v1/templates/preview", params)
}

// Render renders a template with provided variables (for testing).
func (t *Templates) Render(ctx context.Context, params map[string]any) (map[string]any, error) {
	return t.http.post(ctx, "/api/v1/templates/render", params)
}
