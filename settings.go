package proof

import (
	"context"
	"net/url"
)

// Settings provides access to the settings API.
type Settings struct {
	http *httpClient
}

// Get gets user settings.
func (s *Settings) Get(ctx context.Context) (map[string]any, error) {
	return s.http.get(ctx, "/api/v1/me/settings", nil)
}

// Update updates user settings.
func (s *Settings) Update(ctx context.Context, params map[string]any) (map[string]any, error) {
	return s.http.patch(ctx, "/api/v1/me/settings", params)
}

// GetUsage gets usage metrics.
func (s *Settings) GetUsage(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return s.http.get(ctx, "/api/v1/me/usage", q)
}

// Export exports user data (GDPR).
func (s *Settings) Export(ctx context.Context) (map[string]any, error) {
	return s.http.get(ctx, "/api/v1/me/export", nil)
}
