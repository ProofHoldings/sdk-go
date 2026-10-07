package proof

import (
	"context"
	"net/url"
)

// Profiles is the multi-brand public profiles resource under
// /api/v1/me/profiles: profile CRUD, primary selection, and per-profile
// message template management.
type Profiles struct {
	http *httpClient
}

// List lists all profiles for the authenticated user.
func (p *Profiles) List(ctx context.Context) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/me/profiles", nil)
}

// Create creates a new profile.
func (p *Profiles) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return p.http.post(ctx, "/api/v1/me/profiles", params)
}

// Get gets a profile by ID.
func (p *Profiles) Get(ctx context.Context, profileID string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID), nil)
}

// Update updates a profile.
func (p *Profiles) Update(ctx context.Context, profileID string, params map[string]any) (map[string]any, error) {
	return p.http.requestWithBody(ctx, "PATCH", "/api/v1/me/profiles/"+url.PathEscape(profileID), params)
}

// Delete deletes a profile.
func (p *Profiles) Delete(ctx context.Context, profileID string) (map[string]any, error) {
	return p.http.del(ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID))
}

// SetPrimary sets a profile as the primary profile.
func (p *Profiles) SetPrimary(ctx context.Context, profileID string) (map[string]any, error) {
	return p.http.post(ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID)+"/primary", nil)
}

// ListTemplates lists a profile's message templates (custom and default).
func (p *Profiles) ListTemplates(ctx context.Context, profileID string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID)+"/templates", nil)
}

// UpdateTemplate creates or updates a profile template for a channel/message type.
func (p *Profiles) UpdateTemplate(ctx context.Context, profileID, channel, messageType string, content map[string]any) (map[string]any, error) {
	return p.http.put(ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID)+"/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType), content)
}

// DeleteTemplate deletes a profile template (resets to default).
func (p *Profiles) DeleteTemplate(ctx context.Context, profileID, channel, messageType string) (map[string]any, error) {
	return p.http.del(ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID)+"/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType))
}

// PreviewTemplate previews a profile template with the profile's branding.
func (p *Profiles) PreviewTemplate(ctx context.Context, profileID string, params map[string]any) (map[string]any, error) {
	return p.http.post(ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID)+"/templates/preview", params)
}
