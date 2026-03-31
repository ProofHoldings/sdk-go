package proof

import (
	"context"
	"net/url"
)

// Profiles provides access to the profiles API.
type Profiles struct {
	http *httpClient
}

// List lists all profiles for the authenticated user.
func (p *Profiles) List(ctx context.Context) ([]PublicProfile, error) {
	return getAs[[]PublicProfile](p.http, ctx, "/api/v1/me/profiles", nil)
}

// Create creates a new profile.
func (p *Profiles) Create(ctx context.Context, params map[string]any) (PublicProfile, error) {
	return postAs[PublicProfile](p.http, ctx, "/api/v1/me/profiles", params)
}

// Retrieve gets a specific profile by ID.
func (p *Profiles) Retrieve(ctx context.Context, profileID string) (PublicProfile, error) {
	return getAs[PublicProfile](p.http, ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID), nil)
}

// Update updates a specific profile.
func (p *Profiles) Update(ctx context.Context, profileID string, params map[string]any) (PublicProfile, error) {
	return patchAs[PublicProfile](p.http, ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID), params)
}

// Delete deletes a profile.
func (p *Profiles) Delete(ctx context.Context, profileID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](p.http, ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID))
}

// SetPrimary sets a profile as the primary profile.
func (p *Profiles) SetPrimary(ctx context.Context, profileID string) (PublicProfile, error) {
	return postAs[PublicProfile](p.http, ctx, "/api/v1/me/profiles/"+url.PathEscape(profileID)+"/primary", nil)
}
