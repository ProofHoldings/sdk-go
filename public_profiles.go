package proof

import (
	"context"
	"net/url"
)

// PublicProfiles provides access to public profile endpoints.
type PublicProfiles struct {
	http *httpClient
}

// GetByID gets a public profile by profile ID.
func (p *PublicProfiles) GetByID(ctx context.Context, profileID string) (PublicProfile, error) {
	return getAs[PublicProfile](p.http, ctx, "/api/v1/profiles/p/"+url.PathEscape(profileID), nil)
}

// GetAvatar gets the profile avatar image.
func (p *PublicProfiles) GetAvatar(ctx context.Context, profileID string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/profiles/p/"+url.PathEscape(profileID)+"/avatar", nil)
}

// GetByUsername gets a public profile by username.
func (p *PublicProfiles) GetByUsername(ctx context.Context, username string) (PublicProfile, error) {
	return getAs[PublicProfile](p.http, ctx, "/api/v1/profiles/u/"+url.PathEscape(username), nil)
}

// CheckUsername checks username availability.
func (p *PublicProfiles) CheckUsername(ctx context.Context, username string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/profiles/check-username/"+url.PathEscape(username), nil)
}

// ListProfiles lists all profiles.
func (p *PublicProfiles) ListProfiles(ctx context.Context) ([]PublicProfile, error) {
	return getAs[[]PublicProfile](p.http, ctx, "/api/v1/profiles/profiles", nil)
}

// CreateProfile creates a new profile.
func (p *PublicProfiles) CreateProfile(ctx context.Context, params map[string]any) (PublicProfile, error) {
	return postAs[PublicProfile](p.http, ctx, "/api/v1/profiles/profiles", params)
}

// GetProfile gets a specific profile by ID.
func (p *PublicProfiles) GetProfile(ctx context.Context, profileID string) (PublicProfile, error) {
	return getAs[PublicProfile](p.http, ctx, "/api/v1/profiles/profiles/"+url.PathEscape(profileID), nil)
}

// UpdateProfile updates a specific profile.
func (p *PublicProfiles) UpdateProfile(ctx context.Context, profileID string, params map[string]any) (PublicProfile, error) {
	return patchAs[PublicProfile](p.http, ctx, "/api/v1/profiles/profiles/"+url.PathEscape(profileID), params)
}

// DeleteProfile deletes a profile.
func (p *PublicProfiles) DeleteProfile(ctx context.Context, profileID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](p.http, ctx, "/api/v1/profiles/profiles/"+url.PathEscape(profileID))
}

// SetPrimary sets a profile as primary.
func (p *PublicProfiles) SetPrimary(ctx context.Context, profileID string) (PublicProfile, error) {
	return postAs[PublicProfile](p.http, ctx, "/api/v1/profiles/profiles/"+url.PathEscape(profileID)+"/primary", nil)
}

// UpdateProfileProofs updates proofs for a specific profile.
func (p *PublicProfiles) UpdateProfileProofs(ctx context.Context, profileID string, params map[string]any) (PublicProfile, error) {
	return putAs[PublicProfile](p.http, ctx, "/api/v1/profiles/profiles/"+url.PathEscape(profileID)+"/proofs", params)
}

// GetMyProfile gets the current user's primary profile.
func (p *PublicProfiles) GetMyProfile(ctx context.Context) (PublicProfile, error) {
	return getAs[PublicProfile](p.http, ctx, "/api/v1/profiles/me", nil)
}

// UpdateMyProfile updates the current user's profile.
func (p *PublicProfiles) UpdateMyProfile(ctx context.Context, params map[string]any) (PublicProfile, error) {
	return putAs[PublicProfile](p.http, ctx, "/api/v1/profiles/me", params)
}

// ClaimUsername claims a username.
func (p *PublicProfiles) ClaimUsername(ctx context.Context, params map[string]any) (PublicProfile, error) {
	return postAs[PublicProfile](p.http, ctx, "/api/v1/profiles/me/username", params)
}

// GetAvailableAssets gets available assets for the public profile.
func (p *PublicProfiles) GetAvailableAssets(ctx context.Context) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/profiles/me/assets", nil)
}

// UpdatePublicProofs updates public proofs.
func (p *PublicProfiles) UpdatePublicProofs(ctx context.Context, params map[string]any) (PublicProfile, error) {
	return putAs[PublicProfile](p.http, ctx, "/api/v1/profiles/me/proofs", params)
}
