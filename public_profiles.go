package proof

import (
	"context"
	"net/url"
)

// PublicProfiles is the public profile reads resource — unauthenticated
// endpoints under /api/v1/profiles; the client's Authorization header is
// sent but ignored by the server.
type PublicProfiles struct {
	http *httpClient
}

// GetByID gets a public profile by its PUBLIC profile_id (the profile_id
// field on /me/profiles responses) — the internal id is NOT accepted by
// this endpoint and will 404.
func (p *PublicProfiles) GetByID(ctx context.Context, profileID string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/profiles/p/"+url.PathEscape(profileID), nil)
}

// GetAvatar gets a profile's avatar image. Accepts either the public
// profile_id or the internal id. Returns a map with "data" ([]byte) and
// "content_type" (string); https-hosted avatars are followed through the
// server's 301 redirect.
func (p *PublicProfiles) GetAvatar(ctx context.Context, profileID string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/profiles/p/"+url.PathEscape(profileID)+"/avatar", nil)
}

// GetByUsername gets a public profile by username.
func (p *PublicProfiles) GetByUsername(ctx context.Context, username string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/profiles/u/"+url.PathEscape(username), nil)
}

// GetBadge gets the embeddable badge descriptor for a username.
//
// Everything needed to embed the verification badge in one call: the subject
// it asserts, the live verified count, the badge image URL for each style,
// and ready-to-paste snippets. A username with no public record answers 200
// with state "no_public_record" rather than a 404, so a caller never has to
// treat "nothing to show" as an error.
func (p *PublicProfiles) GetBadge(ctx context.Context, username string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/profiles/badge/"+url.PathEscape(username), nil)
}

// CheckUsername checks username availability.
func (p *PublicProfiles) CheckUsername(ctx context.Context, username string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/profiles/check-username/"+url.PathEscape(username), nil)
}
