package proof

import (
	"context"
	"net/url"
)

// Circles provides access to the Circle people-primitive API: named groups of
// trusted contacts, their members, and per-member channels. Member and channel
// responses expose reachability booleans (plus a member's masked enrollment
// phone) only — an identifier is NEVER returned (SEC-PM-006).
type Circles struct {
	http *httpClient
}

// Create creates a new Circle (optionally with initial members).
func (c *Circles) Create(ctx context.Context, params map[string]any) (map[string]any, error) {
	return c.http.post(ctx, "/api/v1/circles", params)
}

// List lists Circles with optional filters (archived excluded by default).
func (c *Circles) List(ctx context.Context, params map[string]string) (map[string]any, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return c.http.get(ctx, "/api/v1/circles", q)
}

// Retrieve gets a Circle by ID.
func (c *Circles) Retrieve(ctx context.Context, id string) (map[string]any, error) {
	return c.http.get(ctx, "/api/v1/circles/"+url.PathEscape(id), nil)
}

// Update updates a Circle's name (the profile binding is create-only).
func (c *Circles) Update(ctx context.Context, id string, params map[string]any) (map[string]any, error) {
	return c.http.requestWithBody(ctx, "PATCH", "/api/v1/circles/"+url.PathEscape(id), params)
}

// Archive soft-deletes a Circle.
func (c *Circles) Archive(ctx context.Context, id string) (map[string]any, error) {
	return c.http.del(ctx, "/api/v1/circles/"+url.PathEscape(id))
}

// AddMember adds a pending member by name (+ an optional pre-declared WhatsApp phone).
func (c *Circles) AddMember(ctx context.Context, id string, params map[string]any) (map[string]any, error) {
	return c.http.post(ctx, "/api/v1/circles/"+url.PathEscape(id)+"/members", params)
}

// ListMembers lists a Circle's members (channel presence booleans and a masked enrollment phone only).
func (c *Circles) ListMembers(ctx context.Context, id string) (map[string]any, error) {
	return c.http.get(ctx, "/api/v1/circles/"+url.PathEscape(id)+"/members", nil)
}

// InviteMember mints a single-use enrollment deep link (both channels + QR) for a member.
func (c *Circles) InviteMember(ctx context.Context, id string, memberID string) (map[string]any, error) {
	return c.http.post(ctx, "/api/v1/circles/"+url.PathEscape(id)+"/members/invite", map[string]any{"member_id": memberID})
}

// TriggerDrill fires a cross-channel Proof-Me identity challenge against an enrolled member.
func (c *Circles) TriggerDrill(ctx context.Context, id string, memberID string) (map[string]any, error) {
	return c.http.post(ctx, "/api/v1/circles/"+url.PathEscape(id)+"/members/"+url.PathEscape(memberID)+"/drill", nil)
}

// RemoveMember removes a member (deletes its channels and revokes its live authorizations).
func (c *Circles) RemoveMember(ctx context.Context, id string, memberID string) (map[string]any, error) {
	return c.http.del(ctx, "/api/v1/circles/"+url.PathEscape(id)+"/members/"+url.PathEscape(memberID))
}

// AddMemberChannel declares a channel for a member (409 if that channel type already exists).
func (c *Circles) AddMemberChannel(ctx context.Context, id string, memberID string, params map[string]any) (map[string]any, error) {
	return c.http.post(ctx, "/api/v1/circles/"+url.PathEscape(id)+"/members/"+url.PathEscape(memberID)+"/channels", params)
}

// ListMemberChannels lists a member's channels (metadata only, never an identifier).
func (c *Circles) ListMemberChannels(ctx context.Context, id string, memberID string) (map[string]any, error) {
	return c.http.get(ctx, "/api/v1/circles/"+url.PathEscape(id)+"/members/"+url.PathEscape(memberID)+"/channels", nil)
}

// RemoveMemberChannel removes a member channel (removing the last channel is allowed).
func (c *Circles) RemoveMemberChannel(ctx context.Context, id string, memberID string, channelID string) (map[string]any, error) {
	return c.http.del(ctx, "/api/v1/circles/"+url.PathEscape(id)+"/members/"+url.PathEscape(memberID)+"/channels/"+url.PathEscape(channelID))
}
