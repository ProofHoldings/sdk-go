package proof

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicProfiles_GetByID(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.PublicProfiles.GetByID(context.Background(), "pr_1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/profiles/p/pr_1" {
		t.Errorf("want GET /api/v1/profiles/p/pr_1, got %s %s", rec.method, rec.path)
	}
}

func TestPublicProfiles_GetAvatar(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.PublicProfiles.GetAvatar(context.Background(), "pr_1")
	if err != nil {
		t.Fatalf("GetAvatar: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/profiles/p/pr_1/avatar" {
		t.Errorf("want GET /api/v1/profiles/p/pr_1/avatar, got %s %s", rec.method, rec.path)
	}
}

func TestPublicProfiles_GetByUsername(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.PublicProfiles.GetByUsername(context.Background(), "acme")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/profiles/u/acme" {
		t.Errorf("want GET /api/v1/profiles/u/acme, got %s %s", rec.method, rec.path)
	}
}

func TestPublicProfiles_GetBadge(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.PublicProfiles.GetBadge(context.Background(), "team_mgmt")
	if err != nil {
		t.Fatalf("GetBadge: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/profiles/badge/team_mgmt" {
		t.Errorf("want GET /api/v1/profiles/badge/team_mgmt, got %s %s", rec.method, rec.path)
	}
}

func TestPublicProfiles_CheckUsername(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.PublicProfiles.CheckUsername(context.Background(), "acme")
	if err != nil {
		t.Fatalf("CheckUsername: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/profiles/check-username/acme" {
		t.Errorf("want GET /api/v1/profiles/check-username/acme, got %s %s", rec.method, rec.path)
	}
}

// TestPublicProfiles_GetAvatar_BinaryEnvelope exercises the http layer's
// non-JSON success path: an image/png body must come back as a
// {data, content_type} envelope with the raw bytes intact.
func TestPublicProfiles_GetAvatar_BinaryEnvelope(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4E, 0x47}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient("pk_test_avatar", WithBaseURL(srv.URL), WithMaxRetries(0))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := c.PublicProfiles.GetAvatar(context.Background(), "pr_1")
	if err != nil {
		t.Fatalf("GetAvatar: %v", err)
	}
	ct, _ := result["content_type"].(string)
	if ct != "image/png" {
		t.Errorf("content_type: want image/png, got %v", result["content_type"])
	}
	data, ok := result["data"].([]byte)
	if !ok {
		t.Fatalf("data: want []byte, got %T", result["data"])
	}
	if string(data) != string(png) {
		t.Errorf("data bytes mismatch: got %v", data)
	}
}
