package proof

import (
	"context"
	"net/http"
	"testing"
)

func TestMe_Summary(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Me.Summary(context.Background(), map[string]string{"environment": "test"})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/me/summary" {
		t.Errorf("want GET /api/v1/me/summary, got %s %s", rec.method, rec.path)
	}
	if rec.query != "environment=test" {
		t.Errorf("query: want environment=test, got %q", rec.query)
	}
}

func TestMe_Search(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Me.Search(context.Background(), map[string]string{"q": "acme", "type": "verifications", "limit": "5"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/me/search" {
		t.Errorf("want GET /api/v1/me/search, got %s %s", rec.method, rec.path)
	}
	// url.Values.Encode sorts keys alphabetically.
	if rec.query != "limit=5&q=acme&type=verifications" {
		t.Errorf("query: want limit=5&q=acme&type=verifications, got %q", rec.query)
	}
}

func TestMe_ApiKeySelf(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Me.ApiKeySelf(context.Background())
	if err != nil {
		t.Fatalf("ApiKeySelf: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/me/api-key" {
		t.Errorf("want GET /api/v1/me/api-key, got %s %s", rec.method, rec.path)
	}
}

func TestMe_ApiKeyUsage(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Me.ApiKeyUsage(context.Background(), "key_1", map[string]string{"environment": "production"})
	if err != nil {
		t.Fatalf("ApiKeyUsage: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/me/api-keys/key_1/usage" {
		t.Errorf("want GET /api/v1/me/api-keys/key_1/usage, got %s %s", rec.method, rec.path)
	}
	if rec.query != "environment=production" {
		t.Errorf("query: want environment=production, got %q", rec.query)
	}
}
