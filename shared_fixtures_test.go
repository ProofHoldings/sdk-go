// Unit-level test (no build tag) that loads the shared wire fixtures from
// ``sdks/shared/fixtures/`` and asserts the Go SDK deserializes them into
// the expected map shape. The canonical fixture validator lives in
// ``src/__tests__/drift/sdk-fixtures.test.ts``; this file is the Go-side
// companion that fails if the SDK ever drifts from what the backend
// actually returns on the wire.

package proof

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadSharedFixture reads a JSON file under sdks/shared/fixtures and strips
// top-level metadata keys (those starting with underscore) so callers get
// exactly the wire shape the SDK expects.
func loadSharedFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	// sdks/go/shared_fixtures_test.go → up two to sdks/, then /shared/fixtures/<name>.
	p := filepath.Join("..", "shared", "fixtures", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture %s: %v", p, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("parse fixture %s: %v", p, err)
	}
	for k := range raw {
		if strings.HasPrefix(k, "_") {
			delete(raw, k)
		}
	}
	return raw
}

func fixtureString(t *testing.T, fixture map[string]any, key string) string {
	t.Helper()
	v, ok := fixture[key].(string)
	if !ok {
		t.Fatalf("fixture.%s is not a string (got %T) — fixture schema changed?", key, fixture[key])
	}
	return v
}

func TestSharedFixture_VerificationRoundTrip(t *testing.T) {
	verification := loadSharedFixture(t, "verification.json")
	verificationID := fixtureString(t, verification, "id")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/verifications":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(verification)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/verifications/"+verificationID:
			_ = json.NewEncoder(w).Encode(verification)
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": "not_found", "message": "no handler"},
			})
		}
	}))
	defer srv.Close()

	client, err := NewClient("pk_test_integration", WithBaseURL(srv.URL), WithMaxRetries(0))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()

	created, err := client.Verifications.Create(ctx, map[string]any{
		"type":       verification["type"],
		"channel":    verification["channel"],
		"identifier": verification["identifier"],
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created["id"] != verification["id"] {
		t.Errorf("created.id=%v, want %v", created["id"], verification["id"])
	}

	fetched, err := client.Verifications.Retrieve(ctx, verificationID)
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if fetched["identifier"] != verification["identifier"] {
		t.Errorf("fetched.identifier=%v, want %v", fetched["identifier"], verification["identifier"])
	}
	if fetched["created_at"] != verification["created_at"] {
		t.Errorf("fetched.created_at=%v, want %v", fetched["created_at"], verification["created_at"])
	}
}

func TestSharedFixture_VerificationListPaginationEnvelope(t *testing.T) {
	listEnvelope := loadSharedFixture(t, "verification_list.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listEnvelope)
	}))
	defer srv.Close()

	client, err := NewClient("pk_test_integration", WithBaseURL(srv.URL), WithMaxRetries(0))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	page, err := client.Verifications.List(context.Background(), nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, ok := page["data"].([]any); !ok {
		t.Errorf("page.data is not []any: %T", page["data"])
	}
	pg, ok := page["pagination"].(map[string]any)
	if !ok {
		t.Fatalf("page.pagination is not map[string]any: %T", page["pagination"])
	}
	for _, key := range []string{"page", "limit", "total", "total_pages"} {
		if _, ok := pg[key]; !ok {
			t.Errorf("pagination missing %q", key)
		}
	}
}
