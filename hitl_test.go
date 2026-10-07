package proof

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// recordedRequest captures what the SDK actually sent.
type recordedRequest struct {
	method  string
	path    string
	rawPath string
	query   string
	rawBody string
	body    map[string]any
}

// newRecordingClient returns a client pointed at an httptest server that
// records every request and responds with an empty JSON object.
func newRecordingClient(t *testing.T) (*Client, *recordedRequest) {
	t.Helper()
	rec := &recordedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.rawPath = r.URL.EscapedPath()
		rec.query = r.URL.RawQuery
		rec.rawBody = ""
		rec.body = nil
		if raw, err := io.ReadAll(r.Body); err == nil && len(raw) > 0 {
			rec.rawBody = string(raw)
			_ = json.Unmarshal(raw, &rec.body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient("pk_test_hitl", WithBaseURL(srv.URL), WithMaxRetries(0))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, rec
}

func TestHITL_Create(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.HITL.Create(context.Background(), map[string]any{
		"name":            "Production Approvals",
		"channels":        []map[string]any{{"type": "telegram", "config": map[string]any{"chat_id": "12345"}}},
		"timeout_seconds": 3600,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/hitl" {
		t.Errorf("want POST /api/v1/hitl, got %s %s", rec.method, rec.path)
	}
	if rec.body["name"] != "Production Approvals" {
		t.Errorf("body name: want %q, got %v", "Production Approvals", rec.body["name"])
	}
	if rec.body["timeout_seconds"] != float64(3600) {
		t.Errorf("body timeout_seconds: want 3600, got %v", rec.body["timeout_seconds"])
	}
}

func TestHITL_List(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.HITL.List(context.Background(), map[string]string{"status": "active", "limit": "10", "empty": ""})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/hitl" {
		t.Errorf("want GET /api/v1/hitl, got %s %s", rec.method, rec.path)
	}
	if rec.query != "limit=10&status=active" {
		t.Errorf("query: want limit=10&status=active (empty params skipped), got %q", rec.query)
	}
}

func TestHITL_Get_EncodesID(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.HITL.Get(context.Background(), "hitl/special&id")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// httptest decodes the escaped path; EscapedPath is preserved in RequestURI
	if rec.method != http.MethodGet || rec.path != "/api/v1/hitl/hitl/special&id" {
		t.Errorf("want GET decoded path /api/v1/hitl/hitl/special&id, got %s %s", rec.method, rec.path)
	}
}

func TestHITL_Update(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.HITL.Update(context.Background(), "hitl_123", map[string]any{"name": "Renamed", "timeout_seconds": 7200})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if rec.method != http.MethodPatch || rec.path != "/api/v1/hitl/hitl_123" {
		t.Errorf("want PATCH /api/v1/hitl/hitl_123, got %s %s", rec.method, rec.path)
	}
	if rec.body["name"] != "Renamed" {
		t.Errorf("body name: want %q, got %v", "Renamed", rec.body["name"])
	}
}

func TestHITL_Archive(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.HITL.Archive(context.Background(), "hitl_123")
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/hitl/hitl_123" {
		t.Errorf("want DELETE /api/v1/hitl/hitl_123, got %s %s", rec.method, rec.path)
	}
}

func TestHITL_Finalize(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.HITL.Finalize(context.Background(), "hitl_123")
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/hitl/hitl_123/finalize" {
		t.Errorf("want POST /api/v1/hitl/hitl_123/finalize, got %s %s", rec.method, rec.path)
	}
	if len(rec.body) != 0 {
		t.Errorf("finalize body: want empty, got %v", rec.body)
	}
}

func TestHITL_RequestAuthorization(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.HITL.RequestAuthorization(context.Background(), "hitl_123")
	if err != nil {
		t.Fatalf("RequestAuthorization: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/hitl/hitl_123/authorize" {
		t.Errorf("want POST /api/v1/hitl/hitl_123/authorize, got %s %s", rec.method, rec.path)
	}
}

func TestHITL_CreateChatIDDiscovery(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.HITL.CreateChatIDDiscovery(context.Background())
	if err != nil {
		t.Fatalf("CreateChatIDDiscovery: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/hitl/chat-id-discovery" {
		t.Errorf("want POST /api/v1/hitl/chat-id-discovery, got %s %s", rec.method, rec.path)
	}
}

func TestConfirmations_ApprovalLink(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Confirmations.ApprovalLink(context.Background(), "conf_123")
	if err != nil {
		t.Fatalf("ApprovalLink: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/confirmations/conf_123/approval-link" {
		t.Errorf("want POST /api/v1/confirmations/conf_123/approval-link, got %s %s", rec.method, rec.path)
	}
}

func TestVerificationRequests_GetProofs(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.VerificationRequests.GetProofs(context.Background(), "vr_123")
	if err != nil {
		t.Fatalf("GetProofs: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/verification-requests/vr_123/proofs" {
		t.Errorf("want GET /api/v1/verification-requests/vr_123/proofs, got %s %s", rec.method, rec.path)
	}
}
