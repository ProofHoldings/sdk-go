package proof

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

const (
	testDlgHandle = "ph_dlg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testCtlHandle = "ph_ctl_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestDelegations_Create(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Delegations.Create(context.Background(), map[string]any{
		"control_proof": testCtlHandle,
		"delegate":      map[string]any{"type": "purl", "value": "pkg:npm/@postmark/mcp"},
		"scope":         []string{"email:send"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/delegations" {
		t.Errorf("want POST /api/v1/delegations, got %s %s", rec.method, rec.path)
	}
	if rec.body["control_proof"] != testCtlHandle {
		t.Errorf("body.control_proof: want %s, got %v", testCtlHandle, rec.body["control_proof"])
	}
}

func TestDelegations_Retrieve(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Delegations.Retrieve(context.Background(), testDlgHandle)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/delegations/"+testDlgHandle {
		t.Errorf("want GET /api/v1/delegations/%s, got %s %s", testDlgHandle, rec.method, rec.path)
	}
}

func TestDelegations_RetrieveEscapesID(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Delegations.Retrieve(context.Background(), "dlg/special id")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	// r.URL.Path is decoded; EscapedPath preserves the wire form the escaping produced.
	if !strings.Contains(rec.rawPath, "dlg%2Fspecial%20id") {
		t.Errorf("id was not path-escaped: %s", rec.rawPath)
	}
}

func TestDelegations_List(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Delegations.List(context.Background(), map[string]string{"status": "revoked", "page": "2"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/delegations" {
		t.Errorf("want GET /api/v1/delegations, got %s %s", rec.method, rec.path)
	}
	if !strings.Contains(rec.query, "status=revoked") || !strings.Contains(rec.query, "page=2") {
		t.Errorf("query: want status=revoked&page=2, got %q", rec.query)
	}
}

func TestDelegations_ListSkipsEmptyParams(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Delegations.List(context.Background(), map[string]string{"status": ""})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rec.query != "" {
		t.Errorf("query: want empty, got %q", rec.query)
	}
}

func TestDelegations_RevokeNilParamsSendsNoBody(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Delegations.Revoke(context.Background(), testDlgHandle, nil)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// A typed-nil map forwarded as `any` is a non-nil interface: json.Marshal
	// would emit the body `null`, which express.json (strict) rejects with 400.
	if rec.rawBody != "" {
		t.Errorf("want no body, got %q", rec.rawBody)
	}
}

func TestDelegations_Revoke(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Delegations.Revoke(context.Background(), testDlgHandle, map[string]any{"reason": "key_compromise"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/delegations/"+testDlgHandle+"/revoke" {
		t.Errorf("want POST /api/v1/delegations/%s/revoke, got %s %s", testDlgHandle, rec.method, rec.path)
	}
	if rec.body["reason"] != "key_compromise" {
		t.Errorf("body.reason: want key_compromise, got %v", rec.body["reason"])
	}
}
