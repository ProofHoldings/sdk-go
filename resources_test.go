package proof

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// requestCapture stores the HTTP request details for assertion.
type requestCapture struct {
	Body  map[string]any
	Query url.Values
}

func resourceServer(t *testing.T, wantMethod, wantPath string, response any) (*Client, *requestCapture) {
	t.Helper()
	cap := &requestCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.Query = r.URL.Query()
		if r.Method != wantMethod {
			t.Errorf("method: want %s, got %s", wantMethod, r.Method)
		}
		if r.URL.Path != wantPath {
			t.Errorf("path: want %s, got %s", wantPath, r.URL.Path)
		}
		if r.Body != nil {
			bodyBytes, _ := io.ReadAll(r.Body)
			if len(bodyBytes) > 0 {
				_ = json.Unmarshal(bodyBytes, &cap.Body)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	client, err := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	t.Cleanup(srv.Close)
	return client, cap
}


// assertBodyField compares a captured JSON body field using reflect.DeepEqual.
// NOTE: json.Unmarshal into map[string]any decodes numbers as float64.
// For numeric assertions, pass float64 (e.g., float64(5)), not int.
func assertBodyField(t *testing.T, cap *requestCapture, key string, want any) {
	t.Helper()
	got, ok := cap.Body[key]
	if !ok {
		t.Errorf("body missing key %q", key)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("body[%q]: want %v (%T), got %v (%T)", key, want, want, got, got)
	}
}

func assertQuery(t *testing.T, cap *requestCapture, key, want string) {
	t.Helper()
	got := cap.Query.Get(key)
	if got != want {
		t.Errorf("query[%q]: want %q, got %q", key, want, got)
	}
}

// ---------------------------------------------------------------------------
// Verifications (11 methods, skip WaitForCompletion — tested in polling_test.go)
// ---------------------------------------------------------------------------

func TestVerifications_Create(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/verifications", map[string]any{
		"id": "ver_123", "status": "pending",
	})
	result, err := client.Verifications.Create(context.Background(), map[string]any{
		"type": "phone", "channel": "whatsapp", "identifier": "+1234567890",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "type", "phone")
	assertBodyField(t, cap, "channel", "whatsapp")
	if result.ID != "ver_123" {
		t.Errorf("want ID ver_123, got %s", result.ID)
	}
}

func TestVerifications_Retrieve(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/verifications/ver_123", map[string]any{
		"id": "ver_123", "status": "pending",
	})
	result, err := client.Verifications.Retrieve(context.Background(), "ver_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "ver_123" {
		t.Errorf("want ID ver_123, got %s", result.ID)
	}
}

func TestVerifications_Retrieve_EncodesSpecialChars(t *testing.T) {
	var rawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": "ver/special&id"})
	}))
	defer srv.Close()
	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	_, _ = client.Verifications.Retrieve(context.Background(), "ver/special&id")
	if !strings.Contains(rawPath, "ver%2Fspecial") {
		t.Errorf("path slash not encoded: %s", rawPath)
	}
}

func TestVerifications_List(t *testing.T) {
	client, cap := resourceServer(t, "GET", "/api/v1/verifications", map[string]any{
		"data": []any{}, "pagination": map[string]any{},
	})
	_, err := client.Verifications.List(context.Background(), map[string]string{"status": "verified"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertQuery(t, cap, "status", "verified")
}

func TestVerifications_Verify(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/verifications/ver_123/verify", map[string]any{
		"status": "verified",
	})
	_, err := client.Verifications.Verify(context.Background(), "ver_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifications_Submit(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/verifications/ver_123/submit", map[string]any{
		"status": "verified",
	})
	_, err := client.Verifications.Submit(context.Background(), "ver_123", "ABC123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "code", "ABC123")
}

func TestVerifications_Resend(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/verifications/ver_123/resend", map[string]any{
		"success": true,
	})
	_, err := client.Verifications.Resend(context.Background(), "ver_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifications_TestVerify(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/verifications/ver_123/test-verify", map[string]any{
		"status": "verified",
	})
	_, err := client.Verifications.TestVerify(context.Background(), "ver_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifications_ListVerifiedUsers(t *testing.T) {
	client, cap := resourceServer(t, "GET", "/api/v1/verifications/users", map[string]any{
		"data": []any{},
	})
	_, err := client.Verifications.ListVerifiedUsers(context.Background(), map[string]string{"limit": "10"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertQuery(t, cap, "limit", "10")
}

func TestVerifications_GetVerifiedUser(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/verifications/users/ext_123", map[string]any{
		"external_user_id": "ext_123",
	})
	_, err := client.Verifications.GetVerifiedUser(context.Background(), "ext_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifications_StartDomainVerification(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/verifications/domain", map[string]any{
		"id": "ver_dom", "status": "pending",
	})
	_, err := client.Verifications.StartDomainVerification(context.Background(), map[string]any{
		"domain": "example.com", "verification_method": "dns",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "domain", "example.com")
}

func TestVerifications_CheckDomainVerification(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/verifications/domain/ver_dom/check", map[string]any{
		"verified": true,
	})
	_, err := client.Verifications.CheckDomainVerification(context.Background(), "ver_dom")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// VerificationRequests (4 methods, skip WaitForCompletion)
// ---------------------------------------------------------------------------

func TestVerificationRequests_Create(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/verification-requests", map[string]any{
		"id": "vr_123", "status": "pending",
	})
	_, err := client.VerificationRequests.Create(context.Background(), map[string]any{
		"reference_id": "user_123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "reference_id", "user_123")
}

func TestVerificationRequests_Retrieve(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/verification-requests/vr_123", map[string]any{
		"id": "vr_123",
	})
	result, err := client.VerificationRequests.Retrieve(context.Background(), "vr_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "vr_123" {
		t.Errorf("want ID vr_123, got %s", result.ID)
	}
}

func TestVerificationRequests_List(t *testing.T) {
	client, cap := resourceServer(t, "GET", "/api/v1/verification-requests", map[string]any{
		"data": []any{}, "pagination": map[string]any{},
	})
	_, err := client.VerificationRequests.List(context.Background(), map[string]string{"status": "pending"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertQuery(t, cap, "status", "pending")
}

func TestVerificationRequests_GetByReference(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/verification-requests/by-reference/ref_abc", map[string]any{
		"id": "vr_123", "reference_id": "ref_abc",
	})
	_, err := client.VerificationRequests.GetByReference(context.Background(), "ref_abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerificationRequests_Cancel(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/verification-requests/vr_123", map[string]any{
		"status": "cancelled",
	})
	_, err := client.VerificationRequests.Cancel(context.Background(), "vr_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Proofs (4 methods, skip VerifyOffline/RefreshJWKS — need JWKS server)
// ---------------------------------------------------------------------------

func TestProofs_Validate(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/proofs/validate", map[string]any{
		"valid": true,
	})
	_, err := client.Proofs.Validate(context.Background(), "proof_token_abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "proof_token", "proof_token_abc")
}

func TestProofs_Revoke(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/proofs/ver_123/revoke", map[string]any{
		"success": true,
	})
	_, err := client.Proofs.Revoke(context.Background(), "ver_123", "fraudulent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "reason", "fraudulent")
}

func TestProofs_Revoke_NoReason(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/proofs/ver_123/revoke", map[string]any{
		"success": true,
	})
	_, err := client.Proofs.Revoke(context.Background(), "ver_123", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.Body != nil && cap.Body["reason"] != nil {
		t.Error("expected no reason in body when empty")
	}
}

func TestProofs_Status(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/proofs/ver_123/status", map[string]any{
		"status": "valid",
	})
	_, err := client.Proofs.Status(context.Background(), "ver_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProofs_ListRevoked(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/proofs/revoked", map[string]any{
		"revocations": []any{},
	})
	_, err := client.Proofs.ListRevoked(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Sessions (2 methods, skip WaitForCompletion)
// ---------------------------------------------------------------------------

func TestSessions_Create(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/sessions", map[string]any{
		"id": "sess_123", "status": "pending", "channel": "telegram",
	})
	result, err := client.Sessions.Create(context.Background(), map[string]any{"channel": "telegram"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "channel", "telegram")
	if result.ID != "sess_123" {
		t.Errorf("want ID sess_123, got %s", result.ID)
	}
}

func TestSessions_Retrieve(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/sessions/sess_123", map[string]any{
		"id": "sess_123", "status": "pending",
	})
	result, err := client.Sessions.Retrieve(context.Background(), "sess_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "sess_123" {
		t.Errorf("want ID sess_123, got %s", result.ID)
	}
}

// ---------------------------------------------------------------------------
// WebhookDeliveries (4 methods)
// ---------------------------------------------------------------------------

func TestWebhookDeliveries_Stats(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/webhook-deliveries/stats", map[string]any{
		"total": 100,
	})
	_, err := client.WebhookDeliveries.Stats(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWebhookDeliveries_List(t *testing.T) {
	client, cap := resourceServer(t, "GET", "/api/v1/webhook-deliveries", map[string]any{
		"data": []any{}, "pagination": map[string]any{},
	})
	_, err := client.WebhookDeliveries.List(context.Background(), map[string]string{"status": "failed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertQuery(t, cap, "status", "failed")
}

func TestWebhookDeliveries_Retrieve(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/webhook-deliveries/del_123", map[string]any{
		"id": "del_123",
	})
	result, err := client.WebhookDeliveries.Retrieve(context.Background(), "del_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "del_123" {
		t.Errorf("want ID del_123, got %s", result.ID)
	}
}

func TestWebhookDeliveries_Retry(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/webhook-deliveries/del_123/retry", map[string]any{
		"success": true,
	})
	_, err := client.WebhookDeliveries.Retry(context.Background(), "del_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Templates (7 methods)
// ---------------------------------------------------------------------------

func TestTemplates_List(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/templates", map[string]any{})
	// Array return type — verify request only (requestAs round-trips through map[string]any)
	client.Templates.List(context.Background())
}

func TestTemplates_GetDefaults(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/templates/defaults", map[string]any{})
	client.Templates.GetDefaults(context.Background())
}

func TestTemplates_Retrieve(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/templates/email/verification_request", map[string]any{
		"channel": "email", "message_type": "verification_request",
	})
	result, err := client.Templates.Retrieve(context.Background(), "email", "verification_request")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Channel != "email" {
		t.Errorf("want channel email, got %s", result.Channel)
	}
}

func TestTemplates_Upsert(t *testing.T) {
	client, cap := resourceServer(t, "PUT", "/api/v1/templates/email/verification_request", map[string]any{
		"channel": "email",
	})
	_, err := client.Templates.Upsert(context.Background(), "email", "verification_request", map[string]any{
		"subject": "Verify your email",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "subject", "Verify your email")
}

func TestTemplates_Delete(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/templates/email/verification_request", map[string]any{
		"success": true,
	})
	_, err := client.Templates.Delete(context.Background(), "email", "verification_request")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTemplates_Preview(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/templates/preview", map[string]any{
		"rendered": "<p>Hello</p>",
	})
	_, err := client.Templates.Preview(context.Background(), map[string]any{
		"channel": "email", "message_type": "verification_request",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTemplates_Render(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/templates/render", map[string]any{
		"rendered": "<p>Code: 123456</p>",
	})
	_, err := client.Templates.Render(context.Background(), map[string]any{
		"channel": "email", "variables": map[string]any{"code": "123456"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Profiles (6 methods)
// ---------------------------------------------------------------------------

func TestProfiles_List(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/profiles", map[string]any{})
	client.Profiles.List(context.Background())
}

func TestProfiles_Create(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/profiles", map[string]any{
		"id": "prof_123",
	})
	_, err := client.Profiles.Create(context.Background(), map[string]any{"display_name": "Test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "display_name", "Test")
}

func TestProfiles_Retrieve(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/profiles/prof_123", map[string]any{
		"id": "prof_123",
	})
	_, err := client.Profiles.Retrieve(context.Background(), "prof_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProfiles_Update(t *testing.T) {
	client, cap := resourceServer(t, "PATCH", "/api/v1/me/profiles/prof_123", map[string]any{
		"id": "prof_123",
	})
	_, err := client.Profiles.Update(context.Background(), "prof_123", map[string]any{"display_name": "Updated"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "display_name", "Updated")
}

func TestProfiles_Delete(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/profiles/prof_123", map[string]any{
		"success": true,
	})
	_, err := client.Profiles.Delete(context.Background(), "prof_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProfiles_SetPrimary(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/profiles/prof_123/primary", map[string]any{
		"id": "prof_123", "is_primary": true,
	})
	_, err := client.Profiles.SetPrimary(context.Background(), "prof_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Projects (9 methods)
// ---------------------------------------------------------------------------

func TestProjects_List(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/projects", map[string]any{})
	client.Projects.List(context.Background())
}

func TestProjects_Create(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/projects", map[string]any{
		"id": "proj_123", "name": "Test Project",
	})
	_, err := client.Projects.Create(context.Background(), map[string]any{"name": "Test Project"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "name", "Test Project")
}

func TestProjects_Retrieve(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/projects/proj_123", map[string]any{
		"id": "proj_123",
	})
	result, err := client.Projects.Retrieve(context.Background(), "proj_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "proj_123" {
		t.Errorf("want ID proj_123, got %s", result.ID)
	}
}

func TestProjects_Update(t *testing.T) {
	client, _ := resourceServer(t, "PUT", "/api/v1/me/projects/proj_123", map[string]any{
		"id": "proj_123",
	})
	_, err := client.Projects.Update(context.Background(), "proj_123", map[string]any{"name": "Updated"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProjects_Delete(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/projects/proj_123", map[string]any{
		"success": true,
	})
	_, err := client.Projects.Delete(context.Background(), "proj_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProjects_ListTemplates(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/projects/proj_123/templates", map[string]any{})
	client.Projects.ListTemplates(context.Background(), "proj_123")
}

func TestProjects_UpdateTemplate(t *testing.T) {
	client, _ := resourceServer(t, "PUT", "/api/v1/me/projects/proj_123/templates/email/verification_request", map[string]any{
		"channel": "email",
	})
	_, err := client.Projects.UpdateTemplate(context.Background(), "proj_123", "email", "verification_request", map[string]any{
		"subject": "Verify",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProjects_DeleteTemplate(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/projects/proj_123/templates/email/verification_request", map[string]any{
		"success": true,
	})
	_, err := client.Projects.DeleteTemplate(context.Background(), "proj_123", "email", "verification_request")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProjects_PreviewTemplate(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/projects/proj_123/templates/preview", map[string]any{
		"rendered": "<p>Preview</p>",
	})
	_, err := client.Projects.PreviewTemplate(context.Background(), "proj_123", map[string]any{
		"channel": "email",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Billing (3 methods)
// ---------------------------------------------------------------------------

func TestBilling_Subscription(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/billing/subscription", map[string]any{
		"plan": "pro", "status": "active",
	})
	result, err := client.Billing.Subscription(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["plan"] != "pro" {
		t.Errorf("want plan pro, got %v", result["plan"])
	}
}

func TestBilling_Checkout(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/billing/checkout", map[string]any{
		"url": "https://checkout.stripe.com/session",
	})
	_, err := client.Billing.Checkout(context.Background(), map[string]any{
		"plan": "pro", "success_url": "https://example.com/success",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "plan", "pro")
}

func TestBilling_Portal(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/billing/portal", map[string]any{
		"url": "https://billing.stripe.com/portal",
	})
	_, err := client.Billing.Portal(context.Background(), map[string]any{
		"return_url": "https://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Phones (5 methods)
// ---------------------------------------------------------------------------

func TestPhones_List(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/phones", map[string]any{})
	client.Phones.List(context.Background())
}

func TestPhones_Remove(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/phones/ph_123", map[string]any{
		"success": true,
	})
	_, err := client.Phones.Remove(context.Background(), "ph_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPhones_SetPrimary(t *testing.T) {
	client, _ := resourceServer(t, "PUT", "/api/v1/me/phones/ph_123/primary", map[string]any{
		"id": "ph_123", "is_primary": true,
	})
	_, err := client.Phones.SetPrimary(context.Background(), "ph_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPhones_StartAdd(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/phones/add", map[string]any{
		"session_id": "add_sess_123",
	})
	_, err := client.Phones.StartAdd(context.Background(), map[string]any{"phone": "+1234567890"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPhones_GetAddStatus(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/phones/add/add_sess_123", map[string]any{
		"status": "pending",
	})
	_, err := client.Phones.GetAddStatus(context.Background(), "add_sess_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Emails (7 methods)
// ---------------------------------------------------------------------------

func TestEmails_List(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/emails", map[string]any{})
	client.Emails.List(context.Background())
}

func TestEmails_Remove(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/emails/em_123", map[string]any{
		"success": true,
	})
	_, err := client.Emails.Remove(context.Background(), "em_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmails_SetPrimary(t *testing.T) {
	client, _ := resourceServer(t, "PUT", "/api/v1/me/emails/em_123/primary", map[string]any{
		"id": "em_123", "is_primary": true,
	})
	_, err := client.Emails.SetPrimary(context.Background(), "em_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmails_StartAdd(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/emails/add", map[string]any{
		"session_id": "add_sess_456",
	})
	_, err := client.Emails.StartAdd(context.Background(), map[string]any{"email": "test@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmails_GetAddStatus(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/emails/add/add_sess_456", map[string]any{
		"status": "pending",
	})
	_, err := client.Emails.GetAddStatus(context.Background(), "add_sess_456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmails_VerifyOTP(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/emails/add/add_sess_456/verify", map[string]any{
		"id": "em_123",
	})
	_, err := client.Emails.VerifyOTP(context.Background(), "add_sess_456", map[string]any{"code": "123456"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "code", "123456")
}

func TestEmails_ResendOTP(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/emails/add/add_sess_456/resend", map[string]any{
		"success": true,
	})
	_, err := client.Emails.ResendOTP(context.Background(), "add_sess_456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Assets (3 methods)
// ---------------------------------------------------------------------------

func TestAssets_List(t *testing.T) {
	client, cap := resourceServer(t, "GET", "/api/v1/me/assets", map[string]any{})
	client.Assets.List(context.Background(), map[string]string{"type": "phone"})
	assertQuery(t, cap, "type", "phone")
}

func TestAssets_Get(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/assets/asset_123", map[string]any{
		"id": "asset_123",
	})
	result, err := client.Assets.Get(context.Background(), "asset_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "asset_123" {
		t.Errorf("want ID asset_123, got %s", result.ID)
	}
}

func TestAssets_Revoke(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/assets/asset_123", map[string]any{
		"success": true,
	})
	_, err := client.Assets.Revoke(context.Background(), "asset_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Auth (3 methods)
// ---------------------------------------------------------------------------

func TestAuth_GetMe(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/auth/me", map[string]any{
		"id": "user_123", "email": "test@example.com",
	})
	result, err := client.Auth.GetMe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "user_123" {
		t.Errorf("want ID user_123, got %s", result.ID)
	}
}

func TestAuth_ListSessions(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/auth/sessions", map[string]any{
		"sessions": []any{},
	})
	_, err := client.Auth.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuth_RevokeSession(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/auth/sessions/sess_abc", map[string]any{
		"success": true,
	})
	_, err := client.Auth.RevokeSession(context.Background(), "sess_abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Settings (4 methods)
// ---------------------------------------------------------------------------

func TestSettings_Get(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/settings", map[string]any{
		"branding": map[string]any{"business_name": "Test Corp"},
	})
	result, err := client.Settings.Get(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["branding"] == nil {
		t.Error("want branding in response")
	}
}

func TestSettings_Update(t *testing.T) {
	client, _ := resourceServer(t, "PATCH", "/api/v1/me/settings", map[string]any{
		"success": true,
	})
	_, err := client.Settings.Update(context.Background(), map[string]any{
		"branding": map[string]any{"business_name": "Updated Corp"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSettings_GetUsage(t *testing.T) {
	client, cap := resourceServer(t, "GET", "/api/v1/me/usage", map[string]any{
		"plan": "pro", "current_usage": 42,
	})
	result, err := client.Settings.GetUsage(context.Background(), map[string]string{"period": "2026-02"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertQuery(t, cap, "period", "2026-02")
	if result["plan"] != "pro" {
		t.Errorf("want plan pro, got %v", result["plan"])
	}
}

func TestSettings_Export(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/export", map[string]any{
		"exported_at": "2026-02-27", "account": map[string]any{},
	})
	result, err := client.Settings.Export(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["exported_at"] == nil {
		t.Error("want exported_at in response")
	}
}

// ---------------------------------------------------------------------------
// APIKeys (4 methods)
// ---------------------------------------------------------------------------

func TestAPIKeys_List(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/api-keys", map[string]any{})
	client.APIKeys.List(context.Background())
}

func TestAPIKeys_Create(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/api-keys", map[string]any{
		"id": "key_123", "key": "pk_test_new",
	})
	_, err := client.APIKeys.Create(context.Background(), map[string]any{"name": "Test Key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "name", "Test Key")
}

func TestAPIKeys_Create_NilParams(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/api-keys", map[string]any{
		"id": "key_123",
	})
	_, err := client.APIKeys.Create(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKeys_Revoke(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/api-keys/key_123", map[string]any{
		"success": true,
	})
	_, err := client.APIKeys.Revoke(context.Background(), "key_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKeys_Regenerate(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/api-keys/key_123/regenerate", map[string]any{
		"id": "key_123", "key": "pk_test_regenerated",
	})
	_, err := client.APIKeys.Regenerate(context.Background(), "key_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Account (5 methods)
// ---------------------------------------------------------------------------

func TestAccount_InitiateDeletion(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/account/delete", map[string]any{
		"success": true,
	})
	_, err := client.Account.InitiateDeletion(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAccount_DeletionStatus(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/account/delete/del_sess_123", map[string]any{
		"status": "pending_verification",
	})
	result, err := client.Account.DeletionStatus(context.Background(), "del_sess_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["status"] != "pending_verification" {
		t.Errorf("want status pending_verification, got %v", result["status"])
	}
}

func TestAccount_VerifyDeletion(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/account/delete/del_sess_123/verify", map[string]any{
		"success": true,
	})
	_, err := client.Account.VerifyDeletion(context.Background(), "del_sess_123", map[string]any{"code": "123456"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "code", "123456")
}

func TestAccount_VerifyDeletionMagicLink(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/account/delete/magic/magic_token_abc", map[string]any{
		"success": true,
	})
	_, err := client.Account.VerifyDeletionMagicLink(context.Background(), "magic_token_abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAccount_Delete(t *testing.T) {
	client, cap := resourceServer(t, "DELETE", "/api/v1/me/account", map[string]any{
		"success": true,
	})
	_, err := client.Account.Delete(context.Background(), map[string]any{"session_id": "del_sess_123"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "session_id", "del_sess_123")
}

// ---------------------------------------------------------------------------
// TwoFA (4 methods)
// ---------------------------------------------------------------------------

func TestTwoFA_Start(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/2fa/start", map[string]any{
		"session_id": "2fa_sess_123",
	})
	result, err := client.TwoFA.Start(context.Background(), map[string]any{
		"action_type": "login", "channel": "email",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "action_type", "login")
	if result["session_id"] != "2fa_sess_123" {
		t.Errorf("want session_id 2fa_sess_123, got %v", result["session_id"])
	}
}

func TestTwoFA_GetStatus(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/2fa/2fa_sess_123", map[string]any{
		"status": "pending",
	})
	_, err := client.TwoFA.GetStatus(context.Background(), "2fa_sess_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTwoFA_Verify(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/2fa/2fa_sess_123/verify", map[string]any{
		"success": true,
	})
	_, err := client.TwoFA.Verify(context.Background(), "2fa_sess_123", map[string]any{"code": "654321"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "code", "654321")
}

func TestTwoFA_VerifyMagicLink(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/2fa/magic/magic_2fa_token", map[string]any{
		"success": true,
	})
	_, err := client.TwoFA.VerifyMagicLink(context.Background(), "magic_2fa_token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DNSCredentials (3 methods)
// ---------------------------------------------------------------------------

func TestDNSCredentials_List(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/dns-credentials", map[string]any{
		"credentials": []any{},
	})
	result, err := client.DNSCredentials.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["credentials"] == nil {
		t.Error("want credentials in response")
	}
}

func TestDNSCredentials_Create(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/dns-credentials", map[string]any{
		"id": "cred_123",
	})
	result, err := client.DNSCredentials.Create(context.Background(), map[string]any{
		"provider": "cloudflare", "api_token": "cf_token_abc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "provider", "cloudflare")
	if result["id"] != "cred_123" {
		t.Errorf("want id cred_123, got %v", result["id"])
	}
}

func TestDNSCredentials_Delete(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/dns-credentials/cred_123", map[string]any{
		"success": true,
	})
	_, err := client.DNSCredentials.Delete(context.Background(), "cred_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Domains (18 methods)
// ---------------------------------------------------------------------------

func TestDomains_List(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/domains", map[string]any{})
	client.Domains.List(context.Background())
}

func TestDomains_Add(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/domains", map[string]any{
		"id": "dom_123", "domain": "example.com",
	})
	_, err := client.Domains.Add(context.Background(), map[string]any{"domain": "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "domain", "example.com")
}

func TestDomains_Get(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/domains/dom_123", map[string]any{
		"id": "dom_123",
	})
	_, err := client.Domains.Get(context.Background(), "dom_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_Delete(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/domains/dom_123", map[string]any{
		"success": true,
	})
	_, err := client.Domains.Delete(context.Background(), "dom_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_OAuthURL(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/oauth-url", map[string]any{
		"url": "https://oauth.provider.com/authorize",
	})
	result, err := client.Domains.OAuthURL(context.Background(), "dom_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["url"] == nil {
		t.Error("want url in response")
	}
}

func TestDomains_Verify(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/verify", map[string]any{
		"verified": true,
	})
	_, err := client.Domains.Verify(context.Background(), "dom_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_ConnectCloudflare(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/connect/cloudflare", map[string]any{
		"success": true,
	})
	_, err := client.Domains.ConnectCloudflare(context.Background(), "dom_123", map[string]any{"api_token": "cf_tok"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_ConnectGoDaddy(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/connect/godaddy", map[string]any{
		"success": true,
	})
	_, err := client.Domains.ConnectGoDaddy(context.Background(), "dom_123", map[string]any{"api_key": "gd_key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_ConnectProvider(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/connect/namecheap", map[string]any{
		"success": true,
	})
	_, err := client.Domains.ConnectProvider(context.Background(), "dom_123", "namecheap", map[string]any{"api_key": "nc_key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_AddProvider(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/add-provider/route53", map[string]any{
		"success": true,
	})
	_, err := client.Domains.AddProvider(context.Background(), "dom_123", "route53", map[string]any{"access_key": "ak"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_GetProviders(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/dns-providers", map[string]any{
		"providers": []any{},
	})
	_, err := client.Domains.GetProviders(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_VerifyWithCredentials(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/verify-with-credentials", map[string]any{
		"verified": true,
	})
	_, err := client.Domains.VerifyWithCredentials(context.Background(), "dom_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_CheckCredentials(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/domains/dom_123/check-credentials", map[string]any{
		"has_access": true,
	})
	_, err := client.Domains.CheckCredentials(context.Background(), "dom_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_StartEmailVerification(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/verify-email", map[string]any{
		"success": true,
	})
	_, err := client.Domains.StartEmailVerification(context.Background(), "dom_123", map[string]any{
		"email": "admin@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_ConfirmEmailCode(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/verify-email/confirm", map[string]any{
		"verified": true,
	})
	_, err := client.Domains.ConfirmEmailCode(context.Background(), "dom_123", map[string]any{"code": "123456"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_ResendEmail(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/verify-email/resend", map[string]any{
		"success": true,
	})
	_, err := client.Domains.ResendEmail(context.Background(), "dom_123", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_EmailSetup(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/domains/dom_123/email-setup", map[string]any{
		"success": true,
	})
	_, err := client.Domains.EmailSetup(context.Background(), "dom_123", map[string]any{"from_name": "Test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDomains_EmailStatus(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/domains/dom_123/email-status", map[string]any{
		"status": "active",
	})
	result, err := client.Domains.EmailStatus(context.Background(), "dom_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["status"] != "active" {
		t.Errorf("want status active, got %v", result["status"])
	}
}

// ---------------------------------------------------------------------------
// UserRequests (7 methods)
// ---------------------------------------------------------------------------

func TestUserRequests_List(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/verification-requests", map[string]any{
		"data": []any{}, "pagination": map[string]any{},
	})
	_, err := client.UserRequests.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUserRequests_ListIncoming(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/verification-requests/incoming", map[string]any{
		"data": []any{}, "pagination": map[string]any{},
	})
	_, err := client.UserRequests.ListIncoming(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUserRequests_Create(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/verification-requests", map[string]any{
		"id": "vr_user_123",
	})
	_, err := client.UserRequests.Create(context.Background(), map[string]any{
		"assets": []any{map[string]any{"type": "phone", "required": true}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUserRequests_Claim(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/verification-requests/vr_123/claim", map[string]any{
		"success": true,
	})
	_, err := client.UserRequests.Claim(context.Background(), "vr_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUserRequests_Cancel(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/me/verification-requests/vr_123", map[string]any{
		"status": "cancelled",
	})
	_, err := client.UserRequests.Cancel(context.Background(), "vr_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUserRequests_Extend(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/verification-requests/vr_123/extend", map[string]any{
		"id": "vr_123",
	})
	_, err := client.UserRequests.Extend(context.Background(), "vr_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUserRequests_ShareEmail(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/verification-requests/vr_123/share-email", map[string]any{
		"success": true,
	})
	_, err := client.UserRequests.ShareEmail(context.Background(), "vr_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UserDomainVerify (3 methods)
// ---------------------------------------------------------------------------

func TestUserDomainVerify_Start(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/me/verify/domain", map[string]any{
		"session_id": "dv_sess_123",
	})
	_, err := client.UserDomainVerify.Start(context.Background(), map[string]any{
		"domain": "example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "domain", "example.com")
}

func TestUserDomainVerify_Status(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/me/verify/domain/dv_sess_123", map[string]any{
		"verified": false,
	})
	_, err := client.UserDomainVerify.Status(context.Background(), "dv_sess_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUserDomainVerify_Check(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/me/verify/domain/dv_sess_123/check", map[string]any{
		"verified": true,
	})
	_, err := client.UserDomainVerify.Check(context.Background(), "dv_sess_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// PublicProfiles (16 methods)
// ---------------------------------------------------------------------------

func TestPublicProfiles_GetByID(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/profiles/p/prof_pub_123", map[string]any{
		"id": "prof_pub_123",
	})
	_, err := client.PublicProfiles.GetByID(context.Background(), "prof_pub_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_GetAvatar(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/profiles/p/prof_pub_123/avatar", map[string]any{
		"url": "https://cdn.example.com/avatar.jpg",
	})
	_, err := client.PublicProfiles.GetAvatar(context.Background(), "prof_pub_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_GetByUsername(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/profiles/u/johndoe", map[string]any{
		"username": "johndoe",
	})
	_, err := client.PublicProfiles.GetByUsername(context.Background(), "johndoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_CheckUsername(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/profiles/check-username/johndoe", map[string]any{
		"available": true,
	})
	result, err := client.PublicProfiles.CheckUsername(context.Background(), "johndoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["available"] != true {
		t.Error("want available=true")
	}
}

func TestPublicProfiles_ListProfiles(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/profiles/profiles", map[string]any{})
	client.PublicProfiles.ListProfiles(context.Background())
}

func TestPublicProfiles_CreateProfile(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/profiles/profiles", map[string]any{
		"id": "prof_new",
	})
	_, err := client.PublicProfiles.CreateProfile(context.Background(), map[string]any{"display_name": "New Profile"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_GetProfile(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/profiles/profiles/prof_123", map[string]any{
		"id": "prof_123",
	})
	_, err := client.PublicProfiles.GetProfile(context.Background(), "prof_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_UpdateProfile(t *testing.T) {
	client, cap := resourceServer(t, "PATCH", "/api/v1/profiles/profiles/prof_123", map[string]any{
		"id": "prof_123",
	})
	_, err := client.PublicProfiles.UpdateProfile(context.Background(), "prof_123", map[string]any{"bio": "Updated bio"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "bio", "Updated bio")
}

func TestPublicProfiles_DeleteProfile(t *testing.T) {
	client, _ := resourceServer(t, "DELETE", "/api/v1/profiles/profiles/prof_123", map[string]any{
		"success": true,
	})
	_, err := client.PublicProfiles.DeleteProfile(context.Background(), "prof_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_SetPrimary(t *testing.T) {
	client, _ := resourceServer(t, "POST", "/api/v1/profiles/profiles/prof_123/primary", map[string]any{
		"id": "prof_123",
	})
	_, err := client.PublicProfiles.SetPrimary(context.Background(), "prof_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_UpdateProfileProofs(t *testing.T) {
	client, _ := resourceServer(t, "PUT", "/api/v1/profiles/profiles/prof_123/proofs", map[string]any{
		"id": "prof_123",
	})
	_, err := client.PublicProfiles.UpdateProfileProofs(context.Background(), "prof_123", map[string]any{
		"proofs": []any{"proof_1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_GetMyProfile(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/profiles/me", map[string]any{
		"id": "prof_me",
	})
	_, err := client.PublicProfiles.GetMyProfile(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_UpdateMyProfile(t *testing.T) {
	client, _ := resourceServer(t, "PUT", "/api/v1/profiles/me", map[string]any{
		"id": "prof_me",
	})
	_, err := client.PublicProfiles.UpdateMyProfile(context.Background(), map[string]any{"bio": "My bio"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_ClaimUsername(t *testing.T) {
	client, cap := resourceServer(t, "POST", "/api/v1/profiles/me/username", map[string]any{
		"username": "johndoe",
	})
	_, err := client.PublicProfiles.ClaimUsername(context.Background(), map[string]any{"username": "johndoe"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyField(t, cap, "username", "johndoe")
}

func TestPublicProfiles_GetAvailableAssets(t *testing.T) {
	client, _ := resourceServer(t, "GET", "/api/v1/profiles/me/assets", map[string]any{
		"assets": []any{},
	})
	_, err := client.PublicProfiles.GetAvailableAssets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublicProfiles_UpdatePublicProofs(t *testing.T) {
	client, _ := resourceServer(t, "PUT", "/api/v1/profiles/me/proofs", map[string]any{
		"id": "prof_me",
	})
	_, err := client.PublicProfiles.UpdatePublicProofs(context.Background(), map[string]any{
		"proofs": []any{"proof_1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
