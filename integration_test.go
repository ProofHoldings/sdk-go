//go:build integration
// +build integration

// Integration suite: runs when the `integration` build tag is passed to
// `go test`. Mirrors the scope of the JS/Python/PHP integration suites and
// is the Go SDK's only mechanism for verifying live-mode behavior against
// staging and production. Default (unit) runs never see these tests.
//
// Live mode:  PROOF_BASE_URL + PROOF_API_KEY_TEST set → hit a real origin.
// Mock mode:  otherwise → drive the SDK against an httptest.Server so the
//             wire contract is still exercised.
//
// When staging is fronted by Cloudflare Access, CF_ACCESS_CLIENT_ID and
// CF_ACCESS_CLIENT_SECRET must also be set so the test harness can traverse
// the Access perimeter. The SDK production client stays unaware of CF
// Access — header injection happens in a test-only http.RoundTripper.

package proof

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func isLiveMode() bool {
	return os.Getenv("PROOF_BASE_URL") != "" && os.Getenv("PROOF_API_KEY_TEST") != ""
}

func cfAccessHeaders() map[string]string {
	headers := map[string]string{}
	id := os.Getenv("CF_ACCESS_CLIENT_ID")
	secret := os.Getenv("CF_ACCESS_CLIENT_SECRET")
	if id != "" && secret != "" {
		headers["CF-Access-Client-Id"] = id
		headers["CF-Access-Client-Secret"] = secret
	}
	if vs := os.Getenv("VISUAL_TEST_SECRET"); vs != "" {
		headers["X-Visual-Test-Secret"] = vs
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// cfAccessTransport wraps a base http.RoundTripper and adds CF Access
// service-token headers to every outbound request. No-op when the env vars
// aren't set.
type cfAccessTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *cfAccessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(t.headers) > 0 {
		req = req.Clone(req.Context())
		for k, v := range t.headers {
			req.Header.Set(k, v)
		}
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// newLiveClient builds a *Client against the live origin with CF Access
// headers applied via a custom RoundTripper. Only usable in live mode —
// mock-mode tests construct their own httptest.Server.
func newLiveClient(t *testing.T, opts ...ClientOption) *Client {
	t.Helper()
	if !isLiveMode() {
		t.Skip("live mode not configured (PROOF_BASE_URL/PROOF_API_KEY_TEST unset)")
	}
	apiKey := os.Getenv("PROOF_API_KEY_TEST")
	baseURL := os.Getenv("PROOF_BASE_URL")

	opts = append([]ClientOption{WithBaseURL(baseURL), WithTimeout(15 * time.Second), WithMaxRetries(0)}, opts...)
	client, err := NewClient(apiKey, opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Swap the internal http.Client's transport for one that adds CF Access
	// headers. Reach through any resource's private http field — they all
	// share the same httpClient instance. Verify that assumption: a future
	// SDK refactor fragmenting httpClient per resource would silently make
	// WebhookDeliveries / Proofs live tests bypass the Access perimeter
	// and produce opaque 403s instead of a clear failure here.
	if client.Verifications.http != client.WebhookDeliveries.http {
		t.Fatal("shared httpClient assumption broken — update installCFAccess to patch every resource")
	}
	installCFAccess(client.Verifications.http)
	return client
}

func installCFAccess(h *httpClient) {
	headers := cfAccessHeaders()
	if len(headers) == 0 {
		return
	}
	base := h.client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	h.client.Transport = &cfAccessTransport{base: base, headers: headers}
}

// TestLiveHealthReachable proves the harness can actually traverse Cloudflare
// Access and reach the API origin. If this fails, every other live-mode
// assertion below is suspect.
func TestLiveHealthReachable(t *testing.T) {
	if !isLiveMode() {
		t.Skip("live mode not configured")
	}

	base := strings.TrimRight(os.Getenv("PROOF_BASE_URL"), "/")

	transport := &cfAccessTransport{headers: cfAccessHeaders()}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/health", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Mirror the SDK's production UA. The staging origin's marketing nginx
	// (frontend.conf) drops `Go-http-client/*` with `return 444`, surfacing as
	// CF 520. Every raw http.Client in this suite must carry the branded UA.
	req.Header.Set("User-Agent", "proof-sdk-go/"+Version)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /health, got %d", resp.StatusCode)
	}
}

// TestLiveBadAPIKeyIsRejected asserts that a syntactically-valid-but-unknown
// API key produces an authentication error from the real API. Without the
// CF Access headers installed by newLiveClient, this test would pass on a
// false positive — CF would return 403 and the assertion on a generic
// ProofError would succeed without the request ever reaching the backend.
// We therefore assert the specific AuthenticationError type.
func TestLiveBadAPIKeyIsRejected(t *testing.T) {
	if !isLiveMode() {
		t.Skip("live mode only")
	}
	baseURL := os.Getenv("PROOF_BASE_URL")
	client, err := NewClient("pk_test_this_key_does_not_exist",
		WithBaseURL(baseURL),
		WithTimeout(15*time.Second),
		WithMaxRetries(0),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	installCFAccess(client.Verifications.http)

	_, err = client.Verifications.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected an error from bogus API key, got nil")
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthenticationError, got %T: %v", err, err)
	}
}

// --- Deep live-mode lifecycle coverage ---
//
// Every test below skips outside live mode. In live mode they exercise the
// real verification lifecycle against staging (or production on the
// production-branch pipeline) using a test-mode API key so /test-verify can
// auto-complete without triggering real channel traffic. Created resources
// are tagged via client_metadata so the staging-data pruner can reclaim
// them later.

func testRunID() string {
	if v := os.Getenv("CI_PIPELINE_ID"); v != "" {
		return v
	}
	if v := os.Getenv("PROOF_TEST_RUN_ID"); v != "" {
		return v
	}
	user := os.Getenv("USER")
	if user == "" {
		user = "unknown"
	}
	return "local-" + user + "-" + time.Now().Format("20060102150405")
}

func tagMetadata(extra map[string]any) map[string]any {
	meta := map[string]any{
		"test_harness": "sdk-integration",
		"test_run_id":  testRunID(),
		"sdk":          "go",
	}
	for k, v := range extra {
		meta[k] = v
	}
	return meta
}

// testPhoneIdentifier returns the real Proof-controlled phone number used
// by the live-mode suite. Defaults to the staging SMS DID; override via
// TEST_PHONE_IDENTIFIER for other environments. The backend's phone
// validator rejects reserved/fictional ranges, so fixtures must use real
// numbers we control. Reusing one number across concurrent tests is safe
// because the pk_test_* key path routes through /test-verify and never
// triggers real SMS dispatch — the number is effectively an opaque label,
// not a delivery target. Each Verifications.Create writes a fresh
// document, and tests key their state off the returned id, not off the
// phone.
func testPhoneIdentifier() string {
	if v := os.Getenv("TEST_PHONE_IDENTIFIER"); v != "" {
		return v
	}
	return "+19295909022"
}

func externalUserID() string {
	return "sdk_go_" + testRunID()
}

func TestLiveVerificationLifecycle(t *testing.T) {
	client := newLiveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	created, err := client.Verifications.Create(ctx, map[string]any{
		"type":             "phone",
		"channel":          "sms",
		"identifier":       testPhoneIdentifier(),
		"external_user_id": externalUserID(),
		"client_metadata":  tagMetadata(map[string]any{"stage": "lifecycle"}),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	vid, _ := created["id"].(string)
	if vid == "" {
		t.Fatalf("create returned no id: %v", created)
	}
	if got, _ := created["status"].(string); got != "pending" {
		t.Errorf("expected status=pending, got %q", got)
	}

	fetched, err := client.Verifications.Retrieve(ctx, vid)
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if fetched["id"] != vid {
		t.Errorf("retrieve returned id %v, want %s", fetched["id"], vid)
	}

	listed, err := client.Verifications.List(ctx, map[string]string{"limit": "5"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, ok := listed["data"].([]any); !ok {
		t.Errorf("list returned no data array: %v", listed)
	}
	if _, ok := listed["pagination"].(map[string]any); !ok {
		t.Errorf("list returned no pagination envelope: %v", listed)
	}

	verified, err := client.Verifications.TestVerify(ctx, vid)
	if err != nil {
		t.Fatalf("testVerify: %v", err)
	}
	if got, _ := verified["status"].(string); got != "verified" {
		t.Errorf("expected status=verified, got %q", got)
	}
	if tok, _ := verified["proof_token"].(string); tok == "" {
		t.Errorf("testVerify returned empty proof_token")
	}
}

func TestLiveRetrieveUnknownIDNotFound(t *testing.T) {
	client := newLiveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := client.Verifications.Retrieve(ctx, "000000000000000000000000")
	if err == nil {
		t.Fatal("expected NotFoundError, got nil")
	}
	var nfe *NotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected *NotFoundError, got %T: %v", err, err)
	}
}

func TestLiveCreateRejectsInvalidPayload(t *testing.T) {
	client := newLiveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := client.Verifications.Create(ctx, map[string]any{
		"type":       "phone",
		"channel":    "not_a_real_channel",
		"identifier": "not-a-phone",
	})
	if err == nil {
		t.Fatal("expected ValidationError, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
}

func TestLiveVerifiedUsersReadOnly(t *testing.T) {
	client := newLiveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	page, err := client.Verifications.ListVerifiedUsers(ctx, map[string]string{"limit": "3"})
	if err != nil {
		t.Fatalf("listVerifiedUsers: %v", err)
	}
	if _, ok := page["data"].([]any); !ok {
		t.Errorf("expected data[] in response, got %v", page)
	}
}

func TestLiveWebhookDeliveriesReadOnly(t *testing.T) {
	client := newLiveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	page, err := client.WebhookDeliveries.List(ctx, map[string]string{"limit": "3"})
	if err != nil {
		t.Fatalf("webhookDeliveries.list: %v", err)
	}
	// NOTE: this endpoint is the one outlier in the API surface — backend
	// returns {deliveries: [...], pagination: {...}} instead of the standard
	// {data: [...], pagination: {...}}. See src/controllers/webhookDeliveries.ts.
	if _, ok := page["deliveries"].([]any); !ok {
		t.Errorf("expected deliveries[] in response, got %v", page)
	}
}

// TestClientExposesEveryResource mirrors the JS/Python/PHP surface check, but
// runs in integration mode too so the same assertion serves as a smoke test
// on pipelines. Works in live OR mock mode.
func TestClientExposesEveryResource(t *testing.T) {
	var client *Client
	if isLiveMode() {
		client = newLiveClient(t)
	} else {
		// Mock mode — httptest server, no real network.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}))
		t.Cleanup(srv.Close)
		c, err := NewClient("pk_test_integration", WithBaseURL(srv.URL), WithMaxRetries(0))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		client = c
	}

	cases := []struct {
		name string
		got  any
	}{
		{"Verifications", client.Verifications},
		{"VerificationRequests", client.VerificationRequests},
		{"Proofs", client.Proofs},
		{"Sessions", client.Sessions},
		{"WebhookDeliveries", client.WebhookDeliveries},
		{"Authorizations", client.Authorizations},
		{"Confirmations", client.Confirmations},
		{"HitlKeys", client.HitlKeys},
		{"HITL", client.HITL},
		{"Auth", client.Auth},
		{"Me", client.Me},
	}
	for _, c := range cases {
		if c.got == nil {
			t.Errorf("client.%s is nil", c.name)
		}
	}
}
