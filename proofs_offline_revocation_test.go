package proof

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Offline verification reads the token's status list (h-sdk-offline-revocation).
//
// Before this task VerifyOffline checked the signature, `iss` and `exp` and stopped, so a REVOKED
// proof verified as valid — measured against production on 2026-09-20. Go's doc comment was the
// only one of the four SDKs that admitted the gap; these cases close it.
//
// The packed list comes from sdks/shared/fixtures/status_list_slots.json, the same fixture the
// issuer's drift suite and the other three SDKs read, so a disagreement about the byte order
// fails here rather than in production.

type statusListOverrides struct {
	typ       string
	sub       string
	expiresIn time.Duration
	omitExp   bool
	key       *ecdsa.PrivateKey
}

type revocationFixture struct {
	key      *ecdsa.PrivateKey
	otherKey *ecdsa.PrivateKey
	kid      string
	server   *httptest.Server

	mu        sync.Mutex
	reply     string // "token" | "error" | "oversized" | "hangup"
	overrides statusListOverrides
	requests  []string
}

func newRevocationFixture(t *testing.T) *revocationFixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other ec key: %v", err)
	}

	f := &revocationFixture{key: key, otherKey: other, kid: "es256-kid-1", reply: "token"}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.URL.Path)
		reply, overrides := f.reply, f.overrides
		f.mu.Unlock()

		switch r.URL.Path {
		case "/.well-known/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.jwks())
		case "/api/v1/proofs/status-list":
			switch reply {
			case "hangup":
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.(*net.TCPConn).Close()
				}
			case "error":
				w.WriteHeader(http.StatusServiceUnavailable)
			case "oversized":
				// No Content-Length: net/http chunks a body this size, so the read ceiling is
				// what has to catch it.
				w.Header().Set("Content-Type", "application/statuslist+jwt")
				_, _ = w.Write([]byte(strings.Repeat("x", 600*1024)))
			case "oversized_declared":
				// The same body with its length declared, so the refusal can happen before the
				// body is read at all. Both spellings must be refused; declaring the length is a
				// shortcut, not a second guarantee.
				body := strings.Repeat("x", 600*1024)
				w.Header().Set("Content-Type", "application/statuslist+jwt")
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				_, _ = w.Write([]byte(body))
			default:
				w.Header().Set("Content-Type", "application/statuslist+jwt")
				_, _ = w.Write([]byte(f.mintStatusList(t, overrides)))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.server.Close)

	return f
}

// jwks is the key set the issuer publishes for f.key.
func (f *revocationFixture) jwks() JWKS {
	crv := "P-256"
	// Left-padded to the full 32 octets RFC 7518 §6.2.1.2 requires. Go's own reader rebuilds
	// through big.Int and would accept a short coordinate, but publishing one is off-spec — and
	// an unpadded fixture is exactly what made the PHP suite flake.
	x := base64.RawURLEncoding.EncodeToString(padCoordinate(f.key.PublicKey.X.Bytes()))
	y := base64.RawURLEncoding.EncodeToString(padCoordinate(f.key.PublicKey.Y.Bytes()))
	return JWKS{Keys: []JWK{{Kty: "EC", Crv: &crv, X: &x, Y: &y, Use: "sig", Alg: "ES256", Kid: f.kid}}}
}

// padCoordinate left-pads a P-256 coordinate to the 32 octets the JWK spec requires.
func padCoordinate(raw []byte) []byte {
	if len(raw) >= 32 {
		return raw
	}
	padded := make([]byte, 32)
	copy(padded[32-len(raw):], raw)
	return padded
}

func (f *revocationFixture) statusListURL() string {
	return f.server.URL + "/api/v1/proofs/status-list"
}

func (f *revocationFixture) proofsFor() *Proofs {
	h := newHTTPClient("pk_test_x", f.server.URL, 5*time.Second, 0)
	return &Proofs{http: h, jwksURL: f.server.URL + "/.well-known/jwks.json"}
}

// countingTransport records every request that actually leaves the process, so a case can assert
// that one was never issued — an assertion on the error text alone would survive the origin guard
// being moved AFTER the fetch.
type countingTransport struct {
	mu    sync.Mutex
	hosts []string
	inner http.RoundTripper
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.hosts = append(t.hosts, req.URL.Host)
	t.mu.Unlock()
	return t.inner.RoundTrip(req)
}

func (t *countingTransport) requestedHosts() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.hosts...)
}

// proofsWithCountingTransport is proofsFor plus a transport spy on the SDK's own http client.
func (f *revocationFixture) proofsWithCountingTransport() (*Proofs, *countingTransport) {
	proofs := f.proofsFor()
	spy := &countingTransport{inner: http.DefaultTransport}
	proofs.http.client.Transport = spy
	return proofs, spy
}

func (f *revocationFixture) setReply(reply string, overrides statusListOverrides) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reply, f.overrides = reply, overrides
}

func (f *revocationFixture) jwksRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, path := range f.requests {
		if path == "/.well-known/jwks.json" {
			count++
		}
	}
	return count
}

func (f *revocationFixture) statusListRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, path := range f.requests {
		if path == "/api/v1/proofs/status-list" {
			count++
		}
	}
	return count
}

// mintProof mints a proof token; slot nil means the token carries no status-list claim.
func (f *revocationFixture) mintProof(t *testing.T, slot map[string]any, key *ecdsa.PrivateKey, issuer string) string {
	t.Helper()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":             issuer,
		"sub":             "ph_ctl_0123456789abcdef0123456789abcdef",
		"iat":             now - 60,
		"exp":             now + 3600,
		"user_id":         "507f1f77bcf86cd799439012",
		"type":            "domain",
		"channel":         "dns",
		"identifier_hash": "abc123",
		"verified_at":     "2026-09-21T10:00:00.000Z",
	}
	if slot != nil {
		claims["status"] = map[string]any{"status_list": slot}
	}

	signing := key
	if signing == nil {
		signing = f.key
	}
	return signEcToken(t, signing, map[string]any{"alg": "ES256", "typ": "JWT", "kid": f.kid}, claims)
}

func (f *revocationFixture) slot(idx int) map[string]any {
	return map[string]any{"idx": idx, "uri": f.statusListURL()}
}

func (f *revocationFixture) mintStatusList(t *testing.T, o statusListOverrides) string {
	t.Helper()

	fixture := loadSharedFixture(t, "status_list_slots.json")
	now := time.Now().Unix()

	claims := map[string]any{
		"sub": f.statusListURL(),
		"iat": now,
		"ttl": 55,
		"status_list": map[string]any{
			"bits": fixture["bits"],
			"lst":  fixture["lst"],
		},
	}
	if o.sub != "" {
		claims["sub"] = o.sub
	}
	if !o.omitExp {
		lifetime := o.expiresIn
		if lifetime == 0 {
			lifetime = 5 * time.Minute
		}
		claims["exp"] = time.Now().Add(lifetime).Unix()
	}

	typ := o.typ
	if typ == "" {
		typ = "statuslist+jwt"
	}
	key := o.key
	if key == nil {
		key = f.key
	}

	return signEcToken(t, key, map[string]any{"alg": "ES256", "typ": typ, "kid": f.kid}, claims)
}

// namedSlot resolves an index in the shared fixture to the status it is packed with.
func namedSlots(t *testing.T) map[string]string {
	t.Helper()
	fixture := loadSharedFixture(t, "status_list_slots.json")
	raw, ok := fixture["slots"].(map[string]any)
	if !ok {
		t.Fatal("fixture has no slots map")
	}
	slots := make(map[string]string, len(raw))
	for index, name := range raw {
		slots[index] = name.(string)
	}
	return slots
}

func TestVerifyOffline_RefusesRevokedSlot(t *testing.T) {
	f := newRevocationFixture(t)

	res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(1), nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid || res.Reason != "revoked" || !res.RevocationChecked {
		t.Errorf("want revoked and checked, got %+v", res)
	}
}

func TestVerifyOffline_RefusesSuspendedSlot(t *testing.T) {
	f := newRevocationFixture(t)

	res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(2), nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid || res.Reason != "suspended" || !res.RevocationChecked {
		t.Errorf("want suspended and checked, got %+v", res)
	}
}

func TestVerifyOffline_AcceptsClearSlot(t *testing.T) {
	f := newRevocationFixture(t)

	res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if !res.Valid || !res.RevocationChecked || res.Payload == nil {
		t.Errorf("want valid and checked, got %+v (%s)", res, res.Error)
	}
}

func TestVerifyOffline_RefusesApplicationReservedSlot(t *testing.T) {
	f := newRevocationFixture(t)

	res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(3), nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid || res.Reason != "status_unavailable" || res.RevocationChecked {
		t.Errorf("want status_unavailable and unchecked, got %+v", res)
	}
}

func TestVerifyOffline_RefusesSlotBeyondList(t *testing.T) {
	f := newRevocationFixture(t)
	fixture := loadSharedFixture(t, "status_list_slots.json")
	beyond := int(fixture["beyond_end_index"].(float64))

	res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(beyond), nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid || res.Reason != "status_unavailable" {
		t.Errorf("want status_unavailable, got %+v", res)
	}
}

func TestVerifyOffline_TokenWithoutSlotStaysValid(t *testing.T) {
	f := newRevocationFixture(t)

	res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, nil, nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	// The issuer answers valid:true for a token it cannot resolve in the registry
	// (src/controllers/proofs.ts) — a client refusing it would be stricter than the server.
	if !res.Valid || res.RevocationChecked || res.Reason != "" {
		t.Errorf("want valid and unchecked, got %+v", res)
	}
	if f.statusListRequests() != 0 {
		t.Errorf("want no status-list request, got %d", f.statusListRequests())
	}
}

func TestVerifyOffline_UnreachableListFailsClosed(t *testing.T) {
	cases := []struct{ name, reply, wantMessage string }{
		{"connection dropped", "hangup", ""},
		{"http error", "error", ""},
		// The size cases assert the MESSAGE too: a 600 KiB run of "x" also fails to parse as a
		// JWT, so `status_unavailable` alone stays green with the ceiling deleted.
		{"oversized body", "oversized", "too large"},
		{"oversized body declaring its length", "oversized_declared", "too large"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRevocationFixture(t)
			f.setReply(tc.reply, statusListOverrides{})

			res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(1), nil, "proof.holdings"))
			if err != nil {
				t.Fatalf("VerifyOffline: %v", err)
			}
			if res.Valid || res.Reason != "status_unavailable" || res.RevocationChecked {
				t.Errorf("want status_unavailable and unchecked, got %+v", res)
			}
			if tc.wantMessage != "" && !strings.Contains(res.Error, tc.wantMessage) {
				t.Errorf("want the error to name %q, got %q", tc.wantMessage, res.Error)
			}
		})
	}
}

func TestVerifyOffline_ForeignStatusListOriginIsNeverContacted(t *testing.T) {
	f := newRevocationFixture(t)
	slot := map[string]any{"idx": 1, "uri": "https://evil.example.net/api/v1/proofs/status-list"}

	proofs, spy := f.proofsWithCountingTransport()
	res, err := proofs.VerifyOffline(context.Background(), f.mintProof(t, slot, nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid || res.Reason != "status_unavailable" {
		t.Errorf("want status_unavailable, got %+v", res)
	}
	// An unreachable host would answer status_unavailable too, so the claim under test is that
	// nothing was contacted — asserted on what actually left the process, not on the message.
	for _, host := range spy.requestedHosts() {
		if strings.Contains(host, "evil.example.net") {
			t.Fatalf("a request went to the foreign origin: %v", spy.requestedHosts())
		}
	}
	if !strings.Contains(res.Error, "origin") {
		t.Errorf("want the origin rule named in the error, got %q", res.Error)
	}
}

func TestVerifyOffline_StatusListIsReadOnceAcrossTwoVerifications(t *testing.T) {
	f := newRevocationFixture(t)
	proofs := f.proofsFor()

	if _, err := proofs.VerifyOffline(context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings")); err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if _, err := proofs.VerifyOffline(context.Background(), f.mintProof(t, f.slot(1), nil, "proof.holdings")); err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}

	if got := f.statusListRequests(); got != 1 {
		t.Errorf("want the list read once and reused, got %d reads", got)
	}
}

func TestVerifyOffline_StatusListIsRereadOnceItsWindowPasses(t *testing.T) {
	// That window is what keeps the product's 60-second revocation-visibility promise on the
	// client side: past it the list must be re-read, or a revocation stays invisible for as long
	// as the proof itself lives.
	f := newRevocationFixture(t)
	proofs := f.proofsFor()
	if _, err := proofs.VerifyOffline(context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings")); err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}

	proofs.statusListMu.Lock()
	if !proofs.statusListCache.expiresAt.After(time.Now()) {
		t.Fatal("the cached list was already stale before the case expired it")
	}
	proofs.statusListCache.expiresAt = time.Now().Add(-time.Second)
	proofs.statusListMu.Unlock()

	if _, err := proofs.VerifyOffline(context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings")); err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}

	if got := f.statusListRequests(); got != 2 {
		t.Errorf("want the list re-read after its window, got %d reads", got)
	}
}

func TestVerifyOffline_RefreshJWKSDropsTheStatusListToo(t *testing.T) {
	f := newRevocationFixture(t)
	proofs := f.proofsFor()
	if _, err := proofs.VerifyOffline(context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings")); err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}

	proofs.RefreshJWKS()
	if _, err := proofs.VerifyOffline(context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings")); err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}

	if got := f.statusListRequests(); got != 2 {
		t.Errorf("want the list re-read after RefreshJWKS, got %d reads", got)
	}
}

func TestVerifyOffline_MalformedStatusClaimReadsAsNoSlot(t *testing.T) {
	// The other three SDKs ignore a `status` claim that is not an object and leave the token
	// valid; a typed field here used to fail the whole payload decode instead, turning "carries
	// no readable slot" into "bad token".
	f := newRevocationFixture(t)
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "proof.holdings", "sub": "ph_ctl_x", "iat": now - 60, "exp": now + 3600,
		"user_id": "u", "type": "domain", "channel": "dns", "identifier_hash": "h",
		"verified_at": "2026-09-21T10:00:00.000Z",
		"status":      "not-an-object",
	}
	token := signEcToken(t, f.key, map[string]any{"alg": "ES256", "typ": "JWT", "kid": f.kid}, claims)

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if !res.Valid || res.RevocationChecked {
		t.Errorf("want valid and unchecked, got %+v (%s)", res, res.Error)
	}
}

func TestVerifyOffline_NegativeSlotIndexReadsAsNoSlot(t *testing.T) {
	f := newRevocationFixture(t)

	res, err := f.proofsFor().VerifyOffline(
		context.Background(), f.mintProof(t, map[string]any{"idx": -1, "uri": f.statusListURL()}, nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if !res.Valid || res.RevocationChecked {
		t.Errorf("want valid and unchecked, got %+v (%s)", res, res.Error)
	}
}

func TestOriginOf_NormalizesHostCaseAndDefaultPorts(t *testing.T) {
	// One rule across the four SDKs. Asserted directly because this suite's server runs on a
	// loopback address and a non-default port, which can express neither spelling.
	cases := []struct {
		a, b string
		same bool
	}{
		{"https://API.Proof.Holdings/x", "https://api.proof.holdings/y", true},
		{"https://api.proof.holdings:443/x", "https://api.proof.holdings/y", true},
		{"http://api.proof.holdings:80/x", "http://api.proof.holdings/y", true},
		{"https://api.proof.holdings:8443/x", "https://api.proof.holdings/y", false},
		// `:0443` is the same port as `:443` per RFC 3986; a string compare here made Go refuse
		// a uri the other three accept.
		{"https://api.proof.holdings:0443/x", "https://api.proof.holdings/y", true},
		// A port no parser can read must NOT collapse to "no port": dropping it made this uri
		// read as the issuer's own origin, wider than the other three, which refuse it outright.
		{"https://api.proof.holdings:99999999999999999999/x", "https://api.proof.holdings/y", false},
		{"https://api.proof.holdings:99999/x", "https://api.proof.holdings/y", false},
	}
	for _, tc := range cases {
		a, err := url.Parse(tc.a)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.a, err)
		}
		b, err := url.Parse(tc.b)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.b, err)
		}
		if (originOf(a) == originOf(b)) != tc.same {
			t.Errorf("%s vs %s: want same=%v, got %q and %q", tc.a, tc.b, tc.same, originOf(a), originOf(b))
		}
	}
}

func TestVerifyOffline_StatusListAdmissionRules(t *testing.T) {
	cases := []struct {
		name      string
		overrides statusListOverrides
	}{
		{"typ is not statuslist+jwt", statusListOverrides{typ: "JWT"}},
		{"sub is another uri", statusListOverrides{sub: "https://api.example.com/other-list"}},
		{"expired", statusListOverrides{expiresIn: -time.Hour}},
		{"no exp at all", statusListOverrides{omitExp: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRevocationFixture(t)
			f.setReply("token", tc.overrides)

			res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(1), nil, "proof.holdings"))
			if err != nil {
				t.Fatalf("VerifyOffline: %v", err)
			}
			if res.Valid || res.Reason != "status_unavailable" {
				t.Errorf("want status_unavailable, got %+v", res)
			}
		})
	}
}

func TestVerifyOffline_RefusesListSignedByUnpublishedKey(t *testing.T) {
	f := newRevocationFixture(t)
	f.setReply("token", statusListOverrides{key: f.otherKey})

	res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(1), nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid || res.Reason != "status_unavailable" {
		t.Errorf("want status_unavailable, got %+v", res)
	}
}

func TestVerifyOffline_AcceptsListWithoutIssuerClaim(t *testing.T) {
	// The issuer signs its list without an `iss` claim (src/services/statusList.ts), so requiring
	// one would refuse every real list.
	f := newRevocationFixture(t)

	res, err := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if !res.Valid || !res.RevocationChecked {
		t.Errorf("want valid and checked, got %+v (%s)", res, res.Error)
	}
}

func TestVerifyOffline_OptOutSkipsTheList(t *testing.T) {
	f := newRevocationFixture(t)
	revoked := f.mintProof(t, f.slot(1), nil, "proof.holdings")

	res, err := f.proofsFor().VerifyOffline(context.Background(), revoked, WithoutRevocationCheck())
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if !res.Valid || res.RevocationChecked {
		t.Errorf("want valid and unchecked, got %+v", res)
	}
	if f.statusListRequests() != 0 {
		t.Errorf("want no status-list request, got %d", f.statusListRequests())
	}
}

func TestVerifyOffline_SignatureFailuresKeepTheirReason(t *testing.T) {
	f := newRevocationFixture(t)

	foreignKey, err := f.proofsFor().VerifyOffline(
		context.Background(), f.mintProof(t, f.slot(0), f.otherKey, "proof.holdings"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if foreignKey.Valid || foreignKey.Reason != "invalid" || foreignKey.RevocationChecked {
		t.Errorf("want invalid and unchecked for a foreign key, got %+v", foreignKey)
	}

	foreignIssuer, err := f.proofsFor().VerifyOffline(
		context.Background(), f.mintProof(t, f.slot(0), nil, "evil.example.net"))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if foreignIssuer.Valid || foreignIssuer.Reason != "invalid" {
		t.Errorf("want invalid for a foreign issuer, got %+v", foreignIssuer)
	}
}

func TestVerifyOffline_ReadsEverySlotOfTheSharedFixture(t *testing.T) {
	expected := map[string]struct {
		valid  bool
		reason string
	}{
		"valid":       {true, ""},
		"revoked":     {false, "revoked"},
		"suspended":   {false, "suspended"},
		"unavailable": {false, "status_unavailable"},
	}

	for index, name := range namedSlots(t) {
		f := newRevocationFixture(t)
		idx, err := strconv.Atoi(index)
		if err != nil {
			t.Fatalf("fixture slot index %q: %v", index, err)
		}

		res, verifyErr := f.proofsFor().VerifyOffline(context.Background(), f.mintProof(t, f.slot(idx), nil, "proof.holdings"))
		if verifyErr != nil {
			t.Fatalf("VerifyOffline: %v", verifyErr)
		}
		want := expected[name]
		if res.Valid != want.valid || res.Reason != want.reason {
			t.Errorf("slot %s (%s): want valid=%v reason=%q, got valid=%v reason=%q (%s)",
				index, name, want.valid, want.reason, res.Valid, res.Reason, res.Error)
		}
	}
}

func TestVerifyOffline_AnUnreachableKeySetIsNotReportedAsAMissingKid(t *testing.T) {
	// An unknown kid during an outage used to answer "no public key published for kid …" with
	// Reason "invalid" — a FORGERY's answer — when the real problem was that the key set could not
	// be fetched at all. It is an error wrapping ErrJWKSUnavailable instead.
	f := newRevocationFixture(t)
	proofs := f.proofsFor()

	if _, err := proofs.VerifyOffline(
		context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings")); err != nil {
		t.Fatalf("priming call: %v", err)
	}

	// The state a verifier is in when a rotation and an outage coincide.
	f.server.Close()

	rotated := signEcToken(t, f.key,
		map[string]any{"alg": "ES256", "typ": "JWT", "kid": "es256-kid-2"},
		map[string]any{
			"iss": "proof.holdings", "sub": "ph_ctl_x", "iat": time.Now().Unix() - 60,
			"exp": time.Now().Unix() + 3600, "user_id": "u", "type": "domain", "channel": "dns",
			"identifier_hash": "h", "verified_at": "2026-09-22T10:00:00.000Z",
		})

	if _, err := proofs.VerifyOffline(context.Background(), rotated); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("want ErrJWKSUnavailable while the key set is unreachable, got %v", err)
	}

	// Second call, now INSIDE the failed-refetch cooldown: the same "I could not check", never a
	// verdict about the token itself.
	res, err := proofs.VerifyOffline(context.Background(), rotated)
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("want ErrJWKSUnavailable inside the cooldown, got %+v %v", res, err)
	}
	if res != nil {
		t.Errorf("want no result beside the error, got %+v", res)
	}
}

func TestVerifyOffline_TheHeldKeySetIsRefetchedOnceItIsOldEnough(t *testing.T) {
	// The unknown-kid refetch heals a key being ADDED. Nothing healed one being REMOVED, so a
	// withdrawn — possibly compromised — key stayed trusted for the life of the process.
	f := newRevocationFixture(t)
	proofs := f.proofsFor()
	clock := &fixtureClock{}
	proofs.keys().clock = clock
	now := time.Now().Unix()

	clock.set(0, now)
	if _, err := proofs.VerifyOffline(
		context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings")); err != nil {
		t.Fatalf("priming call: %v", err)
	}
	before := f.jwksRequests()

	clock.set(int64(keySetTTL/time.Second)-1, now)
	if _, err := proofs.VerifyOffline(
		context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings")); err != nil {
		t.Fatalf("inside the TTL: %v", err)
	}
	if got := f.jwksRequests(); got != before {
		t.Fatalf("positive control: want the set reused inside the TTL, got %d reads (was %d)", got, before)
	}

	clock.set(int64(keySetTTL/time.Second), now)
	if _, err := proofs.VerifyOffline(
		context.Background(), f.mintProof(t, f.slot(0), nil, "proof.holdings")); err != nil {
		t.Fatalf("second call: %v", err)
	}

	if got := f.jwksRequests(); got <= before {
		t.Errorf("want the aged-out key set refetched, got %d reads (was %d)", got, before)
	}
}

// statusListOriginFixture is sdks/shared/fixtures/status_list_origin.json, shared with the other
// three SDKs and delegation-verifier.
type statusListOriginFixture struct {
	ConfiguredOrigin string `json:"configured_origin"`
	Cases            []struct {
		Name      string `json:"name"`
		URI       string `json:"uri"`
		SDK       string `json:"sdk"`
		URIOrigin string `json:"uri_origin"`
	} `json:"cases"`
}

// routedIssuer answers the key set at a fixed origin and records every url it was asked for.
type routedIssuer struct {
	jwksURL string
	jwks    JWKS

	mu        sync.Mutex
	requested []*url.URL
}

func (r *routedIssuer) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.requested = append(r.requested, req.URL)
	r.mu.Unlock()

	if req.URL.String() == r.jwksURL {
		body, err := json.Marshal(r.jwks)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Request:    req,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("not found")),
		Request:    req,
	}, nil
}

// The cases need a fixed https origin, a default port and an uppercase host, none of which the
// loopback server can be, so they run through a routed transport instead.
func TestVerifyOffline_SharedStatusListOriginFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "shared", "fixtures", "status_list_origin.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture statusListOriginFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("the fixture has no cases")
	}
	configured := fixture.ConfiguredOrigin
	jwksURL := configured + "/.well-known/jwks.json"

	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			f := newRevocationFixture(t)
			issuer := &routedIssuer{jwksURL: jwksURL, jwks: f.jwks()}
			proofs := &Proofs{http: newHTTPClient("pk_test_x", configured, 5*time.Second, 0), jwksURL: jwksURL}
			proofs.http.client.Transport = issuer

			listURL, err := url.Parse(tc.URI)
			if err != nil {
				t.Fatalf("parse case uri: %v", err)
			}
			slot := map[string]any{"idx": 1, "uri": tc.URI}
			res, err := proofs.VerifyOffline(context.Background(), f.mintProof(t, slot, nil, "proof.holdings"))
			if err != nil {
				t.Fatalf("VerifyOffline: %v", err)
			}

			issuer.mu.Lock()
			requested := append([]*url.URL(nil), issuer.requested...)
			issuer.mu.Unlock()
			var jwksRead bool
			var listRequests []*url.URL
			for _, u := range requested {
				if u.String() == jwksURL {
					jwksRead = true
				}
				if u.Path == listURL.Path {
					listRequests = append(listRequests, u)
				}
			}

			// The key set was read and the signature passed, so the origin rule decided the rest.
			if !jwksRead {
				t.Fatalf("the key set was never requested: %v", requested)
			}
			if res.Payload == nil || res.Valid || res.Reason != "status_unavailable" || res.RevocationChecked {
				t.Fatalf("want a verified payload with status_unavailable, got %+v", res)
			}

			if tc.SDK == "accepted" {
				// The list itself is a 404 here: what is pinned is that the origin rule let the
				// request go. Go hands the transport the uri unnormalized, so compare origins.
				if len(listRequests) != 1 || originOf(listRequests[0]) != configured {
					t.Fatalf("want one status-list request to %s, got %v", configured, listRequests)
				}
				if strings.Contains(res.Error, "configured issuer origin") {
					t.Errorf("an accepted uri was refused by the origin rule: %q", res.Error)
				}
				return
			}
			if len(listRequests) != 0 {
				t.Fatalf("a refused status list was requested: %v", listRequests)
			}
			want := "status list uri origin " + tc.URIOrigin + " is not the configured issuer origin " + configured
			if res.Error != want {
				t.Errorf("want error %q, got %q", want, res.Error)
			}
		})
	}
}
