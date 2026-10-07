package proof

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// offlineFixture is a JWKS server plus the key it publishes, so a test can mint tokens
// the SDK should accept and tokens it must reject.
type offlineFixture struct {
	key      *rsa.PrivateKey
	otherKey *rsa.PrivateKey
	kid      string
	server   *httptest.Server
	fetches  *int32
}

func newOfflineFixture(t *testing.T) *offlineFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	var fetches int32
	f := &offlineFixture{key: key, otherKey: otherKey, kid: "test-kid-1", fetches: &fetches}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(f.fetches, 1)
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{{
			Kty: "RSA",
			N:   &n,
			E:   &e,
			Use: "sig",
			Alg: "RS256",
			Kid: f.kid,
		}}})
	}))
	t.Cleanup(f.server.Close)

	return f
}

// proofsFor builds a Proofs resource pointed at the fixture's JWKS.
func (f *offlineFixture) proofsFor() *Proofs {
	h := newHTTPClient("pk_test_x", f.server.URL, 5*time.Second, 0)
	return &Proofs{http: h, jwksURL: f.server.URL + "/.well-known/jwks.json"}
}

// signToken mints a compact JWS with the supplied header/claims, signed by key.
func signToken(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()

	enc := func(v map[string]any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	signingInput := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *offlineFixture) validClaims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"iss":             "proof.holdings",
		"sub":             "507f1f77bcf86cd799439011",
		"iat":             now - 60,
		"exp":             now + 3600,
		"user_id":         "507f1f77bcf86cd799439012",
		"type":            "phone",
		"channel":         "sms",
		"identifier_hash": "abc123",
		"verified_at":     "2026-07-30T10:00:00.000Z",
	}
}

func (f *offlineFixture) header() map[string]any {
	return map[string]any{"alg": "RS256", "typ": "JWT", "kid": f.kid}
}

func TestProofs_VerifyOffline_ValidToken(t *testing.T) {
	f := newOfflineFixture(t)
	token := signToken(t, f.key, f.header(), f.validClaims())

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if !res.Valid {
		t.Fatalf("want valid, got invalid: %s", res.Error)
	}
	if res.Payload == nil {
		t.Fatal("want payload, got nil")
	}
	if res.Payload.Sub != "507f1f77bcf86cd799439011" || res.Payload.Type != "phone" ||
		res.Payload.Channel != "sms" || res.Payload.IdentifierHash != "abc123" ||
		res.Payload.UserID != "507f1f77bcf86cd799439012" ||
		res.Payload.VerifiedAt != "2026-07-30T10:00:00.000Z" || res.Payload.Iss != "proof.holdings" {
		t.Errorf("payload not mapped: %+v", res.Payload)
	}
}

func TestProofs_VerifyOffline_DecisionClaim(t *testing.T) {
	f := newOfflineFixture(t)
	claims := f.validClaims()
	claims["decision"] = "approve"
	token := signToken(t, f.key, f.header(), claims)

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if !res.Valid || res.Payload == nil || res.Payload.Decision != "approve" {
		t.Errorf("want decision=approve on a valid token, got %+v", res)
	}
}

func TestProofs_VerifyOffline_WrongSignature(t *testing.T) {
	f := newOfflineFixture(t)
	// Signed by a key the JWKS does not publish, but carrying the published kid.
	token := signToken(t, f.otherKey, f.header(), f.validClaims())

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid {
		t.Error("want invalid for a token signed by an unpublished key")
	}
}

func TestProofs_VerifyOffline_Expired(t *testing.T) {
	f := newOfflineFixture(t)
	claims := f.validClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := signToken(t, f.key, f.header(), claims)

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid {
		t.Error("want invalid for an expired token")
	}
	if !strings.Contains(res.Error, "expired") {
		t.Errorf("want an expiry-specific error, got %q", res.Error)
	}
}

func TestProofs_VerifyOffline_WrongIssuer(t *testing.T) {
	f := newOfflineFixture(t)
	claims := f.validClaims()
	claims["iss"] = "evil.example"
	token := signToken(t, f.key, f.header(), claims)

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid {
		t.Error("want invalid for a foreign issuer")
	}
}

func TestProofs_VerifyOffline_UnknownKid(t *testing.T) {
	f := newOfflineFixture(t)
	header := f.header()
	header["kid"] = "not-published"
	token := signToken(t, f.key, header, f.validClaims())

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid {
		t.Error("want invalid for a kid absent from the JWKS")
	}
}

func TestProofs_VerifyOffline_UnsupportedAlgRejected(t *testing.T) {
	f := newOfflineFixture(t)
	header := f.header()
	header["alg"] = "none"
	token := signToken(t, f.key, header, f.validClaims())

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid {
		t.Error("want invalid for an alg outside the ES256/RS256 allow-list")
	}
}

func TestProofs_VerifyOffline_MalformedToken(t *testing.T) {
	f := newOfflineFixture(t)
	p := f.proofsFor()

	for _, token := range []string{"", "a.b", "not-a-token", "a.b.c.d", "%%%.%%%.%%%"} {
		res, err := p.VerifyOffline(context.Background(), token)
		if err != nil {
			t.Fatalf("VerifyOffline(%q): %v", token, err)
		}
		if res.Valid {
			t.Errorf("want invalid for malformed token %q", token)
		}
	}
}

func TestProofs_VerifyOffline_CachesJWKS(t *testing.T) {
	f := newOfflineFixture(t)
	p := f.proofsFor()
	token := signToken(t, f.key, f.header(), f.validClaims())

	for i := 0; i < 3; i++ {
		res, err := p.VerifyOffline(context.Background(), token)
		if err != nil || !res.Valid {
			t.Fatalf("VerifyOffline #%d: %v / %+v", i, err, res)
		}
	}
	if got := atomic.LoadInt32(f.fetches); got != 1 {
		t.Errorf("want the JWKS fetched once and cached, got %d fetches", got)
	}

	p.RefreshJWKS()
	if _, err := p.VerifyOffline(context.Background(), token); err != nil {
		t.Fatalf("VerifyOffline after refresh: %v", err)
	}
	if got := atomic.LoadInt32(f.fetches); got != 2 {
		t.Errorf("want a re-fetch after RefreshJWKS, got %d fetches total", got)
	}
}

func TestProofs_VerifyOffline_RefetchesOnUnknownKid(t *testing.T) {
	// Key rotation: a token signed with a kid the cache has not seen triggers ONE refresh,
	// so a rotated key self-heals without the caller intervening.
	f := newOfflineFixture(t)
	p := f.proofsFor()

	if _, err := p.VerifyOffline(context.Background(), signToken(t, f.key, f.header(), f.validClaims())); err != nil {
		t.Fatalf("priming call: %v", err)
	}
	// No aging needed: the first miss inside the TTL may refetch at once; only a second miss
	// within the cooldown is held back.
	before := atomic.LoadInt32(f.fetches)

	header := f.header()
	header["kid"] = "rotated-kid"
	res, err := p.VerifyOffline(context.Background(), signToken(t, f.key, header, f.validClaims()))
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid || res.Reason != "unknown_key" {
		t.Errorf("want unknown_key — the rotated kid is not published either, got %+v", res)
	}
	if got := atomic.LoadInt32(f.fetches); got != before+1 {
		t.Errorf("want exactly one refresh attempt on an unknown kid, got %d extra", got-before)
	}
}

func TestProofs_VerifyOffline_UnknownKidRefetchIsRateLimited(t *testing.T) {
	// Without a cooldown, every junk kid a caller supplies costs one outbound JWKS fetch —
	// so a burst of forged tokens would push the verifier's own IP into the endpoint's rate
	// limit and start failing GOOD tokens. The first unknown kid buys ONE refetch and answers
	// "unknown_key"; for the rest of the cooldown an unknown kid answers "could not check" — it may
	// have been published since — without touching the network.
	f := newOfflineFixture(t)
	p := f.proofsFor()

	if _, err := p.VerifyOffline(context.Background(), signToken(t, f.key, f.header(), f.validClaims())); err != nil {
		t.Fatalf("priming call: %v", err)
	}
	before := atomic.LoadInt32(f.fetches)

	for i := 0; i < 25; i++ {
		header := f.header()
		header["kid"] = fmt.Sprintf("junk-kid-%d", i)
		res, err := p.VerifyOffline(context.Background(), signToken(t, f.key, header, f.validClaims()))
		if i == 0 {
			if err != nil || res.Valid || res.Reason != "unknown_key" {
				t.Fatalf("first junk kid: want unknown_key after a refetch, got %+v %v", res, err)
			}
			continue
		}
		if !errors.Is(err, ErrJWKSUnavailable) || res != nil {
			t.Fatalf("junk kid #%d inside the cooldown: want ErrJWKSUnavailable, got %+v %v", i, res, err)
		}
	}

	if extra := atomic.LoadInt32(f.fetches) - before; extra != 1 {
		t.Errorf("want 1 refetch across 25 unknown kids inside the cooldown, got %d", extra)
	}

	// A good token must still verify while the cooldown is in force.
	res, err := p.VerifyOffline(context.Background(), signToken(t, f.key, f.header(), f.validClaims()))
	if err != nil || !res.Valid {
		t.Errorf("a legitimate token must still verify during the cooldown: %v / %+v", err, res)
	}
}

func TestProofs_VerifyOffline_ConcurrentMissesFetchOnce(t *testing.T) {
	// The cooldown alone is bypassable by being parallel: N goroutines that all miss the cache
	// before any of them stores a result would each issue their own request, which is how a
	// busy verifier would still exceed the JWKS endpoint's own rate limit. The fetch is
	// serialised so the losers read the winner's result instead. A goroutine that arrives after
	// that fetch has answered "unknown_key" finds the miss already recorded and answers "could not
	// check" (ErrJWKSUnavailable) without a request of its own.
	f := newOfflineFixture(t)
	p := f.proofsFor()

	const concurrency = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(i int) {
			defer wg.Done()
			header := f.header()
			header["kid"] = fmt.Sprintf("junk-kid-%d", i)
			res, err := p.VerifyOffline(context.Background(), signToken(t, f.key, header, f.validClaims()))
			if err != nil && !errors.Is(err, ErrJWKSUnavailable) {
				t.Errorf("VerifyOffline #%d: %v", i, err)
			}
			if err == nil && (res.Valid || res.Reason != "unknown_key") {
				t.Errorf("VerifyOffline #%d: want unknown_key, got %+v", i, res)
			}
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(f.fetches); got != 1 {
		t.Errorf("want exactly 1 JWKS fetch for %d concurrent unknown kids, got %d", concurrency, got)
	}
}

func TestProofs_VerifyOffline_RefreshJWKSBypassesCooldown(t *testing.T) {
	f := newOfflineFixture(t)
	p := f.proofsFor()
	token := signToken(t, f.key, f.header(), f.validClaims())

	if _, err := p.VerifyOffline(context.Background(), token); err != nil {
		t.Fatalf("priming call: %v", err)
	}
	before := atomic.LoadInt32(f.fetches)

	p.RefreshJWKS()
	if _, err := p.VerifyOffline(context.Background(), token); err != nil {
		t.Fatalf("VerifyOffline after refresh: %v", err)
	}
	if got := atomic.LoadInt32(f.fetches); got != before+1 {
		t.Errorf("want RefreshJWKS to force a refetch regardless of the cooldown, got %d extra", got-before)
	}
}

func TestProofs_VerifyOffline_JWKSUnreachable(t *testing.T) {
	f := newOfflineFixture(t)
	p := f.proofsFor()
	p.jwksURL = f.server.URL + "/nope"
	token := signToken(t, f.key, f.header(), f.validClaims())

	res, err := p.VerifyOffline(context.Background(), token)
	if err == nil {
		t.Fatal("want a transport error when the JWKS cannot be fetched")
	}
	if res != nil && res.Valid {
		t.Error("want no valid result when the key set is unavailable")
	}
}
