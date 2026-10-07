package proof

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ES256 offline verification (h-proof-signing-es256 / GitHub #235).
//
// The Go SDK was the only one of the four that could not verify an ES256 proof: its JWKS cache
// was typed *rsa.PublicKey and it refused any alg but RS256 by name. These tests drive a P-256
// JWKS through the same public surface the RSA suite next door uses.

// ecOfflineFixture is a JWKS server publishing one P-256 key.
type ecOfflineFixture struct {
	key      *ecdsa.PrivateKey
	otherKey *ecdsa.PrivateKey
	kid      string
	server   *httptest.Server
}

func newEcOfflineFixture(t *testing.T) *ecOfflineFixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other ec key: %v", err)
	}

	f := &ecOfflineFixture{key: key, otherKey: otherKey, kid: "es256-kid-1"}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		crv, x, y := "P-256", base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
			base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{{
			Kty: "EC",
			Crv: &crv,
			X:   &x,
			Y:   &y,
			Use: "sig",
			Alg: "ES256",
			Kid: f.kid,
		}}})
	}))
	t.Cleanup(f.server.Close)

	return f
}

func (f *ecOfflineFixture) proofsFor() *Proofs {
	h := newHTTPClient("pk_test_x", f.server.URL, 5*time.Second, 0)
	return &Proofs{http: h, jwksURL: f.server.URL + "/.well-known/jwks.json"}
}

func (f *ecOfflineFixture) header() map[string]any {
	return map[string]any{"alg": "ES256", "typ": "JWT", "kid": f.kid}
}

func (f *ecOfflineFixture) validClaims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"iss":             "proof.holdings",
		"sub":             "507f1f77bcf86cd799439011",
		"iat":             now - 60,
		"exp":             now + 3600,
		"user_id":         "507f1f77bcf86cd799439012",
		"type":            "domain",
		"channel":         "dns",
		"identifier_hash": "abc123",
		"verified_at":     "2026-08-26T10:00:00.000Z",
	}
}

// signEcToken mints a compact JWS signed with ECDSA/P-256.
//
// The signature is the fixed-width r‖s pair JWS requires (RFC 7518 § 3.4), NOT the ASN.1
// encoding Go's ecdsa.SignASN1 produces — each coordinate left-padded to 32 bytes. This is the
// one place an ES256 implementation is easy to get subtly wrong: an ASN.1 signature is accepted
// by nothing, and an unpadded r‖s fails only for the ~1-in-256 key where a coordinate is short.
func signEcToken(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
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
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestProofs_VerifyOffline_ES256_ValidToken(t *testing.T) {
	f := newEcOfflineFixture(t)
	token := signEcToken(t, f.key, f.header(), f.validClaims())

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
	if res.Payload.Sub != "507f1f77bcf86cd799439011" || res.Payload.Type != "domain" ||
		res.Payload.Channel != "dns" || res.Payload.IdentifierHash != "abc123" {
		t.Errorf("payload not mapped: %+v", res.Payload)
	}
}

func TestProofs_VerifyOffline_ES256_WrongSignature(t *testing.T) {
	f := newEcOfflineFixture(t)
	// Signed by a P-256 key the JWKS does not publish, but carrying the published kid.
	token := signEcToken(t, f.otherKey, f.header(), f.validClaims())

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid {
		t.Error("want invalid for a signature made by an unpublished key")
	}
}

func TestProofs_VerifyOffline_ES256_Expired(t *testing.T) {
	f := newEcOfflineFixture(t)
	claims := f.validClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := signEcToken(t, f.key, f.header(), claims)

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid {
		t.Error("want invalid for an expired token")
	}
}

// A token claiming ES256 against an RSA JWKS entry must be refused rather than mismatched into
// some other verification path — the alg and the key type have to agree.
func TestProofs_VerifyOffline_ES256_AlgKeyTypeMismatch(t *testing.T) {
	rsaFixture := newOfflineFixture(t)
	header := rsaFixture.header()
	header["alg"] = "ES256"
	token := signToken(t, rsaFixture.key, header, rsaFixture.validClaims())

	res, err := rsaFixture.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid {
		t.Error("want invalid when the token's alg does not match the published key type")
	}
}

// A malformed EC JWK (a coordinate that is not base64url) must be reported, never treated as a
// usable key.
func TestProofs_VerifyOffline_ES256_MalformedJWK(t *testing.T) {
	crv, x, y := "P-256", "!!!not-base64!!!", "also-not-base64!!!"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{{
			Kty: "EC", Crv: &crv, X: &x, Y: &y, Use: "sig", Alg: "ES256", Kid: "broken",
		}}})
	}))
	t.Cleanup(server.Close)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	p := &Proofs{
		http:    newHTTPClient("pk_test_x", server.URL, 5*time.Second, 0),
		jwksURL: server.URL + "/.well-known/jwks.json",
	}
	token := signEcToken(t, key, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "broken"},
		map[string]any{"iss": "proof.holdings", "exp": time.Now().Add(time.Hour).Unix()})

	res, err := p.VerifyOffline(context.Background(), token)
	// A malformed entry must not blind the verifier to the rest of the key set, so this is a
	// REFUSAL (`Valid == false`), not a transport error. Asserting only `!(err == nil && Valid)`
	// would also pass if the JWKS fetch failed for an unrelated reason — a green test about
	// nothing.
	if err != nil {
		t.Fatalf("want a refusal, got a transport error: %v", err)
	}
	if res.Valid {
		t.Error("want a refusal for an unparseable EC JWK")
	}
}

// An unsupported curve must be refused by NAME rather than silently read as P-256 — the
// coordinates of a P-384 key would otherwise be truncated into a different, wrong point.
func TestProofs_VerifyOffline_ES256_UnsupportedCurveRejected(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384 key: %v", err)
	}
	crv := "P-384"
	x := base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{{
			Kty: "EC", Crv: &crv, X: &x, Y: &y, Use: "sig", Alg: "ES256", Kid: "p384",
		}}})
	}))
	t.Cleanup(server.Close)

	p := &Proofs{
		http:    newHTTPClient("pk_test_x", server.URL, 5*time.Second, 0),
		jwksURL: server.URL + "/.well-known/jwks.json",
	}
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"p384"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"proof.holdings"}`))
	sig := make([]byte, 64)
	big.NewInt(1).FillBytes(sig[:32])
	big.NewInt(1).FillBytes(sig[32:])
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	res, err := p.VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("want a refusal, got a transport error: %v", err)
	}
	if res.Valid {
		t.Error("want a refusal for a curve other than P-256")
	}
}

// A SYMMETRIC alg must be refused outright. This is the classic JWS forgery: the attacker HMACs
// the token with the verifier's own PUBLIC key as the shared secret, and a verifier that dispatches
// on the token's declared alg without an allow-list computes exactly the same HMAC and accepts it.
//
// The token below is built to VERIFY if the allow-list is ever removed — the HMAC key really is the
// published RSA modulus, so this test fails loudly rather than passing for the wrong reason. Written
// when the allow-list widened from one algorithm to two (h-proof-signing-es256): widening a guard is
// the moment it earns a test.
func TestProofs_VerifyOffline_SymmetricAlgRejected(t *testing.T) {
	f := newOfflineFixture(t)

	header := map[string]any{"alg": "HS256", "typ": "JWT", "kid": f.kid}
	enc := func(v map[string]any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := enc(header) + "." + enc(f.validClaims())

	// The "secret" is the public key material the JWKS publishes — what an attacker has.
	mac := hmac.New(sha256.New, f.key.PublicKey.N.Bytes())
	mac.Write([]byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	res, err := f.proofsFor().VerifyOffline(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if res.Valid {
		t.Error("want invalid for a symmetric alg — HS256 must never reach a verification path")
	}
	if !strings.Contains(res.Error, "HS256") {
		t.Errorf("want the refusal to name the rejected alg, got %q", res.Error)
	}
}
