package proof

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// proofTokenIssuer is the only `iss` an offline verification accepts.
const proofTokenIssuer = "proof.holdings"

// offlineClockToleranceSeconds matches the JS SDK's `clockTolerance: 5` so a verifier whose
// clock drifts by a few seconds does not reject a freshly minted proof.
const offlineClockToleranceSeconds = 5

// Proofs provides access to the proofs API.
type Proofs struct {
	http    *httpClient
	jwksURL string
	// maxJWKSAge bounds a key set that cannot be refreshed; zero means DefaultMaxJWKSAge.
	maxJWKSAge time.Duration

	// The key set is created on first use, so a Proofs built without NewClient still works.
	keySetOnce sync.Once
	keySet     *keySetCache

	// The last status list read, reusable until the issuer's own ttl/exp runs out.
	statusListMu    sync.Mutex
	statusListCache *cachedStatusList
}

// keys is the key set this client verifies against.
func (p *Proofs) keys() *keySetCache {
	p.keySetOnce.Do(func() {
		age := p.maxJWKSAge
		if age == 0 {
			age = DefaultMaxJWKSAge
		}
		p.keySet = newKeySetCache(p.http, p.jwksURL, age)
	})
	return p.keySet
}

// wallNow is "now" for every claim check, read from the same clocks the key set ages on.
func (p *Proofs) wallNow() time.Time {
	return time.UnixMilli(int64(p.keys().clock.wallMs()))
}

// cachedStatusList is one decompressed status list, held until it goes stale.
type cachedStatusList struct {
	uri       string
	data      []byte
	bits      int
	expiresAt time.Time
}

// OfflineProofPayload holds the verified claims of a proof token.
//
// Declared here rather than in types.go: that file is regenerated from the OpenAPI spec
// ("DO NOT EDIT"), and offline verification has no REST endpoint to generate from.
type OfflineProofPayload struct {
	Iss            string `json:"iss"`
	Sub            string `json:"sub"`
	Iat            int64  `json:"iat"`
	Exp            int64  `json:"exp"`
	Type           string `json:"type"`
	Channel        string `json:"channel"`
	IdentifierHash string `json:"identifier_hash"`
	VerifiedAt     string `json:"verified_at"`
	UserID         string `json:"user_id"`
	Decision       string `json:"decision,omitempty"`
	// Status carries the token's slot in the issuer's Token Status List (proof schema 1.3).
	// Absent on a token minted while the issuer could not allocate a slot.
	//
	// Kept as RawMessage and parsed separately: a typed field would make a MALFORMED `status`
	// claim fail the whole payload decode, so a token the other three SDKs read as "carries no
	// slot" would read here as a bad token. The claim is optional, so it must not be able to
	// change the verdict on the token's own signature.
	Status json.RawMessage `json:"status,omitempty"`
}

// OfflineStatusClaim is the token's `status` claim (draft-ietf-oauth-status-list).
type OfflineStatusClaim struct {
	StatusList *OfflineStatusListRef `json:"status_list,omitempty"`
}

// statusListRef reads the token's slot reference, or nil when it carries none — including when
// the claim is present but malformed or names a negative index, which the JS, Python and PHP
// SDKs also treat as "no slot" rather than as a reason to refuse.
func (p *OfflineProofPayload) statusListRef() *OfflineStatusListRef {
	if len(p.Status) == 0 {
		return nil
	}
	var claim OfflineStatusClaim
	if err := json.Unmarshal(p.Status, &claim); err != nil {
		return nil
	}
	if claim.StatusList == nil || claim.StatusList.Idx < 0 || claim.StatusList.URI == "" {
		return nil
	}
	return claim.StatusList
}

// OfflineStatusListRef points at one slot of one published status list.
type OfflineStatusListRef struct {
	Idx int    `json:"idx"`
	URI string `json:"uri"`
}

// OfflineVerificationResult is the outcome of an offline proof-token verification.
type OfflineVerificationResult struct {
	Valid   bool                 `json:"valid"`
	Payload *OfflineProofPayload `json:"payload,omitempty"`
	Error   string               `json:"error,omitempty"`
	// Reason names WHY a verification answered Valid=false, in the issuer's own vocabulary —
	// the same values POST /api/v1/proofs/validate returns: "invalid", "expired", "revoked",
	// "suspended", "status_unavailable". The last of those means the revocation status could not
	// be READ, which is a refusal to guess, not a claim that the proof is withdrawn.
	//
	// The issuer's key-rotation rules add "key_revoked" (see PullHint), "jwks_stale" (see
	// CacheAgeSeconds), "wrong_key_purpose", "outside_key_window", "token_lifetime_exceeded" and
	// "unknown_key" — a kid absent from a key set refetched for it.
	Reason string `json:"reason,omitempty"`
	// RevocationChecked reports whether the proof's revocation status was actually established
	// during this call — false when the token carries no status-list slot, when the check was
	// turned off, and whenever verification failed before the list could be consulted. A caller
	// can therefore never mistake "not checked" for "checked and clear".
	RevocationChecked bool `json:"revocation_checked"`
	// PullHint accompanies "key_revoked": where a token re-issued under a live key can be fetched.
	PullHint *OfflinePullHint `json:"pull_hint,omitempty"`
	// CacheAgeSeconds accompanies "jwks_stale": how old the key set that could not be refreshed is.
	// Call RefreshJWKS once the issuer is reachable again.
	CacheAgeSeconds *int64 `json:"cache_age_seconds,omitempty"`
}

// OfflinePullHint names the issuer and the handle a re-issued token can be fetched by. The handle
// is read from the UNVERIFIED token — the key that signed it is revoked — so treat it as a lookup
// key, never as a verified claim.
type OfflinePullHint struct {
	IssuerOrigin string  `json:"issuer_origin"`
	Handle       *string `json:"handle"`
}

// offlineOptions is the resolved shape of the variadic OfflineOption arguments.
type offlineOptions struct {
	checkRevocation bool
}

// OfflineOption adjusts one VerifyOffline call.
type OfflineOption func(*offlineOptions)

// WithoutRevocationCheck verifies the signature alone, leaving the issuer's status list
// unread — the result then reports RevocationChecked=false.
//
// Use it only when the signature is genuinely the whole question (an air-gapped check against a
// warm key cache, say). The default is to check, because the alternative silently accepts a
// withdrawn proof.
func WithoutRevocationCheck() OfflineOption {
	return func(o *offlineOptions) { o.checkRevocation = false }
}

// Validate validates a proof token online (checks revocation status).
//
// Pass a non-empty identifier to also bind the proof to the identifier you expect it to be
// about: a proof about anything else answers valid:false with reason "identifier_mismatch",
// and a proof of an encrypted decision — whose hash is over ciphertext — answers
// "identifier_unverifiable". For a proof about a verified identifier any format is accepted and
// canonicalized as it was at issuance; a proof of an approval decision binds only on the exact
// recipient value it was issued for.
func (p *Proofs) Validate(ctx context.Context, proofToken string, identifier string) (map[string]any, error) {
	body := map[string]string{"proof_token": proofToken}
	if identifier != "" {
		body["identifier"] = identifier
	}
	return p.http.post(ctx, "/api/v1/proofs/validate", body)
}

// Revoke revokes a proof by public handle (ph_ctl_*/ph_dlg_*) or verification ID.
//
// Revoking a PROOF does not withdraw the asset, consent or delegation it is about — those have
// their own surfaces.
func (p *Proofs) Revoke(ctx context.Context, id string, reason string) (map[string]any, error) {
	var body map[string]string
	if reason != "" {
		body = map[string]string{"reason": reason}
	}
	return p.http.post(ctx, "/api/v1/proofs/"+url.PathEscape(id)+"/revoke", body)
}

// Status gets the status of a proof by public handle (ph_ctl_*/ph_dlg_*) or verification ID.
// A live proof reads "active".
func (p *Proofs) Status(ctx context.Context, id string) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/proofs/"+url.PathEscape(id)+"/status", nil)
}

// ListRevoked gets the revocation list.
func (p *Proofs) ListRevoked(ctx context.Context) (map[string]any, error) {
	return p.http.get(ctx, "/api/v1/proofs/revoked", nil)
}

// VerifyOffline verifies a proof token against the JWKS public keys without calling the API.
//
// ES256 and RS256 are accepted — the algorithm must match the published key's type — and
// `iss`/`exp` are enforced with the same 5-second clock tolerance as the other SDKs.
//
// The key set follows the issuer's key-rotation rules (sdks/shared/fixtures/jwks_rotation/). It is
// reused for 10 minutes; a `kid` it does not know triggers one refetch per 30 s, so a rotated
// signing key self-heals while a stream of junk kids cannot turn into a stream of outbound
// requests. A key the issuer revoked answers Reason "key_revoked" with a PullHint; a key set that
// could not be refreshed for longer than WithMaxJWKSAge answers "jwks_stale" with its
// CacheAgeSeconds; a key of another family, a token signed outside its key's window or living
// longer than the key allows answer "wrong_key_purpose", "outside_key_window" and
// "token_lifetime_exceeded"; a kid the issuer does not publish answers "unknown_key".
//
// A token that fails verification is NOT an error: the result carries Valid=false and a reason.
// The error return — wrapping ErrJWKSUnavailable — is reserved for a key set that could not be
// used to check the token: unreachable with nothing cached to answer from, or a kid it cannot
// vouch for yet. That is the difference between "this proof is bad" and "I could not check".
//
// REVOCATION is checked by default, from the token's own status-list slot (proof schema 1.3):
// a revoked or suspended proof answers Valid=false with Reason "revoked"/"suspended". The list
// is a second public, cacheable document that reveals nothing about which proof is being checked,
// and it is read through the same transport with no API key attached. A list that cannot be read
// — unreachable, failing its own admission rules, or not covering this slot — answers
// "status_unavailable" rather than passing the proof, and a token carrying no slot at all stays
// valid with RevocationChecked=false, which is exactly what the issuer's own
// POST /proofs/validate answers for it. Pass WithoutRevocationCheck() to check the signature
// alone.
func (p *Proofs) VerifyOffline(
	ctx context.Context,
	token string,
	opts ...OfflineOption,
) (*OfflineVerificationResult, error) {
	options := offlineOptions{checkRevocation: true}
	for _, opt := range opts {
		opt(&options)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return invalidOffline("token is not a compact JWS (expected 3 dot-separated parts)"), nil
	}
	var unverified map[string]any
	if err := decodeJWTSegment(parts[1], &unverified); err != nil {
		return invalidOffline("token payload is not valid base64url JSON"), nil
	}
	// The family only selects which key may answer; the signature still has to match that key.
	family := keyFamilyProof
	if unverified["token_type"] == "delegation" {
		family = keyFamilyDelegation
	}

	checked, err := p.checkAgainstKeySet(ctx, parts, family)
	if err != nil {
		return nil, err
	}
	if checked.reason != "" {
		failure := &OfflineVerificationResult{Error: checked.message, Reason: checked.reason}
		switch checked.reason {
		case "key_revoked":
			handleClaim := "proof_id"
			if family == keyFamilyDelegation {
				handleClaim = "sub"
			}
			hint := &OfflinePullHint{IssuerOrigin: p.issuerOrigin()}
			if handle, ok := unverified[handleClaim].(string); ok {
				hint.Handle = &handle
			}
			failure.PullHint = hint
		case "jwks_stale":
			failure.CacheAgeSeconds = checked.cacheAgeSeconds
		}
		return failure, nil
	}

	var payload OfflineProofPayload
	if err := decodeJWTSegment(parts[1], &payload); err != nil {
		return invalidOffline("token payload is not valid base64url JSON"), nil
	}

	if payload.Iss != proofTokenIssuer {
		return invalidOffline(fmt.Sprintf("unexpected issuer %q", payload.Iss)), nil
	}
	if payload.Exp != 0 && payload.Exp+offlineClockToleranceSeconds < p.wallNow().Unix() {
		return &OfflineVerificationResult{Error: "token has expired", Reason: "expired"}, nil
	}

	verified := &OfflineVerificationResult{Valid: true, Payload: &payload}
	if !options.checkRevocation {
		return verified, nil
	}
	ref := payload.statusListRef()
	if ref == nil {
		return verified, nil
	}

	state, message := p.checkStatusList(ctx, ref)
	switch state {
	case statusValid:
		verified.RevocationChecked = true
		return verified, nil
	case statusRevoked, statusSuspended:
		return &OfflineVerificationResult{
			Payload:           &payload,
			Error:             message,
			Reason:            state,
			RevocationChecked: true,
		}, nil
	default:
		return &OfflineVerificationResult{
			Payload: &payload,
			Error:   message,
			Reason:  "status_unavailable",
		}, nil
	}
}

// invalidOffline is the shape every signature-side refusal returns: not valid, reason "invalid",
// revocation never reached.
func invalidOffline(message string) *OfflineVerificationResult {
	return &OfflineVerificationResult{Error: message, Reason: "invalid"}
}

// RefreshJWKS makes the next VerifyOffline refetch the key set, ignoring its 10-minute reuse
// window and the 30-second cooldowns — the remedy a "jwks_stale" answer names. A successful
// refetch resets the set's age. What the verifier knows is kept: key confirmations and tombstones
// survive (ClearTombstones is the separate, deliberate reset).
func (p *Proofs) RefreshJWKS() {
	p.keys().forceRefresh()

	// The status list is verified against this same key set, so a cache kept across a rotation
	// would be one the caller just asked to stop trusting.
	p.statusListMu.Lock()
	p.statusListCache = nil
	p.statusListMu.Unlock()
}

// ClearTombstones forgets every revoked-key tombstone this client has applied or is waiting to
// confirm. They are held in memory only — a restart forgets them too — and otherwise kept until a
// year after the revocation, whatever later key sets say.
func (p *Proofs) ClearTombstones() {
	p.keys().clearTombstones()
}

// issuerOrigin is the configured issuer's origin, as a pull hint names it.
func (p *Proofs) issuerOrigin() string {
	base, err := url.Parse(p.http.baseURL)
	if err != nil {
		return ""
	}
	return originOf(base)
}

// keySetCheck is the outcome of checking a compact JWS against the issuer's key set: the verified
// payload, or a reason (and message) why not.
type keySetCheck struct {
	payload         map[string]any
	reason          string
	message         string
	cacheAgeSeconds *int64
}

func keySetFailure(reason, message string) keySetCheck {
	return keySetCheck{reason: reason, message: message}
}

// checkAgainstKeySet checks the signature against the issuer's key set of `family`, then the
// window and lifetime of the key that made it — so a forgery reads as a bad signature, never as a
// policy violation of a key it did not come from. The token's own claims are the caller's.
//
// The error return wraps ErrJWKSUnavailable and means the key set could not be used at all.
func (p *Proofs) checkAgainstKeySet(ctx context.Context, parts []string, family string) (keySetCheck, error) {
	var header map[string]any
	if err := decodeJWTSegment(parts[0], &header); err != nil {
		return keySetFailure("invalid", "token header is not valid base64url JSON"), nil
	}
	alg, _ := header["alg"].(string)
	// Never trust the token's own algorithm choice: accepting "none" (or an HMAC alg with the
	// public key as the secret) is the classic JWT forgery. The check stays an ALLOW-LIST for
	// that reason — widened to the two algorithms this issuer signs with, never opened up.
	if alg != "RS256" && alg != "ES256" {
		return keySetFailure("invalid", fmt.Sprintf("unsupported alg %q (only ES256 and RS256 are accepted)", alg)), nil
	}
	var kid *string
	if value, ok := header["kid"].(string); ok {
		kid = &value
	}

	resolution := p.keys().resolve(ctx, kid, alg, family)
	switch resolution.kind {
	case resolutionUnavailable:
		if resolution.cause != nil {
			return keySetCheck{}, fmt.Errorf("%w: %w", ErrJWKSUnavailable, resolution.cause)
		}
		return keySetCheck{}, fmt.Errorf("%w: %s", ErrJWKSUnavailable, resolution.message)
	case resolutionStale:
		return keySetCheck{
			reason: "jwks_stale",
			message: "the issuer key set could not be refreshed and the cached copy is older than " +
				"the max JWKS age; call RefreshJWKS once the issuer is reachable",
			cacheAgeSeconds: resolution.cacheAgeSeconds,
		}, nil
	case resolutionRevoked:
		return keySetFailure("key_revoked", fmt.Sprintf("the issuer revoked signing key %q", resolution.kid)), nil
	case resolutionWrongPurpose:
		return keySetFailure("wrong_key_purpose", fmt.Sprintf("signing key %q is not a %s key", resolution.kid, family)), nil
	case resolutionKeys:
	default:
		return keySetFailure("unknown_key", "no key in the issuer key set matches this token"), nil
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return keySetFailure("invalid", "token signature is not valid base64url"), nil
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	var matched *keyCandidate
	for i := range resolution.candidates {
		// Not this key; a token matching none of them is a bad signature.
		if verifySignature(alg, resolution.candidates[i].key, sum[:], signature) == nil {
			matched = &resolution.candidates[i]
			break
		}
	}
	if matched == nil {
		return keySetFailure("invalid", "signature verification failed"), nil
	}

	var payload map[string]any
	if err := decodeJWTSegment(parts[1], &payload); err != nil {
		return keySetFailure("invalid", "token payload is not valid base64url JSON"), nil
	}
	switch checkKeyPolicy(matched.record, payload["iat"], payload["exp"], resolution.registryLive) {
	case "outside_key_window":
		return keySetFailure("outside_key_window", "token iat lies outside the signing key's window"), nil
	case "token_lifetime_exceeded":
		return keySetFailure("token_lifetime_exceeded",
			"token exp lies beyond iat plus the signing key's max_token_lifetime"), nil
	}
	return keySetCheck{payload: payload}, nil
}

// verifySignature checks a JWS signature against the published key, requiring the token's
// declared algorithm and the key's actual type to AGREE.
//
// The agreement is the security property, not a formality: `key` is chosen by the token's own
// `kid`, so without this a token could name an RSA key while declaring ES256 and take whichever
// verification path was cheaper to satisfy. A type assertion that fails is a refusal, never a
// fall-through.
func verifySignature(alg string, key crypto.PublicKey, digest, signature []byte) error {
	switch alg {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("jws: RS256 token against a non-RSA key")
		}
		return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest, signature)
	case "ES256":
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("jws: ES256 token against a non-EC key")
		}
		// JWS ECDSA signatures are the fixed-width r‖s pair (RFC 7518 § 3.4), NOT the ASN.1
		// encoding Go produces by default — 32 bytes each for P-256. Length is checked before
		// splitting so a short or long signature is refused rather than silently reinterpreted.
		if len(signature) != 2*p256CoordinateBytes {
			return errors.New("jws: ES256 signature is not 64 bytes")
		}
		r := new(big.Int).SetBytes(signature[:p256CoordinateBytes])
		s := new(big.Int).SetBytes(signature[p256CoordinateBytes:])
		if !ecdsa.Verify(ecKey, digest, r, s) {
			return errors.New("jws: ES256 signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("jws: unsupported alg %q", alg)
	}
}

// p256CoordinateBytes is the fixed width of each half of an ES256 signature and of each P-256
// public-key coordinate.
const p256CoordinateBytes = 32

// ecdsaPublicKeyFromJWK rebuilds a P-256 public key from the JWK's base64url coordinates.
//
// The curve is checked by NAME rather than inferred from the coordinate lengths: a P-384 key
// whose coordinates happened to be short would otherwise be read as a different point on a
// different curve, and the resulting key would verify nothing while looking valid.
func ecdsaPublicKeyFromJWK(jwk JWK) (*ecdsa.PublicKey, error) {
	if jwk.Crv == nil || *jwk.Crv != "P-256" {
		return nil, errors.New("jwk: only the P-256 curve is supported for ES256")
	}
	if jwk.X == nil || jwk.Y == nil {
		return nil, errors.New("jwk: EC key is missing a coordinate")
	}
	x, err := base64.RawURLEncoding.DecodeString(*jwk.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(*jwk.Y)
	if err != nil {
		return nil, err
	}
	if len(x) == 0 || len(x) > p256CoordinateBytes || len(y) == 0 || len(y) > p256CoordinateBytes {
		return nil, errors.New("jwk: EC coordinate out of range for P-256")
	}
	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	// A point off the curve is not a key. Without this an attacker-supplied JWKS could steer
	// verification onto an invalid point.
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("jwk: EC point is not on the P-256 curve")
	}
	return key, nil
}

// rsaPublicKeyFromJWK rebuilds an RSA public key from the JWK's base64url modulus and exponent.
func rsaPublicKeyFromJWK(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.N == nil || jwk.E == nil {
		return nil, errors.New("jwk: RSA key is missing modulus or exponent")
	}
	n, err := base64.RawURLEncoding.DecodeString(*jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(*jwk.E)
	if err != nil {
		return nil, err
	}
	if len(n) == 0 || len(e) == 0 {
		return nil, errors.New("jwk: empty modulus or exponent")
	}
	exponent := new(big.Int).SetBytes(e)
	if !exponent.IsInt64() || exponent.Int64() > int64(^uint32(0)>>1) {
		return nil, errors.New("jwk: exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent.Int64())}, nil
}

// decodeJWTSegment base64url-decodes one JWS segment into v.
func decodeJWTSegment(segment string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// The draft's 2-bit slot values and the outcome names they map to.
const (
	slotValid           = 0b00
	slotRevoked         = 0b01
	slotSuspended       = 0b10
	statusValid         = "valid"
	statusRevoked       = "revoked"
	statusSuspended     = "suspended"
	statusUnavailable   = "unavailable"
	statusListBodyLimit = 512 * 1024
	statusListTimeout   = 5 * time.Second
)

// checkStatusList resolves one token's slot against the issuer's signed status list, returning
// an outcome name and a message explaining a negative one.
func (p *Proofs) checkStatusList(ctx context.Context, ref *OfflineStatusListRef) (string, string) {
	listURL, err := url.Parse(ref.URI)
	if err != nil || !listURL.IsAbs() {
		return statusUnavailable, "status list uri is not a valid absolute URL"
	}

	// The uri arrives INSIDE the artifact being verified, so fetching whatever it names would
	// hand a forged token both the status authority and a request from your network. Only the
	// origin this client is configured against is honoured.
	base, err := url.Parse(p.http.baseURL)
	if err != nil {
		return statusUnavailable, "client base url is not a valid URL"
	}
	if originOf(listURL) != originOf(base) {
		return statusUnavailable, fmt.Sprintf(
			"status list uri origin %s is not the configured issuer origin %s", originOf(listURL), originOf(base))
	}

	data, bits, message := p.loadStatusList(ctx, ref.URI)
	if message != "" {
		return statusUnavailable, message
	}

	slot, ok := readStatusSlot(data, ref.Idx, bits)
	if !ok {
		return statusUnavailable, fmt.Sprintf("status list has no slot %d", ref.Idx)
	}
	switch slot {
	case slotRevoked:
		return statusRevoked, "This proof has been revoked"
	case slotSuspended:
		return statusSuspended, "This proof is currently suspended"
	case slotValid:
		return statusValid, ""
	default:
		// 0b11 is reserved for application-specific use by the draft; the issuer packs it when it
		// could not resolve a delegation's control proof. It is an absence of an answer.
		return statusUnavailable, fmt.Sprintf("status list slot carries unknown status %d", slot)
	}
}

// loadStatusList fetches, verifies and decompresses the published list, reusing the cached copy
// while the issuer's own ttl/exp allows. A non-empty message means it could not be read.
func (p *Proofs) loadStatusList(ctx context.Context, uri string) ([]byte, int, string) {
	p.statusListMu.Lock()
	cached := p.statusListCache
	p.statusListMu.Unlock()
	if cached != nil && cached.uri == uri && p.wallNow().Before(cached.expiresAt) {
		return cached.data, cached.bits, ""
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, 0, fmt.Sprintf("status list request could not be built: %v", err)
	}
	// No Authorization header: the list is public, and sending a credential would tell the
	// issuer WHICH verifier is asking — the one fact its shared-array shape withholds.
	// The branded User-Agent is required — the marketing edge answers 444 to library defaults.
	req.Header.Set("User-Agent", "proof-sdk-go/"+Version)
	req.Header.Set("Accept", "application/statuslist+jwt, application/jwt, text/plain")

	// A client of its own: redirects are refused because the caller has already decided this
	// url's ORIGIN is trusted, and a redirect would move it.
	client := &http.Client{
		Transport: p.http.client.Transport,
		Timeout:   statusListTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Sprintf("status list fetch failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Sprintf("status list fetch failed with HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > statusListBodyLimit {
		return nil, 0, "status list response is too large"
	}

	// One byte over the ceiling is enough to know the body is oversized, and reading only that
	// much keeps an unbounded response from becoming an unbounded allocation.
	body, err := io.ReadAll(io.LimitReader(resp.Body, statusListBodyLimit+1))
	if err != nil {
		return nil, 0, fmt.Sprintf("status list body could not be read: %v", err)
	}
	if len(body) > statusListBodyLimit {
		return nil, 0, "status list response is too large"
	}

	data, bits, expiresAt, message := p.verifyStatusList(ctx, strings.TrimSpace(string(body)), uri)
	if message != "" {
		return nil, 0, message
	}

	p.statusListMu.Lock()
	p.statusListCache = &cachedStatusList{uri: uri, data: data, bits: bits, expiresAt: expiresAt}
	p.statusListMu.Unlock()

	return data, bits, ""
}

// statusListPayload is the claim set of a signed status list (draft-ietf-oauth-status-list).
// The issuer deliberately publishes NO `iss` here, so none is required.
type statusListPayload struct {
	Sub        string `json:"sub"`
	Exp        int64  `json:"exp"`
	TTL        int64  `json:"ttl"`
	StatusList struct {
		Bits int    `json:"bits"`
		Lst  string `json:"lst"`
	} `json:"status_list"`
}

// verifyStatusList checks a fetched list against the issuer's key set and decompresses it.
func (p *Proofs) verifyStatusList(
	ctx context.Context,
	listToken string,
	uri string,
) ([]byte, int, time.Time, string) {
	parts := strings.Split(listToken, ".")
	if len(parts) != 3 {
		return nil, 0, time.Time{}, "status list is not a compact JWS"
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := decodeJWTSegment(parts[0], &header); err != nil {
		return nil, 0, time.Time{}, "status list header is not valid base64url JSON"
	}
	// The draft mandates this typ, and it is the one header separating a status list from every
	// other token the issuer signs with the SAME key.
	if header.Typ != "statuslist+jwt" {
		return nil, 0, time.Time{}, fmt.Sprintf(
			"status list must carry typ \"statuslist+jwt\", got %q", header.Typ)
	}
	if header.Alg != "RS256" && header.Alg != "ES256" {
		return nil, 0, time.Time{}, fmt.Sprintf("status list uses unsupported alg %q", header.Alg)
	}

	// Held to its own key family and that key's window. A key set that cannot be used here is
	// "status_unavailable" like any other unreadable list, not an error of the whole call.
	checked, err := p.checkAgainstKeySet(ctx, parts, keyFamilyStatusList)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Sprintf("status list signing key unavailable: %v", err)
	}
	if checked.reason != "" {
		return nil, 0, time.Time{}, "status list did not verify: " + checked.message
	}

	var payload statusListPayload
	if err := decodeJWTSegment(parts[1], &payload); err != nil {
		return nil, 0, time.Time{}, "status list payload is not valid base64url JSON"
	}

	// The list must say it is the list we asked for, or a valid list from the same issuer could
	// be replayed in place of another one.
	if payload.Sub != uri {
		return nil, 0, time.Time{}, "status list `sub` does not match the uri it was fetched from"
	}
	// A freshness channel with no expiry is not one: an exp-less list would be honoured forever,
	// so its absence reads as "cannot answer" rather than fail-open.
	if payload.Exp == 0 {
		return nil, 0, time.Time{}, "status list carries no exp"
	}
	if payload.Exp+offlineClockToleranceSeconds < p.wallNow().Unix() {
		return nil, 0, time.Time{}, "status list has expired"
	}
	if payload.StatusList.Lst == "" {
		return nil, 0, time.Time{}, "status list payload has no `lst`"
	}

	compressed, err := base64.RawURLEncoding.DecodeString(payload.StatusList.Lst)
	if err != nil {
		return nil, 0, time.Time{}, "status list `lst` is not valid base64url"
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, 0, time.Time{}, fmt.Sprintf("status list could not be decompressed: %v", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, statusListBodyLimit))
	if err != nil {
		return nil, 0, time.Time{}, fmt.Sprintf("status list could not be decompressed: %v", err)
	}

	bits := payload.StatusList.Bits
	if bits == 0 {
		bits = 2
	}

	// Honour the shorter of the issuer's published ttl and the token's own exp.
	expiresAt := time.Unix(payload.Exp, 0)
	if payload.TTL > 0 {
		if ttlBound := p.wallNow().Add(time.Duration(payload.TTL) * time.Second); ttlBound.Before(expiresAt) {
			expiresAt = ttlBound
		}
	}

	return data, bits, expiresAt, ""
}

// readStatusSlot reads one slot: lowest index in the least significant bits, `bits` statuses per
// byte — the draft's byte order, pinned across the four SDKs and the issuer by
// sdks/shared/fixtures/status_list_slots.json.
//
// ok=false means the array does not reach that index, which is "no answer", never "valid".
func readStatusSlot(data []byte, index int, bits int) (int, bool) {
	if index < 0 || (bits != 1 && bits != 2 && bits != 4 && bits != 8) {
		return 0, false
	}
	perByte := 8 / bits
	byteIndex := index / perByte
	if byteIndex >= len(data) {
		return 0, false
	}
	return int(data[byteIndex]>>((index%perByte)*bits)) & ((1 << bits) - 1), true
}

// originOf normalizes a url to its origin the way `URL.origin` does it in the JS SDK: scheme and
// host lowercased, a port dropped when it is the scheme's default. The four SDKs must answer this
// question identically, or a status-list uri accepted by one is refused by another.
func originOf(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())

	// Compared as a NUMBER, not as text: `:0443` and `:443` are the same port per RFC 3986, and
	// the other three SDKs parse it numerically. A string compare here made Go the odd one out.
	if u.Port() == "" {
		return scheme + "://" + host
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 0 || port > 65535 {
		// Unparseable is NOT "no port": dropping it would let `:99999999999999999999` read as
		// the issuer's own origin, which is wider than the other three, all of which refuse the
		// uri outright. An origin nothing can equal is the fail-closed answer.
		return "invalid://" + host + ":" + u.Port()
	}
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + strconv.Itoa(port)
}
