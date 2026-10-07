package proof

// The issuer's key set as offline verification holds it — the I/O half around jwks_keyset.go,
// which owns the rules. Mirrors packages/delegation-verifier/src/jwks.ts, minus persistence: this
// SDK keeps tombstones in memory only.
//
//   - A fetched set is reused for 10 minutes. An unknown `kid` triggers one refetch per 30 s
//     cooldown; inside that cooldown it answers "could not check" — the kid may have been
//     published since — never "no such key". One fetch is in flight at a time.
//   - A fetch is MERGED into what the verifier knows, never swapped in.
//   - A failed refetch does not discard the cache. Within maxJWKSAge its CONFIRMED keys keep
//     answering; beyond it the answer is stale — except an applied tombstone, which is revoked at
//     any age. A set never fetched has nothing to fall back on and stays unavailable.
//   - A failed refetch of a cached set is retried at most once per cooldown, so an outage does not
//     turn every verification into an outbound request.
//   - Age is measured on a monotonic clock; claim checks use the wall clock.

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"time"
)

const (
	// jwksRefetchCooldown is how long a `kid` miss — or a failed refetch of a cached set —
	// suppresses further fetches. Without it every token carrying an unrecognized kid costs one
	// outbound request, so a caller feeding a service random kids pushes the verifier's own IP
	// into the endpoint's rate limit and starts failing GOOD tokens too.
	jwksRefetchCooldown = 30 * time.Second
	// keySetTTL is how long a fetched key set is reused without refetching.
	keySetTTL = 10 * time.Minute
	// DefaultMaxJWKSAge is how old a key set that cannot be refreshed may grow before offline
	// verification answers "jwks_stale" instead of trusting it.
	DefaultMaxJWKSAge = 24 * time.Hour
	// MaxJWKSAgeCap is the largest accepted WithMaxJWKSAge — below the issuer's ~30-day lead on
	// its next key.
	MaxJWKSAgeCap = 25 * 24 * time.Hour

	jwksTimeout = 5 * time.Second
	// maxJWKSBytes: a key set is kilobytes; anything larger is not one.
	maxJWKSBytes = 512 * 1024
)

// ErrJWKSUnavailable is wrapped by the error VerifyOffline returns when the issuer's key set
// could not be used to check the token — unreachable with nothing cached to answer from, or a kid
// it cannot vouch for yet. It means "I could not check", never "this proof is bad".
var ErrJWKSUnavailable = errors.New("proof: issuer key set unavailable")

// jwksClock is both clocks the key set reads.
type jwksClock interface {
	monotonicMs() float64
	wallMs() float64
}

type systemJWKSClock struct {
	start time.Time
}

func (c systemJWKSClock) monotonicMs() float64 {
	return float64(time.Since(c.start)) / float64(time.Millisecond)
}

func (c systemJWKSClock) wallMs() float64 {
	return float64(time.Now().UnixMilli())
}

func validateMaxJWKSAge(age time.Duration) error {
	if age <= 0 || age > MaxJWKSAgeCap {
		return fmt.Errorf("max JWKS age must be greater than 0 and at most %s (25 days), got %s", MaxJWKSAgeCap, age)
	}
	return nil
}

func durationMs(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

type keyCandidate struct {
	key    crypto.PublicKey
	record *keyRecord
}

const (
	resolutionKeys         = "keys"
	resolutionRevoked      = selectionRevoked
	resolutionWrongPurpose = selectionWrongPurpose
	resolutionUnknown      = selectionUnknown
	resolutionStale        = "stale"
	resolutionUnavailable  = "unavailable"
)

type keyResolution struct {
	kind            string
	candidates      []keyCandidate
	registryLive    bool
	kid             string
	cacheAgeSeconds *int64
	message         string
	// cause is the error behind an unavailable resolution, when there is one — a transport error or
	// the caller's own cancellation — kept so callers can still match it with errors.Is / errors.As.
	cause error
}

type fetchOutcome struct {
	ok      bool
	message string
	err     error
}

// fetchCall is one fetch every concurrent resolution waits on. The outcome travels WITH the call,
// so a waiter can never be handed the result of the next fetch.
type fetchCall struct {
	done    chan struct{}
	outcome fetchOutcome
	// waiters are the lookups waiting on this fetch. A miss among them is recorded in the same
	// critical section that stores the merged set, so a lookup arriving between the two cannot
	// start a second fetch for a kid this one already failed to find.
	waiters []keyLookup
}

type keyLookup struct {
	kid    *string
	family string
	alg    string
}

type keySetCache struct {
	http         *httpClient
	jwksURL      string
	maxJWKSAgeMs float64
	clock        jwksClock
	// onEvent receives every key-set event. Test seam: the SDK has no logger to report them to.
	onEvent func(keySetEvent)

	mu    sync.Mutex
	state *keySetState
	// imported holds keys by key material + algorithm; a nil value records a JWK that failed to
	// import.
	imported     map[string]crypto.PublicKey
	lastMissAt   *float64
	lastFailedAt *float64
	inFlight     *fetchCall
	forceNext    bool
}

func newKeySetCache(h *httpClient, jwksURL string, maxJWKSAge time.Duration) *keySetCache {
	return &keySetCache{
		http:         h,
		jwksURL:      jwksURL,
		maxJWKSAgeMs: durationMs(maxJWKSAge),
		clock:        systemJWKSClock{start: time.Now()},
		state:        emptyKeySetState(),
		imported:     map[string]crypto.PublicKey{},
	}
}

func unavailableResolution(message string, cause error) keyResolution {
	return keyResolution{kind: resolutionUnavailable, message: message, cause: cause}
}

// resolve returns the keys that may verify a token of `family` carrying `kid` (nil: none) — or
// why none may. It fetches when the set is older than the TTL, after forceRefresh, or once per
// cooldown when `kid` is unknown.
func (c *keySetCache) resolve(ctx context.Context, kid *string, alg, family string) keyResolution {
	c.mu.Lock()
	now := c.clock.monotonicMs()
	forced := c.forceNext
	if !forced && c.isFreshLocked(now) {
		cached := c.resolveFromStateLocked(c.state, kid, family, alg)
		if cached.kind != resolutionUnknown {
			c.mu.Unlock()
			return cached
		}
		if c.lastMissAt != nil && now-*c.lastMissAt < durationMs(jwksRefetchCooldown) {
			c.mu.Unlock()
			return unavailableResolution("unknown key; the key set is refetched again after the cooldown", nil)
		}
	}

	recentlyFailed := !forced &&
		c.state.fetchedAt != nil &&
		c.lastFailedAt != nil &&
		now-*c.lastFailedAt < durationMs(jwksRefetchCooldown)
	var outcome fetchOutcome
	if recentlyFailed {
		outcome = fetchOutcome{message: "JWKS refetch failed recently; it is retried after the cooldown"}
	} else {
		call := c.startFetchLocked(ctx)
		call.waiters = append(call.waiters, keyLookup{kid: kid, family: family, alg: alg})
		c.mu.Unlock()
		select {
		case <-call.done:
			outcome = call.outcome
		case <-ctx.Done():
			cause := fmt.Errorf("waiting for the JWKS fetch: %w", ctx.Err())
			return unavailableResolution(cause.Error(), cause)
		}
		c.mu.Lock()
	}
	defer c.mu.Unlock()

	if !outcome.ok {
		if c.state.fetchedAt == nil {
			return unavailableResolution(outcome.message, outcome.err)
		}
		// An applied tombstone is final whatever the cache's age: no refetch could lift it.
		if known := selectKeys(c.state, kid, family); known.kind == selectionRevoked {
			return keyResolution{kind: resolutionRevoked, kid: known.kid}
		}
		age := c.cacheAgeMsLocked(c.clock.monotonicMs())
		if age > c.maxJWKSAgeMs {
			return keyResolution{kind: resolutionStale, cacheAgeSeconds: ageSeconds(age)}
		}
		fallback := withConfirmedKeysOnly(c.state)
		// A no-kid token tries every candidate: if the fallback lost one, a signature matching none
		// of the rest may still be that key's — "could not check", not a forgery.
		if kid == nil && candidateCount(fallback, family) < candidateCount(c.state, family) {
			return unavailableResolution(outcome.message, outcome.err)
		}
		cached := c.resolveFromStateLocked(fallback, kid, family, alg)
		if cached.kind == resolutionUnknown {
			return unavailableResolution(outcome.message, outcome.err)
		}
		return cached
	}

	// A miss here was already recorded by fetchAndMerge, with the set it was missing from.
	return c.resolveFromStateLocked(c.state, kid, family, alg)
}

// forceRefresh makes the next resolution refetch, ignoring the TTL and both cooldowns. It keeps
// what is known.
func (c *keySetCache) forceRefresh() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forceNext = true
}

// clearTombstones forgets every applied and pending tombstone — the documented manual reset.
func (c *keySetCache) clearTombstones() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = withoutTombstones(c.state)
}

type keySetDiagnostics struct {
	cacheAgeSeconds *int64
	registryLive    bool
	vanishedKids    []string
}

// diagnostics reports what the cache holds, for tests.
func (c *keySetCache) diagnostics() keySetDiagnostics {
	c.mu.Lock()
	defer c.mu.Unlock()
	var vanished []string
	for _, record := range c.state.orderedKeys() {
		if record.vanished && record.kid != "" {
			vanished = append(vanished, record.kid)
		}
	}
	return keySetDiagnostics{
		cacheAgeSeconds: ageSeconds(c.cacheAgeMsLocked(c.clock.monotonicMs())),
		registryLive:    isRegistryLive(c.state),
		vanishedKids:    vanished,
	}
}

func ageSeconds(ageMs float64) *int64 {
	if math.IsInf(ageMs, 0) {
		return nil
	}
	seconds := int64(math.Floor(ageMs / 1000))
	return &seconds
}

func (c *keySetCache) cacheAgeMsLocked(now float64) float64 {
	if c.state.fetchedAt == nil {
		return math.Inf(1)
	}
	return now - c.state.fetchedAt.monotonicMs
}

func (c *keySetCache) isFreshLocked(now float64) bool {
	return c.cacheAgeMsLocked(now) < durationMs(keySetTTL)
}

// startFetchLocked joins the fetch in flight or starts one. The fetch runs detached from the
// caller's cancellation: a waiter that gives up must not fail the fetch every other waiter shares.
func (c *keySetCache) startFetchLocked(ctx context.Context) *fetchCall {
	if c.inFlight != nil {
		return c.inFlight
	}
	c.forceNext = false
	call := &fetchCall{done: make(chan struct{})}
	c.inFlight = call
	go c.fetchAndMerge(context.WithoutCancel(ctx), call)
	return call
}

func (c *keySetCache) fetchAndMerge(ctx context.Context, call *fetchCall) {
	body, fetchErr := c.fetchDocumentRecovering(ctx)

	c.mu.Lock()
	var events []keySetEvent
	outcome := fetchOutcome{}
	if fetchErr != nil {
		outcome.message = fetchErr.Error()
		outcome.err = fetchErr
	} else {
		merged := mergeFetchedDocument(c.state, body, clockReading{
			monotonicMs: c.clock.monotonicMs(),
			wallMs:      c.clock.wallMs(),
		})
		events = merged.events
		if merged.accepted {
			c.state = merged.state
			c.lastFailedAt = nil
			outcome.ok = true
			for _, waiter := range call.waiters {
				if c.resolveFromStateLocked(c.state, waiter.kid, waiter.family, waiter.alg).kind == resolutionUnknown {
					missAt := c.clock.monotonicMs()
					c.lastMissAt = &missAt
					break
				}
			}
		} else if len(merged.events) > 0 {
			outcome.message = merged.events[0].Message
		} else {
			outcome.message = "JWKS refused"
		}
	}
	// Only a set with a cache to fall back on is held back; one never fetched is retried every call.
	if !outcome.ok && c.state.fetchedAt != nil {
		failedAt := c.clock.monotonicMs()
		c.lastFailedAt = &failedAt
	}
	call.outcome = outcome
	if c.inFlight == call {
		c.inFlight = nil
	}
	listener := c.onEvent
	c.mu.Unlock()

	if listener != nil {
		for _, event := range events {
			emitKeySetEvent(listener, event)
		}
	}
	close(call.done)
}

// emitKeySetEvent hands one event to the listener; a panicking listener must not turn into a
// verification failure.
func emitKeySetEvent(listener func(keySetEvent), event keySetEvent) {
	defer func() { _ = recover() }()
	listener(event)
}

// fetchDocumentRecovering runs fetchDocument on the background goroutine every waiter depends on: a
// panic there (a caller-supplied transport, say) becomes a failed fetch rather than taking the
// whole process down, which is what it would do outside the caller's goroutine.
func (c *keySetCache) fetchDocumentRecovering(ctx context.Context) (body map[string]any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			body, err = nil, fmt.Errorf("JWKS fetch panicked: %v", recovered)
		}
	}()
	return c.fetchDocument(ctx)
}

// fetchDocument reads the key set the way the status list is read: no credential, the branded
// User-Agent, redirects refused, a deadline and a size ceiling.
func (c *keySetCache) fetchDocument(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("JWKS request could not be built: %w", err)
	}
	// The branded User-Agent is required — the marketing edge answers 444 to library defaults.
	req.Header.Set("User-Agent", "proof-sdk-go/"+Version)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: c.http.client.Transport,
		Timeout:   jwksTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("JWKS fetch failed with HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxJWKSBytes {
		return nil, errors.New("JWKS response is too large")
	}
	// One byte over the ceiling is enough to know the body is oversized.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("JWKS body could not be read: %w", err)
	}
	if len(raw) > maxJWKSBytes {
		return nil, errors.New("JWKS response is too large")
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, errors.New("JWKS response is not a JSON object")
	}
	if _, ok := body["keys"].([]any); !ok {
		return nil, errors.New("JWKS response has no `keys` array")
	}
	return body, nil
}

func (c *keySetCache) resolveFromStateLocked(state *keySetState, kid *string, family, alg string) keyResolution {
	selection := selectKeys(state, kid, family)
	if selection.kind != selectionCandidates {
		return keyResolution{kind: selection.kind, kid: selection.kid}
	}
	var candidates []keyCandidate
	for _, record := range selection.records {
		if key := c.importRecordLocked(record, alg); key != nil {
			candidates = append(candidates, keyCandidate{key: key, record: record})
		}
	}
	if len(candidates) == 0 {
		return keyResolution{kind: resolutionUnknown}
	}
	return keyResolution{kind: resolutionKeys, candidates: candidates, registryLive: isRegistryLive(state)}
}

// importRecordLocked turns a record into a key usable with `alg`, or nil when it is not a
// candidate for it.
func (c *keySetCache) importRecordLocked(record *keyRecord, alg string) crypto.PublicKey {
	// A key declared for another algorithm, or for anything but signatures (RFC 7517 §4.2, §4.3),
	// is not a candidate. Checked before the import cache, which is keyed by material.
	jwk := record.jwk
	if declared, ok := jwk["alg"].(string); ok && declared != alg {
		return nil
	}
	if use, present := jwk["use"]; present && use != "sig" {
		return nil
	}
	if keyOps, present := jwk["key_ops"]; present && !containsVerify(keyOps) {
		return nil
	}
	cacheKey := record.fingerprint + "|" + alg
	if key, ok := c.imported[cacheKey]; ok {
		return key
	}
	key := importJWKFor(jwk, alg)
	c.imported[cacheKey] = key
	return key
}

func containsVerify(keyOps any) bool {
	ops, ok := keyOps.([]any)
	if !ok {
		return false
	}
	for _, op := range ops {
		if op == "verify" {
			return true
		}
	}
	return false
}

// importJWKFor converts the key material, requiring the key type the algorithm needs — an RSA key
// is no candidate for an ES256 token, exactly as an import for that algorithm refuses it.
func importJWKFor(jwk map[string]any, alg string) crypto.PublicKey {
	material := JWK{Kty: stringMember(jwk, "kty")}
	for member, target := range map[string]**string{"crv": &material.Crv, "x": &material.X, "y": &material.Y, "n": &material.N, "e": &material.E} {
		if value, ok := jwk[member].(string); ok {
			*target = &value
		}
	}
	switch {
	case alg == "RS256" && material.Kty == "RSA":
		key, err := rsaPublicKeyFromJWK(material)
		if err != nil {
			return nil
		}
		return key
	case alg == "ES256" && material.Kty == "EC":
		key, err := ecdsaPublicKeyFromJWK(material)
		if err != nil {
			return nil
		}
		return key
	default:
		return nil
	}
}

func stringMember(object map[string]any, member string) string {
	value, _ := object[member].(string)
	return value
}

func candidateCount(state *keySetState, family string) int {
	selection := selectKeys(state, nil, family)
	if selection.kind != selectionCandidates {
		return 0
	}
	return len(selection.records)
}
