package proof

// The key-rotation rules, free of I/O.
//
// A function-for-function port of packages/delegation-verifier/src/keyset.ts: how a fetched JWKS
// is merged into what the verifier already knows, and which key — if any — may verify a token of a
// given family. The shared cases in sdks/shared/fixtures/jwks_rotation/ pin the outcome of every
// rule across all five verifiers, so change a rule there first and port it here.
//
// The persistence half of the original (state serialization) is not ported: this SDK keeps its key
// set in memory only.
//
// Four properties are load-bearing:
//
//   - One response is never trusted for long. Anything that would outlive the next fetch — a key
//     being remembered, a window narrowing, a tombstone — takes effect only when a second fetch, at
//     least five minutes after the first sighting, says the same. A key verifies from its first
//     sighting, but until it is confirmed the next document replaces or drops it.
//   - A fetch is MERGED, never swapped in. A CONFIRMED registry key that disappears keeps its
//     last-known state, never gets new key material, and its window may narrow (by the rule above)
//     but never widen — a document that widens one is refused whole.
//   - An applied tombstone is sticky until every token the key signed is dead.
//   - "Registry live" is a property of the merged set (some key carries `proof_purpose`). Until then
//     the set is in tolerant mode and behaves exactly as it did before rotation existed.
//
// JSON numbers arrive as float64, as they do in the original: a "whole number" is a finite float64
// with no fractional part, which is what Number.isInteger reads.

import (
	"encoding/json"
	"fmt"
	"math"
)

const (
	keyFamilyProof      = "proof"
	keyFamilyDelegation = "delegation"
	keyFamilyStatusList = "status-list"

	// keyWindowSkewSeconds is the clock skew tolerated on each edge of a key's window.
	keyWindowSkewSeconds = 300
	// confirmSpacingMs is the minimum spacing between the two fetches that confirm a key, a
	// narrowed window or a tombstone.
	confirmSpacingMs = 5 * 60_000
	// tombstoneRetentionSeconds: an applied tombstone is kept until `revoked_at` plus this.
	tombstoneRetentionSeconds = 365 * 86_400
)

// clockReading is both clocks at one instant: monotonic for in-process intervals, wall for claims.
type clockReading struct {
	monotonicMs float64
	wallMs      float64
}

type pendingWindow struct {
	notBefore float64
	notAfter  float64
	firstSeen clockReading
}

type pendingTombstone struct {
	kid       string
	revokedAt float64
	firstSeen clockReading
}

type appliedTombstone struct {
	kid       string
	revokedAt float64
}

type keyRecord struct {
	// kid is "" for a key served without one.
	kid string
	// jwk is the JWK as last accepted, with any narrowing of its window applied.
	jwk map[string]any
	// fingerprint identifies the key material: a protected kid keeps its first material, an
	// unprotected one takes the latest.
	fingerprint string
	// usage is `alg`, `use` and `key_ops` — the members that decide whether the key may verify.
	usage            string
	hasPurposeMember bool
	purpose          string
	legacy           bool
	notBefore        *float64
	notAfter         *float64
	maxTokenLifetime *float64
	vanished         bool
	// firstSeen is when this exact description of the key was first served.
	firstSeen clockReading
	// confirmed: served unchanged by two fetches at least confirmSpacingMs apart.
	confirmed bool
	// pendingWindow is a narrower window served for a confirmed key, applied once a later fetch
	// confirms it.
	pendingWindow *pendingWindow
}

// keySetState is the merged key set. `keys` keeps its insertion order in `order`, as the
// original's Map does, so a no-kid token tries its candidates in the same order everywhere.
type keySetState struct {
	keys      map[string]*keyRecord
	order     []string
	anonymous []*keyRecord
	pending   map[string]pendingTombstone
	applied   map[string]appliedTombstone
	fetchedAt *clockReading
}

type keySetEvent struct {
	Type    string
	Kid     string
	Message string
}

type mergeResult struct {
	state  *keySetState
	events []keySetEvent
	// accepted is false when the document was refused whole; state is then the unchanged input.
	accepted bool
}

const (
	selectionCandidates   = "candidates"
	selectionRevoked      = "revoked"
	selectionWrongPurpose = "wrong_purpose"
	selectionUnknown      = "unknown"
)

type keySelection struct {
	kind    string
	records []*keyRecord
	kid     string
}

func emptyKeySetState() *keySetState {
	return &keySetState{
		keys:    map[string]*keyRecord{},
		pending: map[string]pendingTombstone{},
		applied: map[string]appliedTombstone{},
	}
}

func (s *keySetState) setKey(kid string, record *keyRecord) {
	if _, ok := s.keys[kid]; !ok {
		s.order = append(s.order, kid)
	}
	s.keys[kid] = record
}

func (s *keySetState) deleteKey(kid string) {
	if _, ok := s.keys[kid]; !ok {
		return
	}
	delete(s.keys, kid)
	for i, existing := range s.order {
		if existing == kid {
			s.order = append(s.order[:i:i], s.order[i+1:]...)
			break
		}
	}
}

// orderedKeys is the records of `keys` in insertion order.
func (s *keySetState) orderedKeys() []*keyRecord {
	records := make([]*keyRecord, 0, len(s.order))
	for _, kid := range s.order {
		records = append(records, s.keys[kid])
	}
	return records
}

func wholeNumber(value any) (float64, bool) {
	number, ok := value.(float64)
	if !ok || math.IsInf(number, 0) || math.IsNaN(number) || number != math.Trunc(number) {
		return 0, false
	}
	return number, true
}

func isKeyFamily(value any) bool {
	family, ok := value.(string)
	return ok && (family == keyFamilyProof || family == keyFamilyDelegation || family == keyFamilyStatusList)
}

// jsonOf renders members the way JSON.stringify does for the values a JWK holds; a member that
// is absent renders as null.
func jsonOf(jwk map[string]any, members ...string) string {
	values := make([]any, len(members))
	for i, member := range members {
		values[i] = jwk[member]
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return fmt.Sprintf("%v", values)
	}
	return string(encoded)
}

func fingerprintOf(jwk map[string]any) string {
	return jsonOf(jwk, "kty", "crv", "x", "y", "n", "e")
}

func usageOf(jwk map[string]any) string {
	return jsonOf(jwk, "alg", "use", "key_ops")
}

func parseKeyRecord(jwk map[string]any, firstSeen clockReading) *keyRecord {
	_, hasPurpose := jwk["proof_purpose"]
	legacy, _ := jwk["proof_legacy"].(bool)
	record := &keyRecord{
		jwk:              jwk,
		fingerprint:      fingerprintOf(jwk),
		usage:            usageOf(jwk),
		hasPurposeMember: hasPurpose,
		legacy:           legacy,
		firstSeen:        firstSeen,
	}
	if kid, ok := jwk["kid"].(string); ok && kid != "" {
		record.kid = kid
	}
	if isKeyFamily(jwk["proof_purpose"]) {
		record.purpose = jwk["proof_purpose"].(string)
	}
	if value, ok := wholeNumber(jwk["not_before"]); ok {
		record.notBefore = &value
	}
	if value, ok := wholeNumber(jwk["not_after"]); ok {
		record.notAfter = &value
	}
	if value, ok := wholeNumber(jwk["max_token_lifetime"]); ok {
		record.maxTokenLifetime = &value
	}
	return record
}

func hasWindow(record *keyRecord) bool {
	return record.notBefore != nil && record.notAfter != nil && record.maxTokenLifetime != nil
}

// isProtectedRecord: a key the issuer's registry describes — it carries `proof_purpose` or
// `proof_legacy` — AND that two fetches at least confirmSpacingMs apart served unchanged. The ONE
// predicate behind every rule that outlives a fetch: material lock, no widening, pending
// narrowing, retained when it vanishes.
func isProtectedRecord(record *keyRecord) bool {
	return record.confirmed && (record.hasPurposeMember || record.legacy)
}

func equalOptional(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// describesSameKey: material, usage, purpose, legacy marker and window. Usage counts because the
// record kept is the one first seen: a poisoned first sighting marked `use: "enc"` must be
// replaced by the honest description, not confirmed by it.
func describesSameKey(a, b *keyRecord) bool {
	return a.fingerprint == b.fingerprint &&
		a.usage == b.usage &&
		a.hasPurposeMember == b.hasPurposeMember &&
		a.purpose == b.purpose &&
		a.legacy == b.legacy &&
		equalOptional(a.notBefore, b.notBefore) &&
		equalOptional(a.notAfter, b.notAfter) &&
		equalOptional(a.maxTokenLifetime, b.maxTokenLifetime)
}

func spacingElapsed(since, now clockReading) bool {
	return now.monotonicMs-since.monotonicMs >= confirmSpacingMs
}

func isRegistryLive(state *keySetState) bool {
	for _, record := range state.keys {
		if record.hasPurposeMember {
			return true
		}
	}
	for _, record := range state.anonymous {
		if record.hasPurposeMember {
			return true
		}
	}
	return false
}

func wallSeconds(reading clockReading) float64 {
	return math.Floor(reading.wallMs / 1000)
}

// isLiveKey: whether a kid may still be signing — legacy, window unknown, or not yet past
// `not_after`.
func isLiveKey(record *keyRecord, nowSeconds float64) bool {
	if record.legacy || !hasWindow(record) {
		return true
	}
	return nowSeconds <= *record.notAfter+keyWindowSkewSeconds
}

func parseTombstones(value any) []appliedTombstone {
	entries, ok := value.([]any)
	if !ok {
		return nil
	}
	var tombstones []appliedTombstone
	for _, entry := range entries {
		object, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		kid, ok := object["kid"].(string)
		if !ok || kid == "" {
			continue
		}
		revokedAt, ok := wholeNumber(object["revoked_at"])
		if !ok {
			continue
		}
		tombstones = append(tombstones, appliedTombstone{kid: kid, revokedAt: revokedAt})
	}
	return tombstones
}

func cloneState(state *keySetState) *keySetState {
	next := &keySetState{
		keys:      make(map[string]*keyRecord, len(state.keys)),
		order:     append([]string(nil), state.order...),
		anonymous: make([]*keyRecord, 0, len(state.anonymous)),
		pending:   make(map[string]pendingTombstone, len(state.pending)),
		applied:   make(map[string]appliedTombstone, len(state.applied)),
		fetchedAt: state.fetchedAt,
	}
	for kid, record := range state.keys {
		copied := *record
		next.keys[kid] = &copied
	}
	for _, record := range state.anonymous {
		copied := *record
		next.anonymous = append(next.anonymous, &copied)
	}
	for kid, pending := range state.pending {
		next.pending[kid] = pending
	}
	for kid, applied := range state.applied {
		next.applied[kid] = applied
	}
	return next
}

// mergeFetchedDocument merges one fetched JWKS body (already known to be an object with a `keys`
// array) into `state`. Pure: returns a new state and the events the caller should report.
func mergeFetchedDocument(state *keySetState, body map[string]any, now clockReading) mergeResult {
	nowSeconds := wallSeconds(now)
	entries, _ := body["keys"].([]any)
	served := map[string]*keyRecord{}
	var servedOrder []string
	var anonymous []*keyRecord
	for _, entry := range entries {
		jwk, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		record := parseKeyRecord(jwk, now)
		if record.kid == "" {
			anonymous = append(anonymous, record)
			continue
		}
		if _, seen := served[record.kid]; !seen {
			servedOrder = append(servedOrder, record.kid)
		}
		served[record.kid] = record
	}

	// Widening is checked before anything is touched: such a document is refused whole.
	for _, kid := range servedOrder {
		incoming := served[kid]
		known, ok := state.keys[kid]
		if !ok || !isProtectedRecord(known) || !hasWindow(known) || !hasWindow(incoming) {
			continue
		}
		if *incoming.notBefore < *known.notBefore || *incoming.notAfter > *known.notAfter {
			return mergeResult{
				state:    state,
				accepted: false,
				events: []keySetEvent{{
					Type:    "window_widening_rejected",
					Kid:     kid,
					Message: fmt.Sprintf("JWKS refused: it widens the window of confirmed key %q", kid),
				}},
			}
		}
	}

	next := cloneState(state)
	var events []keySetEvent
	tombstones := parseTombstones(body["proof_tombstones"])
	tombstonedNow := map[string]bool{}
	for _, tombstone := range tombstones {
		tombstonedNow[tombstone.kid] = true
	}

	for _, kid := range servedOrder {
		incoming := served[kid]
		known, ok := next.keys[kid]
		// Not protected yet: the latest document describes the key, exactly as before rotation
		// existed. Serving the same description again, far enough apart, confirms it.
		if !ok || !isProtectedRecord(known) {
			if ok && describesSameKey(known, incoming) {
				if !known.confirmed && spacingElapsed(known.firstSeen, now) {
					known.confirmed = true
				}
			} else {
				next.setKey(kid, incoming)
			}
			continue
		}
		known.vanished = false
		if known.fingerprint != incoming.fingerprint {
			known.pendingWindow = nil
			events = append(events, keySetEvent{
				Type:    "key_material_changed",
				Kid:     kid,
				Message: fmt.Sprintf("JWKS serves different key material for confirmed key %q; the first-seen key is kept", kid),
			})
			continue
		}
		if !hasWindow(known) || !hasWindow(incoming) {
			continue
		}
		if *incoming.notBefore == *known.notBefore && *incoming.notAfter == *known.notAfter {
			known.pendingWindow = nil
			continue
		}
		pending := known.pendingWindow
		if pending == nil || pending.notBefore != *incoming.notBefore || pending.notAfter != *incoming.notAfter {
			known.pendingWindow = &pendingWindow{notBefore: *incoming.notBefore, notAfter: *incoming.notAfter, firstSeen: now}
			events = append(events, keySetEvent{
				Type: "window_narrowing_pending",
				Kid:  kid,
				Message: fmt.Sprintf(
					"JWKS narrows the window of confirmed key %q; applied only if a fetch at least 5 minutes later serves the same window", kid),
			})
			continue
		}
		if !spacingElapsed(pending.firstSeen, now) {
			continue
		}
		notBefore, notAfter := pending.notBefore, pending.notAfter
		known.notBefore = &notBefore
		known.notAfter = &notAfter
		narrowed := make(map[string]any, len(known.jwk))
		for member, value := range known.jwk {
			narrowed[member] = value
		}
		narrowed["not_before"] = notBefore
		narrowed["not_after"] = notAfter
		known.jwk = narrowed
		known.pendingWindow = nil
		events = append(events, keySetEvent{
			Type:    "window_narrowing_applied",
			Kid:     kid,
			Message: fmt.Sprintf("narrowed window of key %q confirmed by a second fetch and applied", kid),
		})
	}

	for _, kid := range append([]string(nil), next.order...) {
		if _, ok := served[kid]; ok {
			continue
		}
		known := next.keys[kid]
		if !isProtectedRecord(known) {
			next.deleteKey(kid)
			continue
		}
		if hasWindow(known) {
			if nowSeconds > *known.notAfter+*known.maxTokenLifetime+keyWindowSkewSeconds {
				next.deleteKey(kid)
				continue
			}
		} else if !known.legacy {
			next.deleteKey(kid)
			continue
		}
		// A narrowing is confirmed by consecutive documents serving it; one that omits the kid
		// breaks the run.
		known.pendingWindow = nil
		if !known.vanished && !tombstonedNow[kid] {
			known.vanished = true
			events = append(events, keySetEvent{
				Type:    "kid_vanished",
				Kid:     kid,
				Message: fmt.Sprintf("key %q is no longer served before its retention ended; its last-known state is kept", kid),
			})
		}
	}

	next.anonymous = anonymous

	for kid := range next.pending {
		if !tombstonedNow[kid] {
			delete(next.pending, kid)
		}
	}
	for _, tombstone := range tombstones {
		if _, ok := next.applied[tombstone.kid]; ok {
			continue
		}
		if pending, ok := next.pending[tombstone.kid]; ok {
			if spacingElapsed(pending.firstSeen, now) {
				delete(next.pending, tombstone.kid)
				next.applied[tombstone.kid] = appliedTombstone{kid: tombstone.kid, revokedAt: pending.revokedAt}
				events = append(events, keySetEvent{
					Type:    "tombstone_applied",
					Kid:     tombstone.kid,
					Message: fmt.Sprintf("tombstone for key %q confirmed by a second fetch and applied", tombstone.kid),
				})
			}
			continue
		}
		next.pending[tombstone.kid] = pendingTombstone{kid: tombstone.kid, revokedAt: tombstone.revokedAt, firstSeen: now}
		events = append(events, keySetEvent{
			Type: "tombstone_pending",
			Kid:  tombstone.kid,
			Message: fmt.Sprintf(
				"tombstone for key %q seen; applied only if a fetch at least 5 minutes later still carries it", tombstone.kid),
		})
		// "Last seen live" is read from what the verifier knew BEFORE this document, which may
		// itself have dropped the key.
		if known, ok := state.keys[tombstone.kid]; ok && isLiveKey(known, nowSeconds) {
			events = append(events, keySetEvent{
				Type:    "tombstone_for_live_key",
				Kid:     tombstone.kid,
				Message: fmt.Sprintf("ANOMALY: tombstone names key %q, which was last seen live", tombstone.kid),
			})
		}
	}

	for kid, applied := range next.applied {
		if nowSeconds > applied.revokedAt+tombstoneRetentionSeconds {
			delete(next.applied, kid)
		}
	}

	fetchedAt := now
	next.fetchedAt = &fetchedAt
	return mergeResult{state: next, events: events, accepted: true}
}

// selectKeys: which keys may verify a token of `family` carrying `kid` (nil: the token has none).
// Checks the applied tombstone and the key's purpose; the signature and the window are the
// caller's next steps, in that order.
func selectKeys(state *keySetState, kid *string, family string) keySelection {
	registryLive := isRegistryLive(state)
	if kid != nil {
		if _, ok := state.applied[*kid]; ok {
			return keySelection{kind: selectionRevoked, kid: *kid}
		}
		record, ok := state.keys[*kid]
		if !ok {
			return keySelection{kind: selectionUnknown}
		}
		if record.legacy || !registryLive {
			return keySelection{kind: selectionCandidates, records: []*keyRecord{record}}
		}
		if record.purpose != family {
			return keySelection{kind: selectionWrongPurpose, kid: *kid}
		}
		return keySelection{kind: selectionCandidates, records: []*keyRecord{record}}
	}

	// No `kid`: once the registry is live only a key marked legacy may answer — trying every key
	// would let a token borrow any family's key and skip the purpose check.
	var records []*keyRecord
	for _, record := range append(append([]*keyRecord(nil), state.anonymous...), state.orderedKeys()...) {
		if record.kid != "" {
			if _, revoked := state.applied[record.kid]; revoked {
				continue
			}
		}
		if registryLive && !record.legacy {
			continue
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return keySelection{kind: selectionUnknown}
	}
	return keySelection{kind: selectionCandidates, records: records}
}

// checkKeyPolicy: the window and lifetime rules for a key whose signature has verified. Returns
// "" when the token passes, else "outside_key_window" or "token_lifetime_exceeded".
func checkKeyPolicy(record *keyRecord, iat, exp any, registryLive bool) string {
	if !registryLive || record.legacy {
		return ""
	}
	if !hasWindow(record) {
		return "outside_key_window"
	}
	issuedAt, ok := wholeNumber(iat)
	if !ok {
		return "outside_key_window"
	}
	if issuedAt < *record.notBefore-keyWindowSkewSeconds {
		return "outside_key_window"
	}
	if issuedAt > *record.notAfter+keyWindowSkewSeconds {
		return "outside_key_window"
	}
	expiresAt, ok := exp.(float64)
	if !ok || expiresAt > issuedAt+*record.maxTokenLifetime {
		return "token_lifetime_exceeded"
	}
	return ""
}

// withConfirmedKeysOnly is the part of a cached set that may answer after a refetch FAILED:
// confirmed keys only. An unconfirmed key is trusted until the next document, and a failing fetch
// must not stretch that to maxJwksAge — otherwise one poisoned response followed by an outage
// would keep its key, and the registry mode it switched on, for a day.
func withConfirmedKeysOnly(state *keySetState) *keySetState {
	next := cloneState(state)
	for _, kid := range append([]string(nil), next.order...) {
		if !next.keys[kid].confirmed {
			next.deleteKey(kid)
		}
	}
	next.anonymous = nil
	return next
}

// withoutTombstones drops every applied and pending tombstone — the documented manual reset.
func withoutTombstones(state *keySetState) *keySetState {
	next := cloneState(state)
	next.applied = map[string]appliedTombstone{}
	next.pending = map[string]pendingTombstone{}
	return next
}
