package proof

// Offline verification follows the issuer's key-rotation rules (h-verifier-jwks-go-php).
//
// The shared cases in sdks/shared/fixtures/jwks_rotation/rotation_cases.json run here through the
// PUBLIC surface — NewClient, Proofs.VerifyOffline, RefreshJWKS, ClearTombstones — with the
// client's transport routed to the case's documents. The same file drives delegation-verifier and
// the other SDKs, so a rule read differently here fails here. Step semantics: the README beside
// the file.
//
// Fixture names map onto this SDK's own vocabulary, which predates them: "bad_signature" is
// Reason "invalid" (pinned further by its message, so an `iss` failure cannot pass for it), and
// "jwks_unavailable" is an error wrapping ErrJWKSUnavailable — or, for a status list that could
// not be checked, Reason "status_unavailable".
//
// The cases move both clocks together, so they cannot tell them apart; the clock-base tests below
// set them apart on purpose.

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	fixtureMinute = 60
	fixtureHour   = 3600
)

type rotationFixture struct {
	Context struct {
		T0                       int64  `json:"t0"`
		JWKSURI                  string `json:"jwks_uri"`
		IssuerOrigin             string `json:"issuer_origin"`
		StatusListURI            string `json:"status_list_uri"`
		DefaultMaxJWKSAgeSeconds int64  `json:"default_max_jwks_age_seconds"`
	} `json:"context"`
	Documents   map[string]json.RawMessage `json:"documents"`
	Tokens      map[string]fixtureJWT      `json:"tokens"`
	StatusLists map[string]fixtureJWT      `json:"status_lists"`
	Cases       []rotationCase             `json:"cases"`
}

type fixtureJWT struct {
	JWT string `json:"jwt"`
}

type rotationCase struct {
	Name              string         `json:"name"`
	Families          []string       `json:"families"`
	Requires          []string       `json:"requires"`
	MaxJWKSAgeSeconds *int64         `json:"max_jwks_age_seconds"`
	Steps             []rotationStep `json:"steps"`
}

type rotationStep struct {
	At          int64   `json:"at"`
	JWKS        *string `json:"jwks"`
	StatusList  *string `json:"status_list"`
	Action      string  `json:"action"`
	Verify      string  `json:"verify"`
	StatusCheck bool    `json:"status_check"`
	Expect      struct {
		Result          string    `json:"result"`
		Fetches         int32     `json:"fetches"`
		PullHintHandle  *string   `json:"pull_hint_handle"`
		CacheAgeSeconds *int64    `json:"cache_age_seconds"`
		Events          []string  `json:"events"`
		VanishedKids    *[]string `json:"vanished_kids"`
	} `json:"expect"`
}

func loadRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "shared", "fixtures", "jwks_rotation", "rotation_cases.json"))
	if err != nil {
		t.Fatalf("read jwks_rotation/rotation_cases.json: %v", err)
	}
	var fixture rotationFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode rotation_cases.json: %v", err)
	}
	return &fixture
}

// runnableRotationCases: the families VerifyOffline checks; this SDK has no key-set persistence.
func runnableRotationCases(fixture *rotationFixture) []rotationCase {
	families := map[string]bool{"proof": true, "delegation": true, "status-list": true}
	var runnable []rotationCase
cases:
	for _, c := range fixture.Cases {
		for _, family := range c.Families {
			if !families[family] {
				continue cases
			}
		}
		if len(c.Requires) > 0 {
			continue
		}
		runnable = append(runnable, c)
	}
	return runnable
}

type fixtureClock struct {
	mu                         sync.Mutex
	monotonicSeconds, wallSecs float64
}

func (c *fixtureClock) set(monotonicSeconds, wallSeconds int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.monotonicSeconds = float64(monotonicSeconds)
	c.wallSecs = float64(wallSeconds)
}

func (c *fixtureClock) monotonicMs() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.monotonicSeconds * 1000
}

func (c *fixtureClock) wallMs() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wallSecs * 1000
}

// fixtureIssuer is what the issuer's two public documents answer, and how often the key set was
// asked for.
type fixtureIssuer struct {
	t           *testing.T
	fixture     *rotationFixture
	mu          sync.Mutex
	jwks        *string
	statusList  *string
	jwksFetches atomic.Int32
	listFetches atomic.Int32
	// rawJWKS, when set, is served as the key-set body with HTTP 200 instead of a named document.
	rawJWKS *string
	// redirectJWKS answers the key-set URL with a 302 to redirectTarget, which serves registry_v1.
	redirectJWKS bool
	// rawStatusList, when set, is served as the status-list body instead of a named list.
	rawStatusList *string
	// failWith makes the key-set request fail in the transport; panicWith makes it panic.
	failWith     error
	panicWith    any
	gate         chan struct{}
	unexpectedTo []string
}

func (i *fixtureIssuer) serve(jwks, statusList *string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.jwks = jwks
	i.statusList = statusList
}

func (i *fixtureIssuer) RoundTrip(req *http.Request) (*http.Response, error) {
	respond := func(status int, body string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	}
	// Both are public documents: no credential, the branded User-Agent.
	if req.Header.Get("Authorization") != "" || !strings.HasPrefix(req.Header.Get("User-Agent"), "proof-sdk-go/") {
		return respond(400, "credential or library user agent on a public read")
	}
	i.mu.Lock()
	jwks, statusList, gate, rawJWKS, redirect := i.jwks, i.statusList, i.gate, i.rawJWKS, i.redirectJWKS
	rawStatusList, failWith, panicWith := i.rawStatusList, i.failWith, i.panicWith
	i.mu.Unlock()
	switch req.URL.String() {
	case redirectTarget:
		return respond(200, string(i.fixture.Documents["registry_v1"]))
	case i.fixture.Context.JWKSURI:
		i.jwksFetches.Add(1)
		if panicWith != nil {
			panic(panicWith)
		}
		if failWith != nil {
			return nil, failWith
		}
		if gate != nil {
			// A real transport gives up when the request's context does; this one must too, or a
			// fetch bound to a cancelled caller would look like one that is not.
			select {
			case <-gate:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		if rawJWKS != nil {
			return respond(200, *rawJWKS)
		}
		if redirect {
			response, _ := respond(302, "")
			response.Header.Set("Location", redirectTarget)
			return response, nil
		}
		if jwks == nil {
			return respond(503, "unavailable")
		}
		return respond(200, string(i.fixture.Documents[*jwks]))
	case i.fixture.Context.StatusListURI:
		i.listFetches.Add(1)
		if rawStatusList != nil {
			return respond(200, *rawStatusList)
		}
		if statusList == nil || *statusList == "" {
			return respond(404, "not found")
		}
		return respond(200, i.fixture.StatusLists[*statusList].JWT)
	}
	i.mu.Lock()
	i.unexpectedTo = append(i.unexpectedTo, req.URL.String())
	i.mu.Unlock()
	return respond(599, "unexpected fetch")
}

// redirectTarget is where a redirecting key-set URL points: a host the client was not configured
// with.
const redirectTarget = "https://elsewhere.example/jwks.json"

type rotationHarness struct {
	fixture *rotationFixture
	issuer  *fixtureIssuer
	clock   *fixtureClock
	proofs  *Proofs
	events  []string
	eventMu sync.Mutex
}

func newRotationHarness(t *testing.T, fixture *rotationFixture, opts ...ClientOption) *rotationHarness {
	t.Helper()
	client, err := NewClient("pk_test_fixture", append([]ClientOption{WithBaseURL(fixture.Context.IssuerOrigin)}, opts...)...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	h := &rotationHarness{
		fixture: fixture,
		issuer:  &fixtureIssuer{t: t, fixture: fixture},
		clock:   &fixtureClock{},
		proofs:  client.Proofs,
	}
	client.Proofs.http.client.Transport = h.issuer
	keys := client.Proofs.keys()
	keys.clock = h.clock
	keys.onEvent = func(event keySetEvent) {
		h.eventMu.Lock()
		defer h.eventMu.Unlock()
		h.events = append(h.events, event.Type)
	}
	t.Cleanup(func() {
		if len(h.issuer.unexpectedTo) > 0 {
			t.Errorf("unexpected fetches: %v", h.issuer.unexpectedTo)
		}
	})
	return h
}

func (h *rotationHarness) token(name string) string {
	return h.fixture.Tokens[name].JWT
}

func (h *rotationHarness) serveJWKS(name string) {
	h.issuer.serve(&name, nil)
}

func (h *rotationHarness) verify(t *testing.T, token string, opts ...OfflineOption) (*OfflineVerificationResult, error) {
	t.Helper()
	return h.proofs.VerifyOffline(context.Background(), token, opts...)
}

// fixtureOutcome is the fixture's name for an SDK answer. A token's key set that cannot be used is
// an ErrJWKSUnavailable error (D-GP2); only a status list that could not be checked answers
// Reason "status_unavailable", so that reading maps only for a step that checks the list.
func fixtureOutcome(result *OfflineVerificationResult, err error, statusCheck bool) string {
	if err != nil {
		if errors.Is(err, ErrJWKSUnavailable) {
			return "jwks_unavailable"
		}
		return "unexpected error: " + err.Error()
	}
	if result.Valid {
		return "valid"
	}
	switch result.Reason {
	case "invalid":
		return "bad_signature"
	case "status_unavailable":
		if statusCheck {
			return "jwks_unavailable"
		}
	case "":
		return "missing reason"
	}
	return result.Reason
}

func TestJWKSRotation_RunsAMeaningfulShareOfTheSharedCases(t *testing.T) {
	// A filter that skips everything must not pass.
	fixture := loadRotationFixture(t)
	runnable := runnableRotationCases(fixture)
	names := map[string]bool{}
	for _, c := range runnable {
		names[c.Name] = true
	}
	if len(runnable) < 30 {
		t.Fatalf("want at least 30 runnable cases, got %d", len(runnable))
	}
	for _, expected := range []string{
		"unknown_status_list_kid",
		"tombstone_proof_pull_hint",
		"clear_tombstones_lifts_applied_tombstone",
		"tolerant_mode",
		"max_jwks_age_refetch_failure_over_bound",
	} {
		if !names[expected] {
			t.Errorf("case %q is not run", expected)
		}
	}
	var skipped []string
	for _, c := range fixture.Cases {
		if !names[c.Name] {
			skipped = append(skipped, c.Name)
		}
	}
	if strings.Join(skipped, ",") != "tombstone_persists_across_reload" {
		t.Errorf("want only tombstone_persists_across_reload skipped, got %v", skipped)
	}
}

func TestJWKSRotation_SharedCases(t *testing.T) {
	fixture := loadRotationFixture(t)
	for _, c := range runnableRotationCases(fixture) {
		t.Run(c.Name, func(t *testing.T) {
			maxAge := fixture.Context.DefaultMaxJWKSAgeSeconds
			if c.MaxJWKSAgeSeconds != nil {
				maxAge = *c.MaxJWKSAgeSeconds
			}
			h := newRotationHarness(t, fixture, WithMaxJWKSAge(time.Duration(maxAge)*time.Second))
			for _, step := range c.Steps {
				where := c.Name + " @ t0" + signedSeconds(step.At-fixture.Context.T0)
				h.clock.set(step.At, step.At)
				h.issuer.serve(step.JWKS, step.StatusList)
				h.issuer.jwksFetches.Store(0)
				h.eventMu.Lock()
				h.events = nil
				h.eventMu.Unlock()

				switch step.Action {
				case "":
				case "refresh":
					h.proofs.RefreshJWKS()
				case "clear_tombstones":
					h.proofs.ClearTombstones()
				default:
					t.Fatalf("%s: unsupported action %q", where, step.Action)
				}

				expected := step.Expect
				if step.Verify != "" {
					var opts []OfflineOption
					if !step.StatusCheck {
						opts = append(opts, WithoutRevocationCheck())
					}
					result, err := h.verify(t, h.token(step.Verify), opts...)
					if got := fixtureOutcome(result, err, step.StatusCheck); got != expected.Result {
						detail := ""
						if result != nil {
							detail = result.Error
						}
						t.Fatalf("%s: want %s, got %s (%s)", where, expected.Result, got, detail)
					}
					if expected.Result == "bad_signature" && result.Error != "signature verification failed" {
						t.Errorf("%s: bad_signature answered %q", where, result.Error)
					}
					if expected.PullHintHandle != nil {
						hint := result.PullHint
						if hint == nil || hint.IssuerOrigin != fixture.Context.IssuerOrigin ||
							hint.Handle == nil || *hint.Handle != *expected.PullHintHandle {
							t.Errorf("%s: pull hint %+v", where, hint)
						}
					}
					if expected.CacheAgeSeconds != nil {
						if result.CacheAgeSeconds == nil || *result.CacheAgeSeconds != *expected.CacheAgeSeconds {
							t.Errorf("%s: cache age %v, want %d", where, result.CacheAgeSeconds, *expected.CacheAgeSeconds)
						}
					}
				}

				if got := h.issuer.jwksFetches.Load(); got != expected.Fetches {
					t.Errorf("%s: JWKS fetches %d, want %d", where, got, expected.Fetches)
				}
				h.eventMu.Lock()
				seen := strings.Join(h.events, ",")
				h.eventMu.Unlock()
				for _, eventType := range expected.Events {
					if !strings.Contains(","+seen+",", ","+eventType+",") {
						t.Errorf("%s: event %s not among [%s]", where, eventType, seen)
					}
				}
				if expected.VanishedKids != nil {
					got := strings.Join(h.proofs.keys().diagnostics().vanishedKids, ",")
					if want := strings.Join(*expected.VanishedKids, ","); got != want {
						t.Errorf("%s: vanished kids [%s], want [%s]", where, got, want)
					}
				}
			}
		})
	}
}

func signedSeconds(delta int64) string {
	if delta >= 0 {
		return "+" + time.Duration(delta*int64(time.Second)).String()
	}
	return "-" + time.Duration(-delta*int64(time.Second)).String()
}

// h-verifier-jwks-go-php SC-8: the two clocks on different bases.

func TestJWKSRotation_ReusesTheKeySetOnTheMonotonicClock(t *testing.T) {
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	t0 := fixture.Context.T0
	h.serveJWKS("registry_v1")

	h.clock.set(t0, t0)
	if result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck()); err != nil || !result.Valid {
		t.Fatalf("first: %+v %v", result, err)
	}
	h.clock.set(t0+fixtureMinute, t0+11*fixtureMinute)
	if result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck()); err != nil || !result.Valid {
		t.Fatalf("second: %+v %v", result, err)
	}
	if got := h.issuer.jwksFetches.Load(); got != 1 {
		t.Fatalf("want the set reused on the monotonic clock, got %d fetches", got)
	}
	h.clock.set(t0+11*fixtureMinute, t0+11*fixtureMinute)
	if result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck()); err != nil || !result.Valid {
		t.Fatalf("third: %+v %v", result, err)
	}
	if got := h.issuer.jwksFetches.Load(); got != 2 {
		t.Fatalf("want a refetch once the monotonic age passes the TTL, got %d fetches", got)
	}
}

func TestJWKSRotation_MeasuresStalenessOnTheMonotonicClock(t *testing.T) {
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	t0 := fixture.Context.T0
	h.serveJWKS("registry_v1")
	h.clock.set(t0, t0)
	if _, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck()); err != nil {
		t.Fatal(err)
	}
	h.issuer.serve(nil, nil)
	h.clock.set(t0+25*fixtureHour, t0+fixtureHour)
	result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck())
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != "jwks_stale" || result.CacheAgeSeconds == nil || *result.CacheAgeSeconds != 25*fixtureHour {
		t.Fatalf("want jwks_stale aged 25h, got %+v", result)
	}
}

func TestJWKSRotation_SpacesATombstoneConfirmationOnTheMonotonicClock(t *testing.T) {
	fixture := loadRotationFixture(t)
	t0 := fixture.Context.T0
	confirmedThenTombstoned := func(monotonic, wall int64) *OfflineVerificationResult {
		h := newRotationHarness(t, fixture)
		h.serveJWKS("registry_v1")
		for _, at := range []int64{t0 - 11*fixtureMinute, t0} {
			h.clock.set(at, at)
			if _, err := h.verify(t, h.token("dlg_retired"), WithoutRevocationCheck()); err != nil {
				t.Fatal(err)
			}
		}
		h.serveJWKS("registry_tombstone_retired_delegation")
		h.clock.set(t0+11*fixtureMinute, t0+11*fixtureMinute)
		if _, err := h.verify(t, h.token("dlg_retired"), WithoutRevocationCheck()); err != nil {
			t.Fatal(err)
		}
		h.clock.set(monotonic, wall)
		h.proofs.RefreshJWKS()
		result, err := h.verify(t, h.token("dlg_retired"), WithoutRevocationCheck())
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	if result := confirmedThenTombstoned(t0+17*fixtureMinute, t0+12*fixtureMinute); result.Reason != "key_revoked" {
		t.Errorf("6 monotonic minutes apart: want key_revoked, got %+v", result)
	}
	if result := confirmedThenTombstoned(t0+12*fixtureMinute, t0+17*fixtureMinute); !result.Valid {
		t.Errorf("1 monotonic minute apart: want still valid, got %+v", result)
	}
}

func TestJWKSRotation_ChecksExpAgainstTheWallClock(t *testing.T) {
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	t0 := fixture.Context.T0
	h.serveJWKS("registry_v1")
	h.clock.set(t0, t0+40*86_400)
	result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck())
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != "expired" {
		t.Fatalf("want expired on the wall clock, got %+v", result)
	}
}

func TestJWKSRotation_ChecksTheStatusListExpAgainstTheWallClock(t *testing.T) {
	fixture := loadRotationFixture(t)
	t0 := fixture.Context.T0
	run := func(wall int64) *OfflineVerificationResult {
		h := newRotationHarness(t, fixture)
		registry, statusList := "registry_v1_status_emergency", "list_on_emergency_status_key"
		h.issuer.serve(&registry, &statusList)
		h.clock.set(t0, wall)
		result, err := h.verify(t, h.token("dlg_active_with_status"))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := run(t0 + 2*fixtureMinute); !result.Valid || !result.RevocationChecked {
		t.Fatalf("positive control: want a checked valid token inside the list's exp, got %+v", result)
	}
	if result := run(t0 + 2*fixtureHour); result.Reason != "status_unavailable" ||
		!strings.Contains(result.Error, "status list has expired") {
		t.Fatalf("want the list expired on the wall clock, got %+v", result)
	}
}

func TestJWKSRotation_TheStatusListCacheExpiresOnTheWallClock(t *testing.T) {
	// The list is reused until its own exp — read on the clock every other claim check reads, not
	// on the host's.
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	t0 := fixture.Context.T0
	registry, statusList := "registry_v1_status_emergency", "list_on_emergency_status_key"
	h.issuer.serve(&registry, &statusList)

	h.clock.set(t0+fixtureMinute, t0+fixtureMinute)
	if result, err := h.verify(t, h.token("dlg_active_with_status")); err != nil || !result.RevocationChecked {
		t.Fatalf("first: %+v %v", result, err)
	}
	h.clock.set(t0+fixtureMinute+1, t0+fixtureHour-1)
	if result, err := h.verify(t, h.token("dlg_active_with_status")); err != nil || !result.Valid {
		t.Fatalf("inside the list's exp: %+v %v", result, err)
	}
	if got := h.issuer.listFetches.Load(); got != 1 {
		t.Fatalf("positive control: want the list reused inside its exp, got %d reads", got)
	}

	h.clock.set(t0+fixtureMinute+2, t0+fixtureHour+100)
	result, err := h.verify(t, h.token("dlg_active_with_status"))
	if err != nil {
		t.Fatal(err)
	}
	if got := h.issuer.listFetches.Load(); got != 2 || result.Reason != "status_unavailable" {
		t.Fatalf("want the list re-read once the wall clock passes its exp, got %d reads and %+v", got, result)
	}
}

func TestJWKSRotation_AResponseThatIsNotAKeySetIsAFailedFetch(t *testing.T) {
	// An HTTP 200 carrying something that is not a key set must count as a FAILED fetch: merged as
	// an empty document it would renew the set's age, and the TTL — what heals a REMOVED key —
	// would stop running.
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	t0 := fixture.Context.T0
	h.serveJWKS("registry_v1")
	for _, at := range []int64{t0 - 11*fixtureMinute, t0} {
		h.clock.set(at, at)
		if result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck()); err != nil || !result.Valid {
			t.Fatalf("confirming: %+v %v", result, err)
		}
	}

	notAKeySet := `{"error":"maintenance"}`
	h.issuer.mu.Lock()
	h.issuer.rawJWKS = &notAKeySet
	h.issuer.mu.Unlock()
	h.clock.set(t0+11*fixtureMinute, t0+11*fixtureMinute)
	h.issuer.jwksFetches.Store(0)
	if result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck()); err != nil || !result.Valid {
		t.Fatalf("the confirmed key must answer from the cache: %+v %v", result, err)
	}

	h.issuer.mu.Lock()
	h.issuer.rawJWKS = nil
	h.issuer.mu.Unlock()
	h.clock.set(t0+11*fixtureMinute+31, t0+11*fixtureMinute+31)
	if _, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck()); err != nil {
		t.Fatal(err)
	}
	if got := h.issuer.jwksFetches.Load(); got != 2 {
		t.Fatalf("want the set still due for a refetch once the cooldown passed, got %d fetches", got)
	}
}

func TestJWKSRotation_AnOversizedKeySetIsAFailedFetch(t *testing.T) {
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	oversized := `{"keys":[],"padding":"` + strings.Repeat("x", maxJWKSBytes) + `"}`
	h.issuer.mu.Lock()
	h.issuer.rawJWKS = &oversized
	h.issuer.mu.Unlock()
	h.clock.set(fixture.Context.T0, fixture.Context.T0)

	result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck())
	if !errors.Is(err, ErrJWKSUnavailable) || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("want a too-large key set refused as unavailable, got %+v %v", result, err)
	}
}

func TestJWKSRotation_AKeySetRedirectIsRefused(t *testing.T) {
	// The key set is trusted for the configured issuer's origin; a redirect would move it.
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	h.serveJWKS("registry_v1")
	h.issuer.mu.Lock()
	h.issuer.redirectJWKS = true
	h.issuer.mu.Unlock()
	h.clock.set(fixture.Context.T0, fixture.Context.T0)

	result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck())
	if !errors.Is(err, ErrJWKSUnavailable) || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("want the redirect refused, got %+v %v", result, err)
	}
}

func TestJWKSRotation_AMissIsRecordedWithTheMergeItCameFrom(t *testing.T) {
	// A lookup that waited on a fetch and still misses records the miss in the same critical
	// section that stores the fetched set. Recorded later, by the waiter itself, a lookup arriving
	// in between saw a fresh set, no miss, and started a second fetch for the same unknown kid.
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	h.serveJWKS("registry_v1")
	h.clock.set(fixture.Context.T0, fixture.Context.T0)
	keys := h.proofs.keys()
	junk := "junk-kid"
	call := &fetchCall{
		done:    make(chan struct{}),
		waiters: []keyLookup{{kid: &junk, family: keyFamilyDelegation, alg: "ES256"}},
	}
	keys.mu.Lock()
	keys.inFlight = call
	keys.mu.Unlock()

	keys.fetchAndMerge(context.Background(), call)

	keys.mu.Lock()
	defer keys.mu.Unlock()
	if !call.outcome.ok || keys.state.fetchedAt == nil {
		t.Fatalf("positive control: want the fetch merged, got %+v", call.outcome)
	}
	if keys.lastMissAt == nil {
		t.Fatal("the waiter's miss was not recorded with the merge")
	}
}

func TestJWKSRotation_AnAbsentWindowMemberIsNotZero(t *testing.T) {
	// Two descriptions of a key differ when one carries `not_before: 0` and the other none.
	at := clockReading{}
	absent := parseKeyRecord(map[string]any{"kid": "k", "kty": "EC"}, at)
	zero := parseKeyRecord(map[string]any{"kid": "k", "kty": "EC", "not_before": float64(0)}, at)
	if describesSameKey(absent, zero) || describesSameKey(zero, absent) {
		t.Fatal("an absent not_before described the same key as not_before 0")
	}
	if !describesSameKey(absent, parseKeyRecord(map[string]any{"kid": "k", "kty": "EC"}, at)) {
		t.Fatal("positive control: two identical descriptions must match")
	}
}

// waitUntil polls for a condition other goroutines bring about, failing — not hanging — when a
// regression means it never holds.
func waitUntil(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// withKid re-addresses a token to another kid; its signature never gets checked.
func withKid(t *testing.T, token, kid string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	header["kid"] = kid
	encoded, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(encoded)
	return strings.Join(parts, ".")
}

// D-GP3: concurrent verifications share one key-set fetch.

func TestJWKSRotation_ConcurrentVerificationsOnAColdCacheShareOneFetch(t *testing.T) {
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	h.serveJWKS("registry_v1")
	h.clock.set(fixture.Context.T0, fixture.Context.T0)

	var wg sync.WaitGroup
	results := make([]*OfflineVerificationResult, 20)
	errs := make([]error, 20)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = h.verify(t, h.token("dlg_active"), WithoutRevocationCheck())
		}(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil || !results[i].Valid {
			t.Fatalf("verification %d: %+v %v", i, results[i], errs[i])
		}
	}
	if got := h.issuer.jwksFetches.Load(); got != 1 {
		t.Fatalf("want one shared fetch, got %d", got)
	}
}

func TestJWKSRotation_ConcurrentUnknownKidsCostOneRefetch(t *testing.T) {
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	t0 := fixture.Context.T0
	h.serveJWKS("registry_v1")
	h.clock.set(t0, t0)
	if _, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck()); err != nil {
		t.Fatal(err)
	}
	h.issuer.jwksFetches.Store(0)
	h.clock.set(t0+60, t0+60)

	var wg sync.WaitGroup
	var valid atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result, err := h.verify(t, withKid(t, h.token("dlg_active"), "junk-"+string(rune('a'+i))), WithoutRevocationCheck())
			if err == nil && result.Valid {
				valid.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if valid.Load() != 0 {
		t.Fatalf("a junk kid verified")
	}
	if got := h.issuer.jwksFetches.Load(); got != 1 {
		t.Fatalf("want one refetch for 20 concurrent junk kids, got %d", got)
	}
}

func TestJWKSRotation_ACancelledWaiterDoesNotCancelTheSharedFetch(t *testing.T) {
	// The caller whose lookup STARTED the fetch gives up while two others wait on it: the fetch
	// must still finish for them.
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	h.serveJWKS("registry_v1")
	h.clock.set(fixture.Context.T0, fixture.Context.T0)
	gate := make(chan struct{})
	h.issuer.mu.Lock()
	h.issuer.gate = gate
	h.issuer.mu.Unlock()
	keys := h.proofs.keys()
	waiting := func() int {
		keys.mu.Lock()
		defer keys.mu.Unlock()
		if keys.inFlight == nil {
			return 0
		}
		return len(keys.inFlight.waiters)
	}

	type answer struct {
		result *OfflineVerificationResult
		err    error
	}
	verifyInto := func(ctx context.Context) chan answer {
		out := make(chan answer, 1)
		go func() {
			result, err := h.proofs.VerifyOffline(ctx, h.token("dlg_active"), WithoutRevocationCheck())
			out <- answer{result, err}
		}()
		return out
	}

	cancelled, cancel := context.WithCancel(context.Background())
	starter := verifyInto(cancelled)
	waitUntil(t, "the starter's fetch to begin", func() bool { return h.issuer.jwksFetches.Load() > 0 })
	others := []chan answer{verifyInto(context.Background()), verifyInto(context.Background())}
	waitUntil(t, "three lookups waiting on the fetch", func() bool { return waiting() >= 3 })
	cancel()
	first := <-starter
	close(gate)

	if !errors.Is(first.err, ErrJWKSUnavailable) || !errors.Is(first.err, context.Canceled) {
		t.Fatalf("the cancelled starter: want ErrJWKSUnavailable wrapping context.Canceled, got %+v %v", first.result, first.err)
	}
	for i, out := range others {
		got := <-out
		if got.err != nil || !got.result.Valid {
			t.Fatalf("waiter %d: %+v %v", i, got.result, got.err)
		}
	}
	if got := h.issuer.jwksFetches.Load(); got != 1 {
		t.Fatalf("want one shared fetch, got %d", got)
	}
	if waiting() != 0 {
		t.Fatal("the finished fetch is still recorded as in flight")
	}
}

// h-verifier-jwks-go-php SC-1, SC-3, SC-4, SC-6.

func TestJWKSRotation_RejectsAnUnusableMaxJWKSAge(t *testing.T) {
	for _, bad := range []time.Duration{MaxJWKSAgeCap + time.Nanosecond, 0, -time.Second} {
		if _, err := NewClient("pk_test_x", WithMaxJWKSAge(bad)); err == nil {
			t.Errorf("WithMaxJWKSAge(%s): want NewClient to fail", bad)
		}
	}
	for _, good := range []time.Duration{MaxJWKSAgeCap, time.Second} {
		if _, err := NewClient("pk_test_x", WithMaxJWKSAge(good)); err != nil {
			t.Errorf("WithMaxJWKSAge(%s): %v", good, err)
		}
	}
	client, err := NewClient("pk_test_x")
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Proofs.keys().maxJWKSAgeMs; got != durationMs(24*time.Hour) {
		t.Errorf("default max JWKS age %vms, want 24h", got)
	}
	if got := (&Proofs{}).keys().maxJWKSAgeMs; got != durationMs(24*time.Hour) {
		t.Errorf("a Proofs built without NewClient: max JWKS age %vms, want 24h", got)
	}
}

func TestJWKSRotation_AnUnreachableKeySetIsAnErrorNotAVerdict(t *testing.T) {
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	h.issuer.serve(nil, nil)
	h.clock.set(fixture.Context.T0, fixture.Context.T0)

	result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck())
	if !errors.Is(err, ErrJWKSUnavailable) || result != nil {
		t.Fatalf("want (nil, ErrJWKSUnavailable), got %+v %v", result, err)
	}
	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("want the fetch failure in the error, got %v", err)
	}
}

func TestJWKSRotation_AnUnreachableKeySetFoldsIntoTheStatusListAnswer(t *testing.T) {
	// The token's key is held, the list's key is not, and the refetch made for it fails: the TOKEN
	// verified, so the call answers with a result — the list "could not be read" — never an error.
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	t0 := fixture.Context.T0
	h.serveJWKS("registry_v1")
	h.clock.set(t0, t0)
	if result, err := h.verify(t, h.token("dlg_active_with_status"), WithoutRevocationCheck()); err != nil || !result.Valid {
		t.Fatalf("priming: %+v %v", result, err)
	}
	statusList := "list_on_emergency_status_key"
	h.issuer.serve(nil, &statusList)
	h.clock.set(t0+fixtureMinute, t0+fixtureMinute)

	result, err := h.verify(t, h.token("dlg_active_with_status"))
	if err != nil {
		t.Fatalf("the status list's key set must not fail the whole call: %v", err)
	}
	if result.Reason != "status_unavailable" || !strings.Contains(result.Error, "status list signing key unavailable") {
		t.Fatalf("want status_unavailable for the list's key, got %+v", result)
	}
}

func TestJWKSRotation_AnUnreachableKeySetKeepsTheTransportError(t *testing.T) {
	// The sentinel says "could not check"; the cause stays matchable underneath it.
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	refused := errors.New("connection refused by the test transport")
	h.issuer.mu.Lock()
	h.issuer.failWith = refused
	h.issuer.mu.Unlock()
	h.clock.set(fixture.Context.T0, fixture.Context.T0)

	_, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck())
	if !errors.Is(err, ErrJWKSUnavailable) || !errors.Is(err, refused) {
		t.Fatalf("want ErrJWKSUnavailable wrapping the transport error, got %v", err)
	}
}

func TestJWKSRotation_APanickingTransportFailsTheFetchNotTheProcess(t *testing.T) {
	// The fetch runs on a goroutine of its own, where nothing of the caller's can recover a panic.
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	h.issuer.mu.Lock()
	h.issuer.panicWith = "transport exploded"
	h.issuer.mu.Unlock()
	h.clock.set(fixture.Context.T0, fixture.Context.T0)

	_, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck())
	if !errors.Is(err, ErrJWKSUnavailable) || !strings.Contains(err.Error(), "transport exploded") {
		t.Fatalf("want the panic reported as an unavailable key set, got %v", err)
	}
	h.issuer.mu.Lock()
	h.issuer.panicWith = nil
	h.issuer.mu.Unlock()
	h.serveJWKS("registry_v1")
	if result, err := h.verify(t, h.token("dlg_active"), WithoutRevocationCheck()); err != nil || !result.Valid {
		t.Fatalf("the next verification must fetch again and pass: %+v %v", result, err)
	}
}

// statusListPolicyKeys is a registry this test signs itself: a proof key, a delegation key, a
// status-list key and a second status-list key the issuer revokes.
type statusListPolicyKeys struct {
	proof, delegation, statusList, revoked *ecdsa.PrivateKey
}

func ecPublicJWK(t *testing.T, key *ecdsa.PrivateKey, members map[string]any) map[string]any {
	t.Helper()
	coordinate := func(value *big.Int) string {
		raw := make([]byte, 32)
		value.FillBytes(raw)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
		"x": coordinate(key.X), "y": coordinate(key.Y),
	}
	for member, value := range members {
		jwk[member] = value
	}
	return jwk
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestJWKSRotation_TheStatusListIsHeldToItsKeyPolicy(t *testing.T) {
	// The list is a token like any other: its signing key must be a live status-list key, its iat
	// inside that key's window and its lifetime within the key's bound. Each refusal leaves the
	// proof "status_unavailable" — never valid on a list its key could not vouch for.
	fixture := loadRotationFixture(t)
	t0 := fixture.Context.T0
	const day = 86_400
	keys := statusListPolicyKeys{newECKey(t), newECKey(t), newECKey(t), newECKey(t)}
	window := func(purpose string, lifetime int64) map[string]any {
		return map[string]any{
			"proof_purpose": purpose, "not_before": t0 - 30*day, "not_after": t0 + 30*day,
			"max_token_lifetime": lifetime,
		}
	}
	withKid := func(members map[string]any, kid string) map[string]any {
		members["kid"] = kid
		return members
	}
	document := func(tombstoned bool) string {
		keysJSON := []any{
			ecPublicJWK(t, keys.proof, withKid(window("proof", 365*day), "prf")),
			ecPublicJWK(t, keys.delegation, withKid(window("delegation", 365*day), "dlg")),
			ecPublicJWK(t, keys.statusList, withKid(window("status-list", day), "sts")),
		}
		tombstones := []any{}
		if tombstoned {
			tombstones = append(tombstones, map[string]any{"kid": "sts-old", "revoked_at": t0 - day})
		} else {
			keysJSON = append(keysJSON, ecPublicJWK(t, keys.revoked, withKid(window("status-list", day), "sts-old")))
		}
		encoded, err := json.Marshal(map[string]any{"keys": keysJSON, "proof_tombstones": tombstones})
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	list := func(key *ecdsa.PrivateKey, kid string, iat, exp int64) string {
		return signEcToken(t, key,
			map[string]any{"alg": "ES256", "typ": "statuslist+jwt", "kid": kid},
			map[string]any{
				"sub": fixture.Context.StatusListURI, "iat": iat, "exp": exp,
				"status_list": map[string]any{"bits": 2, "lst": base64.RawURLEncoding.EncodeToString(compressed.Bytes())},
			})
	}
	proof := signEcToken(t, keys.proof,
		map[string]any{"alg": "ES256", "typ": "JWT", "kid": "prf"},
		map[string]any{
			"iss": "proof.holdings", "sub": "ph_ctl_x", "proof_id": "ph_ctl_x", "iat": t0 - 60, "exp": t0 + 3600,
			"type": "domain", "channel": "dns", "verified_at": "2026-12-31T23:59:00.000Z",
			"status": map[string]any{"status_list": map[string]any{"idx": 0, "uri": fixture.Context.StatusListURI}},
		})

	run := func(statusList string, tombstoned bool) *OfflineVerificationResult {
		h := newRotationHarness(t, fixture)
		live, revoked := document(false), document(true)
		served := &live
		if tombstoned {
			served = &revoked
		}
		h.issuer.mu.Lock()
		h.issuer.rawJWKS = served
		h.issuer.rawStatusList = &statusList
		h.issuer.mu.Unlock()
		// Two fetches six minutes apart: what confirms the keys and applies a tombstone.
		h.clock.set(t0-6*fixtureMinute, t0-6*fixtureMinute)
		if result, err := h.verify(t, proof, WithoutRevocationCheck()); err != nil || !result.Valid {
			t.Fatalf("priming: %+v %v", result, err)
		}
		h.clock.set(t0, t0)
		h.proofs.RefreshJWKS()
		result, err := h.verify(t, proof)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	if result := run(list(keys.statusList, "sts", t0-30, t0+3600), false); !result.Valid || !result.RevocationChecked {
		t.Fatalf("positive control: a list from the live status-list key, got %+v", result)
	}
	for _, refusal := range []struct {
		name, list, want string
		tombstoned       bool
	}{
		{"a delegation key", list(keys.delegation, "dlg", t0-30, t0+3600), "is not a status-list key", false},
		{"a revoked status-list key", list(keys.revoked, "sts-old", t0-30, t0+3600), "revoked signing key", true},
		{"an iat before the key's window", list(keys.statusList, "sts", t0-31*day, t0+3600), "outside the signing key's window", false},
		{"a lifetime beyond the key's bound", list(keys.statusList, "sts", t0-30, t0+2*day), "max_token_lifetime", false},
	} {
		result := run(refusal.list, refusal.tombstoned)
		if result.Valid || result.Reason != "status_unavailable" || !strings.Contains(result.Error, refusal.want) {
			t.Errorf("%s: want status_unavailable (%q), got %+v", refusal.name, refusal.want, result)
		}
	}
}

func TestJWKSRotation_ExposesVerifiedAt(t *testing.T) {
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	h.serveJWKS("registry_v1")
	h.clock.set(fixture.Context.T0, fixture.Context.T0)
	token := h.token("prf_active")
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	verifiedAt, ok := claims["verified_at"].(string)
	if !ok || verifiedAt == "" {
		t.Fatalf("fixture token carries no verified_at: %v", claims)
	}
	result, err := h.verify(t, token, WithoutRevocationCheck())
	if err != nil || !result.Valid {
		t.Fatalf("%+v %v", result, err)
	}
	if result.Payload.VerifiedAt != verifiedAt {
		t.Fatalf("VerifiedAt %q, want %q", result.Payload.VerifiedAt, verifiedAt)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"verified_at":"`+verifiedAt+`"`) {
		t.Fatalf("verified_at missing from the JSON result: %s", encoded)
	}
}

func TestJWKSRotation_RefreshKeepsAnAppliedTombstoneAndOnlyClearLiftsIt(t *testing.T) {
	fixture := loadRotationFixture(t)
	h := newRotationHarness(t, fixture)
	t0 := fixture.Context.T0
	reason := func() string {
		result, err := h.verify(t, h.token("dlg_retired"), WithoutRevocationCheck())
		return fixtureOutcome(result, err, false)
	}
	h.serveJWKS("registry_v1")
	for _, at := range []int64{t0 - 11*fixtureMinute, t0} {
		h.clock.set(at, at)
		reason()
	}
	h.serveJWKS("registry_tombstone_retired_delegation")
	for _, at := range []int64{t0 + 11*fixtureMinute, t0 + 16*fixtureMinute} {
		h.clock.set(at, at)
		h.proofs.RefreshJWKS()
		reason()
	}
	if got := reason(); got != "key_revoked" {
		t.Fatalf("want the tombstone applied, got %s", got)
	}

	h.serveJWKS("registry_v1")
	h.clock.set(t0+17*fixtureMinute, t0+17*fixtureMinute)
	h.proofs.RefreshJWKS()
	if got := reason(); got != "key_revoked" {
		t.Fatalf("a refresh must keep the applied tombstone, got %s", got)
	}
	if got := h.issuer.jwksFetches.Load(); got != 5 {
		t.Fatalf("want 5 fetches, got %d", got)
	}

	h.proofs.ClearTombstones()
	if got := reason(); got != "valid" {
		t.Fatalf("want ClearTombstones to lift it, got %s", got)
	}
}

func TestJWKSRotation_ReadmeStatesThatTombstonesAreKeptInMemoryOnly(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	var section string
	for _, part := range regexp.MustCompile(`(?m)^### `).Split(string(raw), -1) {
		if strings.HasPrefix(part, "Signing-key rotation") {
			section = part
		}
	}
	if section == "" {
		t.Fatal(`README heading "### Signing-key rotation"`)
	}
	for _, phrase := range []string{"in memory", "not persisted", "ClearTombstones()", "ErrJWKSUnavailable"} {
		if !strings.Contains(section, phrase) {
			t.Errorf("README section lacks %q", phrase)
		}
	}
}
