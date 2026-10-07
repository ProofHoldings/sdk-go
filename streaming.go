package proof

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Event represents a single SSE (Server-Sent Event) frame parsed from the
// event stream, or a poll-derived snapshot when SSE is unavailable and the
// stream has fallen back to polling.
//
// For SSE frames:
//   - Name is the "event:" field (e.g. "connected", "status_changed", "update")
//   - ID is the "id:" field when present
//   - Data is the raw "data:" payload bytes (one or more lines joined by "\n")
//   - Parsed holds the JSON-decoded payload when Data is valid JSON
//
// For polling fallback frames:
//   - Name is "poll"
//   - Data is the JSON-encoded snapshot body
//   - Parsed holds the decoded snapshot map
//
// Err is set on terminal transport errors. When Err is non-nil, Name/Data
// are unset and the channel will be closed immediately after this event.
type Event struct {
	Name   string
	ID     string
	Data   []byte
	Parsed map[string]any
	Err    error
}

// defaultPollFallback is the WaitOptions used for polling fallback when SSE
// fails (503 or transport error). Kept small so users see fresh updates.
var defaultPollFallback = &WaitOptions{
	Interval:    2 * time.Second,
	Timeout:     10 * time.Minute,
	Backoff:     1.5,
	MaxInterval: 30 * time.Second,
	Jitter:      500 * time.Millisecond,
}

// streamEndpoint opens an SSE connection to path and returns a channel that
// receives Events until the context is cancelled, the stream ends, or an
// unrecoverable error occurs.
//
// On 503 (SSE disabled) or other SSE-specific failure, streamEndpoint falls
// back to polling via pollFn and forwards snapshots through the same channel
// as synthetic Events with Name == "poll". pollFn may be nil to disable
// fallback, in which case the channel closes and the caller sees an error
// event.
//
// isTerminal, when non-nil, is consulted against each polling snapshot; when
// it returns true the channel closes cleanly.
func (h *httpClient) streamEndpoint(
	ctx context.Context,
	path string,
	pollFn func(context.Context) (map[string]any, error),
	isTerminal func(map[string]any) bool,
) (<-chan Event, error) {
	var fullURL string
	if path != "" {
		u, err := url.Parse(h.baseURL + path)
		if err != nil {
			return nil, &NetworkError{ProofError{Message: err.Error(), Code: "network_error"}}
		}
		fullURL = u.String()
	}

	ch := make(chan Event, 16)

	go func() {
		defer close(ch)
		if fullURL == "" {
			// No SSE endpoint — poll only.
			if pollFn != nil {
				runPollingFallback(ctx, ch, pollFn, isTerminal)
			}
			return
		}
		h.runStream(ctx, fullURL, ch, pollFn, isTerminal)
	}()

	return ch, nil
}

// runStream executes the SSE read loop. It is called from a dedicated
// goroutine; all sends go through ch, and ch is closed by the caller.
func (h *httpClient) runStream(
	ctx context.Context,
	fullURL string,
	ch chan<- Event,
	pollFn func(context.Context) (map[string]any, error),
	isTerminal func(map[string]any) bool,
) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		send(ctx, ch, Event{Err: &NetworkError{ProofError{Message: err.Error(), Code: "network_error"}}})
		return
	}
	req.Header.Set("Authorization", "Bearer "+h.apiKey)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "proof-sdk-go/"+Version)

	// Dedicated client with no timeout — streaming lifetime is governed by ctx.
	streamClient := &http.Client{Transport: h.client.Transport}
	resp, err := streamClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if pollFn != nil {
			runPollingFallback(ctx, ch, pollFn, isTerminal)
			return
		}
		send(ctx, ch, Event{Err: &NetworkError{ProofError{Message: err.Error(), Code: "network_error"}}})
		return
	}
	defer resp.Body.Close()

	// 503 => SSE disabled; fall back to polling.
	if resp.StatusCode == http.StatusServiceUnavailable {
		if pollFn != nil {
			runPollingFallback(ctx, ch, pollFn, isTerminal)
			return
		}
		send(ctx, ch, Event{Err: &ServerError{ProofError{
			Message:    "SSE unavailable (503) and no polling fallback configured",
			Code:       "sse_disabled",
			StatusCode: resp.StatusCode,
		}}})
		return
	}

	// Any other non-2xx => surface typed error and close.
	if resp.StatusCode >= http.StatusBadRequest {
		send(ctx, ch, Event{Err: errorFromResponse(resp.StatusCode, nil)})
		return
	}

	readSSE(ctx, resp.Body, ch)
}

// readSSE parses the SSE byte stream from body, emitting one Event per
// complete frame. A frame is terminated by a blank line. Fields supported:
// "event:", "id:", "data:" (multiple data lines are joined with "\n"). Lines
// starting with ":" are comments (heartbeats) and are ignored.
func readSSE(ctx context.Context, body io.Reader, ch chan<- Event) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		eventName string
		eventID   string
		dataLines []string
	)

	flush := func() {
		if eventName == "" && len(dataLines) == 0 && eventID == "" {
			return
		}
		raw := []byte(strings.Join(dataLines, "\n"))
		ev := Event{
			Name: eventName,
			ID:   eventID,
			Data: raw,
		}
		if len(raw) > 0 {
			var parsed map[string]any
			if err := json.Unmarshal(raw, &parsed); err == nil {
				ev.Parsed = parsed
			}
		}
		if ev.Name == "" {
			ev.Name = "message"
		}
		send(ctx, ch, ev)
		eventName = ""
		eventID = ""
		dataLines = dataLines[:0]
	}

	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		name, value, ok := splitSSEField(line)
		if !ok {
			continue
		}
		switch name {
		case "event":
			eventName = value
		case "id":
			eventID = value
		case "data":
			dataLines = append(dataLines, value)
		}
	}
	flush()

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
		send(ctx, ch, Event{Err: &NetworkError{ProofError{Message: err.Error(), Code: "network_error"}}})
	}
}

// splitSSEField splits an SSE line into (fieldName, value). Per spec, fields
// look like "field: value" with an optional leading space on value.
func splitSSEField(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return line, "", true
	}
	name := line[:idx]
	value := line[idx+1:]
	if strings.HasPrefix(value, " ") {
		value = value[1:]
	}
	return name, value, true
}

// runPollingFallback polls pollFn until ctx is cancelled, pollFn errors, or
// isTerminal reports completion. Each snapshot is forwarded on ch as an
// Event{Name: "poll"}.
func runPollingFallback(
	ctx context.Context,
	ch chan<- Event,
	pollFn func(context.Context) (map[string]any, error),
	isTerminal func(map[string]any) bool,
) {
	r, err := resolveWaitOptions(defaultPollFallback)
	if err != nil {
		send(ctx, ch, Event{Err: err})
		return
	}
	interval := r.interval
	start := time.Now()

	for {
		if ctx.Err() != nil {
			return
		}
		snapshot, err := pollFn(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			send(ctx, ch, Event{Err: err})
			return
		}
		raw, _ := json.Marshal(snapshot)
		ev := Event{Name: "poll", Data: raw, Parsed: snapshot}
		if !send(ctx, ch, ev) {
			return
		}

		if isTerminal != nil && isTerminal(snapshot) {
			return
		}

		if time.Since(start) >= r.timeout {
			send(ctx, ch, Event{Err: &PollingTimeoutError{ProofError{
				Message: fmt.Sprintf("stream polling fallback timed out after %s", r.timeout),
				Code:    "polling_timeout",
			}}})
			return
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}

		next := float64(interval) * r.backoff
		if next > float64(r.maxInterval) {
			interval = r.maxInterval
		} else {
			interval = time.Duration(next)
		}
	}
}

// send is a ctx-aware channel send. Returns false if ctx cancelled first.
func send(ctx context.Context, ch chan<- Event, ev Event) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// ============================================================================
// Per-resource Stream wrappers
// ============================================================================

// Stream opens an SSE stream for the given verification. The channel closes
// when ctx is cancelled, the server closes the stream, or a terminal error
// occurs. On SSE 503 or transport error the stream falls back to polling
// Retrieve until the verification reaches a terminal status.
//
// Endpoint: GET /api/v1/verifications/:id/events
func (v *Verifications) Stream(ctx context.Context, id string) (<-chan Event, error) {
	path := "/api/v1/verifications/" + url.PathEscape(id) + "/events"
	return v.http.streamEndpoint(ctx, path,
		func(c context.Context) (map[string]any, error) { return v.Retrieve(c, id) },
		terminalOnStatus(isTerminalVerificationStatus),
	)
}

// Stream opens an SSE stream for the given confirmation.
//
// Endpoint: GET /api/v1/confirmations/:id/events
func (c *Confirmations) Stream(ctx context.Context, id string) (<-chan Event, error) {
	path := "/api/v1/confirmations/" + url.PathEscape(id) + "/events"
	return c.http.streamEndpoint(ctx, path,
		func(cc context.Context) (map[string]any, error) { return c.Retrieve(cc, id) },
		terminalOnStatus(isTerminalConfirmationStatus),
	)
}

// terminalOnStatus adapts a status predicate to a polled snapshot's "status" field.
func terminalOnStatus(isTerminal func(string) bool) func(map[string]any) bool {
	return func(snapshot map[string]any) bool {
		status, _ := snapshot["status"].(string)
		return isTerminal(status)
	}
}

// isTerminalAssetSnapshot reports whether a polled asset has reached an outcome,
// or its request has closed ("cancelled" / "expired") while the asset stays pending.
func isTerminalAssetSnapshot(snapshot map[string]any) bool {
	if status, _ := snapshot["status"].(string); isTerminalVerificationStatus(status) {
		return true
	}
	requestStatus, _ := snapshot["request_status"].(string)
	return requestStatus == "cancelled" || requestStatus == "expired"
}

// isTerminalConfirmationStatus reports whether a confirmation status is terminal.
func isTerminalConfirmationStatus(s string) bool {
	return s == "approved" || s == "denied" || s == "expired"
}

// StreamAsset opens an SSE stream for a single asset within a verification
// request. assetIndex is the zero-based position of the asset in the request.
//
// Endpoint: GET /api/v1/verify/request/:id/assets/:assetIndex/events
func (vr *VerificationRequests) StreamAsset(ctx context.Context, id string, assetIndex int) (<-chan Event, error) {
	path := fmt.Sprintf("/api/v1/verify/request/%s/assets/%d/events", url.PathEscape(id), assetIndex)
	statusPath := fmt.Sprintf("/api/v1/verify/request/%s/assets/%d/status", url.PathEscape(id), assetIndex)
	return vr.http.streamEndpoint(ctx, path,
		func(c context.Context) (map[string]any, error) {
			return vr.http.get(c, statusPath, nil)
		},
		isTerminalAssetSnapshot,
	)
}

// ============================================================================
// Auth streams
// ============================================================================

// Auth exposes auth-session streaming. Auth sessions use the session ID as
// the bearer secret (format: auth_[a-f0-9]{32}); the server gates access on
// the session ID format + ownership.
type Auth struct {
	http *httpClient
}

// StreamSession opens an SSE stream for an auth session.
//
// Endpoint: GET /api/v1/auth/sessions/:id/events
func (a *Auth) StreamSession(ctx context.Context, id string) (<-chan Event, error) {
	path := "/api/v1/auth/sessions/" + url.PathEscape(id) + "/events"
	return a.http.streamEndpoint(ctx, path, nil, nil)
}

// ============================================================================
// Me streams (2FA, phone add, email add)
// ============================================================================

// Me exposes streaming for dashboard self-service flows (2FA, add-phone,
// add-email). These endpoints are JWT-authenticated on the server; API-key
// clients will receive a 401 and the channel will emit a single error
// Event. Polling fallback is not configured for these flows.
type Me struct {
	http *httpClient
}

// Stream2FA opens an SSE stream for a 2FA session.
//
// Endpoint: GET /api/v1/me/2fa/:sessionId/events
func (m *Me) Stream2FA(ctx context.Context, sessionID string) (<-chan Event, error) {
	path := "/api/v1/me/2fa/" + url.PathEscape(sessionID) + "/events"
	return m.http.streamEndpoint(ctx, path, nil, nil)
}

// StreamAddPhone opens an SSE stream for an add-phone session.
//
// Endpoint: GET /api/v1/me/phones/add/:sessionId/events
func (m *Me) StreamAddPhone(ctx context.Context, sessionID string) (<-chan Event, error) {
	path := "/api/v1/me/phones/add/" + url.PathEscape(sessionID) + "/events"
	return m.http.streamEndpoint(ctx, path, nil, nil)
}

// StreamAddEmail opens an SSE stream for an add-email session.
//
// Endpoint: GET /api/v1/me/emails/add/:sessionId/events
func (m *Me) StreamAddEmail(ctx context.Context, sessionID string) (<-chan Event, error) {
	path := "/api/v1/me/emails/add/" + url.PathEscape(sessionID) + "/events"
	return m.http.streamEndpoint(ctx, path, nil, nil)
}

// ============================================================================
// HITL chat-id discovery stream
// ============================================================================

// HITL exposes HITL chat-id discovery streaming. This is distinct from
// HitlKeys (key management); both share the same underlying httpClient.
type HITL struct {
	http *httpClient
}

// StreamChatIDDiscovery opens an SSE stream for a HITL chat-id discovery
// token. The stream falls back to polling GET /chat-id-discovery/:token on
// SSE failure, closing when status reaches "completed" or "expired".
//
// Endpoint: GET /api/v1/hitl/chat-id-discovery/:token/events
func (h *HITL) StreamChatIDDiscovery(ctx context.Context, token string) (<-chan Event, error) {
	path := "/api/v1/hitl/chat-id-discovery/" + url.PathEscape(token) + "/events"
	return h.http.streamEndpoint(ctx, path,
		func(c context.Context) (map[string]any, error) {
			return h.http.get(c, "/api/v1/hitl/chat-id-discovery/"+url.PathEscape(token), nil)
		},
		terminalOnStatus(func(status string) bool {
			return status == "completed" || status == "expired"
		}),
	)
}
