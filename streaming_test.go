package proof

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- shared helpers ----------

// sseWriter writes SSE frames to w and flushes after each frame.
func sseWriter(w http.ResponseWriter) func(event string, data any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	return func(event string, data any) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// drain returns up to n events from ch or until ch closes.
func drain(ch <-chan Event, n int, within time.Duration) []Event {
	out := make([]Event, 0, n)
	timeout := time.After(within)
	for len(out) < n {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-timeout:
			return out
		}
	}
	return out
}

// ---------- core stream behavior ----------

func TestStream_EventsArriveInOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/events") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Accept"); got != "text/event-stream" {
			t.Errorf("Accept header: want text/event-stream, got %q", got)
		}
		write := sseWriter(w)
		write("connected", map[string]any{"id": "ver_1", "status": "pending"})
		write("status_changed", map[string]any{"id": "ver_1", "status": "verified"})
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := client.Verifications.Stream(ctx, "ver_1")
	if err != nil {
		t.Fatalf("Stream error: %v", err)
	}

	events := drain(ch, 2, 2*time.Second)
	if len(events) < 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	if events[0].Name != "connected" {
		t.Errorf("want first event 'connected', got %q", events[0].Name)
	}
	if events[1].Name != "status_changed" {
		t.Errorf("want second event 'status_changed', got %q", events[1].Name)
	}
	if events[1].Parsed["status"] != "verified" {
		t.Errorf("want parsed status 'verified', got %v", events[1].Parsed["status"])
	}
}

func TestStream_HeartbeatsIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		fmt.Fprintf(w, ":keepalive\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		fmt.Fprintf(w, "event: update\ndata: {\"status\":\"verified\"}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := client.Verifications.Stream(ctx, "ver_1")
	if err != nil {
		t.Fatalf("Stream error: %v", err)
	}
	events := drain(ch, 1, 2*time.Second)
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Name != "update" {
		t.Errorf("want 'update', got %q", events[0].Name)
	}
}

func TestStream_MultiLineData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		// Two data lines should be joined by newline.
		fmt.Fprintf(w, "event: msg\ndata: hello\ndata: world\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, _ := client.Verifications.Stream(ctx, "ver_1")
	events := drain(ch, 1, 2*time.Second)
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if string(events[0].Data) != "hello\nworld" {
		t.Errorf("want 'hello\\nworld', got %q", string(events[0].Data))
	}
}

func TestStream_ContextCancellationClosesChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := sseWriter(w)
		write("connected", map[string]any{"status": "pending"})
		// Keep the connection open until client disconnects.
		<-r.Context().Done()
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithCancel(context.Background())

	ch, err := client.Verifications.Stream(ctx, "ver_1")
	if err != nil {
		t.Fatalf("Stream error: %v", err)
	}

	// Receive first event to confirm stream is open.
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("channel closed before first event")
		}
		if ev.Name != "connected" {
			t.Errorf("want 'connected', got %q", ev.Name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first event")
	}

	cancel()

	// Channel should close cleanly.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("channel did not close after ctx cancel")
		}
	}
}

// ---------- polling fallback ----------

func TestStream_PollingFallbackOn503(t *testing.T) {
	var pollCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/events") {
			http.Error(w, `{"error":{"code":"sse_disabled","message":"disabled"}}`, http.StatusServiceUnavailable)
			return
		}
		// Retrieve handler.
		n := pollCount.Add(1)
		status := "pending"
		if n >= 2 {
			status = "verified"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "ver_1", "status": status})
	}))
	defer srv.Close()

	// Use a small poll interval for the test.
	defaultPollFallback = &WaitOptions{
		Interval:    10 * time.Millisecond,
		Timeout:     5 * time.Second,
		Backoff:     1.0,
		MaxInterval: 100 * time.Millisecond,
		Jitter:      time.Nanosecond,
	}
	t.Cleanup(func() {
		defaultPollFallback = &WaitOptions{
			Interval:    2 * time.Second,
			Timeout:     10 * time.Minute,
			Backoff:     1.5,
			MaxInterval: 30 * time.Second,
			Jitter:      500 * time.Millisecond,
		}
	})

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := client.Verifications.Stream(ctx, "ver_1")
	if err != nil {
		t.Fatalf("Stream error: %v", err)
	}

	var sawVerified bool
	for ev := range ch {
		if ev.Err != nil {
			t.Fatalf("unexpected error event: %v", ev.Err)
		}
		if ev.Name != "poll" {
			t.Errorf("want fallback event name 'poll', got %q", ev.Name)
		}
		if ev.Parsed["status"] == "verified" {
			sawVerified = true
		}
	}
	if !sawVerified {
		t.Error("expected to observe verified status via polling fallback")
	}
	if pollCount.Load() < 2 {
		t.Errorf("want at least 2 poll calls, got %d", pollCount.Load())
	}
}

func TestStream_PollingFallbackTerminalStatusClosesChannel(t *testing.T) {
	// Direct unit test of runPollingFallback to confirm terminal status
	// closes the channel cleanly (shared with 503 and transport-error paths).
	defaultPollFallback = &WaitOptions{
		Interval:    5 * time.Millisecond,
		Timeout:     2 * time.Second,
		Backoff:     1.0,
		MaxInterval: 50 * time.Millisecond,
		Jitter:      time.Nanosecond,
	}
	t.Cleanup(func() {
		defaultPollFallback = &WaitOptions{
			Interval:    2 * time.Second,
			Timeout:     10 * time.Minute,
			Backoff:     1.5,
			MaxInterval: 30 * time.Second,
			Jitter:      500 * time.Millisecond,
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := make(chan Event, 4)
	go func() {
		defer close(ch)
		runPollingFallback(ctx, ch,
			func(c context.Context) (map[string]any, error) {
				return map[string]any{"status": "verified"}, nil
			},
			terminalOnStatus(isTerminalVerificationStatus),
		)
	}()

	ev := <-ch
	if ev.Name != "poll" {
		t.Errorf("want 'poll', got %q", ev.Name)
	}
	if ev.Parsed["status"] != "verified" {
		t.Errorf("want verified, got %v", ev.Parsed["status"])
	}
	// Channel should close.
	if _, ok := <-ch; ok {
		t.Error("channel should close after terminal status")
	}
}

// ---------- error handling ----------

func TestStream_NonSSEErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"not_found","message":"no"}}`, http.StatusNotFound)
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Auth.StreamSession has no polling fallback, so 404 should surface as an error event.
	ch, err := client.Auth.StreamSession(ctx, "auth_abc")
	if err != nil {
		t.Fatalf("Stream error: %v", err)
	}
	ev, ok := <-ch
	if !ok {
		t.Fatal("channel closed without error event")
	}
	if ev.Err == nil {
		t.Fatal("expected error event")
	}
}

// ---------- URL formation: one test per endpoint ----------

type urlCapture struct{ path string }

func captureServer(t *testing.T, cap *urlCapture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.path = r.URL.Path
		write := sseWriter(w)
		write("connected", map[string]any{"ok": true})
	}))
}

func consumeOne(t *testing.T, ch <-chan Event) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for SSE event")
	}
}

func TestStream_URLFormation_Verifications(t *testing.T) {
	cap := &urlCapture{}
	srv := captureServer(t, cap)
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := client.Verifications.Stream(ctx, "ver_abc")
	if err != nil {
		t.Fatal(err)
	}
	consumeOne(t, ch)
	cancel()
	if cap.path != "/api/v1/verifications/ver_abc/events" {
		t.Errorf("path = %q", cap.path)
	}
}

func TestStream_URLFormation_Confirmations(t *testing.T) {
	cap := &urlCapture{}
	srv := captureServer(t, cap)
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := client.Confirmations.Stream(ctx, "conf_xyz")
	if err != nil {
		t.Fatal(err)
	}
	consumeOne(t, ch)
	cancel()
	if cap.path != "/api/v1/confirmations/conf_xyz/events" {
		t.Errorf("path = %q", cap.path)
	}
}

func TestStream_URLFormation_AuthSession(t *testing.T) {
	cap := &urlCapture{}
	srv := captureServer(t, cap)
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := client.Auth.StreamSession(ctx, "auth_deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	consumeOne(t, ch)
	cancel()
	if cap.path != "/api/v1/auth/sessions/auth_deadbeef/events" {
		t.Errorf("path = %q", cap.path)
	}
}

func TestStream_URLFormation_2FA(t *testing.T) {
	cap := &urlCapture{}
	srv := captureServer(t, cap)
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := client.Me.Stream2FA(ctx, "2fa_abc123")
	if err != nil {
		t.Fatal(err)
	}
	consumeOne(t, ch)
	cancel()
	if cap.path != "/api/v1/me/2fa/2fa_abc123/events" {
		t.Errorf("path = %q", cap.path)
	}
}

func TestStream_URLFormation_AddPhone(t *testing.T) {
	cap := &urlCapture{}
	srv := captureServer(t, cap)
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := client.Me.StreamAddPhone(ctx, "addphone_xyz")
	if err != nil {
		t.Fatal(err)
	}
	consumeOne(t, ch)
	cancel()
	if cap.path != "/api/v1/me/phones/add/addphone_xyz/events" {
		t.Errorf("path = %q", cap.path)
	}
}

func TestStream_URLFormation_AddEmail(t *testing.T) {
	cap := &urlCapture{}
	srv := captureServer(t, cap)
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := client.Me.StreamAddEmail(ctx, "addemail_xyz")
	if err != nil {
		t.Fatal(err)
	}
	consumeOne(t, ch)
	cancel()
	if cap.path != "/api/v1/me/emails/add/addemail_xyz/events" {
		t.Errorf("path = %q", cap.path)
	}
}

func TestStream_URLFormation_ChatIDDiscovery(t *testing.T) {
	cap := &urlCapture{}
	srv := captureServer(t, cap)
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := client.HITL.StreamChatIDDiscovery(ctx, "tok_123")
	if err != nil {
		t.Fatal(err)
	}
	consumeOne(t, ch)
	cancel()
	if cap.path != "/api/v1/hitl/chat-id-discovery/tok_123/events" {
		t.Errorf("path = %q", cap.path)
	}
}

func TestStream_URLFormation_AssetEvents(t *testing.T) {
	cap := &urlCapture{}
	srv := captureServer(t, cap)
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := client.VerificationRequests.StreamAsset(ctx, "req_abc", 2)
	if err != nil {
		t.Fatal(err)
	}
	consumeOne(t, ch)
	cancel()
	if cap.path != "/api/v1/verify/request/req_abc/assets/2/events" {
		t.Errorf("path = %q", cap.path)
	}
}

// ---------- SSE parser unit tests ----------

func TestSplitSSEField(t *testing.T) {
	cases := []struct {
		in, name, value string
	}{
		{"event: foo", "event", "foo"},
		{"event:foo", "event", "foo"},
		{"data: hello world", "data", "hello world"},
		{"data:no-space", "data", "no-space"},
		{"id: 42", "id", "42"},
	}
	for _, tc := range cases {
		n, v, _ := splitSSEField(tc.in)
		if n != tc.name || v != tc.value {
			t.Errorf("splitSSEField(%q) = (%q, %q); want (%q, %q)", tc.in, n, v, tc.name, tc.value)
		}
	}
}

func TestStream_AuthHeaderSent(t *testing.T) {
	var sawAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer pk_test_xxx" {
			sawAuth.Store(true)
		}
		write := sseWriter(w)
		write("connected", map[string]any{"ok": true})
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_xxx", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := client.Verifications.Stream(ctx, "ver_1")
	if err != nil {
		t.Fatal(err)
	}
	consumeOne(t, ch)
	cancel()
	if !sawAuth.Load() {
		t.Error("Authorization header not sent")
	}
}

func TestStream_AssetPollingFallbackClosesOnClosedRequest(t *testing.T) {
	defaultPollFallback = &WaitOptions{
		Interval:    5 * time.Millisecond,
		Timeout:     2 * time.Second,
		Backoff:     1.0,
		MaxInterval: 50 * time.Millisecond,
		Jitter:      time.Nanosecond,
	}
	t.Cleanup(func() {
		defaultPollFallback = &WaitOptions{
			Interval:    2 * time.Second,
			Timeout:     10 * time.Minute,
			Backoff:     1.5,
			MaxInterval: 30 * time.Second,
			Jitter:      500 * time.Millisecond,
		}
	})

	for _, requestStatus := range []string{"cancelled", "expired"} {
		t.Run(requestStatus, func(t *testing.T) {
			var statusPath atomic.Value
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/events") {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				statusPath.Store(r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"asset_index":0,"status":"pending","request_status":"` + requestStatus + `"}`))
			}))
			defer srv.Close()

			client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			ch, err := client.VerificationRequests.StreamAsset(ctx, "req_abc", 0)
			if err != nil {
				t.Fatal(err)
			}
			ev := <-ch
			if ev.Err != nil || ev.Name != "poll" || ev.Parsed["request_status"] != requestStatus {
				t.Fatalf("first event = %+v", ev)
			}
			if next, ok := <-ch; ok {
				t.Fatalf("channel should close after a %s request, got %+v", requestStatus, next)
			}
			if got := statusPath.Load(); got != "/api/v1/verify/request/req_abc/assets/0/status" {
				t.Errorf("status path = %v", got)
			}
		})
	}
}
