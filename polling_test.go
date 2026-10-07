package proof

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPolling_ImmediateTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": "ver_1", "status": "verified"})
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	result, err := client.Verifications.WaitForCompletion(context.Background(), "ver_1", &WaitOptions{
		Interval: 10 * time.Millisecond,
		Timeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["status"] != "verified" {
		t.Errorf("want status 'verified', got %v", result["status"])
	}
}

func TestPolling_PollsUntilTerminal(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		status := "pending"
		if n >= 3 {
			status = "verified"
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "ver_1", "status": status})
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	result, err := client.Verifications.WaitForCompletion(context.Background(), "ver_1", &WaitOptions{
		Interval: 10 * time.Millisecond,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["status"] != "verified" {
		t.Errorf("want 'verified', got %v", result["status"])
	}
	if callCount.Load() < 3 {
		t.Errorf("expected at least 3 calls, got %d", callCount.Load())
	}
}

func TestPolling_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": "ver_1", "status": "pending"})
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	_, err := client.Verifications.WaitForCompletion(context.Background(), "ver_1", &WaitOptions{
		Interval: 10 * time.Millisecond,
		Timeout:  50 * time.Millisecond,
	})
	var pollErr *PollingTimeoutError
	if !errors.As(err, &pollErr) {
		t.Fatalf("want PollingTimeoutError, got %T: %v", err, err)
	}
}

func TestPolling_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": "ver_1", "status": "pending"})
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := client.Verifications.WaitForCompletion(ctx, "ver_1", &WaitOptions{
		Interval: 10 * time.Millisecond,
		Timeout:  5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestPolling_DefaultOptions(t *testing.T) {
	r, err := resolveWaitOptions(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.interval != 2*time.Second {
		t.Errorf("default interval: want 2s, got %v", r.interval)
	}
	if r.timeout != 10*time.Minute {
		t.Errorf("default timeout: want 10m, got %v", r.timeout)
	}
	if r.backoff != 1.5 {
		t.Errorf("default backoff: want 1.5, got %v", r.backoff)
	}
	if r.maxInterval != 30*time.Second {
		t.Errorf("default maxInterval: want 30s, got %v", r.maxInterval)
	}
	if r.jitter != 500*time.Millisecond {
		t.Errorf("default jitter: want 500ms, got %v", r.jitter)
	}
}

func TestPolling_BackoffGrowsInterval(t *testing.T) {
	var callCount atomic.Int32
	callTimes := make([]time.Time, 0, 6)
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callTimes = append(callTimes, time.Now())
		mu.Unlock()
		n := callCount.Add(1)
		status := "pending"
		if n >= 4 {
			status = "verified"
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "ver_1", "status": status})
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	_, err := client.Verifications.WaitForCompletion(context.Background(), "ver_1", &WaitOptions{
		Interval:    20 * time.Millisecond,
		Timeout:     5 * time.Second,
		Backoff:     2.0,
		MaxInterval: 1 * time.Second,
		Jitter:      time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(callTimes) < 3 {
		t.Fatalf("want at least 3 calls, got %d", len(callTimes))
	}
	gap1 := callTimes[1].Sub(callTimes[0])
	gap2 := callTimes[2].Sub(callTimes[1])
	if gap2 <= gap1 {
		t.Errorf("expected gap2 (%v) > gap1 (%v) due to backoff", gap2, gap1)
	}
}

func TestPolling_MaxIntervalCaps(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		status := "pending"
		if n >= 5 {
			status = "verified"
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "ver_1", "status": status})
	}))
	defer srv.Close()

	client, _ := NewClient("pk_test_123", WithBaseURL(srv.URL), WithMaxRetries(0))
	start := time.Now()
	_, err := client.Verifications.WaitForCompletion(context.Background(), "ver_1", &WaitOptions{
		Interval:    10 * time.Millisecond,
		Timeout:     5 * time.Second,
		Backoff:     10.0,
		MaxInterval: 50 * time.Millisecond,
		Jitter:      time.Nanosecond,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 5 calls with cap at 50ms should complete in under 1s
	if elapsed > time.Second {
		t.Errorf("max interval cap not applied: elapsed %v", elapsed)
	}
}

func TestPolling_VerificationTerminalStates(t *testing.T) {
	for _, status := range []string{"verified", "failed", "expired", "revoked"} {
		t.Run(status, func(t *testing.T) {
			if !isTerminalVerificationStatus(status) {
				t.Errorf("%q should be terminal", status)
			}
		})
	}
	if isTerminalVerificationStatus("pending") {
		t.Error("'pending' should not be terminal")
	}
}

func TestPolling_SessionTerminalStates(t *testing.T) {
	for _, status := range []string{"verified", "failed", "expired"} {
		if !isTerminalSessionStatus(status) {
			t.Errorf("%q should be terminal", status)
		}
	}
	if isTerminalSessionStatus("pending") {
		t.Error("'pending' should not be terminal")
	}
}

func TestPolling_RequestTerminalStates(t *testing.T) {
	for _, status := range []string{"completed", "expired", "cancelled"} {
		if !isTerminalRequestStatus(status) {
			t.Errorf("%q should be terminal", status)
		}
	}
	if isTerminalRequestStatus("pending") {
		t.Error("'pending' should not be terminal")
	}
}
