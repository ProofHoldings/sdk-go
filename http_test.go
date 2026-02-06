package proof

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func testServer(handler http.HandlerFunc) (*httptest.Server, *httpClient) {
	srv := httptest.NewServer(handler)
	client := newHTTPClient("pk_test_123", srv.URL, 5e9, 0) // 5s timeout, 0 retries
	return srv, client
}

func TestHTTPClient_GetSuccess(t *testing.T) {
	srv, client := testServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("want GET, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer pk_test_123" {
			t.Error("missing auth header")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing content-type header")
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "ver_123"})
	})
	defer srv.Close()

	result, err := client.get(context.Background(), "/api/v1/test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["id"] != "ver_123" {
		t.Errorf("want id 'ver_123', got %v", result["id"])
	}
}

func TestHTTPClient_PostWithBody(t *testing.T) {
	srv, client := testServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("want POST, got %s", r.Method)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["type"] != "phone" {
			t.Errorf("want type 'phone', got %v", body["type"])
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "ver_new"})
	})
	defer srv.Close()

	_, err := client.post(context.Background(), "/api/v1/test", map[string]string{"type": "phone"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPClient_400ReturnsValidationError(t *testing.T) {
	srv, client := testServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": "invalid", "message": "Bad"},
		})
	})
	defer srv.Close()

	_, err := client.get(context.Background(), "/test", nil)
	var valErr *ValidationError
	if !errors.As(err, &valErr) {
		t.Fatalf("want ValidationError, got %T: %v", err, err)
	}
}

func TestHTTPClient_404ReturnsNotFoundError(t *testing.T) {
	srv, client := testServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": "not_found", "message": "Not found"},
		})
	})
	defer srv.Close()

	_, err := client.get(context.Background(), "/test", nil)
	var nfErr *NotFoundError
	if !errors.As(err, &nfErr) {
		t.Fatalf("want NotFoundError, got %T: %v", err, err)
	}
}

func TestHTTPClient_500ReturnsServerError(t *testing.T) {
	srv, client := testServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]any{})
	})
	defer srv.Close()

	_, err := client.get(context.Background(), "/test", nil)
	var sErr *ServerError
	if !errors.As(err, &sErr) {
		t.Fatalf("want ServerError, got %T: %v", err, err)
	}
}

func TestHTTPClient_RetryOn500(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]any{})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()

	client := newHTTPClient("pk_test_123", srv.URL, 5e9, 1)
	result, err := client.get(context.Background(), "/test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["ok"] != true {
		t.Errorf("want ok=true, got %v", result["ok"])
	}
	if callCount.Load() != 2 {
		t.Errorf("want 2 calls, got %d", callCount.Load())
	}
}

func TestHTTPClient_RetryExhaustedOn500(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer srv.Close()

	client := newHTTPClient("pk_test_123", srv.URL, 5e9, 1)
	_, err := client.get(context.Background(), "/test", nil)
	var sErr *ServerError
	if !errors.As(err, &sErr) {
		t.Fatalf("want ServerError, got %T: %v", err, err)
	}
	if callCount.Load() != 2 {
		t.Errorf("want 2 calls (initial + 1 retry), got %d", callCount.Load())
	}
}

func TestHTTPClient_Backoff(t *testing.T) {
	client := newHTTPClient("pk_test", "http://localhost", 5e9, 0)
	tests := []struct {
		attempt int
		wantMs  float64
	}{
		{0, 1000},
		{1, 2000},
		{2, 4000},
		{3, 8000},
		{4, 10000}, // capped
		{10, 10000},
	}
	for _, tt := range tests {
		got := client.backoff(tt.attempt).Milliseconds()
		if got != int64(tt.wantMs) {
			t.Errorf("backoff(%d): want %vms, got %vms", tt.attempt, tt.wantMs, got)
		}
	}
}
