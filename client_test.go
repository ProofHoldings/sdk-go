package proof

import "testing"

func TestNewClient_EmptyKey(t *testing.T) {
	_, err := NewClient("")
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestNewClient_ValidKey(t *testing.T) {
	client, err := NewClient("pk_test_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Verifications == nil {
		t.Error("Verifications should not be nil")
	}
	if client.VerificationRequests == nil {
		t.Error("VerificationRequests should not be nil")
	}
	if client.Proofs == nil {
		t.Error("Proofs should not be nil")
	}
	if client.Sessions == nil {
		t.Error("Sessions should not be nil")
	}
	if client.WebhookDeliveries == nil {
		t.Error("WebhookDeliveries should not be nil")
	}
}

func TestNewClient_WithOptions(t *testing.T) {
	client, err := NewClient("pk_test_123",
		WithBaseURL("https://custom.api.com"),
		WithMaxRetries(5),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestResolveWaitOptions_Defaults(t *testing.T) {
	interval, timeout := resolveWaitOptions(nil)
	if interval != 3e9 { // 3 seconds in nanoseconds
		t.Errorf("expected 3s interval, got %v", interval)
	}
	if timeout != 600e9 { // 10 minutes in nanoseconds
		t.Errorf("expected 10m timeout, got %v", timeout)
	}
}

func TestResolveWaitOptions_Custom(t *testing.T) {
	opts := &WaitOptions{Interval: 1e9, Timeout: 30e9}
	interval, timeout := resolveWaitOptions(opts)
	if interval != 1e9 {
		t.Errorf("expected 1s interval, got %v", interval)
	}
	if timeout != 30e9 {
		t.Errorf("expected 30s timeout, got %v", timeout)
	}
}
