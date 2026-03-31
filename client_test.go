package proof

import (
	"testing"
	"time"
)

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
	if client.Templates == nil {
		t.Error("Templates should not be nil")
	}
	if client.Profiles == nil {
		t.Error("Profiles should not be nil")
	}
	if client.Projects == nil {
		t.Error("Projects should not be nil")
	}
	if client.Billing == nil {
		t.Error("Billing should not be nil")
	}
	if client.Phones == nil {
		t.Error("Phones should not be nil")
	}
	if client.Emails == nil {
		t.Error("Emails should not be nil")
	}
	if client.Assets == nil {
		t.Error("Assets should not be nil")
	}
	if client.Auth == nil {
		t.Error("Auth should not be nil")
	}
	if client.Settings == nil {
		t.Error("Settings should not be nil")
	}
	if client.APIKeys == nil {
		t.Error("APIKeys should not be nil")
	}
	if client.Account == nil {
		t.Error("Account should not be nil")
	}
	if client.TwoFA == nil {
		t.Error("TwoFA should not be nil")
	}
	if client.DNSCredentials == nil {
		t.Error("DNSCredentials should not be nil")
	}
	if client.Domains == nil {
		t.Error("Domains should not be nil")
	}
	if client.UserRequests == nil {
		t.Error("UserRequests should not be nil")
	}
	if client.UserDomainVerify == nil {
		t.Error("UserDomainVerify should not be nil")
	}
	if client.PublicProfiles == nil {
		t.Error("PublicProfiles should not be nil")
	}
}

func TestNewClient_WithOptions(t *testing.T) {
	client, err := NewClient("pk_test_123",
		WithBaseURL("https://custom.api.com"),
		WithTimeout(10*time.Second),
		WithMaxRetries(5),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestProofs_VerifyOffline_InvalidToken(t *testing.T) {
	client, err := NewClient("pk_test_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := client.Proofs.VerifyOffline("not.a.valid-token")
	if err != nil {
		t.Fatalf("VerifyOffline should not return error, got: %v", err)
	}
	valid, _ := result["valid"].(bool)
	if valid {
		t.Error("expected valid=false for invalid token")
	}
	if _, ok := result["error"]; !ok {
		t.Error("expected error field in result")
	}
}

func TestProofs_RefreshJWKS(t *testing.T) {
	client, err := NewClient("pk_test_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not panic even when cache is nil
	client.Proofs.RefreshJWKS()

	// After calling VerifyOffline (which initializes the cache), RefreshJWKS should still work
	_, _ = client.Proofs.VerifyOffline("invalid")
	client.Proofs.RefreshJWKS()
}

func TestResolveWaitOptions_Defaults(t *testing.T) {
	interval, timeout := resolveWaitOptions(nil)
	if interval != 3*time.Second {
		t.Errorf("expected 3s interval, got %v", interval)
	}
	if timeout != 10*time.Minute {
		t.Errorf("expected 10m timeout, got %v", timeout)
	}
}

func TestResolveWaitOptions_Custom(t *testing.T) {
	opts := &WaitOptions{Interval: 1 * time.Second, Timeout: 30 * time.Second}
	interval, timeout := resolveWaitOptions(opts)
	if interval != 1*time.Second {
		t.Errorf("expected 1s interval, got %v", interval)
	}
	if timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", timeout)
	}
}
