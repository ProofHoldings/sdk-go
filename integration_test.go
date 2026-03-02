// Go SDK -- Live API integration tests.
//
// Run against a real server using pk_test_* keys.
// NOT included in the default test suite -- use build tag "integration".
//
// Prerequisites:
//
//	PROOF_API_KEY_TEST -- Required, must start with "pk_test_"
//	PROOF_BASE_URL     -- Optional, defaults to "https://api.proof.holdings"
//
// Run:
//
//	PROOF_API_KEY_TEST=pk_test_xxx go test -tags integration -v ./...

//go:build integration

package proof

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

var emailCounter atomic.Int64

func uniqueEmail(prefix string) string {
	n := emailCounter.Add(1)
	return fmt.Sprintf("%s-%d-%d@example.com", prefix, time.Now().UnixMilli(), n)
}

func integrationClient(t *testing.T) *Client {
	t.Helper()
	apiKey := os.Getenv("PROOF_API_KEY_TEST")
	if apiKey == "" || len(apiKey) < 8 || apiKey[:8] != "pk_test_" {
		t.Skip("PROOF_API_KEY_TEST not set or not a test key")
	}
	baseURL := os.Getenv("PROOF_BASE_URL")
	opts := []ClientOption{}
	if baseURL != "" {
		opts = append(opts, WithBaseURL(baseURL))
	}
	client, err := NewClient(apiKey, opts...)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client
}

func TestIntegration_CreatePhoneVerification(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()
	v, err := client.Verifications.Create(ctx, map[string]interface{}{
		"type":       "phone",
		"channel":    "sms",
		"identifier": "+14155550100",
	})
	if err != nil {
		t.Fatalf("create verification failed: %v", err)
	}
	if v.ID == "" {
		t.Error("expected verification ID")
	}
	if v.Status != "pending" {
		t.Errorf("expected status pending, got %s", v.Status)
	}
}

func TestIntegration_ListVerifications(t *testing.T) {
	client := integrationClient(t)
	result, err := client.Verifications.List(context.Background(), map[string]string{"limit": "5"})
	if err != nil {
		t.Fatalf("list verifications failed: %v", err)
	}
	if result.Data == nil {
		t.Error("expected data array")
	}
}

func TestIntegration_VerifyAndValidateProof(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()
	v, err := client.Verifications.Create(ctx, map[string]interface{}{
		"type":       "email",
		"channel":    "email",
		"identifier": uniqueEmail("go-sdk-proof"),
	})
	if err != nil {
		t.Fatalf("create verification failed: %v", err)
	}
	if v.Status != "pending" {
		t.Errorf("expected status pending, got %s", v.Status)
	}

	verified, err := client.Verifications.TestVerify(ctx, v.ID)
	if err != nil {
		t.Fatalf("test-verify failed: %v", err)
	}
	if verified.ProofToken == "" {
		t.Fatal("expected proof_token")
	}

	proof, err := client.Proofs.Validate(ctx, verified.ProofToken)
	if err != nil {
		t.Fatalf("validate proof failed: %v", err)
	}
	if !proof.Valid {
		t.Error("expected proof to be valid")
	}
}

func TestIntegration_CreateVerificationRequest(t *testing.T) {
	client := integrationClient(t)
	vr, err := client.VerificationRequests.Create(context.Background(), map[string]interface{}{
		"assets": []map[string]string{
			{"type": "email", "identifier": uniqueEmail("go-sdk-vr")},
		},
	})
	if err != nil {
		t.Fatalf("create verification request failed: %v", err)
	}
	if vr.ID == "" {
		t.Error("expected verification request ID")
	}
}

func TestIntegration_ListRevokedProofs(t *testing.T) {
	client := integrationClient(t)
	result, err := client.Proofs.ListRevoked(context.Background())
	if err != nil {
		t.Fatalf("list revoked failed: %v", err)
	}
	if result.Revoked == nil {
		t.Error("expected revoked array")
	}
}

func TestIntegration_WaitForCompletion(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()
	v, err := client.Verifications.Create(ctx, map[string]interface{}{
		"type":       "email",
		"channel":    "email",
		"identifier": uniqueEmail("go-sdk-wait"),
	})
	if err != nil {
		t.Fatalf("create verification failed: %v", err)
	}

	// Test-verify to complete it
	_, err = client.Verifications.TestVerify(ctx, v.ID)
	if err != nil {
		t.Fatalf("test-verify failed: %v", err)
	}

	result, err := client.Verifications.WaitForCompletion(context.Background(), v.ID, &WaitOptions{
		Interval: 100 * time.Millisecond,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("wait for completion failed: %v", err)
	}
	if result.Status != "verified" {
		t.Errorf("expected status verified, got %s", result.Status)
	}
}
