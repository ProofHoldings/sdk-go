# sdk-go

Official Go SDK for the [proof.holdings](https://proof.holdings) verification API.

## Installation

```bash
go get github.com/ProofHoldings/sdk-go
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	proof "github.com/ProofHoldings/sdk-go"
)

func main() {
	client, err := proof.NewClient("pk_live_...")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Create a phone verification
	v, err := client.Verifications.Create(ctx, map[string]any{
		"type":       "phone",
		"channel":    "whatsapp",
		"identifier": "+1234567890",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Verification %s created: %s\n", v["id"], v["status"])

	// Wait for user to complete verification
	result, err := client.Verifications.WaitForCompletion(ctx, v["id"].(string), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Result: %s\n", result["status"])
}
```

## Resources

### Verifications

```go
// Create
v, _ := client.Verifications.Create(ctx, map[string]any{
	"type": "domain", "channel": "dns", "identifier": "example.com",
})

// Retrieve
v, _ = client.Verifications.Retrieve(ctx, "ver_abc123")

// List with filters
page, _ := client.Verifications.List(ctx, map[string]string{
	"status": "verified", "type": "phone", "limit": "10",
})

// Trigger DNS/HTTP check
v, _ = client.Verifications.Verify(ctx, "ver_abc123")

// Submit OTP code
v, _ = client.Verifications.Submit(ctx, "ver_abc123", "ABC123")

// Poll until complete
v, _ = client.Verifications.WaitForCompletion(ctx, "ver_abc123", &proof.WaitOptions{
	Interval: 2 * time.Second,
	Timeout:  5 * time.Minute,
})
```

### Verification Requests (Multi-Asset)

```go
req, _ := client.VerificationRequests.Create(ctx, map[string]any{
	"assets": []map[string]any{
		{"type": "phone", "required": true},
		{"type": "email", "identifier": "user@example.com"},
	},
	"reference_id": "user_123",
	"callback_url": "https://yourapp.com/webhook",
	"expires_in":   86400,
})
fmt.Println("Send user to:", req["verification_url"])

result, _ := client.VerificationRequests.WaitForCompletion(ctx, req["id"].(string), nil)
```

### Proofs

```go
// Validate online
result, _ := client.Proofs.Validate(ctx, "eyJhbGciOi...", "")

// Revoke
resp, _ := client.Proofs.Revoke(ctx, "ver_abc123", "User requested")

// Get revocation list
revoked, _ := client.Proofs.ListRevoked(ctx)
```

### Sessions (Phone-First Flow)

```go
session, _ := client.Sessions.Create(ctx, map[string]any{"channel": "telegram"})
fmt.Println("Deep link:", session["deep_link"])

result, _ := client.Sessions.WaitForCompletion(ctx, session["id"].(string), nil)
```

### Webhook Deliveries

```go
deliveries, _ := client.WebhookDeliveries.List(ctx, map[string]string{"status": "failed"})
result, _ := client.WebhookDeliveries.Retry(ctx, "del_abc123")
```

## Error Handling

```go
import "errors"

v, err := client.Verifications.Retrieve(ctx, "nonexistent")
if err != nil {
	var notFound *proof.NotFoundError
	var rateLimit *proof.RateLimitError
	var apiErr *proof.ProofHoldingsError

	switch {
	case errors.As(err, &notFound):
		fmt.Println("Not found:", notFound.Code)
	case errors.As(err, &rateLimit):
		fmt.Println("Rate limited, try again later")
	case errors.As(err, &apiErr):
		fmt.Printf("API error %d: %s - %s\n", apiErr.StatusCode, apiErr.Code, apiErr.Message)
	default:
		fmt.Println("Error:", err)
	}
}
```

## Configuration

```go
client, _ := proof.NewClient("pk_live_...",
	proof.WithBaseURL("https://api.proof.holdings"),
	proof.WithTimeout(30 * time.Second),
	proof.WithMaxRetries(2),
)
```

## Context & Cancellation

All methods accept a `context.Context` for cancellation and timeouts:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

v, err := client.Verifications.Retrieve(ctx, "ver_abc123")
```

## Requirements

- Go >= 1.21
- No external dependencies (uses `net/http` from the standard library)
