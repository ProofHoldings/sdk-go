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

// Validate online AND bind the proof to the identifier you expect it to be about.
// A proof about anything else comes back valid:false with reason "identifier_mismatch".
bound, _ := client.Proofs.Validate(ctx, "eyJhbGciOi...", "+19295909022")

// Verify offline — no API call with your key. Two public documents are read: the JWKS for the
// signature, and the issuer's status list for revocation, which is checked by default.
offline, err := client.Proofs.VerifyOffline(ctx, "eyJhbGciOi...")
if err != nil {
    // errors.Is(err, proof.ErrJWKSUnavailable): the key set could not be used to check the token —
    // "I could not check", not "the proof is bad". There is no result to read on this path:
    // offline is nil.
    return err
}
if offline.Valid {
    fmt.Println(offline.Payload.Sub, offline.Payload.Type, offline.Payload.IdentifierHash)
} else {
    // Reason: "revoked", "suspended", "expired", "invalid", "status_unavailable", or one of the
    // key-rotation reasons below.
    fmt.Println("rejected:", offline.Reason, offline.Error)
}

// "status_unavailable" means the revocation status could NOT be read — an unreachable list, one
// that failed its own checks, or a slot the list does not cover. It is a refusal to guess, not a
// claim that the proof is withdrawn. A token minted without a status-list slot stays valid and
// reports RevocationChecked=false, exactly as the issuer's own Validate answers for it.

// Signature only, for an air-gapped check against a warm key cache:
signatureOnly, _ := client.Proofs.VerifyOffline(ctx, "eyJhbGciOi...", proof.WithoutRevocationCheck())
fmt.Println(signatureOnly.RevocationChecked) // false — never assume it was checked

// Revoke
resp, _ := client.Proofs.Revoke(ctx, "ver_abc123", "User requested")

// Get revocation list
revoked, _ := client.Proofs.ListRevoked(ctx)
```

### Signing-key rotation

`VerifyOffline` fetches and caches the issuer's key set (JWKS) itself and follows its rotation
rules. The cached set is reused for 10 minutes; a `kid` it does not know triggers one refetch, at
most once every 30 seconds — inside that window another unknown `kid` returns an error wrapping
`ErrJWKSUnavailable` (it may have been published since), and a `kid` still absent after the
refetch answers `unknown_key`.

- **`key_revoked`** — the issuer revoked the key that signed the token. The result carries
  `PullHint{IssuerOrigin, Handle}`: where to fetch the re-signed token (`Handle` is the proof's
  `proof_id`, or a delegation's `sub`). The handle is read from the token itself, whose signature a
  revoked key no longer vouches for: escape it before building a request from it. A revocation
  takes effect only after two key-set fetches at least 5 minutes apart both carry it, and is then
  kept for a year.
- **`jwks_stale`** — the key set could not be refreshed and the cached copy is older than the max
  JWKS age (default 24 hours, at most 25 days; `proof.WithMaxJWKSAge(...)`, which `NewClient`
  validates). The result carries `CacheAgeSeconds`. Call `RefreshJWKS()` once the issuer is
  reachable.
- **`wrong_key_purpose`**, **`outside_key_window`**, **`token_lifetime_exceeded`** — the key belongs
  to another token family, the token was signed outside the key's validity window, or it lives
  longer than the key allows. **`unknown_key`** — no published key matches the token's `kid`.

A key set that cannot be used at all — never fetched and unreachable, or a failed refetch with no
confirmed key left to answer — returns an error wrapping `ErrJWKSUnavailable`, never a verdict. The
cause stays wrapped underneath it: `errors.Is(err, context.Canceled)` still tells your own
cancellation apart from an unreachable issuer. `context.DeadlineExceeded` does not: the key-set read
has a 5-second timeout of its own, so compare with your `ctx.Err()` to know whose deadline passed.
Revoked-key tombstones are kept in memory only — they are not persisted, so a restarted process
learns them again from the issuer. `ClearTombstones()` forgets them on purpose. `RefreshJWKS()`
makes the next verification refetch the key set (and drops the cached status list); it does not
forget tombstones.

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
	var apiErr *proof.ProofError

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
	proof.WithMaxJWKSAge(24 * time.Hour), // offline verification: stale key-set bound
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
