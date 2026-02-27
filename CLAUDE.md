# Go SDK CLAUDE.md

## Purpose

Official Go client library for the proof.holdings API, providing typed struct returns, context.Context support, and generic HTTP helpers for all 22 resource groups.

## Narrative Summary

The Go SDK wraps the proof.holdings REST API into idiomatic Go. All public resource methods accept `context.Context` as their first parameter and return typed structs (auto-generated from the OpenAPI spec) rather than raw `map[string]any`. The SDK uses Go generics for HTTP helpers (`requestAs[T]`, `getAs[T]`, `postAs[T]`, `putAs[T]`, `patchAs[T]`, `delAs[T]`, `delWithBodyAs[T]`) that unmarshal JSON responses directly into typed structs. A generic polling helper `pollUntilCompleteAs[T]` supports waiting for terminal states on any struct implementing the `statusGetter` interface.

Type definitions in `types.go` (1,172 lines) are auto-generated from the OpenAPI 3.1 spec by `scripts/generate-sdk-types.ts`. Client-only types (`WaitOptions`, `ClientOption`, error types) are hand-maintained in `client.go` and `errors.go`.

## Key Files

### Client
- `client.go` - `Client` struct with 22 resource fields, `NewClient()` constructor, `ClientOption` functional options (`WithBaseURL`, `WithTimeout`, `WithMaxRetries`), `WaitOptions` struct
- `version.go` - SDK version constant

### HTTP Layer
- `http.go:1-160` - `httpClient` with untyped methods (`get`, `post`, `put`, `patch`, `del`), exponential backoff, retry logic (429/5xx), error parsing
- `http.go:162-217` - Generic typed helpers: `requestAs[T]`, `getAs[T]`, `postAs[T]`, `putAs[T]`, `patchAs[T]`, `delAs[T]`, `delWithBodyAs[T]`

### Types (Auto-Generated)
- `types.go` - 1,172 lines of Go structs generated from OpenAPI 3.1 schemas. Includes JSON struct tags, pointer types for optional fields, and type aliases for enums
- `types_methods.go` - `statusGetter` interface implementations: `GetStatus()` methods on `Verification`, `Session`, and `VerificationRequest` structs

### Polling
- `polling.go:1-46` - Untyped `pollUntilComplete` (returns `map[string]any`)
- `polling.go:48-51` - `statusGetter` interface definition
- `polling.go:56-93` - Generic `pollUntilCompleteAs[T statusGetter]` for typed polling with context cancellation support

### Error Handling
- `errors.go` - Error types: `ProofError` (base), `ValidationError`, `AuthenticationError`, `NotFoundError`, `RateLimitError`, `NetworkError`, `PollingTimeoutError`

### Resource Modules (22 resources)
- `verifications.go` - Verifications (Create, Retrieve, List, Verify, Submit, Resend, TestVerify, ListVerifiedUsers, GetVerifiedUser, StartDomain, CheckDomain, WaitForCompletion)
- `verification_requests.go` - Verification Requests
- `proofs.go` - Proofs (Validate, GetStatus, Revoke, ListRevoked)
- `sessions.go` - Sessions (Create, Retrieve, WaitForCompletion)
- `webhook_deliveries.go` - Webhook Deliveries
- `templates.go` - Message Templates
- `profiles.go` - Profiles
- `projects.go` - Projects
- `billing.go` - Billing
- `phones.go` - Phone management
- `emails.go` - Email management
- `assets.go` - Asset management
- `auth.go` - Authentication
- `settings.go` - Settings
- `api_keys.go` - API Keys
- `two_fa.go` - Two-Factor Authentication
- `dns_credentials.go` - DNS Credentials
- `domains.go` - Domain management
- `user_requests.go` - User Requests
- `user_domain_verify.go` - User Domain Verification
- `public_profiles.go` - Public Profiles
- `account.go` - Account management

### Tests
- `client_test.go` - Client initialization tests
- `http_test.go` - HTTP layer tests (retries, backoff, errors)
- `errors_test.go` - Error type tests
- `polling_test.go` - Polling helper tests
- `resources_test.go` - Resource method tests covering all 22 resource types (136 tests): request building, URL construction, query parameters, typed response unmarshalling
- `integration_test.go` - Integration tests against live API

## Key Patterns

### Generic Typed Helpers
All resource methods use generic functions (e.g., `getAs[Verification]`) to unmarshal API responses directly into Go structs. The untyped `get`/`post`/etc. methods returning `map[string]any` remain in `http.go` for backward compatibility but are not used by resource methods.

### statusGetter Interface
Types that support polling (`Verification`, `Session`, `VerificationRequest`) implement `GetStatus() string` via `types_methods.go`. This enables `pollUntilCompleteAs[T]` to extract status from any pollable struct without reflection.

### Type Generation Chain
Zod schemas (`src/openapi/schemas.ts`) -> OpenAPI 3.1 spec (`src/openapi/registry.ts`) -> `scripts/generate-sdk-types.ts` -> `types.go`

## Configuration

### Client Options
- `WithBaseURL(url)` - Custom API base URL (default: `https://api.proof.holdings`)
- `WithTimeout(d)` - HTTP request timeout (default: 30s)
- `WithMaxRetries(n)` - Max retry attempts (default: 2)

### Polling Options
- `WaitOptions.Interval` - Poll interval (default: 3s)
- `WaitOptions.Timeout` - Max wait time (default: 10m)

## Dependencies
- Go standard library only (no external dependencies)

## Related Documentation
- `../CLAUDE.md` - Root project documentation
- `../../scripts/generate-sdk-types.ts` - Type generation script
- `../../src/openapi/` - OpenAPI spec source
- `../../docs/api-map.yaml` - API parity map
