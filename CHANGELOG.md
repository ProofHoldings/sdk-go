# Changelog

Notable changes to `github.com/ProofHoldings/sdk-go`. Each version is a `vX.Y.Z` tag of
[ProofHoldings/sdk-go](https://github.com/ProofHoldings/sdk-go).

## 1.1.0 — 2026-10-14

### Added

- `NewDefaultClient` resolves the API key when none is given: a non-empty `PROOF_API_KEY`, else the
  entry that `npx @proof-holdings/mcp-server login` saved in `~/.proof-holdings/credentials` for the
  client's base URL. The base URL is the option, else `PROOF_BASE_URL`, else
  `https://api.proof.holdings`. `NewClient` with an explicit key behaves as before.
- `Verifications.DeleteDomainVerification` deletes a domain verification attempt that is not verified
  (pending, verifying or failed). A verified domain is refused with 409 `domain_verified`.
- Types for account deletion and export, identifier, domain and project removal, and the
  `account.deletion_scheduled` / `account.deletion_cancelled` webhook events with their 2FA actions.
- Types for the artifact claim lookup (`ArtifactClaim` and its parts) and for the Delegations section
  of a public profile (`PublicProfileDelegation`, `show_delegations`).
- API-key listings carry `replaced_key_ids`: a key's usage covers every key it replaced.
- `BillingPlanFree`.

### Fixed

- The README stated Go 1.21 and no dependencies; the module requires Go 1.25 and
  `golang.org/x/crypto`, as it already did in 1.0.0.

## 1.0.0 — 2026-10-07

- First tagged release.
