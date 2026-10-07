package proof

import (
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	DefaultBaseURL    = "https://api.proof.holdings"
	DefaultTimeout    = 30 * time.Second
	DefaultMaxRetries = 2
)

// WaitOptions configures polling behavior per the standard polling contract.
// Zero values on any field fall back to the contract defaults:
//   - Interval: 2s initial
//   - Timeout: 10min
//   - Backoff: 1.5x
//   - MaxInterval: 30s
//   - Jitter: 500ms
//
// To disable jitter entirely, pass Jitter: time.Nanosecond (a zero value is
// interpreted as "unset" for consistency with the other fields). Negative
// values and Backoff < 1 are rejected — pollUntilComplete returns an error
// from resolveWaitOptions.
type WaitOptions struct {
	Interval    time.Duration
	Timeout     time.Duration
	Backoff     float64
	MaxInterval time.Duration
	Jitter      time.Duration
}

type resolvedWaitOptions struct {
	interval    time.Duration
	timeout     time.Duration
	backoff     float64
	maxInterval time.Duration
	jitter      time.Duration
}

func resolveWaitOptions(opts *WaitOptions) (resolvedWaitOptions, error) {
	r := resolvedWaitOptions{
		interval:    2 * time.Second,
		timeout:     10 * time.Minute,
		backoff:     1.5,
		maxInterval: 30 * time.Second,
		jitter:      500 * time.Millisecond,
	}
	if opts == nil {
		return r, nil
	}
	if opts.Interval < 0 {
		return r, fmt.Errorf("Interval must be >= 0, got %s", opts.Interval)
	}
	if opts.Timeout < 0 {
		return r, fmt.Errorf("Timeout must be >= 0, got %s", opts.Timeout)
	}
	if opts.MaxInterval < 0 {
		return r, fmt.Errorf("MaxInterval must be >= 0, got %s", opts.MaxInterval)
	}
	if opts.Jitter < 0 {
		return r, fmt.Errorf("Jitter must be >= 0, got %s", opts.Jitter)
	}
	if opts.Backoff != 0 {
		if math.IsNaN(opts.Backoff) || math.IsInf(opts.Backoff, 0) || opts.Backoff < 1 {
			return r, fmt.Errorf("Backoff must be a finite number >= 1, got %v", opts.Backoff)
		}
		r.backoff = opts.Backoff
	}
	if opts.Interval > 0 {
		r.interval = opts.Interval
	}
	if opts.Timeout > 0 {
		r.timeout = opts.Timeout
	}
	if opts.MaxInterval > 0 {
		r.maxInterval = opts.MaxInterval
	}
	if opts.Jitter > 0 {
		r.jitter = opts.Jitter
	}
	return r, nil
}

// ClientOption configures the Proof client.
type ClientOption func(*clientConfig)

type clientConfig struct {
	baseURL    string
	timeout    time.Duration
	maxRetries int
	maxJWKSAge time.Duration
}

// WithBaseURL sets a custom API base URL.
func WithBaseURL(url string) ClientOption {
	return func(c *clientConfig) { c.baseURL = url }
}

// WithTimeout sets the HTTP request timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *clientConfig) { c.timeout = d }
}

// WithMaxRetries sets the maximum number of retries for failed requests.
func WithMaxRetries(n int) ClientOption {
	return func(c *clientConfig) { c.maxRetries = n }
}

// WithMaxJWKSAge bounds how old the issuer's key set may grow, while it cannot be refreshed,
// before VerifyOffline answers "jwks_stale" instead of trusting it. The default is
// DefaultMaxJWKSAge (24h); anything above MaxJWKSAgeCap (25 days), zero or negative makes NewClient
// fail.
func WithMaxJWKSAge(d time.Duration) ClientOption {
	return func(c *clientConfig) { c.maxJWKSAge = d }
}

// Client is the main proof.holdings API client.
type Client struct {
	Verifications        *Verifications
	VerificationRequests *VerificationRequests
	Proofs               *Proofs
	Sessions             *Sessions
	WebhookDeliveries    *WebhookDeliveries
	Authorizations       *Authorizations
	Confirmations        *Confirmations
	HitlKeys             *HitlKeys
	HITL                 *HITL
	Auth                 *Auth
	Me                   *Me
	Templates            *Templates
	Profiles             *Profiles
	PublicProfiles       *PublicProfiles
	ProofMe              *ProofMe
	Circles              *Circles
	Delegations          *Delegations
}

// NewClient creates a new proof.holdings API client.
func NewClient(apiKey string, opts ...ClientOption) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("api_key is required: proof.NewClient(\"pk_live_...\")")
	}

	cfg := &clientConfig{
		baseURL:    DefaultBaseURL,
		timeout:    DefaultTimeout,
		maxRetries: DefaultMaxRetries,
		maxJWKSAge: DefaultMaxJWKSAge,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if err := validateMaxJWKSAge(cfg.maxJWKSAge); err != nil {
		return nil, err
	}

	http := newHTTPClient(apiKey, cfg.baseURL, cfg.timeout, cfg.maxRetries)

	return &Client{
		Verifications:        &Verifications{http: http},
		VerificationRequests: &VerificationRequests{http: http},
		Proofs:               &Proofs{http: http, jwksURL: cfg.baseURL + "/.well-known/jwks.json", maxJWKSAge: cfg.maxJWKSAge},
		Sessions:             &Sessions{http: http},
		WebhookDeliveries:    &WebhookDeliveries{http: http},
		Authorizations:       &Authorizations{http: http},
		Confirmations:        &Confirmations{http: http},
		HitlKeys:             &HitlKeys{http: http},
		HITL:                 &HITL{http: http},
		Auth:                 &Auth{http: http},
		Me:                   &Me{http: http},
		Templates:            &Templates{http: http},
		Profiles:             &Profiles{http: http},
		PublicProfiles:       &PublicProfiles{http: http},
		ProofMe:              &ProofMe{http: http},
		Circles:              &Circles{http: http},
		Delegations:          &Delegations{http: http},
	}, nil
}
