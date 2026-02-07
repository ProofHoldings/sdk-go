package proof

import (
	"errors"
	"time"
)

const (
	DefaultBaseURL    = "https://api.proof.holdings"
	DefaultTimeout    = 30 * time.Second
	DefaultMaxRetries = 2
)

// WaitOptions configures polling behavior.
type WaitOptions struct {
	Interval time.Duration
	Timeout  time.Duration
}

func resolveWaitOptions(opts *WaitOptions) (interval, timeout time.Duration) {
	interval = 3 * time.Second
	timeout = 10 * time.Minute
	if opts != nil {
		if opts.Interval > 0 {
			interval = opts.Interval
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}
	return
}

// ClientOption configures the Proof client.
type ClientOption func(*clientConfig)

type clientConfig struct {
	baseURL    string
	timeout    time.Duration
	maxRetries int
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

// Client is the main proof.holdings API client.
type Client struct {
	Verifications        *Verifications
	VerificationRequests *VerificationRequests
	Proofs               *Proofs
	Sessions             *Sessions
	WebhookDeliveries    *WebhookDeliveries
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
	}
	for _, opt := range opts {
		opt(cfg)
	}

	http := newHTTPClient(apiKey, cfg.baseURL, cfg.timeout, cfg.maxRetries)

	return &Client{
		Verifications:        &Verifications{http: http},
		VerificationRequests: &VerificationRequests{http: http},
		Proofs:               &Proofs{http: http, jwksURL: cfg.baseURL + "/.well-known/jwks.json"},
		Sessions:             &Sessions{http: http},
		WebhookDeliveries:    &WebhookDeliveries{http: http},
	}, nil
}
