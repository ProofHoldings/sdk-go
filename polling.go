package proof

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// pollUntilComplete is a generic polling helper. It calls retrieve repeatedly
// until the returned map's "status" field matches a terminal state, or the
// timeout is reached. Uses exponential backoff with jitter per the standard
// polling contract. Context cancellation is respected between polls.
func pollUntilComplete(
	ctx context.Context,
	retrieve func(context.Context) (map[string]any, error),
	isTerminal func(string) bool,
	label string,
	opts *WaitOptions,
) (map[string]any, error) {
	r, err := resolveWaitOptions(opts)
	if err != nil {
		return nil, err
	}
	interval := r.interval
	start := time.Now()

	for {
		resource, err := retrieve(ctx)
		if err != nil {
			return nil, err
		}

		status, _ := resource["status"].(string)
		if isTerminal(status) {
			return resource, nil
		}

		if time.Since(start) >= r.timeout {
			return nil, &PollingTimeoutError{ProofError{
				Message: fmt.Sprintf("%s did not complete within %s (last status: %s)", label, r.timeout, status),
				Code:    "polling_timeout",
			}}
		}

		var jitter time.Duration
		if r.jitter > 0 {
			jitter = time.Duration(rand.Int63n(int64(r.jitter) + 1))
		}

		timer := time.NewTimer(interval + jitter)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}

		// Multiply via float64 but clamp against overflow to maxInterval.
		next := float64(interval) * r.backoff
		if next > float64(r.maxInterval) || math.IsInf(next, 0) {
			interval = r.maxInterval
		} else {
			interval = time.Duration(next)
		}
	}
}
