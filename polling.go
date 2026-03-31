package proof

import (
	"context"
	"fmt"
	"time"
)

// pollUntilComplete is a generic polling helper. It calls retrieve repeatedly
// until the returned map's "status" field matches a terminal state, or the
// timeout is reached. Context cancellation is respected between polls.
func pollUntilComplete(
	ctx context.Context,
	retrieve func(context.Context) (map[string]any, error),
	isTerminal func(string) bool,
	label string,
	opts *WaitOptions,
) (map[string]any, error) {
	interval, timeout := resolveWaitOptions(opts)
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

		if time.Since(start) >= timeout {
			return nil, &PollingTimeoutError{ProofError{
				Message: fmt.Sprintf("%s did not complete within %s (last status: %s)", label, timeout, status),
				Code:    "polling_timeout",
			}}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// statusGetter is an interface for typed structs that expose a Status field.
type statusGetter interface {
	GetStatus() string
}

// pollUntilCompleteAs is a typed polling helper. It calls retrieve repeatedly
// until the returned struct's Status matches a terminal state, or the timeout
// is reached. T must implement statusGetter.
func pollUntilCompleteAs[T statusGetter](
	ctx context.Context,
	retrieve func(context.Context) (T, error),
	isTerminal func(string) bool,
	label string,
	opts *WaitOptions,
) (T, error) {
	interval, timeout := resolveWaitOptions(opts)
	start := time.Now()

	for {
		resource, err := retrieve(ctx)
		if err != nil {
			var zero T
			return zero, err
		}

		status := resource.GetStatus()
		if isTerminal(status) {
			return resource, nil
		}

		if time.Since(start) >= timeout {
			var zero T
			return zero, &PollingTimeoutError{ProofError{
				Message: fmt.Sprintf("%s did not complete within %s (last status: %s)", label, timeout, status),
				Code:    "polling_timeout",
			}}
		}

		select {
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		case <-time.After(interval):
		}
	}
}
