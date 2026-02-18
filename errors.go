package proof

import (
	"fmt"
	"net/http"
)

// ProofError is the base error type for all API errors.
type ProofError struct {
	Message    string `json:"message"`              // Human-readable error message
	Code       string `json:"code"`                 // Machine-readable error code
	StatusCode int    `json:"status_code"`          // HTTP status code
	Details    any    `json:"details,omitempty"`     // Additional error context
	RequestID  string `json:"request_id,omitempty"` // Server request ID for debugging
}

func (e *ProofError) Error() string {
	return fmt.Sprintf("%s (code: %s, status: %d)", e.Message, e.Code, e.StatusCode)
}

// Typed error subtypes for specific HTTP status codes.

type ValidationError struct{ ProofError }
type AuthenticationError struct{ ProofError }
type ForbiddenError struct{ ProofError }
type NotFoundError struct{ ProofError }
type ConflictError struct{ ProofError }
// RateLimitError includes optional lockout fields for auth rate limiting.
type RateLimitError struct {
	ProofError
	// RetryAfter is the number of seconds to wait before retrying (from error response retryAfter field).
	RetryAfter *int
	// RemainingAttempts is the number of remaining attempts before lockout (auth endpoints only).
	RemainingAttempts *int
}
type ServerError struct{ ProofError }
type NetworkError struct{ ProofError }
type TimeoutError struct{ ProofError }
type PollingTimeoutError struct{ ProofError }

func errorFromResponse(statusCode int, apiErr *apiErrorBody) error {
	code := fmt.Sprintf("http_%d", statusCode)
	message := fmt.Sprintf("Request failed with status %d", statusCode)
	var details any
	var requestID string

	if apiErr != nil {
		if apiErr.Code != "" {
			code = apiErr.Code
		}
		if apiErr.Message != "" {
			message = apiErr.Message
		}
		details = apiErr.Details
		requestID = apiErr.RequestID
	}

	base := ProofError{
		Message:    message,
		Code:       code,
		StatusCode: statusCode,
		Details:    details,
		RequestID:  requestID,
	}

	switch statusCode {
	case http.StatusBadRequest:
		return &ValidationError{base}
	case http.StatusUnauthorized:
		return &AuthenticationError{base}
	case http.StatusForbidden:
		return &ForbiddenError{base}
	case http.StatusNotFound:
		return &NotFoundError{base}
	case http.StatusConflict:
		return &ConflictError{base}
	case http.StatusTooManyRequests:
		rl := &RateLimitError{ProofError: base}
		if apiErr != nil {
			rl.RetryAfter = apiErr.RetryAfter
			rl.RemainingAttempts = apiErr.RemainingAttempts
		}
		return rl
	default:
		if statusCode >= http.StatusInternalServerError {
			return &ServerError{base}
		}
		return &base
	}
}

type apiErrorBody struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	Details           any    `json:"details,omitempty"`
	RequestID         string `json:"request_id,omitempty"`
	RetryAfter        *int   `json:"retryAfter,omitempty"`
	RemainingAttempts *int   `json:"remaining_attempts,omitempty"`
}
