package proof

import "fmt"

// ProofHoldingsError is the base error type for all API errors.
type ProofHoldingsError struct {
	Message    string `json:"message"`
	Code       string `json:"code"`
	StatusCode int    `json:"status_code"`
	Details    any    `json:"details,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
}

func (e *ProofHoldingsError) Error() string {
	return fmt.Sprintf("%s (code: %s, status: %d)", e.Message, e.Code, e.StatusCode)
}

// Typed error subtypes for specific HTTP status codes.

type ValidationError struct{ ProofHoldingsError }
type AuthenticationError struct{ ProofHoldingsError }
type ForbiddenError struct{ ProofHoldingsError }
type NotFoundError struct{ ProofHoldingsError }
type ConflictError struct{ ProofHoldingsError }
type RateLimitError struct{ ProofHoldingsError }
type ServerError struct{ ProofHoldingsError }
type NetworkError struct{ ProofHoldingsError }
type TimeoutError struct{ ProofHoldingsError }
type PollingTimeoutError struct{ ProofHoldingsError }

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

	base := ProofHoldingsError{
		Message:    message,
		Code:       code,
		StatusCode: statusCode,
		Details:    details,
		RequestID:  requestID,
	}

	switch statusCode {
	case 400:
		return &ValidationError{base}
	case 401:
		return &AuthenticationError{base}
	case 403:
		return &ForbiddenError{base}
	case 404:
		return &NotFoundError{base}
	case 409:
		return &ConflictError{base}
	case 429:
		return &RateLimitError{base}
	default:
		if statusCode >= 500 {
			return &ServerError{base}
		}
		return &base
	}
}

type apiErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Details   any    `json:"details,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}
