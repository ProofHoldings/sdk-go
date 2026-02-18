package proof

import (
	"errors"
	"testing"
)

func TestErrorFromResponse_StatusMapping(t *testing.T) {
	tests := []struct {
		status   int
		wantType string
	}{
		{400, "*proof.ValidationError"},
		{401, "*proof.AuthenticationError"},
		{403, "*proof.ForbiddenError"},
		{404, "*proof.NotFoundError"},
		{409, "*proof.ConflictError"},
		{429, "*proof.RateLimitError"},
		{500, "*proof.ServerError"},
		{502, "*proof.ServerError"},
	}

	for _, tt := range tests {
		err := errorFromResponse(tt.status, nil)
		got := ""
		switch err.(type) {
		case *ValidationError:
			got = "*proof.ValidationError"
		case *AuthenticationError:
			got = "*proof.AuthenticationError"
		case *ForbiddenError:
			got = "*proof.ForbiddenError"
		case *NotFoundError:
			got = "*proof.NotFoundError"
		case *ConflictError:
			got = "*proof.ConflictError"
		case *RateLimitError:
			got = "*proof.RateLimitError"
		case *ServerError:
			got = "*proof.ServerError"
		default:
			got = "unknown"
		}
		if got != tt.wantType {
			t.Errorf("status %d: want %s, got %s", tt.status, tt.wantType, got)
		}
	}
}

func TestErrorFromResponse_WithBody(t *testing.T) {
	err := errorFromResponse(400, &apiErrorBody{
		Code:      "invalid_param",
		Message:   "Bad input",
		Details:   map[string]any{"field": "email"},
		RequestID: "req_abc",
	})

	var valErr *ValidationError
	if !errors.As(err, &valErr) {
		t.Fatal("expected ValidationError")
	}
	if valErr.Code != "invalid_param" {
		t.Errorf("want code 'invalid_param', got %q", valErr.Code)
	}
	if valErr.Message != "Bad input" {
		t.Errorf("want message 'Bad input', got %q", valErr.Message)
	}
	if valErr.RequestID != "req_abc" {
		t.Errorf("want request_id 'req_abc', got %q", valErr.RequestID)
	}
}

func TestErrorFromResponse_Defaults(t *testing.T) {
	err := errorFromResponse(418, nil)
	var phErr *ProofError
	if !errors.As(err, &phErr) {
		t.Fatal("expected ProofError")
	}
	if phErr.Code != "http_418" {
		t.Errorf("want code 'http_418', got %q", phErr.Code)
	}
}

func TestErrorFromResponse_RateLimitWithLockoutFields(t *testing.T) {
	retryAfter := 3600
	remaining := 0
	err := errorFromResponse(429, &apiErrorBody{
		Code:              "auth_lockout",
		Message:           "Too many attempts",
		RetryAfter:        &retryAfter,
		RemainingAttempts: &remaining,
	})

	var rlErr *RateLimitError
	if !errors.As(err, &rlErr) {
		t.Fatal("expected RateLimitError")
	}
	if rlErr.Code != "auth_lockout" {
		t.Errorf("want code 'auth_lockout', got %q", rlErr.Code)
	}
	if rlErr.RetryAfter == nil || *rlErr.RetryAfter != 3600 {
		t.Errorf("want RetryAfter 3600, got %v", rlErr.RetryAfter)
	}
	if rlErr.RemainingAttempts == nil || *rlErr.RemainingAttempts != 0 {
		t.Errorf("want RemainingAttempts 0, got %v", rlErr.RemainingAttempts)
	}
}

func TestError_ImplementsError(t *testing.T) {
	err := &ProofError{Message: "test", Code: "test", StatusCode: 400}
	var _ error = err // compile-time check
	if err.Error() == "" {
		t.Error("Error() should not be empty")
	}
}
