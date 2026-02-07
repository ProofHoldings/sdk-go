package proof

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	backoffBaseMs = 1000
	backoffMaxMs  = 10000
)

type httpClient struct {
	apiKey     string
	baseURL    string
	timeout    time.Duration
	maxRetries int
	client     *http.Client
}

func newHTTPClient(apiKey, baseURL string, timeout time.Duration, maxRetries int) *httpClient {
	return &httpClient{
		apiKey:     apiKey,
		baseURL:    baseURL,
		timeout:    timeout,
		maxRetries: maxRetries,
		client:     &http.Client{Timeout: timeout},
	}
}

func (h *httpClient) get(ctx context.Context, path string, query url.Values) (map[string]any, error) {
	return h.request(ctx, http.MethodGet, path, nil, query)
}

func (h *httpClient) post(ctx context.Context, path string, body any) (map[string]any, error) {
	return h.request(ctx, http.MethodPost, path, body, nil)
}

func (h *httpClient) del(ctx context.Context, path string) (map[string]any, error) {
	return h.request(ctx, http.MethodDelete, path, nil, nil)
}

func (h *httpClient) request(ctx context.Context, method, path string, body any, query url.Values) (map[string]any, error) {
	u, err := url.Parse(h.baseURL + path)
	if err != nil {
		return nil, &NetworkError{ProofError{Message: err.Error(), Code: "network_error"}}
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}

	var lastErr error

	for attempt := 0; attempt <= h.maxRetries; attempt++ {
		var bodyReader io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal request body: %w", err)
			}
			bodyReader = bytes.NewReader(data)
		}

		req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
		if err != nil {
			return nil, &NetworkError{ProofError{Message: err.Error(), Code: "network_error"}}
		}

		req.Header.Set("Authorization", "Bearer "+h.apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "proof-sdk-go/"+Version)

		resp, err := h.client.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, &TimeoutError{ProofError{
					Message: fmt.Sprintf("Request to %s %s timed out", method, path),
					Code:    "timeout",
				}}
			}
			if attempt < h.maxRetries {
				time.Sleep(h.backoff(attempt))
				continue
			}
			break
		}

		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)

		// Rate limiting — retry with backoff
		if resp.StatusCode == http.StatusTooManyRequests && attempt < h.maxRetries {
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if sec, err := strconv.ParseFloat(ra, 64); err == nil {
					time.Sleep(time.Duration(sec * float64(time.Second)))
					continue
				}
			}
			time.Sleep(h.backoff(attempt))
			continue
		}

		// Server errors — retry with backoff
		if resp.StatusCode >= http.StatusInternalServerError && attempt < h.maxRetries {
			time.Sleep(h.backoff(attempt))
			continue
		}

		// Parse response
		var result map[string]any
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, &result); err != nil {
				result = make(map[string]any)
			}
		} else {
			result = make(map[string]any)
		}

		// Error responses
		if resp.StatusCode >= http.StatusBadRequest {
			var apiErr *apiErrorBody
			if errData, ok := result["error"]; ok && errData != nil {
				if errBytes, err := json.Marshal(errData); err == nil {
					apiErr = &apiErrorBody{}
					_ = json.Unmarshal(errBytes, apiErr)
				}
			}
			return nil, errorFromResponse(resp.StatusCode, apiErr)
		}

		return result, nil
	}

	if lastErr != nil {
		return nil, &NetworkError{ProofError{Message: lastErr.Error(), Code: "network_error"}}
	}
	return nil, &NetworkError{ProofError{Message: "Network request failed", Code: "network_error"}}
}

func (h *httpClient) backoff(attempt int) time.Duration {
	ms := math.Min(backoffBaseMs*math.Pow(2, float64(attempt)), backoffMaxMs)
	return time.Duration(ms) * time.Millisecond
}
