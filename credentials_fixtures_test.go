package proof

// Key and base-URL resolution follows the MCP server's chain (m-implement-sdk-key-resolution).
//
// The shared cases in sdks/shared/fixtures/credentials/cases.json run here through the PUBLIC
// surface — NewClient(key, opts...) or NewDefaultClient(opts...) — with HOME pointed at a temp
// directory holding the case's credentials file and the two variables set from the case. What is
// asserted is what reaches the wire: the Authorization header a recording RoundTripper sees and
// the origin it was sent to. The same file drives the MCP reference (through the root drift test)
// and the other three SDKs, so a rule read differently here fails here.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type credentialsFixture struct {
	LoginCommand   string                     `json:"login_command"`
	DefaultBaseURL string                     `json:"default_base_url"`
	Files          map[string]json.RawMessage `json:"files"`
	Cases          []credentialsCase          `json:"cases"`
}

type credentialsCase struct {
	Name     string            `json:"name"`
	Explicit *string           `json:"explicit"`
	Env      map[string]string `json:"env"`
	File     *string           `json:"file"`
	BaseURL  *string           `json:"base_url"`
	Expect   struct {
		APIKey  *string `json:"api_key"`
		Source  string  `json:"source"`
		BaseURL string  `json:"base_url"`
		Notice  bool    `json:"notice"`
		Error   bool    `json:"error"`
	} `json:"expect"`
}

func loadCredentialsFixture(t *testing.T) *credentialsFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "shared", "fixtures", "credentials", "cases.json"))
	if err != nil {
		t.Fatalf("read credentials/cases.json: %v", err)
	}
	var fixture credentialsFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse credentials/cases.json: %v", err)
	}
	if fixture.LoginCommand != LoginCommand {
		t.Fatalf("fixture login_command %q != LoginCommand %q", fixture.LoginCommand, LoginCommand)
	}
	return &fixture
}

// fileBody is what the fixture's `files` entry writes: a string entry verbatim, an object as JSON.
func fileBody(raw json.RawMessage) []byte {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []byte(s)
	}
	return raw
}

// writeCredentialsFile writes the fixture's named file under home and returns its path.
func writeCredentialsFile(t *testing.T, fixture *credentialsFixture, home string, name *string) string {
	t.Helper()
	path := filepath.Join(home, ".proof-holdings", "credentials")
	if name == nil {
		return path
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, fileBody(fixture.Files[*name]), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// setCaseEnv sets the case's variables and unsets the absent ones; t.Setenv restores both.
func setCaseEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for _, key := range []string{"PROOF_API_KEY", "PROOF_BASE_URL"} {
		if value, ok := env[key]; ok {
			t.Setenv(key, value)
			continue
		}
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
}

type recordingTransport struct {
	authorization string
	url           string
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.authorization = req.Header.Get("Authorization")
	r.url = req.URL.String()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader("{}")),
		Request:    req,
	}, nil
}

// origin is scheme, lowercased host and effective port — what every runner compares, since the
// transports differ in how they rewrite the rest of a base URL.
func origin(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = defaultPort(scheme)
	}
	return scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

func TestCredentialsFixture_SharedCases(t *testing.T) {
	fixture := loadCredentialsFixture(t)
	for _, c := range fixture.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			file := writeCredentialsFile(t, fixture, home, c.File)
			setCaseEnv(t, c.Env)

			opts := []ClientOption{WithMaxRetries(0)}
			if c.BaseURL != nil {
				opts = append(opts, WithBaseURL(*c.BaseURL))
			}
			var client *Client
			var err error
			if c.Explicit != nil {
				client, err = NewClient(*c.Explicit, opts...)
			} else {
				client, err = NewDefaultClient(opts...)
			}

			if c.Expect.Error {
				if err == nil {
					t.Fatal("expected construction to fail")
				}
				msg := err.Error()
				if !strings.Contains(msg, "api_key is required") {
					t.Fatalf("message %q does not name the missing key", msg)
				}
				if c.Explicit != nil {
					// Today's error, verbatim: the chain was never consulted.
					if strings.Contains(msg, LoginCommand) {
						t.Fatalf("explicit empty key consulted the chain: %q", msg)
					}
				} else {
					if !strings.Contains(msg, LoginCommand) || !strings.Contains(msg, "PROOF_API_KEY") {
						t.Fatalf("message %q does not name the three roads", msg)
					}
				}
				if strings.Contains(msg, file) != c.Expect.Notice {
					t.Fatalf("notice naming %s: got %v in %q, want %v", file, !c.Expect.Notice, msg, c.Expect.Notice)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			rec := &recordingTransport{}
			client.Verifications.http.client.Transport = rec
			if _, err := client.Verifications.Retrieve(context.Background(), "ver_x"); err != nil {
				t.Fatalf("retrieve: %v", err)
			}
			if want := "Bearer " + *c.Expect.APIKey; rec.authorization != want {
				t.Fatalf("Authorization = %q, want %q", rec.authorization, want)
			}
			if got, want := origin(t, rec.url), origin(t, c.Expect.BaseURL); got != want {
				t.Fatalf("request origin = %s (url %s), want %s", got, rec.url, want)
			}
		})
	}
}

func TestCredentialsResolveAPIKey_Direct(t *testing.T) {
	fixture := loadCredentialsFixture(t)
	const baseURL = "https://api.proof.holdings"
	getenv := func(env map[string]string) func(string) string {
		return func(key string) string { return env[key] }
	}
	validFile := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "credentials")
		if err := os.WriteFile(path, fileBody(fixture.Files["valid"]), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("env wins without reading the file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "credentials")
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		got := resolveAPIKey(baseURL, path, getenv(map[string]string{"PROOF_API_KEY": "pk_live_env"}))
		if got != (ResolvedKey{APIKey: "pk_live_env", Source: KeySourceEnv}) {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("file entry for exactly this base URL", func(t *testing.T) {
		path := validFile(t)
		got := resolveAPIKey("https://API.Proof.Holdings:443/", path, getenv(nil))
		if got != (ResolvedKey{APIKey: "pk_live_file_production", Source: KeySourceFile}) {
			t.Fatalf("got %+v", got)
		}
		got = resolveAPIKey("http://localhost:3000/proxy/", path, getenv(map[string]string{"PROOF_API_KEY": ""}))
		if got != (ResolvedKey{APIKey: "pk_test_file_proxy", Source: KeySourceFile}) {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("none is silent without a file and a notice when it cannot be used", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "credentials")
		if got := resolveAPIKey(baseURL, missing, getenv(nil)); got != (ResolvedKey{Source: KeySourceNone}) {
			t.Fatalf("missing file: got %+v", got)
		}
		if got := resolveAPIKey(baseURL, "", getenv(nil)); got != (ResolvedKey{Source: KeySourceNone}) {
			t.Fatalf("no home: got %+v", got)
		}
		path := validFile(t)
		if got := resolveAPIKey("https://api.staging.proof.holdings", path, getenv(nil)); got != (ResolvedKey{Source: KeySourceNone}) {
			t.Fatalf("other base URL: got %+v", got)
		}
		broken := resolveAPIKey("not a url", path, getenv(nil))
		if broken.Source != KeySourceNone || broken.APIKey != "" || !strings.Contains(broken.Notice, path) {
			t.Fatalf("non-URL base: got %+v", broken)
		}
		if err := os.WriteFile(path, []byte(`{"version": 2, "credentials": {}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		wrongVersion := resolveAPIKey(baseURL, path, getenv(nil))
		if wrongVersion.Source != KeySourceNone || !strings.Contains(wrongVersion.Notice, path) || !strings.Contains(wrongVersion.Notice, LoginCommand) {
			t.Fatalf("wrong version: got %+v", wrongVersion)
		}
	})
}

func TestCredentialsCredentialKey(t *testing.T) {
	cases := map[string]string{
		"https://api.proof.holdings":      "https://api.proof.holdings",
		"https://api.proof.holdings/":     "https://api.proof.holdings",
		"https://API.Proof.Holdings:443/": "https://api.proof.holdings",
		"http://localhost:3000/proxy/":    "http://localhost:3000/proxy",
		"http://localhost:8080":           "http://localhost:8080",
	}
	for in, want := range cases {
		got, err := credentialKey(in)
		if err != nil || got != want {
			t.Fatalf("credentialKey(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := credentialKey("not a url"); err == nil {
		t.Fatal("expected an error for a non-URL")
	}
}

func TestCredentialsResolveBaseURL(t *testing.T) {
	const staging = "https://api.staging.proof.holdings"
	t.Setenv("PROOF_BASE_URL", staging)
	if got := ResolveBaseURL("http://localhost:3000"); got != "http://localhost:3000" {
		t.Fatalf("explicit: got %q", got)
	}
	if got := ResolveBaseURL(""); got != staging {
		t.Fatalf("env: got %q", got)
	}
	t.Setenv("PROOF_BASE_URL", "")
	if got := ResolveBaseURL(""); got != DefaultBaseURL {
		t.Fatalf("empty env: got %q", got)
	}
}
