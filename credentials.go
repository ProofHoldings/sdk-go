package proof

// Where the key comes from when NewDefaultClient is given none.
//
// The chain is the MCP server's (mcp/src/credentials.ts, the reference): a non-empty
// PROOF_API_KEY, else the entry `npx @proof-holdings/mcp-server login` saved for exactly this base
// URL in ~/.proof-holdings/credentials, else none. NewClient, which takes an explicit key, never
// runs it: an explicit key is used as given and an explicit empty one is the caller's error (a
// multi-tenant host passing a tenant's key must not fall through to its own). The shared cases in
// sdks/shared/fixtures/credentials/cases.json hold this file and the other three SDKs to the
// reference.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// LoginCommand is how every message names the login: the scoped package, never the bare bin
// name, which npx would resolve to an unscoped package somebody else publishes.
const LoginCommand = "npx @proof-holdings/mcp-server login"

// KeySource says where a resolved key came from.
type KeySource string

const (
	KeySourceExplicit KeySource = "explicit"
	KeySourceEnv      KeySource = "env"
	KeySourceFile     KeySource = "file"
	KeySourceNone     KeySource = "none"
)

// ResolvedKey is the answer of ResolveAPIKey: the key and its source, or no key and, when the
// credentials file exists but could not be used, a Notice saying why — never a key.
type ResolvedKey struct {
	APIKey string
	Source KeySource
	Notice string
}

type storedCredential struct {
	APIKey      string
	KeyID       string
	Name        string
	Environment string
	CreatedAt   string
}

var errNoCredentialsFile = errors.New("no credentials file")

// credentialsFileError: the file exists but cannot be read or is not a credentials file this
// version understands.
type credentialsFileError struct{ msg string }

func (e *credentialsFileError) Error() string { return e.msg }

// DefaultCredentialsPath is ~/.proof-holdings/credentials, the file the login writes.
func DefaultCredentialsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".proof-holdings", "credentials"), nil
}

func defaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// credentialKey is the origin plus path, no trailing slash — the entry name the login saves
// under: https://API.Proof.Holdings:443/ → https://api.proof.holdings,
// http://localhost:3000/proxy/ → http://localhost:3000/proxy.
func credentialKey(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "" || host == "" {
		return "", fmt.Errorf("not a URL: %q", baseURL)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	origin := scheme + "://" + host
	if port := u.Port(); port != "" && port != defaultPort(scheme) {
		origin += ":" + port
	}
	return origin + strings.TrimRight(u.Path, "/"), nil
}

// ResolveBaseURL is the explicit base URL, else a non-empty PROOF_BASE_URL, else DefaultBaseURL.
func ResolveBaseURL(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if fromEnv := os.Getenv("PROOF_BASE_URL"); fromEnv != "" {
		return fromEnv
	}
	return DefaultBaseURL
}

func asStoredCredential(value any) (storedCredential, bool) {
	entry, ok := value.(map[string]any)
	if !ok {
		return storedCredential{}, false
	}
	apiKey, _ := entry["api_key"].(string)
	keyID, _ := entry["key_id"].(string)
	name, _ := entry["name"].(string)
	environment, _ := entry["environment"].(string)
	createdAt, _ := entry["created_at"].(string)
	if !strings.HasPrefix(apiKey, "pk_") || keyID == "" || name == "" || createdAt == "" {
		return storedCredential{}, false
	}
	if environment != "production" && environment != "test" {
		return storedCredential{}, false
	}
	return storedCredential{APIKey: apiKey, KeyID: keyID, Name: name, Environment: environment, CreatedAt: createdAt}, true
}

// readCredentialsFile returns the file's entries by base URL, errNoCredentialsFile when there is
// no file, and a *credentialsFileError when it is unreadable or malformed.
func readCredentialsFile(path string) (map[string]storedCredential, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNoCredentialsFile
		}
		return nil, &credentialsFileError{fmt.Sprintf("cannot read %s: %v", path, err)}
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, &credentialsFileError{path + " is not valid JSON"}
	}
	top, isObject := parsed.(map[string]any)
	version, _ := top["version"].(float64)
	credentials, hasCredentials := top["credentials"].(map[string]any)
	if !isObject || version != 1 || !hasCredentials {
		return nil, &credentialsFileError{path + " is not a version 1 Proof credentials file"}
	}
	entries := make(map[string]storedCredential, len(credentials))
	for key, value := range credentials {
		entry, ok := asStoredCredential(value)
		if !ok {
			return nil, &credentialsFileError{fmt.Sprintf("%s has a malformed entry for %s", path, key)}
		}
		entries[key] = entry
	}
	return entries, nil
}

// resolveAPIKey is the chain: a non-empty PROOF_API_KEY, else the saved entry for exactly
// baseURL, else none. A broken file or a base URL that is not a URL never fails here — it
// becomes a Notice on the none answer. An empty path means there is no file to look in.
func resolveAPIKey(baseURL, path string, getenv func(string) string) ResolvedKey {
	if key := getenv("PROOF_API_KEY"); key != "" {
		return ResolvedKey{APIKey: key, Source: KeySourceEnv}
	}
	if path == "" {
		return ResolvedKey{Source: KeySourceNone}
	}
	entries, err := readCredentialsFile(path)
	if errors.Is(err, errNoCredentialsFile) {
		return ResolvedKey{Source: KeySourceNone}
	}
	if err != nil {
		return ResolvedKey{
			Source: KeySourceNone,
			Notice: fmt.Sprintf("ignoring the saved credentials — %v. Fix or delete %s, then run %s.", err, path, LoginCommand),
		}
	}
	key, err := credentialKey(baseURL)
	if err != nil {
		return ResolvedKey{
			Source: KeySourceNone,
			Notice: fmt.Sprintf("the base URL %q is not a URL, so the saved credentials in %s were not read.", baseURL, path),
		}
	}
	if entry, ok := entries[key]; ok {
		return ResolvedKey{APIKey: entry.APIKey, Source: KeySourceFile}
	}
	return ResolvedKey{Source: KeySourceNone}
}

// ResolveAPIKey finds the key NewDefaultClient would use for baseURL: a non-empty PROOF_API_KEY,
// else the entry saved by `npx @proof-holdings/mcp-server login` for exactly baseURL in
// ~/.proof-holdings/credentials. A home directory that cannot be determined counts as no file.
func ResolveAPIKey(baseURL string) ResolvedKey {
	path, err := DefaultCredentialsPath()
	if err != nil {
		path = ""
	}
	return resolveAPIKey(baseURL, path, os.Getenv)
}

// missingKeyError is the one error a missing key produces, whatever road the caller tried.
func missingKeyError(baseURL, notice string) error {
	msg := fmt.Sprintf(
		"api_key is required: proof.NewClient(\"pk_live_...\"), set PROOF_API_KEY, or run `%s` to save one for %s.",
		LoginCommand, baseURL,
	)
	if notice != "" {
		msg += " " + notice
	}
	return errors.New(msg)
}
