package proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwksCache caches a fetched JWKS keyset.
type jwksCache struct {
	mu   sync.RWMutex
	keys map[string]crypto.PublicKey // kid → public key
	url  string
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{url: url}
}

func (c *jwksCache) getKey(kid string) (crypto.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.keys == nil {
		return nil, false
	}
	key, ok := c.keys[kid]
	return key, ok
}

func (c *jwksCache) refresh() error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.url)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, raw := range jwks.Keys {
		var header struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			continue
		}

		var pubKey crypto.PublicKey
		switch header.Kty {
		case "RSA":
			pubKey, err = parseRSAKey(raw)
		case "EC":
			pubKey, err = parseECKey(raw)
		default:
			continue
		}
		if err != nil {
			continue
		}
		keys[header.Kid] = pubKey
	}

	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
	return nil
}

func (c *jwksCache) clear() {
	c.mu.Lock()
	c.keys = nil
	c.mu.Unlock()
}

// parseRSAKey parses an RSA JWK into an *rsa.PublicKey.
func parseRSAKey(raw json.RawMessage) (*rsa.PublicKey, error) {
	var k struct {
		N string `json:"n"`
		E string `json:"e"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() > 1<<31-1 || e.Int64() < 2 {
		return nil, fmt.Errorf("invalid RSA public exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// parseECKey parses an EC JWK into an *ecdsa.PublicKey.
func parseECKey(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var k struct {
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// verifyJWT verifies a JWT token using the cached JWKS keys.
// Returns the decoded payload claims on success.
func verifyJWT(cache *jwksCache, token string, issuer string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse token header: %w", err)
	}

	// Ensure keys are loaded
	if _, ok := cache.getKey(header.Kid); !ok {
		if err := cache.refresh(); err != nil {
			return nil, err
		}
	}

	key, ok := cache.getKey(header.Kid)
	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", header.Kid)
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	if err := verifySignature(header.Alg, key, signingInput, signature); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	// Validate issuer
	if iss, _ := claims["iss"].(string); issuer != "" && iss != issuer {
		return nil, fmt.Errorf("issuer mismatch: got %q, want %q", iss, issuer)
	}

	// Validate expiry and not-before with clock tolerance for minor skew between servers
	const clockToleranceSecs int64 = 5
	now := time.Now().Unix()
	if exp, ok := claims["exp"].(float64); ok {
		if now > int64(exp)+clockToleranceSecs {
			return nil, errors.New("token has expired")
		}
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		if now < int64(nbf)-clockToleranceSecs {
			return nil, errors.New("token is not yet valid")
		}
	}

	return claims, nil
}

// verifySignature verifies a JWT signature using the given algorithm and key.
func verifySignature(alg string, key crypto.PublicKey, signingInput string, signature []byte) error {
	data := []byte(signingInput)

	switch alg {
	case "RS256":
		return verifyRSA(key, crypto.SHA256, sha256.New(), data, signature)
	case "RS384":
		return verifyRSA(key, crypto.SHA384, sha512.New384(), data, signature)
	case "RS512":
		return verifyRSA(key, crypto.SHA512, sha512.New(), data, signature)
	case "ES256":
		return verifyECDSA(key, sha256.New(), data, signature)
	case "ES384":
		return verifyECDSA(key, sha512.New384(), data, signature)
	case "ES512":
		return verifyECDSA(key, sha512.New(), data, signature)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func verifyRSA(key crypto.PublicKey, hashType crypto.Hash, h hash.Hash, data, signature []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("key is not RSA")
	}
	h.Write(data)
	return rsa.VerifyPKCS1v15(rsaKey, hashType, h.Sum(nil), signature)
}

func verifyECDSA(key crypto.PublicKey, h hash.Hash, data, signature []byte) error {
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("key is not ECDSA")
	}
	h.Write(data)

	// JWT ECDSA signatures use raw R || S format (RFC 7515), not ASN.1 DER
	keySize := (ecKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keySize {
		return fmt.Errorf("invalid ECDSA signature length: got %d, want %d", len(signature), 2*keySize)
	}
	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	if !ecdsa.Verify(ecKey, h.Sum(nil), r, s) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}
