package proof

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	envelopeVersion   = 1
	messageAlg        = "RSA-OAEP-256+AES-256-GCM"
	privateKeyAlg     = "PBKDF2-SHA256+AES-256-GCM"
	aesKeyBytes       = 32
	aesIVBytes        = 12
	aesTagBytes       = 16
	rsaEKBytes        = 512 // 4096-bit RSA
	pbkdf2Iterations  = 600000
	pbkdf2SaltBytes   = 16
	pbkdf2KeyBytes    = 32
	minRSAModulusBits = 4096
)

var errDecryptionFailed = errors.New("decryption failed")

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// CiphertextEnvelope represents an encrypted message (Section 2 of envelope spec).
type CiphertextEnvelope struct {
	V   int    `json:"v"`
	Alg string `json:"alg"`
	EK  string `json:"ek"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
	Tag string `json:"tag"`
	KID string `json:"kid"`
}

// EncryptedPrivateKey represents an encrypted private key for storage (Section 4.2).
type EncryptedPrivateKey struct {
	V    int    `json:"v"`
	Alg  string `json:"alg"`
	IV   string `json:"iv"`
	CT   string `json:"ct"`
	Tag  string `json:"tag"`
	Salt string `json:"salt"`
	KID  string `json:"kid"`
}

// HitlKeyPairResult is returned by GenerateEncryptionKeyPair.
type HitlKeyPairResult struct {
	PublicKeyPEM        string
	EncryptedPrivateKey EncryptedPrivateKey
	KDFSalt             string
	KID                 string
}

// ---------------------------------------------------------------------------
// Base64url helpers
// ---------------------------------------------------------------------------

func toBase64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func fromBase64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ---------------------------------------------------------------------------
// Key Identifier
// ---------------------------------------------------------------------------

// ComputeKID computes kid = lowercase_hex(SHA-256(DER-encoded SPKI public key bytes)).
func ComputeKID(publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", errors.New("failed to parse PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	hash := sha256.Sum256(der)
	return hex.EncodeToString(hash[:]), nil
}

// ---------------------------------------------------------------------------
// RSA Key Generation
// ---------------------------------------------------------------------------

// GenerateKeyPair generates an RSA-4096 key pair. Returns (publicKeyPEM, privateKeyPEM, error).
func GenerateKeyPair() (string, string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, minRSAModulusBits)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return string(pubPEM), string(privPEM), nil
}

// ---------------------------------------------------------------------------
// PBKDF2
// ---------------------------------------------------------------------------

// DeriveKey derives a 256-bit key from password + salt using PBKDF2-SHA256 at 600k iterations.
func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyBytes, sha256.New)
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

func aesGCMEncrypt(key, iv, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, aesIVBytes)
	if err != nil {
		return nil, nil, err
	}
	// GCM appends the tag to the ciphertext
	sealed := gcm.Seal(nil, iv, plaintext, aad)
	ct := sealed[:len(sealed)-aesTagBytes]
	t := sealed[len(sealed)-aesTagBytes:]
	return ct, t, nil
}

func aesGCMDecrypt(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errDecryptionFailed
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, aesIVBytes)
	if err != nil {
		return nil, errDecryptionFailed
	}
	// Append tag to ciphertext for Open
	combined := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, combined, aad)
	if err != nil {
		return nil, errDecryptionFailed
	}
	return plaintext, nil
}

// ---------------------------------------------------------------------------
// RSA-OAEP-SHA256 wrap/unwrap
// ---------------------------------------------------------------------------

func rsaOAEPWrap(publicKeyPEM string, plaintext []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, plaintext, nil)
}

func rsaOAEPUnwrap(privateKeyPEM string, ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errDecryptionFailed
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errDecryptionFailed
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errDecryptionFailed
	}
	result, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ciphertext, nil)
	if err != nil {
		return nil, errDecryptionFailed
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Envelope Validation
// ---------------------------------------------------------------------------

// ValidateMessageEnvelope checks if a CiphertextEnvelope has valid structure.
func ValidateMessageEnvelope(e *CiphertextEnvelope) bool {
	if e.V != 1 || e.Alg != messageAlg {
		return false
	}
	ek, err := fromBase64url(e.EK)
	if err != nil || len(ek) != rsaEKBytes {
		return false
	}
	iv, err := fromBase64url(e.IV)
	if err != nil || len(iv) != aesIVBytes {
		return false
	}
	tag, err := fromBase64url(e.Tag)
	if err != nil || len(tag) != aesTagBytes {
		return false
	}
	if e.CT == "" || len(e.KID) != 64 {
		return false
	}
	return true
}

// ValidatePrivateKeyEnvelope checks if an EncryptedPrivateKey has valid structure.
func ValidatePrivateKeyEnvelope(e *EncryptedPrivateKey) bool {
	if e.V != 1 || e.Alg != privateKeyAlg {
		return false
	}
	iv, err := fromBase64url(e.IV)
	if err != nil || len(iv) != aesIVBytes {
		return false
	}
	tag, err := fromBase64url(e.Tag)
	if err != nil || len(tag) != aesTagBytes {
		return false
	}
	salt, err := fromBase64url(e.Salt)
	if err != nil || len(salt) != pbkdf2SaltBytes {
		return false
	}
	if e.CT == "" || len(e.KID) != 64 {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Message Encryption (Section 4.1)
// ---------------------------------------------------------------------------

// EncryptMessage encrypts a confirmation message. AAD = "{hitlID}".
func EncryptMessage(plaintext, publicKeyPEM, hitlID string) (*CiphertextEnvelope, error) {
	aesKey := make([]byte, aesKeyBytes)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}
	iv := make([]byte, aesIVBytes)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return encryptMessageWithInputs(plaintext, publicKeyPEM, hitlID, aesKey, iv)
}

func encryptMessageWithInputs(plaintext, publicKeyPEM, hitlID string, aesKey, iv []byte) (*CiphertextEnvelope, error) {
	aad := []byte(hitlID)
	ct, tag, err := aesGCMEncrypt(aesKey, iv, []byte(plaintext), aad)
	if err != nil {
		return nil, err
	}
	ek, err := rsaOAEPWrap(publicKeyPEM, aesKey)
	if err != nil {
		return nil, err
	}
	kid, err := ComputeKID(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	return &CiphertextEnvelope{
		V:   envelopeVersion,
		Alg: messageAlg,
		EK:  toBase64url(ek),
		IV:  toBase64url(iv),
		CT:  toBase64url(ct),
		Tag: toBase64url(tag),
		KID: kid,
	}, nil
}

// DecryptMessage decrypts a confirmation message envelope. AAD = "{hitlID}".
func DecryptMessage(envelope *CiphertextEnvelope, privateKeyPEM, hitlID string) (string, error) {
	if !ValidateMessageEnvelope(envelope) {
		return "", errDecryptionFailed
	}
	ek, _ := fromBase64url(envelope.EK)
	iv, _ := fromBase64url(envelope.IV)
	ct, _ := fromBase64url(envelope.CT)
	tag, _ := fromBase64url(envelope.Tag)
	aad := []byte(hitlID)

	aesKey, err := rsaOAEPUnwrap(privateKeyPEM, ek)
	if err != nil {
		return "", errDecryptionFailed
	}
	plaintext, err := aesGCMDecrypt(aesKey, iv, ct, tag, aad)
	if err != nil {
		return "", errDecryptionFailed
	}
	return string(plaintext), nil
}

// ---------------------------------------------------------------------------
// Private Key Encryption (Section 4.2)
// ---------------------------------------------------------------------------

// EncryptPrivateKey encrypts an RSA private key with a user password. AAD = "{hitlID}:{userID}".
func EncryptPrivateKey(privateKeyPEM, password, publicKeyPEM, hitlID, userID string) (*EncryptedPrivateKey, error) {
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	derivedKey := DeriveKey(password, salt)
	iv := make([]byte, aesIVBytes)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	aad := []byte(hitlID + ":" + userID)

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM private key")
	}
	// Re-marshal to ensure PKCS#8 DER
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	ct, tag, err := aesGCMEncrypt(derivedKey, iv, der, aad)
	if err != nil {
		return nil, err
	}
	kid, err := ComputeKID(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	return &EncryptedPrivateKey{
		V:    envelopeVersion,
		Alg:  privateKeyAlg,
		IV:   toBase64url(iv),
		CT:   toBase64url(ct),
		Tag:  toBase64url(tag),
		Salt: toBase64url(salt),
		KID:  kid,
	}, nil
}

// DecryptPrivateKey decrypts an RSA private key using the user's password. Returns PEM string.
func DecryptPrivateKey(envelope *EncryptedPrivateKey, password, hitlID, userID string) (string, error) {
	if !ValidatePrivateKeyEnvelope(envelope) {
		return "", errDecryptionFailed
	}
	salt, _ := fromBase64url(envelope.Salt)
	derivedKey := DeriveKey(password, salt)
	iv, _ := fromBase64url(envelope.IV)
	ct, _ := fromBase64url(envelope.CT)
	tag, _ := fromBase64url(envelope.Tag)
	aad := []byte(hitlID + ":" + userID)

	der, err := aesGCMDecrypt(derivedKey, iv, ct, tag, aad)
	if err != nil {
		return "", errDecryptionFailed
	}
	// Verify it's a valid PKCS#8 private key
	_, err = x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", errDecryptionFailed
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return string(privPEM), nil
}

// ---------------------------------------------------------------------------
// Convenience
// ---------------------------------------------------------------------------

// GenerateEncryptionKeyPair generates RSA-4096 and encrypts the private key with a password.
func GenerateEncryptionKeyPair(password, hitlID, userID string) (*HitlKeyPairResult, error) {
	pubPEM, privPEM, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	encrypted, err := EncryptPrivateKey(privPEM, password, pubPEM, hitlID, userID)
	if err != nil {
		return nil, err
	}
	kid, err := ComputeKID(pubPEM)
	if err != nil {
		return nil, err
	}
	return &HitlKeyPairResult{
		PublicKeyPEM:        pubPEM,
		EncryptedPrivateKey: *encrypted,
		KDFSalt:             encrypted.Salt,
		KID:                 kid,
	}, nil
}

// MarshalEnvelope serializes a CiphertextEnvelope to JSON string.
func MarshalEnvelope(e *CiphertextEnvelope) (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UnmarshalEnvelope parses a JSON string into a CiphertextEnvelope.
func UnmarshalEnvelope(data string) (*CiphertextEnvelope, error) {
	var e CiphertextEnvelope
	if err := json.Unmarshal([]byte(data), &e); err != nil {
		return nil, err
	}
	// Check for unknown fields
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil, err
	}
	allowed := map[string]bool{"v": true, "alg": true, "ek": true, "iv": true, "ct": true, "tag": true, "kid": true}
	for k := range raw {
		if !allowed[k] {
			return nil, fmt.Errorf("unknown field: %s", k)
		}
	}
	return &e, nil
}

