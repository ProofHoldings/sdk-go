package proof

import (
	"context"
	"net/url"
)

// HitlKeys provides access to the HITL encryption key management API.
type HitlKeys struct {
	http *httpClient
}

// HitlKeysResponse is returned by GetKeys.
type HitlKeysResponse struct {
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	KDFSalt             string `json:"kdf_salt"`
	KID                 string `json:"kid"`
}

// HitlKeysPutResponse is returned by UploadKeys.
type HitlKeysPutResponse struct {
	KID     string `json:"kid"`
	Message string `json:"message"`
}

// HitlKeysDeleteResponse is returned by DeleteKeys.
type HitlKeysDeleteResponse struct {
	Message string `json:"message"`
}

// GetKeys retrieves the encryption keypair for a HITL config.
func (h *HitlKeys) GetKeys(ctx context.Context, hitlID string) (HitlKeysResponse, error) {
	return getAs[HitlKeysResponse](h.http, ctx, "/api/v1/hitl/"+url.PathEscape(hitlID)+"/keys", nil)
}

// UploadKeys uploads an encryption keypair for a HITL config.
func (h *HitlKeys) UploadKeys(ctx context.Context, hitlID string, params map[string]any) (HitlKeysPutResponse, error) {
	return putAs[HitlKeysPutResponse](h.http, ctx, "/api/v1/hitl/"+url.PathEscape(hitlID)+"/keys", params)
}

// DeleteKeys deletes the encryption keypair from a HITL config.
func (h *HitlKeys) DeleteKeys(ctx context.Context, hitlID string) (HitlKeysDeleteResponse, error) {
	return delAs[HitlKeysDeleteResponse](h.http, ctx, "/api/v1/hitl/"+url.PathEscape(hitlID)+"/keys")
}
