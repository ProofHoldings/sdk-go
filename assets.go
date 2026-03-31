package proof

import (
	"context"
	"net/url"
)

// Assets provides access to the verified assets API.
type Assets struct {
	http *httpClient
}

// List lists all verified assets for the authenticated user.
func (a *Assets) List(ctx context.Context, params map[string]string) ([]UserAsset, error) {
	q := url.Values{}
	for k, val := range params {
		if val != "" {
			q.Set(k, val)
		}
	}
	return getAs[[]UserAsset](a.http, ctx, "/api/v1/me/assets", q)
}

// Get gets a specific asset by ID.
func (a *Assets) Get(ctx context.Context, assetID string) (UserAsset, error) {
	return getAs[UserAsset](a.http, ctx, "/api/v1/me/assets/"+url.PathEscape(assetID), nil)
}

// Revoke revokes an asset by ID.
func (a *Assets) Revoke(ctx context.Context, assetID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](a.http, ctx, "/api/v1/me/assets/"+url.PathEscape(assetID))
}
