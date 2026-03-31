package proof

import (
	"context"
	"net/url"
)

// Projects provides access to the /api/v1/me/projects endpoints.
type Projects struct {
	http *httpClient
}

// List returns all projects for the authenticated user.
func (p *Projects) List(ctx context.Context) ([]Project, error) {
	return getAs[[]Project](p.http, ctx, "/api/v1/me/projects", nil)
}

// Create creates a new project.
func (p *Projects) Create(ctx context.Context, params map[string]any) (Project, error) {
	return postAs[Project](p.http, ctx, "/api/v1/me/projects", params)
}

// Retrieve gets a specific project by ID.
func (p *Projects) Retrieve(ctx context.Context, projectID string) (Project, error) {
	return getAs[Project](p.http, ctx, "/api/v1/me/projects/"+url.PathEscape(projectID), nil)
}

// Update updates a specific project.
func (p *Projects) Update(ctx context.Context, projectID string, params map[string]any) (Project, error) {
	return putAs[Project](p.http, ctx, "/api/v1/me/projects/"+url.PathEscape(projectID), params)
}

// Delete deletes a specific project (soft delete).
func (p *Projects) Delete(ctx context.Context, projectID string) (SuccessResponse, error) {
	return delAs[SuccessResponse](p.http, ctx, "/api/v1/me/projects/"+url.PathEscape(projectID))
}

// ListTemplates returns all templates for a project.
func (p *Projects) ListTemplates(ctx context.Context, projectID string) ([]Template, error) {
	return getAs[[]Template](p.http, ctx, "/api/v1/me/projects/"+url.PathEscape(projectID)+"/templates", nil)
}

// UpdateTemplate upserts a template for a project by channel and message type.
func (p *Projects) UpdateTemplate(ctx context.Context, projectID, channel, messageType string, params map[string]any) (Template, error) {
	return putAs[Template](p.http, ctx, "/api/v1/me/projects/"+url.PathEscape(projectID)+"/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType), params)
}

// DeleteTemplate removes a custom template, reverting to the default.
func (p *Projects) DeleteTemplate(ctx context.Context, projectID, channel, messageType string) (SuccessResponse, error) {
	return delAs[SuccessResponse](p.http, ctx, "/api/v1/me/projects/"+url.PathEscape(projectID)+"/templates/"+url.PathEscape(channel)+"/"+url.PathEscape(messageType))
}

// PreviewTemplate renders a template preview with sample variables.
func (p *Projects) PreviewTemplate(ctx context.Context, projectID string, params map[string]any) (map[string]any, error) {
	return p.http.post(ctx, "/api/v1/me/projects/"+url.PathEscape(projectID)+"/templates/preview", params)
}
