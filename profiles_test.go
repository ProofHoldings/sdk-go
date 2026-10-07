package proof

import (
	"context"
	"net/http"
	"testing"
)

func TestProfiles_List(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/me/profiles" {
		t.Errorf("want GET /api/v1/me/profiles, got %s %s", rec.method, rec.path)
	}
}

func TestProfiles_Create(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.Create(context.Background(), map[string]any{
		"display_name": "Acme",
		"is_business":  true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/me/profiles" {
		t.Errorf("want POST /api/v1/me/profiles, got %s %s", rec.method, rec.path)
	}
	if rec.body["display_name"] != "Acme" {
		t.Errorf("body.display_name: want Acme, got %v", rec.body["display_name"])
	}
	if rec.body["is_business"] != true {
		t.Errorf("body.is_business: want true, got %v", rec.body["is_business"])
	}
}

func TestProfiles_Get(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.Get(context.Background(), "pr_1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/me/profiles/pr_1" {
		t.Errorf("want GET /api/v1/me/profiles/pr_1, got %s %s", rec.method, rec.path)
	}
}

func TestProfiles_Update(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.Update(context.Background(), "pr_1", map[string]any{"bio": "New bio"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if rec.method != http.MethodPatch || rec.path != "/api/v1/me/profiles/pr_1" {
		t.Errorf("want PATCH /api/v1/me/profiles/pr_1, got %s %s", rec.method, rec.path)
	}
	if rec.body["bio"] != "New bio" {
		t.Errorf("body.bio: want New bio, got %v", rec.body["bio"])
	}
}

func TestProfiles_Delete(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.Delete(context.Background(), "pr_1")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/me/profiles/pr_1" {
		t.Errorf("want DELETE /api/v1/me/profiles/pr_1, got %s %s", rec.method, rec.path)
	}
}

func TestProfiles_SetPrimary(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.SetPrimary(context.Background(), "pr_1")
	if err != nil {
		t.Fatalf("SetPrimary: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/me/profiles/pr_1/primary" {
		t.Errorf("want POST /api/v1/me/profiles/pr_1/primary, got %s %s", rec.method, rec.path)
	}
}

func TestProfiles_ListTemplates(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.ListTemplates(context.Background(), "pr_1")
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/me/profiles/pr_1/templates" {
		t.Errorf("want GET /api/v1/me/profiles/pr_1/templates, got %s %s", rec.method, rec.path)
	}
}

func TestProfiles_UpdateTemplate(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.UpdateTemplate(context.Background(), "pr_1", "telegram", "confirmation_request", map[string]any{
		"body": "Approve {{business_name}}?",
	})
	if err != nil {
		t.Fatalf("UpdateTemplate: %v", err)
	}
	if rec.method != http.MethodPut || rec.path != "/api/v1/me/profiles/pr_1/templates/telegram/confirmation_request" {
		t.Errorf("want PUT .../templates/telegram/confirmation_request, got %s %s", rec.method, rec.path)
	}
	if rec.body["body"] != "Approve {{business_name}}?" {
		t.Errorf("body.body mismatch: %v", rec.body["body"])
	}
}

func TestProfiles_DeleteTemplate(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.DeleteTemplate(context.Background(), "pr_1", "email", "login_request")
	if err != nil {
		t.Fatalf("DeleteTemplate: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/me/profiles/pr_1/templates/email/login_request" {
		t.Errorf("want DELETE .../templates/email/login_request, got %s %s", rec.method, rec.path)
	}
}

func TestProfiles_PreviewTemplate(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Profiles.PreviewTemplate(context.Background(), "pr_1", map[string]any{
		"channel":      "sms",
		"message_type": "2fa_request",
		"body":         "Code: {{code}}",
	})
	if err != nil {
		t.Fatalf("PreviewTemplate: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/me/profiles/pr_1/templates/preview" {
		t.Errorf("want POST /api/v1/me/profiles/pr_1/templates/preview, got %s %s", rec.method, rec.path)
	}
	if rec.body["channel"] != "sms" {
		t.Errorf("body.channel: want sms, got %v", rec.body["channel"])
	}
}
