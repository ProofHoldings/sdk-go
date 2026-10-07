package proof

import (
	"context"
	"net/http"
	"testing"
)

func TestTemplates_List(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Templates.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/templates" {
		t.Errorf("want GET /api/v1/templates, got %s %s", rec.method, rec.path)
	}
}

func TestTemplates_GetDefaults(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Templates.GetDefaults(context.Background())
	if err != nil {
		t.Fatalf("GetDefaults: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/templates/defaults" {
		t.Errorf("want GET /api/v1/templates/defaults, got %s %s", rec.method, rec.path)
	}
}

func TestTemplates_Get(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Templates.Get(context.Background(), "telegram", "confirmation_request")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/templates/telegram/confirmation_request" {
		t.Errorf("want GET /api/v1/templates/telegram/confirmation_request, got %s %s", rec.method, rec.path)
	}
}

func TestTemplates_Upsert(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Templates.Upsert(context.Background(), "whatsapp", "verification_request", map[string]any{
		"body":        "Your code is {{code}}",
		"button_text": "Verify",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if rec.method != http.MethodPut || rec.path != "/api/v1/templates/whatsapp/verification_request" {
		t.Errorf("want PUT /api/v1/templates/whatsapp/verification_request, got %s %s", rec.method, rec.path)
	}
	if rec.body["body"] != "Your code is {{code}}" {
		t.Errorf("body.body: want template text, got %v", rec.body["body"])
	}
	if rec.body["button_text"] != "Verify" {
		t.Errorf("body.button_text: want Verify, got %v", rec.body["button_text"])
	}
}

func TestTemplates_Delete(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Templates.Delete(context.Background(), "email", "login_request")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/templates/email/login_request" {
		t.Errorf("want DELETE /api/v1/templates/email/login_request, got %s %s", rec.method, rec.path)
	}
}

func TestTemplates_Preview(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Templates.Preview(context.Background(), map[string]any{
		"channel":      "telegram",
		"message_type": "confirmation_request",
		"body":         "Hi {{business_name}}",
	})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/templates/preview" {
		t.Errorf("want POST /api/v1/templates/preview, got %s %s", rec.method, rec.path)
	}
	if rec.body["channel"] != "telegram" || rec.body["message_type"] != "confirmation_request" {
		t.Errorf("body channel/message_type mismatch: %v", rec.body)
	}
}

func TestTemplates_Render(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Templates.Render(context.Background(), map[string]any{
		"channel":      "sms",
		"message_type": "verification_request",
		"variables":    map[string]any{"code": "123456"},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/templates/render" {
		t.Errorf("want POST /api/v1/templates/render, got %s %s", rec.method, rec.path)
	}
	vars, _ := rec.body["variables"].(map[string]any)
	if vars["code"] != "123456" {
		t.Errorf("body.variables.code: want 123456, got %v", vars["code"])
	}
}
