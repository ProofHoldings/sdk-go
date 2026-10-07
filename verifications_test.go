package proof

import (
	"context"
	"net/http"
	"testing"
)

func TestVerifications_CreateMultiChannel(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Verifications.CreateMultiChannel(context.Background(), map[string]any{
		"type":       "phone",
		"identifier": "+1234567890",
		"channels":   []string{"whatsapp", "sms"},
	})
	if err != nil {
		t.Fatalf("CreateMultiChannel: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/verifications/multi-channel" {
		t.Errorf("want POST /api/v1/verifications/multi-channel, got %s %s", rec.method, rec.path)
	}
	if rec.body["type"] != "phone" || rec.body["identifier"] != "+1234567890" {
		t.Errorf("body: want type=phone identifier=+1234567890, got %v", rec.body)
	}
	channels, ok := rec.body["channels"].([]any)
	if !ok || len(channels) != 2 || channels[0] != "whatsapp" || channels[1] != "sms" {
		t.Errorf("body channels: want [whatsapp sms], got %v", rec.body["channels"])
	}
}

func TestVerifications_GetMultiChannelStatus(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.Verifications.GetMultiChannelStatus(context.Background(), "vg_abc123")
	if err != nil {
		t.Fatalf("GetMultiChannelStatus: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/verifications/multi-channel/vg_abc123/status" {
		t.Errorf("want GET /api/v1/verifications/multi-channel/vg_abc123/status, got %s %s", rec.method, rec.path)
	}
}
