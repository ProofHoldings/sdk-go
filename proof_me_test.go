package proof

import (
	"context"
	"net/http"
	"testing"
)

func TestProofMe_CreateIdentityChallenge(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.ProofMe.CreateIdentityChallenge(context.Background(), map[string]any{
		"circle_id": "circle1",
		"member_id": "member1",
	})
	if err != nil {
		t.Fatalf("CreateIdentityChallenge: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/identity-challenges" {
		t.Errorf("want POST /api/v1/identity-challenges, got %s %s", rec.method, rec.path)
	}
	if rec.body["circle_id"] != "circle1" || rec.body["member_id"] != "member1" {
		t.Errorf("body: want circle_id=circle1 member_id=member1, got %v", rec.body)
	}
}

func TestProofMe_GetIdentityChallenge(t *testing.T) {
	c, rec := newRecordingClient(t)

	_, err := c.ProofMe.GetIdentityChallenge(context.Background(), "idc1")
	if err != nil {
		t.Fatalf("GetIdentityChallenge: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/identity-challenges/idc1" {
		t.Errorf("want GET /api/v1/identity-challenges/idc1, got %s %s", rec.method, rec.path)
	}
}
