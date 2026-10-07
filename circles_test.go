package proof

import (
	"context"
	"net/http"
	"testing"
)

func TestCircles_Create(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.Create(context.Background(), map[string]any{"name": "Family"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/circles" {
		t.Errorf("want POST /api/v1/circles, got %s %s", rec.method, rec.path)
	}
	if rec.body["name"] != "Family" {
		t.Errorf("body.name: want Family, got %v", rec.body["name"])
	}
}

func TestCircles_List(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.List(context.Background(), map[string]string{"status": "archived"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/circles" {
		t.Errorf("want GET /api/v1/circles, got %s %s", rec.method, rec.path)
	}
	if rec.query != "status=archived" {
		t.Errorf("query: want status=archived, got %q", rec.query)
	}
}

func TestCircles_Retrieve(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.Retrieve(context.Background(), "circ_1")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/circles/circ_1" {
		t.Errorf("want GET /api/v1/circles/circ_1, got %s %s", rec.method, rec.path)
	}
}

func TestCircles_Update(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.Update(context.Background(), "circ_1", map[string]any{"name": "Close Family"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if rec.method != http.MethodPatch || rec.path != "/api/v1/circles/circ_1" {
		t.Errorf("want PATCH /api/v1/circles/circ_1, got %s %s", rec.method, rec.path)
	}
	if rec.body["name"] != "Close Family" {
		t.Errorf("body.name: want Close Family, got %v", rec.body["name"])
	}
}

func TestCircles_Archive(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.Archive(context.Background(), "circ_1")
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/circles/circ_1" {
		t.Errorf("want DELETE /api/v1/circles/circ_1, got %s %s", rec.method, rec.path)
	}
}

func TestCircles_AddMember(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.AddMember(context.Background(), "circ_1", map[string]any{"name": "Mum"})
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/circles/circ_1/members" {
		t.Errorf("want POST /api/v1/circles/circ_1/members, got %s %s", rec.method, rec.path)
	}
}

func TestCircles_ListMembers(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.ListMembers(context.Background(), "circ_1")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/circles/circ_1/members" {
		t.Errorf("want GET /api/v1/circles/circ_1/members, got %s %s", rec.method, rec.path)
	}
}

func TestCircles_InviteMember(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.InviteMember(context.Background(), "circ_1", "mem_1")
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/circles/circ_1/members/invite" {
		t.Errorf("want POST /api/v1/circles/circ_1/members/invite, got %s %s", rec.method, rec.path)
	}
	if rec.body["member_id"] != "mem_1" {
		t.Errorf("body.member_id: want mem_1, got %v", rec.body["member_id"])
	}
}

func TestCircles_TriggerDrill(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.TriggerDrill(context.Background(), "circ_1", "mem_1")
	if err != nil {
		t.Fatalf("TriggerDrill: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/circles/circ_1/members/mem_1/drill" {
		t.Errorf("want POST /api/v1/circles/circ_1/members/mem_1/drill, got %s %s", rec.method, rec.path)
	}
}

func TestCircles_RemoveMember(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.RemoveMember(context.Background(), "circ_1", "mem_1")
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/circles/circ_1/members/mem_1" {
		t.Errorf("want DELETE /api/v1/circles/circ_1/members/mem_1, got %s %s", rec.method, rec.path)
	}
}

func TestCircles_AddMemberChannel(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.AddMemberChannel(context.Background(), "circ_1", "mem_1", map[string]any{
		"channel":    "whatsapp",
		"identifier": "+15551112222",
	})
	if err != nil {
		t.Fatalf("AddMemberChannel: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/circles/circ_1/members/mem_1/channels" {
		t.Errorf("want POST /api/v1/circles/circ_1/members/mem_1/channels, got %s %s", rec.method, rec.path)
	}
	if rec.body["channel"] != "whatsapp" {
		t.Errorf("body.channel: want whatsapp, got %v", rec.body["channel"])
	}
}

func TestCircles_ListMemberChannels(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.ListMemberChannels(context.Background(), "circ_1", "mem_1")
	if err != nil {
		t.Fatalf("ListMemberChannels: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/circles/circ_1/members/mem_1/channels" {
		t.Errorf("want GET /api/v1/circles/circ_1/members/mem_1/channels, got %s %s", rec.method, rec.path)
	}
}

func TestCircles_RemoveMemberChannel(t *testing.T) {
	c, rec := newRecordingClient(t)
	_, err := c.Circles.RemoveMemberChannel(context.Background(), "circ_1", "mem_1", "chan_1")
	if err != nil {
		t.Fatalf("RemoveMemberChannel: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/circles/circ_1/members/mem_1/channels/chan_1" {
		t.Errorf("want DELETE /api/v1/circles/circ_1/members/mem_1/channels/chan_1, got %s %s", rec.method, rec.path)
	}
}
