package dockercontrol

import (
	"context"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"testing"
)

func TestControlSourceSessionCannotBeFabricated(t *testing.T) {
	var s *ControlSourceSession
	if _, e := s.Observe(context.Background()); e == nil {
		t.Fatal("nil session")
	}
	s.Close()
	var zero ControlSourceSession
	// An uninitialized exported session has no retained physical proof.
	if _, e := zero.Observe(context.Background()); e == nil {
		t.Fatal("zero session")
	}
	zero.Close()
	if _, e := PrepareControlSource(nil, nil, phase6fdloader.StartupBinding{}); e == nil {
		t.Fatal("nil context")
	}
	if _, _, _, e := sourceSessionBinding([]byte(`{}`), phase6fdloader.StartupBinding{}); e == nil {
		t.Fatal("fabricated declaration")
	}
}

func TestControlTrustCannotUseLegacyStoreConstructors(t *testing.T) {
	a := []phase6security.TrustAnchor{{ID: "internal-client-ca"}}
	for _, b := range []controlStorageBinding{
		{profileSource: &phase6security.ControlSourceReview{TrustAnchors: a}},
		{boundary: &phase6security.ControlConsumerBoundary{Review: phase6security.ControlSourceReview{TrustAnchors: a}}},
		{sourceService: &phase6security.ControlServiceIdentityV1{Launch: phase6security.ControlServiceLaunchV1{Target: phase6security.ControlTrustTarget}}},
	} {
		if !controlTrustStorageHeld(b) {
			t.Fatal("trust mode missed")
		}
		if _, err := openSourceBoundControlStorage(context.Background(), codingBoundUnixEndpoint{path: controlStorageSocketTarget}, b, true); err == nil {
			t.Fatal("legacy Store opened")
		}
	}
	if controlTrustStorageHeld(controlStorageBinding{}) {
		t.Fatal("legacy mode changed")
	}
}
