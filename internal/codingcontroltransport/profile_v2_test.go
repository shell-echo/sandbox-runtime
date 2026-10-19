package codingcontroltransport

import (
	"context"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
)

func TestStatusCompositionRetainsV2Hold(t *testing.T) {
	p := phase6security.ProfileV2{}
	a := phase6tls.PrivateServiceAuthorityV2{Scope: "coding", Address: "127.0.0.1:8444"}
	if RunStatusV2(context.Background(), p, a, dockercontrol.CodingReceiptBinding{}) == nil {
		t.Fatal("invalid profile admitted")
	}
	if RunCodingV2(context.Background(), p, a, dockercontrol.CodingReceiptBinding{}, CodingMutationInputs{}) == nil {
		t.Fatal("mutation composition bypassed Profile-v2 hold")
	}
	if observer, err := NewStatusObserverV2(context.Background(), p, a, statusTestDigest("a")); err == nil || observer != nil {
		t.Fatal("held profile admitted")
	}
	var observer *StatusObserverV2
	if _, err := observer.Observe(context.Background(), codingcontrolprotocol.Request{}); err == nil {
		t.Fatal("nil observer admitted")
	}
	observer.Close()
}
