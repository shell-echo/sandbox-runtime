package phase6egress

import (
	"context"
	"errors"
	"testing"
)

func TestBrowserExternalClientsRejectsUnboundProductionDependencies(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"nil context":       nil,
		"missing profile":   context.Background(),
		"cancelled context": func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }(),
	} {
		t.Run(name, func(t *testing.T) {
			clients, err := NewBrowserExternalClients(ctx, BrowserExternalOptions{})
			if clients != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unbound Browser clients = %v, %v", clients, err)
			}
		})
	}
}

func TestBrowserExternalClientsCloseIsIdempotent(t *testing.T) {
	clients := new(BrowserExternalClients)
	if err := clients.Close(); err != nil {
		t.Fatal(err)
	}
	if err := clients.Close(); err != nil {
		t.Fatal(err)
	}
}
