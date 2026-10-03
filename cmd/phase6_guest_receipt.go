package cmd

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/roleprocess"
	"github.com/shell-echo/sandbox-runtime/server"
)

func newLocalGuestReceipt(deployment string, profile phase6security.Profile, origin string) (*phase6guestreceipt.Recorder, error) {
	configDigest, ok := config.Phase6CoreStartupDigest(deployment)
	if !ok || phase6security.VerifySlice6GuestReceiptLocalProfile(profile, origin) != nil {
		return nil, errors.New("private Guest receipt local candidate is unavailable")
	}
	role := ""
	switch deployment {
	case "product-runtime":
		role = "product"
	case "guest-runtime":
		role = "guest"
	default:
		return nil, errors.New("private Guest receipt role is unavailable")
	}
	return phase6guestreceipt.New(os.Stdout, role, profile.ProfileDigest, configDigest)
}

type guestReceiptFinalizer interface {
	Seal(context.Context) error
	Abort()
}

func sealLocalGuestReceipt(ctx context.Context, recorder guestReceiptFinalizer) error {
	if recorder == nil {
		return phase6guestreceipt.ErrUnavailable
	}
	if ctx == nil || ctx.Err() != nil {
		recorder.Abort()
		return phase6guestreceipt.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return recorder.Seal(ctx)
}

type productGuestReceiptServer struct {
	server.Server
	hub      *guestagent.Hub
	recorder guestReceiptFinalizer
}

func (s productGuestReceiptServer) Shutdown(ctx context.Context) error {
	if err := s.Server.Shutdown(ctx); err != nil {
		s.recorder.Abort()
		return err
	}
	if err := s.hub.QuiesceObservation(ctx); err != nil {
		s.recorder.Abort()
		return err
	}
	return sealLocalGuestReceipt(ctx, s.recorder)
}

// Guest's sole observation producer is Agent.Run. The opt-in graph wrapper
// waits for that actual lifecycle before sealing under RunE's existing
// shutdown context; ordinary Guest graphs retain their original semantics.
func bindGuestReceiptGraph(graph *roleprocess.ApplicationGraph, recorder guestReceiptFinalizer) error {
	if graph == nil || graph.Start == nil || graph.Shutdown == nil || recorder == nil {
		return phase6guestreceipt.ErrUnavailable
	}
	start, shutdown := graph.Start, graph.Shutdown
	done := make(chan struct{})
	graph.Start = func(ctx context.Context) error {
		defer close(done)
		return start(ctx)
	}
	graph.Shutdown = func(ctx context.Context) error {
		err := shutdown(ctx)
		if err != nil {
			recorder.Abort()
			return err
		}
		if ctx == nil {
			recorder.Abort()
			return phase6guestreceipt.ErrUnavailable
		}
		select {
		case <-done:
		case <-ctx.Done():
			recorder.Abort()
			return phase6guestreceipt.ErrUnavailable
		}
		return sealLocalGuestReceipt(ctx, recorder)
	}
	return nil
}

func productGuestReceiptOrigin(profile phase6security.Profile) string {
	for _, edge := range profile.TrustEdges {
		if edge.ID == "guest-product" {
			return "wss://" + edge.TargetAddress + edge.RoutePath
		}
	}
	return ""
}
