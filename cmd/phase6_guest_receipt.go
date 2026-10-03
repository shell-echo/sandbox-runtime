package cmd

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
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

func sealLocalGuestReceipt(recorder *phase6guestreceipt.Recorder) {
	if recorder == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = recorder.Seal(ctx)
}

func productGuestReceiptOrigin(profile phase6security.Profile) string {
	for _, edge := range profile.TrustEdges {
		if edge.ID == "guest-product" {
			return "wss://" + edge.TargetAddress + edge.RoutePath
		}
	}
	return ""
}
