//go:build phase5desktopgate

package productphase5gate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/product"
	productdevelopment "github.com/shell-echo/sandbox-runtime/product/adapter/development"
)

func runGuestNode(config nodeConfig) error {
	privateKey, err := base64.RawStdEncoding.DecodeString(config.GuestPrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid Guest private key")
	}
	template, err := (productdevelopment.LockedCatalog{}).Get(context.Background(), product.DevelopmentTemplateID)
	if err != nil {
		return err
	}
	mounts := make([]guestdevelopment.Mount, len(template.Mounts))
	for index, mount := range template.Mounts {
		mounts[index] = guestdevelopment.Mount{Path: mount.Path, Mode: mount.Mode}
	}
	toolchains := make([]guestdevelopment.Toolchain, len(template.Toolchains))
	for index, toolchain := range template.Toolchains {
		toolchains[index] = guestdevelopment.Toolchain{ID: toolchain.ID, Version: toolchain.Version, Digest: toolchain.Digest, Executable: toolchain.Executable}
	}
	service, err := guestdevelopment.New(guestdevelopment.Options{WorkspaceRoot: config.GuestRoot, StateRoot: config.GuestState, Mounts: mounts, Toolchains: toolchains})
	if err != nil {
		return err
	}
	agent, err := guestagent.NewAgent(guestagent.AgentOptions{
		URL: "ws://" + config.ProductAddress + "/guest", GuestID: config.GuestID, BindingGeneration: config.GuestGeneration,
		PrivateKey: ed25519.PrivateKey(privateKey), Handlers: service.Handlers(), ReconnectBackoff: 50 * time.Millisecond,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = agent.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
