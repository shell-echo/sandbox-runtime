package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		protocol, keys, err := bridgeAuthority(os.Getenv)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(64)
		}
		if protocol == desktopbroker.SessionProtocolV2ID {
			if err := desktopbroker.ServeWithBridge(ctx, os.Stderr, keys); err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}
	if err := desktopbroker.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func bridgeAuthority(getenv func(string) string) (string, map[string]ed25519.PublicKey, error) {
	if getenv == nil {
		return "", nil, errors.New("Desktop session environment is unavailable")
	}
	protocol := getenv(desktopbroker.SessionProtocolEnv)
	keyDocument := getenv("SANDBOX_RUNTIME_DESKTOP_BRIDGE_PUBLIC_KEY")
	keyID := getenv("SANDBOX_RUNTIME_DESKTOP_BRIDGE_KEY_ID")
	switch protocol {
	case desktopbroker.SessionProtocolV2ID:
		key, err := base64.RawStdEncoding.DecodeString(keyDocument)
		if err != nil || len(key) != ed25519.PublicKeySize || keyID == "" {
			return "", nil, errors.New("invalid Desktop bridge public key authority")
		}
		return protocol, map[string]ed25519.PublicKey{keyID: ed25519.PublicKey(key)}, nil
	case desktopbroker.SessionProtocolID:
		if keyDocument != "" || keyID != "" {
			return "", nil, errors.New("legacy Desktop session cannot carry bridge authority")
		}
		return protocol, nil, nil
	case "":
		return "", nil, errors.New("Desktop session protocol is required")
	default:
		return "", nil, errors.New("unsupported Desktop session protocol")
	}
}
