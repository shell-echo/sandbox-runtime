// break-glass-controller is the independent online single-use emergency-access
// authority. Its signing key arrives only through an inherited anonymous file
// descriptor; its persistent authority and hash-chained audit are separate.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
)

const (
	configProtocol = "sandbox-runtime.break-glass-controller-config.v1"
	maxConfigBytes = 1 << 20
	signingKeyFD   = 3
)

type configDocument struct {
	Protocol          string          `json:"protocol"`
	SocketPath        string          `json:"socket_path"`
	LedgerPath        string          `json:"ledger_path"`
	AuditPath         string          `json:"audit_path"`
	SocketUID         uint32          `json:"socket_uid"`
	SocketGID         uint32          `json:"socket_gid"`
	ExpectedClientUID uint32          `json:"expected_client_uid"`
	ExpectedClientGID uint32          `json:"expected_client_gid"`
	MaxConnections    int             `json:"max_connections"`
	MaxTTLSeconds     int             `json:"max_ttl_seconds"`
	Actors            []actorDocument `json:"actors"`
}

type actorDocument struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "break-glass controller failed")
		os.Exit(1)
	}
}

func run() error {
	document, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes+1))
	if err != nil || len(document) < 1 || len(document) > maxConfigBytes {
		clear(document)
		return breakglass.ErrUnavailable
	}
	defer clear(document)
	var config configDocument
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return breakglass.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return breakglass.ErrUnavailable
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, document) || config.Protocol != configProtocol || len(config.Actors) < 5 ||
		config.MaxTTLSeconds < 60 || config.MaxTTLSeconds > 900 {
		clear(canonical)
		return breakglass.ErrUnavailable
	}
	clear(canonical)
	actors := make([]breakglass.Actor, 0, len(config.Actors))
	for _, configured := range config.Actors {
		publicKey, err := base64.RawURLEncoding.DecodeString(configured.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			clear(publicKey)
			return breakglass.ErrUnavailable
		}
		actors = append(actors, breakglass.Actor{ID: configured.ID, Kind: configured.Kind, PublicKey: ed25519.PublicKey(publicKey)})
	}
	keyFile := os.NewFile(signingKeyFD, "break-glass-signing-key")
	if keyFile == nil {
		return breakglass.ErrUnavailable
	}
	privateKey, err := io.ReadAll(io.LimitReader(keyFile, ed25519.PrivateKeySize+1))
	_ = keyFile.Close()
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		clear(privateKey)
		return breakglass.ErrUnavailable
	}
	defer clear(privateKey)
	controller, err := breakglass.NewProduction(breakglass.Config{LedgerPath: config.LedgerPath, AuditPath: config.AuditPath,
		Actors: actors, ControllerPrivateKey: ed25519.PrivateKey(privateKey), MaxTTL: time.Duration(config.MaxTTLSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return breakglass.ErrUnavailable
	}
	defer controller.Close()
	server, err := breakglass.Listen(breakglass.ServerConfig{SocketPath: config.SocketPath, SocketUID: config.SocketUID, SocketGID: config.SocketGID,
		ExpectedClientUID: config.ExpectedClientUID, ExpectedClientGID: config.ExpectedClientGID, MaxConnections: config.MaxConnections}, controller)
	if err != nil {
		return breakglass.ErrUnavailable
	}
	defer server.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err = server.Serve(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
