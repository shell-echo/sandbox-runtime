package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type configDocumentV2 struct {
	Protocol              string          `json:"protocol"`
	SecurityProfilePath   string          `json:"security_profile_path"`
	SecurityProfileDigest string          `json:"security_profile_digest"`
	LedgerPath            string          `json:"ledger_path"`
	AuditPath             string          `json:"audit_path"`
	MaxTTLSeconds         int             `json:"max_ttl_seconds"`
	Actors                []actorDocument `json:"actors"`
}

type preparedV2 struct {
	actors           []breakglass.Actor
	sockets          []breakglass.V2ControllerServerConfig
	ledgerPath       string
	auditPath        string
	maxTTL           time.Duration
	controllerDigest string
}

// prepareV2 checks every source-derived authority before the controller can
// create or reopen its ledger and before any Unix listener is allocated.
func prepareV2(document []byte) (preparedV2, error) {
	var config configDocumentV2
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return preparedV2{}, breakglass.ErrUnavailable
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return preparedV2{}, breakglass.ErrUnavailable
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, document) || config.Protocol != configProtocolV2 ||
		config.MaxTTLSeconds < 60 || config.MaxTTLSeconds > 900 {
		return preparedV2{}, breakglass.ErrUnavailable
	}
	profile, err := phase6security.VerifyFile(config.SecurityProfilePath)
	if err != nil || profile.ProfileDigest != config.SecurityProfileDigest ||
		phase6security.VerifySlice6FinalGateProfile(profile) != nil ||
		phase6security.VerifySlice6PrivateConfigPath(profile, "break-glass-controller",
			phase6security.Slice6ProfileConfigFile, config.SecurityProfilePath) != nil {
		return preparedV2{}, breakglass.ErrUnavailable
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount("break-glass-controller")
	if err != nil {
		return preparedV2{}, breakglass.ErrUnavailable
	}
	auditPath, err := phase6security.Slice6BreakGlassAuditPath()
	if err != nil || config.LedgerPath != ledgerPath || config.AuditPath != auditPath ||
		len(config.Actors) != len(profile.BreakGlassKeyAuthority.Actors) {
		return preparedV2{}, breakglass.ErrUnavailable
	}
	var controller *phase6security.Principal
	for i := range profile.Principals {
		if profile.Principals[i].Name == "break-glass-controller" {
			controller = &profile.Principals[i]
			break
		}
	}
	if controller == nil || uint32(os.Getuid()) != controller.UID || uint32(os.Getgid()) != controller.GID {
		return preparedV2{}, breakglass.ErrUnavailable
	}
	result := preparedV2{ledgerPath: ledgerPath, auditPath: auditPath,
		maxTTL:           time.Duration(config.MaxTTLSeconds) * time.Second,
		controllerDigest: profile.BreakGlassKeyAuthority.ControllerPublicKeyDigest,
		actors:           make([]breakglass.Actor, 0, len(config.Actors)),
		sockets:          make([]breakglass.V2ControllerServerConfig, 0, 8)}
	for i, actor := range config.Actors {
		binding := profile.BreakGlassKeyAuthority.Actors[i]
		public, err := base64.RawURLEncoding.DecodeString(actor.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || actor.ID != binding.ID ||
			actor.Kind != v2BusinessKind(binding.Kind) ||
			phase6security.Slice6BreakGlassPublicKeyDigest(public) != binding.PublicKeyDigest {
			return preparedV2{}, breakglass.ErrUnavailable
		}
		result.actors = append(result.actors, breakglass.Actor{ID: actor.ID, Kind: actor.Kind, PublicKey: public})
	}
	for _, binding := range profile.BreakGlassSockets {
		if binding.ServerDeployment != controller.Name {
			continue
		}
		if binding.Kind != "control" && binding.Kind != "consume" {
			return preparedV2{}, breakglass.ErrUnavailable
		}
		result.sockets = append(result.sockets, breakglass.V2ControllerServerConfig{
			ServerConfig: breakglass.ServerConfig{SocketPath: binding.SocketPath, SocketUID: binding.ServerUID,
				SocketGID: binding.ClientGID, ExpectedClientUID: binding.ClientUID,
				ExpectedClientGID: binding.ClientGID, MaxConnections: binding.MaxConnections},
			Kind: binding.Kind, TargetAgentID: binding.TargetAgent})
	}
	if len(result.sockets) != 8 {
		return preparedV2{}, breakglass.ErrUnavailable
	}
	return result, nil
}

func v2BusinessKind(kind string) string {
	if kind == "target" {
		return breakglass.ActorTarget
	}
	return kind
}

func runV2(document []byte) error {
	prepared, err := prepareV2(document)
	if err != nil {
		return breakglass.ErrUnavailable
	}
	keyFile := os.NewFile(signingKeyFD, "break-glass-controller-v2-signing-key")
	if keyFile == nil {
		return breakglass.ErrUnavailable
	}
	private, err := io.ReadAll(io.LimitReader(keyFile, ed25519.PrivateKeySize+1))
	_ = keyFile.Close()
	if err != nil || len(private) != ed25519.PrivateKeySize ||
		!bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) ||
		phase6security.Slice6BreakGlassPublicKeyDigest(ed25519.PrivateKey(private).Public().(ed25519.PublicKey)) != prepared.controllerDigest {
		clear(private)
		return breakglass.ErrUnavailable
	}
	defer clear(private)
	controller, err := breakglass.NewProduction(breakglass.Config{LedgerPath: prepared.ledgerPath,
		AuditPath: prepared.auditPath, Actors: prepared.actors, ControllerPrivateKey: ed25519.PrivateKey(private),
		MaxTTL: prepared.maxTTL, Now: time.Now})
	if err != nil {
		return breakglass.ErrUnavailable
	}
	defer controller.Close()
	servers := make([]*breakglass.V2ControllerServer, 0, len(prepared.sockets))
	defer func() {
		for _, server := range servers {
			_ = server.Close()
		}
	}()
	for _, socket := range prepared.sockets {
		server, err := breakglass.ListenV2Controller(socket, controller)
		if err != nil {
			return breakglass.ErrUnavailable
		}
		servers = append(servers, server)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	results := make(chan error, len(servers))
	var group sync.WaitGroup
	for _, server := range servers {
		group.Add(1)
		go func(s *breakglass.V2ControllerServer) { defer group.Done(); results <- s.Serve(ctx) }(server)
	}
	first := <-results
	cancel()
	for _, server := range servers {
		_ = server.Close()
	}
	group.Wait()
	if errors.Is(first, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return first
}
