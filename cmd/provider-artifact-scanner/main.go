// provider-artifact-scanner composes the fixed private scanner role. Its typed
// Profile-v2 admission remains held until the independently reviewed live gate.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/artifactscanner"
	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
)

const scannerConfigProtocol = "sandbox-runtime.provider-artifact-scanner-config.v1"

var errScanner = errors.New("private scanner unavailable")

type configDocument struct {
	Protocol                string `json:"protocol"`
	SecurityProfilePath     string `json:"security_profile_path"`
	SecurityProfileDigest   string `json:"security_profile_digest"`
	EnvironmentDigest       string `json:"environment_digest"`
	PrincipalProfileDigest  string `json:"principal_profile_digest"`
	ListenAddress           string `json:"listen_address"`
	PeerCRLRolePath         string `json:"peer_crl_role_path"`
	PeerCRLRoleDigest       string `json:"peer_crl_role_digest"`
	SourceMappingDigest     string `json:"source_mapping_digest"`
	AgentSocket             string `json:"agent_socket"`
	AgentUID                uint32 `json:"agent_uid"`
	AgentGID                uint32 `json:"agent_gid"`
	OperationTimeoutSeconds int    `json:"operation_timeout_seconds"`
	EngineInputImageDigest  string `json:"engine_input_image_digest"`
	RuleManifest            []byte `json:"rule_manifest"`
}

type scannerStartup struct {
	profile   phase6security.ProfileV2
	boundary  phase6security.PrivateServiceBoundaryV2
	authority phase6tls.PrivateServiceAuthorityV2
	rules     *artifactscanner.RuleVerifier
}

func decodeConfig(document []byte) (configDocument, error) {
	var c configDocument
	if len(document) < 1 || len(document) > 256<<10 {
		return c, errScanner
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return configDocument{}, errScanner
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(canonical, document) || c.Protocol != scannerConfigProtocol || c.OperationTimeoutSeconds < 1 || c.OperationTimeoutSeconds > 30 || len(c.RuleManifest) < 1 || len(c.RuleManifest) > 16<<10 {
		return configDocument{}, errScanner
	}
	return c, nil
}

func preflight(c configDocument) (scannerStartup, error) {
	var s scannerStartup
	if c.Protocol != scannerConfigProtocol || c.OperationTimeoutSeconds < 1 || c.OperationTimeoutSeconds > 30 {
		return s, errScanner
	}
	p, err := phase6security.VerifyFileV2(c.SecurityProfilePath)
	if err != nil || p.ProfileDigest != c.SecurityProfileDigest || p.EnvironmentDigest != c.EnvironmentDigest || p.PrincipalProfileDigest != c.PrincipalProfileDigest {
		return s, errScanner
	}
	b, err := p.PrivateServiceBoundary("scanner", c.ListenAddress)
	if err != nil || phase6security.VerifySlice6PrivateConfigPathV2(p, b.Service.Name, phase6security.Slice6ProfileConfigFile, c.SecurityProfilePath) != nil ||
		phase6security.VerifySlice6PrivateConfigPathV2(p, b.Service.Name, phase6security.Slice6PeerCRLRoleFile, c.PeerCRLRolePath) != nil {
		return s, errScanner
	}
	role, err := phase6security.VerifyPeerCRLRoleFileV2(c.PeerCRLRolePath, p, c.SourceMappingDigest, c.PeerCRLRoleDigest, b.Service.PrincipalDigest)
	if err != nil {
		return s, errScanner
	}
	rules, err := artifactscanner.NewRuleVerifierFromDocument(c.RuleManifest, p.ArtifactScanner.RuleTarget, p.ArtifactScanner.RuleManifestDigest, c.EngineInputImageDigest, digestBytes(engineConfiguration()))
	if err != nil {
		return s, errScanner
	}
	return scannerStartup{profile: p, boundary: b, rules: rules, authority: phase6tls.PrivateServiceAuthorityV2{Scope: "scanner", Address: c.ListenAddress, PeerCRLRole: role,
		SourceMappingDigest: c.SourceMappingDigest, RoleDigest: c.PeerCRLRoleDigest, AgentSocket: c.AgentSocket, AgentUID: c.AgentUID, AgentGID: c.AgentGID, OperationTimeout: time.Duration(c.OperationTimeoutSeconds) * time.Second}}, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "private scanner failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, input io.Reader) error {
	if ctx == nil || ctx.Err() != nil || input == nil {
		return errScanner
	}
	data, err := io.ReadAll(io.LimitReader(input, (256<<10)+1))
	if err != nil {
		return errScanner
	}
	defer clear(data)
	c, err := decodeConfig(data)
	if err != nil {
		return err
	}
	s, err := preflight(c)
	if err != nil {
		return err
	}
	transport, probe, peer, err := phase6tls.PrivateServiceServerV2(s.profile, s.authority)
	if err != nil {
		return errScanner
	}
	defer peer.Close()
	operation, cancel := context.WithTimeout(ctx, s.authority.OperationTimeout)
	_, err = s.rules.Verify(operation, time.Now().UTC())
	cancel()
	if err != nil {
		return errScanner
	}
	engine, err := startEngine(ctx, s.boundary.Service.UID, s.boundary.Service.GID)
	if err != nil {
		return errScanner
	}
	defer engine.Close()
	operation, cancel = context.WithTimeout(ctx, s.authority.OperationTimeout)
	if _, err = s.rules.Verify(operation, time.Now().UTC()); err == nil {
		err = probe(operation)
	}
	cancel()
	if err != nil {
		return errScanner
	}
	service, err := artifactscanner.NewService(artifactscanner.ServiceConfig{TLSConfig: transport, ExpectedClientURI: s.boundary.Provider.TLS.URI, ProfileDigest: s.profile.ProfileDigest,
		OperationTimeout: s.authority.OperationTimeout, Engine: engine.adapter, Rules: s.rules, Peer: peer, Clock: time.Now})
	if err != nil {
		return errScanner
	}
	defer service.Close()
	registry, err := connectiondrain.NewBounded(time.Duration(s.boundary.Edge.MaxConnectionSeconds)*time.Second, 2)
	if err != nil {
		return errScanner
	}
	if registry.OnClose(peer.Forget) != nil {
		return errScanner
	}
	defer registry.Drain()
	listener, err := net.Listen("tcp", s.boundary.Edge.TargetAddress)
	if err != nil {
		return errScanner
	}
	defer listener.Close()
	bounded, err := registry.Wrap(listener)
	if err != nil {
		return errScanner
	}
	lifetime, stop := context.WithCancel(ctx)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- service.Serve(lifetime, bounded) }()
	select {
	case err := <-result:
		if err != nil {
			return errScanner
		}
		return ctx.Err()
	case <-engine.done:
		stop()
		_ = service.Close()
		<-result
		return errScanner
	case <-ctx.Done():
		stop()
		_ = service.Close()
		<-result
		return nil
	}
}
func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
