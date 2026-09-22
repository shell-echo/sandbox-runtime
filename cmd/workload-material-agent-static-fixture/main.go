// workload-material-agent-static-fixture is an integration-only process
// harness. It receives a bounded material set over an anonymous stdin pipe;
// it is not a production secret backend or deployment profile.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
)

const (
	fixtureProtocol = "sandbox-runtime.workload-material-static-fixture.v1"
	maxInputBytes   = 8 << 20
)

type inputDocument struct {
	Protocol          string             `json:"protocol"`
	SocketPath        string             `json:"socket_path"`
	ExpectedClientUID uint32             `json:"expected_client_uid"`
	ExpectedClientGID uint32             `json:"expected_client_gid"`
	Role              secretref.Role     `json:"role"`
	MaxConnections    int                `json:"max_connections"`
	MaxResolutions    int                `json:"max_resolutions"`
	Materials         []materialDocument `json:"materials"`
}

type materialDocument struct {
	Binding   secretref.Binding  `json:"binding"`
	Revision  string             `json:"revision"`
	Digest    string             `json:"digest"`
	State     secretref.KeyState `json:"state"`
	NotBefore string             `json:"not_before"`
	NotAfter  string             `json:"not_after"`
	Material  []byte             `json:"material"`
}

type staticProvider struct {
	materials map[string]secretref.SecretMaterial
}

func (p *staticProvider) ResolveSecret(ctx context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	if ctx == nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return secretref.SecretMaterial{}, err
	}
	material, ok := p.materials[binding.Digest()]
	if !ok || material.Binding != binding {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	material.Bytes = append([]byte(nil), material.Bytes...)
	return material, nil
}

func (p *staticProvider) close() {
	for digest, material := range p.materials {
		material.Destroy()
		delete(p.materials, digest)
	}
}

func main() {
	if run() != nil {
		_, _ = fmt.Fprintln(os.Stderr, "static workload material fixture failed")
		os.Exit(1)
	}
}

func run() error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxInputBytes+1))
	if err != nil || len(raw) < 1 || len(raw) > maxInputBytes {
		clear(raw)
		return secretref.ErrUnavailable
	}
	defer clear(raw)
	var input inputDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return secretref.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return secretref.ErrUnavailable
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(canonical, raw) || input.Protocol != fixtureProtocol || len(input.Materials) < 1 || len(input.Materials) > 32 {
		clear(canonical)
		return secretref.ErrUnavailable
	}
	clear(canonical)
	now := time.Now().UTC()
	provider := &staticProvider{materials: make(map[string]secretref.SecretMaterial, len(input.Materials))}
	defer provider.close()
	bindings := make([]secretref.Binding, 0, len(input.Materials))
	purposes := make([]secretref.Purpose, 0, len(input.Materials))
	for index := range input.Materials {
		configured := &input.Materials[index]
		notBefore, beforeErr := time.Parse(time.RFC3339Nano, configured.NotBefore)
		notAfter, afterErr := time.Parse(time.RFC3339Nano, configured.NotAfter)
		material := secretref.SecretMaterial{
			Binding: configured.Binding, Bytes: append([]byte(nil), configured.Material...), Digest: configured.Digest,
			Revision: configured.Revision,
			Window:   secretref.RotationWindow{NotBefore: notBefore, NotAfter: notAfter, State: configured.State},
		}
		clear(configured.Material)
		if beforeErr != nil || afterErr != nil || configured.NotBefore != notBefore.UTC().Format(time.RFC3339Nano) ||
			configured.NotAfter != notAfter.UTC().Format(time.RFC3339Nano) || material.Validate(now) != nil || material.Binding.Role != input.Role {
			material.Destroy()
			return secretref.ErrUnavailable
		}
		digest := material.Binding.Digest()
		if _, duplicate := provider.materials[digest]; duplicate {
			material.Destroy()
			return secretref.ErrUnavailable
		}
		provider.materials[digest] = material
		bindings = append(bindings, material.Binding)
		purposes = append(purposes, material.Binding.Purpose)
	}
	server, err := workloadagent.Listen(workloadagent.ServerConfig{
		SocketPath: input.SocketPath, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: input.ExpectedClientUID, ExpectedClientGID: input.ExpectedClientGID, Role: input.Role,
		AllowedPurposes: purposes, Bindings: bindings, MaxConnections: input.MaxConnections, MaxResolutions: input.MaxResolutions, Now: time.Now,
	}, provider)
	if err != nil {
		return secretref.ErrUnavailable
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
