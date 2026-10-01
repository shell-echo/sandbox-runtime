// phase6-terminal-cleanup is a one-shot operator task, not a resident
// workload or a Provider endpoint. All secrets arrive through bounded stdin;
// no token, key or accessor is accepted from argv or the environment.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
)

const (
	inputProtocol = "sandbox-runtime.phase6-terminal-cleanup-input.v1"
	// Both canonical controller ledgers are independently bounded at 8 MiB.
	// Leave a fixed allowance for the full Profile, peer sources and PEMs.
	maxInputBytes = 18 << 20
)

type input struct {
	Protocol              string    `json:"protocol"`
	RunID                 string    `json:"run_id"`
	ProfileJSON           []byte    `json:"profile_json"`
	PeerSourcesJSON       []byte    `json:"peer_sources_json"`
	CertificateLedgerJSON []byte    `json:"certificate_ledger_json"`
	CredentialLedgerJSON  []byte    `json:"credential_ledger_json"`
	ManagementAccessor    string    `json:"management_accessor"`
	PlanDigest            string    `json:"plan_digest"`
	VaultEndpoint         string    `json:"vault_endpoint"`
	VaultServerCAPEM      []byte    `json:"vault_server_ca_pem"`
	ClientCertificatePEM  []byte    `json:"client_certificate_pem"`
	ClientPrivateKeyPEM   []byte    `json:"client_private_key_pem"`
	OperatorToken         []byte    `json:"operator_token"`
	TokenExpiresAt        time.Time `json:"token_expires_at"`
}

func main() {
	if len(os.Args) != 2 || os.Args[1] != "--one-shot" {
		fmt.Fprintln(os.Stderr, "phase6-terminal-cleanup: unavailable")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := run(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "phase6-terminal-cleanup: unavailable")
		os.Exit(1)
	}
}

func run(ctx context.Context, reader io.Reader, writer io.Writer) error {
	if ctx == nil || reader == nil || writer == nil {
		return phase6terminalcleanup.ErrInvalid
	}
	type readResult struct {
		value []byte
		err   error
	}
	completed := make(chan readResult, 1)
	go func() {
		value, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
		completed <- readResult{value: value, err: err}
	}()
	var document []byte
	select {
	case <-ctx.Done():
		return phase6terminalcleanup.ErrInvalid
	case result := <-completed:
		if result.err != nil || len(result.value) < 1 || len(result.value) > maxInputBytes {
			clear(result.value)
			return phase6terminalcleanup.ErrInvalid
		}
		document = result.value
	}
	defer clear(document)
	value, err := decodeInput(document)
	if err != nil {
		return err
	}
	defer func() {
		clear(value.VaultServerCAPEM)
		clear(value.ClientCertificatePEM)
		clear(value.ClientPrivateKeyPEM)
		clear(value.OperatorToken)
		clear(value.ProfileJSON)
		clear(value.PeerSourcesJSON)
		clear(value.CertificateLedgerJSON)
		clear(value.CredentialLedgerJSON)
	}()
	profile, err := phase6security.Decode(value.ProfileJSON)
	if err != nil {
		return phase6terminalcleanup.ErrInvalid
	}
	sources, err := phase6security.DecodePeerCRLSources(value.PeerSourcesJSON, profile)
	if err != nil {
		return phase6terminalcleanup.ErrInvalid
	}
	plan, err := phase6terminalcleanup.Build(value.RunID, profile, sources,
		value.CertificateLedgerJSON, value.CredentialLedgerJSON, value.ManagementAccessor, time.Now().UTC())
	if err != nil || plan.Digest != value.PlanDigest {
		return phase6terminalcleanup.ErrInvalid
	}
	remote, err := phase6terminalcleanup.NewVaultRemote(phase6terminalcleanup.VaultRemoteConfig{
		Plan: plan, Endpoint: value.VaultEndpoint, ServerCAPEM: value.VaultServerCAPEM,
		ClientCertificate: value.ClientCertificatePEM, ClientPrivateKey: value.ClientPrivateKeyPEM,
		Token: value.OperatorToken, TokenExpiresAt: value.TokenExpiresAt, Now: time.Now})
	if err != nil {
		return phase6terminalcleanup.ErrInvalid
	}
	defer remote.Close()
	receipt, err := phase6terminalcleanup.Execute(ctx, plan, remote, time.Now)
	encoded, encodeErr := json.Marshal(receipt)
	if encodeErr != nil || len(encoded) > 16<<10 {
		clear(encoded)
		return phase6terminalcleanup.ErrInvalid
	}
	defer clear(encoded)
	if _, writeErr := writer.Write(append(encoded, '\n')); writeErr != nil {
		return phase6terminalcleanup.ErrInvalid
	}
	return err
}

func decodeInput(document []byte) (input, error) {
	var value input
	if len(document) < 1 || len(document) > maxInputBytes {
		return value, phase6terminalcleanup.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return input{}, phase6terminalcleanup.ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return input{}, phase6terminalcleanup.ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) || value.Protocol != inputProtocol ||
		value.RunID == "" || value.PlanDigest == "" || len(value.OperatorToken) == 0 ||
		len(value.ClientPrivateKeyPEM) == 0 || value.TokenExpiresAt.IsZero() {
		clear(canonical)
		return input{}, phase6terminalcleanup.ErrInvalid
	}
	clear(canonical)
	return value, nil
}
