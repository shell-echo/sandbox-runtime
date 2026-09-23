// egress-policy-state-authority is the operator-owned durable writer and
// online current-state attestor for exactly one immutable egress policy.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/egresspolicystate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const (
	configProtocol = "sandbox-runtime.egress-policy-state-authority-config.v1"
	maxConfigBytes = 16 << 10
	signingKeyFD   = 3
)

type configDocument struct {
	Protocol                 string `json:"protocol"`
	Mode                     string `json:"mode"`
	SecurityProfilePath      string `json:"security_profile_path"`
	PolicyID                 string `json:"policy_id"`
	LedgerPath               string `json:"ledger_path"`
	SocketPath               string `json:"socket_path"`
	OperatorKeyID            string `json:"operator_key_id"`
	OperatorPublicKey        []byte `json:"operator_public_key"`
	ExpectedBrokerUID        uint32 `json:"expected_broker_uid"`
	ExpectedBrokerGID        uint32 `json:"expected_broker_gid"`
	MaxConnections           int    `json:"max_connections"`
	StateRefreshMillis       int    `json:"state_refresh_millis"`
	PolicyStateMaxAgeSeconds int    `json:"policy_state_max_age_seconds"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "egress policy state authority failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	document, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes+1))
	if err != nil || len(document) == 0 || len(document) > maxConfigBytes {
		return stageError("config-read")
	}
	defer clear(document)
	config, err := decodeConfig(document)
	if err != nil {
		return err
	}
	profile, err := phase6security.VerifyFile(config.SecurityProfilePath)
	if err != nil {
		return stageError("security-profile")
	}
	var policy phase6security.EgressPolicy
	for _, candidate := range profile.EgressPolicies {
		if candidate.ID == config.PolicyID {
			policy = candidate
		}
	}
	if policy.ID == "" {
		return stageError("policy")
	}
	if !validateProfileBinding(profile, policy, config) {
		return stageError("profile-binding")
	}
	binding, err := egresspolicystate.NewBinding(egresspolicystate.BindingConfig{
		EnvironmentDigest: profile.EnvironmentDigest, ProfileDigest: profile.ProfileDigest,
		Policy: policy, OperatorKeyID: config.OperatorKeyID, OperatorPublicKey: config.OperatorPublicKey,
		MaxAge: time.Duration(config.PolicyStateMaxAgeSeconds) * time.Second})
	if err != nil {
		return stageError("binding")
	}
	if config.Mode == "inspect" {
		receipt, err := egresspolicystate.InspectRevoked(config.LedgerPath, binding)
		if err != nil {
			return stageError("inspect-revocation")
		}
		encoded, err := json.Marshal(receipt)
		if err != nil {
			return stageError("receipt-encode")
		}
		_, err = os.Stdout.Write(append(encoded, '\n'))
		if err != nil {
			return stageError("receipt-write")
		}
		return nil
	}
	privateKey, err := readSigningKey()
	if err != nil {
		return stageError("signing-key")
	}
	defer clear(privateKey)
	if !privateKey.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(config.OperatorPublicKey)) {
		return stageError("signing-key-binding")
	}
	authority, err := egresspolicystate.OpenAuthority(egresspolicystate.AuthorityConfig{
		Binding: binding, LedgerPath: config.LedgerPath,
		PrivateKey: privateKey, Now: time.Now, AllowInitialize: config.Mode == "initialize"})
	if err != nil {
		return stageError("ledger")
	}
	defer authority.Close()
	lifetime := time.Duration(config.PolicyStateMaxAgeSeconds) * time.Second
	if config.Mode == "initialize" {
		if _, err := authority.Commit(0, "active", lifetime); err != nil {
			return stageError("initialize")
		}
		return nil
	}
	committed, err := authority.Committed()
	if err != nil || committed.Status != "active" {
		return stageError("committed-status")
	}
	if _, err := authority.Commit(committed.Generation, "active", lifetime); err != nil {
		return stageError("refresh-on-start")
	}
	server, err := egresspolicystate.ListenAuthority(egresspolicystate.AuthorityServerConfig{
		SocketPath: config.SocketPath, AuthorityUID: uint32(os.Getuid()), BrokerGID: config.ExpectedBrokerGID,
		ExpectedBrokerUID: config.ExpectedBrokerUID, ExpectedBrokerGID: config.ExpectedBrokerGID,
		MaxConnections: config.MaxConnections}, authority)
	if err != nil {
		return stageError("listen")
	}
	defer server.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	revocations := make(chan os.Signal, 1)
	signal.Notify(revocations, syscall.SIGUSR1)
	defer signal.Stop(revocations)
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx) }()
	ticker := time.NewTicker(time.Duration(config.StateRefreshMillis) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			<-served
			return nil
		case serveErr := <-served:
			if ctx.Err() != nil && errors.Is(serveErr, context.Canceled) {
				return nil
			}
			return stageError("serve")
		case <-ticker.C:
			committed, err := authority.Committed()
			if err != nil || committed.Status != "active" {
				cancel()
				<-served
				return stageError("refresh-current")
			}
			if _, err := authority.Commit(committed.Generation, "active", lifetime); err != nil {
				cancel()
				<-served
				return stageError("refresh-commit")
			}
		case <-revocations:
			committed, err := authority.Committed()
			if err != nil || committed.Status != "active" {
				cancel()
				<-served
				return stageError("revoke-current")
			}
			if _, err := authority.Commit(committed.Generation, "revoked", lifetime); err != nil {
				cancel()
				<-served
				return stageError("revoke-commit")
			}
			cancel()
			<-served
			return nil
		}
	}
}

func decodeConfig(document []byte) (configDocument, error) {
	var config configDocument
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return configDocument{}, stageError("config-decode")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return configDocument{}, stageError("config-trailing")
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, document) || config.Protocol != configProtocol ||
		(config.Mode != "initialize" && config.Mode != "serve" && config.Mode != "inspect") || !validPath(config.SecurityProfilePath) ||
		!validPath(config.LedgerPath) || !validPath(config.SocketPath) ||
		config.PolicyID == "" || config.OperatorKeyID == "" ||
		len(config.OperatorPublicKey) != ed25519.PublicKeySize ||
		config.MaxConnections < 1 || config.MaxConnections > 64 ||
		config.PolicyStateMaxAgeSeconds < 1 || config.PolicyStateMaxAgeSeconds > 30 ||
		config.StateRefreshMillis < 50 || config.StateRefreshMillis > 1000 ||
		config.StateRefreshMillis*2 > config.PolicyStateMaxAgeSeconds*1000 {
		clear(canonical)
		return configDocument{}, stageError("config-validate")
	}
	clear(canonical)
	return config, nil
}

func validPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validateProfileBinding(profile phase6security.Profile, policy phase6security.EgressPolicy, config configDocument) bool {
	var authority, broker phase6security.Principal
	for _, principal := range profile.Principals {
		if principal.Name == policy.Authority.DeploymentName {
			authority = principal
		}
		if principal.Name == policy.Broker {
			broker = principal
		}
	}
	return authority.Name != "" && broker.Name != "" && authority.Kind == "controller" && broker.Kind == "egress_broker" &&
		authority.PrincipalDigest == policy.Authority.PrincipalDigest &&
		uint32(os.Getuid()) == authority.UID && uint32(os.Getgid()) == authority.GID &&
		config.ExpectedBrokerUID == broker.UID && config.ExpectedBrokerGID == broker.GID &&
		config.OperatorKeyID == policy.Authority.KeyID &&
		phase6security.OperatorPublicKeyDigest(config.OperatorPublicKey) == policy.Authority.PublicKeyDigest &&
		config.PolicyStateMaxAgeSeconds == policy.Authority.StateMaxAgeSeconds &&
		config.LedgerPath == filepath.Join(policy.Authority.LedgerMountTarget, "ledger.json") &&
		config.SocketPath == filepath.Join(policy.Authority.SocketDirectory, "current.sock")
}

func readSigningKey() (ed25519.PrivateKey, error) {
	file := os.NewFile(signingKeyFD, "policy-state-signing-key")
	if file == nil {
		return nil, egresspolicystate.ErrInvalid
	}
	defer file.Close()
	info, statErr := file.Stat()
	offset, seekErr := file.Seek(0, io.SeekCurrent)
	if statErr != nil || seekErr != nil || offset != 0 || info == nil {
		return nil, egresspolicystate.ErrInvalid
	}
	owner, ownerOK := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || info.Size() != ed25519.PrivateKeySize ||
		!ownerOK || owner.Uid != uint32(os.Getuid()) {
		return nil, egresspolicystate.ErrInvalid
	}
	key, err := io.ReadAll(io.LimitReader(file, ed25519.PrivateKeySize+1))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		return nil, egresspolicystate.ErrInvalid
	}
	return ed25519.PrivateKey(key), nil
}

func stageError(stage string) error {
	return fmt.Errorf("stage %s: %w", stage, egresspolicystate.ErrInvalid)
}
