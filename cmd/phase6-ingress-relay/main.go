// Command phase6-ingress-relay runs the operator-owned, fixed-target L4 public
// ingress relay. It cannot parse application traffic or select an upstream.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/ingressrelay"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type authority struct {
	Version               int    `json:"version"`
	SecurityProfilePath   string `json:"security_profile_path"`
	SecurityProfileDigest string `json:"security_profile_digest"`
	RelayPrincipalDigest  string `json:"relay_principal_digest"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "phase6-ingress-relay failed")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) != 2 || arguments[0] != "serve" || !filepath.IsAbs(arguments[1]) {
		return errors.New("usage: phase6-ingress-relay serve /absolute/path/to/authority.json")
	}
	document, err := secretfile.Read(arguments[1], 16<<10)
	if err != nil {
		return errors.New("read ingress relay authority")
	}
	defer clear(document)
	value, err := parseAuthority(document)
	if err != nil {
		return err
	}
	profile, err := phase6security.VerifyFile(value.SecurityProfilePath)
	if err != nil || profile.ProfileDigest != value.SecurityProfileDigest {
		return errors.New("ingress relay security profile mismatch")
	}
	config, principal, err := profile.IngressRelayConfig()
	if err != nil || principal.PrincipalDigest != value.RelayPrincipalDigest || principal.Kind != "ingress_relay" ||
		uint32(os.Getuid()) != principal.UID || uint32(os.Getgid()) != principal.GID {
		return errors.New("ingress relay principal does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return errors.New("ingress relay supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != principal.GID {
			return errors.New("ingress relay has supplementary group authority")
		}
	}
	relay, err := ingressrelay.New(config)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return relay.Serve(ctx)
}

func parseAuthority(document []byte) (authority, error) {
	var value authority
	if len(document) < 1 || len(document) > 16<<10 || json.Unmarshal(document, &value) != nil {
		return authority{}, errors.New("invalid ingress relay authority")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) || value.Version != 1 ||
		!filepath.IsAbs(value.SecurityProfilePath) || filepath.Clean(value.SecurityProfilePath) != value.SecurityProfilePath ||
		!digestPattern.MatchString(value.SecurityProfileDigest) || !digestPattern.MatchString(value.RelayPrincipalDigest) {
		return authority{}, errors.New("invalid ingress relay authority")
	}
	return value, nil
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
