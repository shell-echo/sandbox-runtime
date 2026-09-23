// currentclient is a Docker-only probe of the production policy authority's
// Unix Current boundary. It is not the production egress broker.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/egresspolicystate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type input struct {
	Profile   json.RawMessage `json:"profile"`
	PublicKey []byte          `json:"public_key"`
}

func main() {
	document, err := io.ReadAll(io.LimitReader(os.Stdin, 2<<20))
	if err != nil {
		fatal(err)
	}
	var config input
	if err := json.Unmarshal(document, &config); err != nil {
		fatal(err)
	}
	profile, err := phase6security.Decode(config.Profile)
	if err != nil || len(profile.EgressPolicies) != 1 {
		fatal(egresspolicystate.ErrInvalid)
	}
	policy := profile.EgressPolicies[0]
	var authority, broker phase6security.Principal
	for _, principal := range profile.Principals {
		if principal.Name == policy.Authority.DeploymentName {
			authority = principal
		}
		if principal.Name == policy.Broker {
			broker = principal
		}
	}
	if authority.Name == "" || broker.Name == "" || uint32(os.Getgid()) != broker.GID {
		fatal(egresspolicystate.ErrInvalid)
	}
	binding, err := egresspolicystate.NewBinding(egresspolicystate.BindingConfig{
		EnvironmentDigest: profile.EnvironmentDigest, ProfileDigest: profile.ProfileDigest,
		Policy: policy, OperatorKeyID: policy.Authority.KeyID, OperatorPublicKey: config.PublicKey,
		MaxAge: time.Duration(policy.Authority.StateMaxAgeSeconds) * time.Second})
	if err != nil {
		fatal(err)
	}
	client, err := egresspolicystate.NewAuthorityClient(egresspolicystate.AuthorityClientConfig{
		SocketPath:           filepath.Join(policy.Authority.SocketDirectory, "current.sock"),
		ExpectedAuthorityUID: authority.UID, ExpectedAuthorityGID: authority.GID, BrokerGID: broker.GID,
		Binding: binding, Timeout: time.Duration(policy.Authority.CurrentTimeoutMS) * time.Millisecond, Now: time.Now})
	if err != nil {
		fatal(err)
	}
	response, err := client.Current(context.Background())
	if err != nil {
		fatal(err)
	}
	_, _ = fmt.Fprintln(os.Stdout, response.Status)
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "Current probe failed: %v\n", err)
	os.Exit(1)
}
