// provider-docker-control composes held Profile-v2 Coding Control. The old
// status-only config remains read-only; mutation composition is explicit.
// Browser/Desktop listeners and public Profile admission remain unavailable.
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

	"github.com/shell-echo/sandbox-runtime/internal/codingcontroltransport"
	"github.com/shell-echo/sandbox-runtime/internal/controlbootstrap"
	"github.com/shell-echo/sandbox-runtime/internal/controldelivery"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const controlConfigProtocol = "sandbox-runtime.provider-docker-control-status-config.v1"
const controlMutationConfigProtocol = "sandbox-runtime.provider-docker-control-coding-config.v2"
const controlDeliveryConfigProtocol = "sandbox-runtime.provider-docker-control-delivery-config.v4"
const controlSourceConfigProtocol = "sandbox-runtime.provider-docker-control-source-config.v5"
const controlTrustConfigProtocol = "sandbox-runtime.provider-docker-control-trust-config.v6"
const controlBootstrapConfigProtocol = "sandbox-runtime.provider-docker-control-bootstrap-config.v3"

var errControl = errors.New("private Control status unavailable")

type configDocument struct {
	Protocol                string                                       `json:"protocol"`
	SecurityProfilePath     string                                       `json:"security_profile_path"`
	SecurityProfileDigest   string                                       `json:"security_profile_digest"`
	EnvironmentDigest       string                                       `json:"environment_digest"`
	PrincipalProfileDigest  string                                       `json:"principal_profile_digest"`
	ListenAddress           string                                       `json:"listen_address"`
	PeerCRLRolePath         string                                       `json:"peer_crl_role_path"`
	PeerCRLRoleDigest       string                                       `json:"peer_crl_role_digest"`
	SourceMappingDigest     string                                       `json:"source_mapping_digest"`
	AgentSocket             string                                       `json:"agent_socket"`
	AgentUID                uint32                                       `json:"agent_uid"`
	AgentGID                uint32                                       `json:"agent_gid"`
	OperationTimeoutSeconds int                                          `json:"operation_timeout_seconds"`
	ReceiptBinding          dockercontrol.CodingReceiptBinding           `json:"receipt_binding"`
	MutationInputs          *codingcontroltransport.CodingMutationInputs `json:"mutation_inputs,omitempty"`
}

func validConfigMode(c configDocument) bool {
	if c.Protocol == controlConfigProtocol {
		return c.MutationInputs == nil
	}
	// Bootstrap-only composition remains held; it cannot silently fall back to
	// the older pipe-based diagnostic admission or enable Coding mutations.
	if c.Protocol == controlBootstrapConfigProtocol || c.Protocol == controlDeliveryConfigProtocol || c.Protocol == controlSourceConfigProtocol || c.Protocol == controlTrustConfigProtocol {
		return c.MutationInputs == nil
	}
	if c.Protocol != controlMutationConfigProtocol || c.MutationInputs == nil {
		return false
	}
	i := c.MutationInputs
	return len(i.SeccompPolicy) > 0 && len(i.SeccompPolicy) <= 64<<10 &&
		len(i.Documents.Index) > 0 && len(i.Documents.Index) <= 64<<10 &&
		len(i.Documents.Manifest) > 0 && len(i.Documents.Manifest) <= 64<<10 &&
		len(i.Documents.Config) > 0 && len(i.Documents.Config) <= 64<<10
}

func decodeConfig(data []byte) (configDocument, error) {
	var c configDocument
	if len(data) == 0 || len(data) > 256<<10 {
		return c, errControl
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return configDocument{}, errControl
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(data, canonical) || !validConfigMode(c) || c.OperationTimeoutSeconds < 1 || c.OperationTimeoutSeconds > 30 {
		return configDocument{}, errControl
	}
	return c, nil
}
func preflight(c configDocument) (phase6security.ProfileV2, phase6tls.PrivateServiceAuthorityV2, error) {
	var p phase6security.ProfileV2
	var a phase6tls.PrivateServiceAuthorityV2
	if !validConfigMode(c) || c.OperationTimeoutSeconds < 1 || c.OperationTimeoutSeconds > 30 {
		return p, a, errControl
	}
	p, err := phase6security.VerifyFileV2(c.SecurityProfilePath)
	if err != nil || p.ProfileDigest != c.SecurityProfileDigest || p.EnvironmentDigest != c.EnvironmentDigest || p.PrincipalProfileDigest != c.PrincipalProfileDigest {
		return p, a, errControl
	}
	b, err := p.PrivateServiceBoundary("coding", c.ListenAddress)
	if err != nil || c.ReceiptBinding.Validate() != nil || c.ReceiptBinding.ProfileDigest != p.ProfileDigest || c.ReceiptBinding.PeerPrincipalDigest != b.Provider.PrincipalDigest || p.CodingTemplate.BindPlan(c.ReceiptBinding.Plan) != nil {
		return p, a, errControl
	}
	if phase6security.VerifySlice6PrivateConfigPathV2(p, b.Service.Name, phase6security.Slice6ProfileConfigFile, c.SecurityProfilePath) != nil || phase6security.VerifySlice6PrivateConfigPathV2(p, b.Service.Name, phase6security.Slice6PeerCRLRoleFile, c.PeerCRLRolePath) != nil {
		return p, a, errControl
	}
	role, err := phase6security.VerifyPeerCRLRoleFileV2(c.PeerCRLRolePath, p, c.SourceMappingDigest, c.PeerCRLRoleDigest, b.Service.PrincipalDigest)
	if err != nil {
		return p, a, errControl
	}
	return p, phase6tls.PrivateServiceAuthorityV2{Scope: "coding", Address: c.ListenAddress, PeerCRLRole: role, SourceMappingDigest: c.SourceMappingDigest, RoleDigest: c.PeerCRLRoleDigest,
		AgentSocket: c.AgentSocket, AgentUID: c.AgentUID, AgentGID: c.AgentGID, OperationTimeout: time.Duration(c.OperationTimeoutSeconds) * time.Second}, nil
}
func run(ctx context.Context, input io.Reader) error {
	if ctx == nil || ctx.Err() != nil || input == nil {
		return errControl
	}
	data, err := io.ReadAll(io.LimitReader(input, (256<<10)+1))
	if err != nil {
		return errControl
	}
	defer clear(data)
	c, err := decodeConfig(data)
	if err != nil {
		return err
	}
	if c.Protocol == controlBootstrapConfigProtocol || c.Protocol == controlDeliveryConfigProtocol || c.Protocol == controlSourceConfigProtocol || c.Protocol == controlTrustConfigProtocol {
		if c.SecurityProfilePath != phase6security.Slice6PrivateConfigDirectory+"/"+phase6security.Slice6ProfileConfigFile {
			return errControl
		}
		document, e := secretfile.Read(c.SecurityProfilePath, 4<<20)
		if e != nil {
			return errControl
		}
		defer clear(document)
		credential, e := controlbootstrap.Open(ctx, document, os.NewFile(3, "control-operator-verification-key"))
		if e != nil {
			if c.Protocol == controlDeliveryConfigProtocol || c.Protocol == controlSourceConfigProtocol || c.Protocol == controlTrustConfigProtocol {
				return fmt.Errorf("%w: bootstrap", controldelivery.ErrUnavailable)
			}
			return errControl
		}
		r, e := credential.Review()
		if e != nil || r.ProfileDigest != c.SecurityProfileDigest {
			return errControl
		}
		if c.Protocol == controlDeliveryConfigProtocol || c.Protocol == controlSourceConfigProtocol || c.Protocol == controlTrustConfigProtocol {
			want := phase6security.ControlDeliveryTarget
			if c.Protocol == controlSourceConfigProtocol || c.Protocol == controlTrustConfigProtocol {
				want = phase6security.ControlSourceTarget
			}
			if c.Protocol == controlTrustConfigProtocol {
				want = phase6security.ControlTrustTarget
			}
			if r.Bootstrap.Target != want {
				return errControl
			}
			if e := controldelivery.Run(ctx, credential); e != nil {
				return e
			}
		} else if r.Bootstrap.Target != phase6security.ControlBootstrapTarget {
			return errControl
		}
		// A delivery receipt never opens Store or removes the public startup hold.
		return errControl
	}
	p, a, err := preflight(c)
	if err != nil {
		return err
	}
	if c.MutationInputs != nil {
		return codingcontroltransport.RunCodingV2(ctx, p, a, c.ReceiptBinding, *c.MutationInputs)
	}
	return codingcontroltransport.RunStatusV2(ctx, p, a, c.ReceiptBinding)
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Stdin); err != nil {
		if errors.Is(err, controldelivery.ErrUnavailable) {
			fmt.Fprintln(os.Stderr, err)
		}
		fmt.Fprintln(os.Stderr, "private Control failed")
		os.Exit(1)
	}
}
