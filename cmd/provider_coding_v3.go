package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/artifactscanner"
	"github.com/shell-echo/sandbox-runtime/internal/codingcontroltransport"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/rolematerials"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	artifactstaging "github.com/shell-echo/sandbox-runtime/provider/artifact/staging"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclecoordinator "github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

var errCodingV3 = errors.New("Coding v3 dependency composition unavailable")
var errCodingV3Execution = errors.New("Coding v3 remaining daemon-free runtime ports remain unavailable")

type codingV3Inputs struct {
	profile          phase6security.ProfileV2
	binding          dockercontrol.CodingReceiptBinding
	control, scanner phase6tls.PrivateServiceAuthorityV2
}

func decodeCodingReceiptBinding(document string) (dockercontrol.CodingReceiptBinding, error) {
	var b dockercontrol.CodingReceiptBinding
	if len(document) == 0 || len(document) > 64<<10 {
		return b, errCodingV3
	}
	decoder := json.NewDecoder(bytes.NewBufferString(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&b) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || b.Validate() != nil {
		return dockercontrol.CodingReceiptBinding{}, errCodingV3
	}
	canonical, err := json.Marshal(b)
	if err != nil || string(canonical) != document {
		return dockercontrol.CodingReceiptBinding{}, errCodingV3
	}
	return b, nil
}

// Preflight resolves every static authority before any material agent, PG
// connection or private-service client is opened. Public ProfileV2 stays held.
func preflightProviderCodingV3(cfg *config.ProviderProcessConfig) (codingV3Inputs, error) {
	var empty codingV3Inputs
	if cfg == nil || !cfg.Enabled || cfg.SchemaVersion != config.ProviderProductionSchemaV3 || cfg.Profile != config.ProviderProcessCodingShellProfile || cfg.Validate() != nil {
		return empty, errCodingV3
	}
	p, err := phase6security.VerifyFileV2(cfg.Transport.SecurityProfilePath)
	if err != nil || p.ProfileDigest != cfg.Transport.SecurityProfileDigest {
		return empty, errCodingV3
	}
	for file, path := range map[string]string{
		phase6security.Slice6ProfileConfigFile:       cfg.Transport.SecurityProfilePath,
		phase6security.Slice6PeerCRLRoleFile:         cfg.Transport.PeerCRLRoleFile,
		phase6security.Slice6PostgresPeerCRLRoleFile: cfg.Postgres.PeerCRLRoleFile} {
		if phase6security.VerifySlice6PrivateConfigPathV2(p, "provider-runtime", file, path) != nil {
			return empty, errCodingV3
		}
	}
	edge, _, owner, _, _, err := p.ProductProviderInstanceBoundary("provider-runtime")
	if err != nil || edge.TargetAddress != cfg.Transport.Address.Addr() {
		return empty, errCodingV3
	}
	signer, _, _, err := p.TLSAgentForSubject(owner.Name)
	if err != nil || signer.SocketPath != cfg.Transport.AgentSocket || signer.AgentUID != cfg.Transport.AgentUID || signer.AgentGID != cfg.Transport.AgentGID {
		return empty, errCodingV3
	}
	pg, err := p.ResolveSlice6FinalPostgresAuthority(owner.Name)
	if err != nil || pg.BrokerOnly || pg.Dialer != owner.Name || pg.Migration || pg.Database != "provider" || pg.SQLRole != cfg.Postgres.RuntimeRole ||
		pg.Signer.SocketPath != cfg.Postgres.ClientAgentSocket || pg.Signer.AgentUID != cfg.Postgres.ClientAgentUID || pg.Signer.AgentGID != cfg.Postgres.ClientAgentGID {
		return empty, errCodingV3
	}
	if _, err := phase6security.VerifyPostgresPeerCRLRoleFileV2(cfg.Postgres.PeerCRLRoleFile, p, cfg.Postgres.PeerCRLSourceMappingDigest, cfg.Postgres.PeerCRLRoleDigest, owner.Name, owner.PrincipalDigest); err != nil {
		return empty, errCodingV3
	}
	role, err := phase6security.VerifyPeerCRLRoleFileV2(cfg.Transport.PeerCRLRoleFile, p, cfg.Transport.PeerCRLSourceMappingDigest, cfg.Transport.PeerCRLRoleDigest, owner.PrincipalDigest)
	if err != nil {
		return empty, errCodingV3
	}
	binding, err := decodeCodingReceiptBinding(cfg.Coding.PrivateServices.ReceiptBindingJSON)
	if err != nil || binding.ProfileDigest != p.ProfileDigest || binding.PeerPrincipalDigest != owner.PrincipalDigest ||
		binding.RuntimePlatform != p.CodingTemplate.Image.Platform || p.CodingTemplate.BindPlan(binding.Plan) != nil {
		return empty, errCodingV3
	}
	makeAuthority := func(scope, address string) (phase6tls.PrivateServiceAuthorityV2, error) {
		b, err := p.PrivateServiceBoundary(scope, address)
		if err != nil || b.Provider.PrincipalDigest != owner.PrincipalDigest {
			return phase6tls.PrivateServiceAuthorityV2{}, errCodingV3
		}
		return phase6tls.PrivateServiceAuthorityV2{Scope: scope, Address: address, PeerCRLRole: role,
			SourceMappingDigest: cfg.Transport.PeerCRLSourceMappingDigest, RoleDigest: cfg.Transport.PeerCRLRoleDigest,
			AgentSocket: cfg.Transport.AgentSocket, AgentUID: cfg.Transport.AgentUID, AgentGID: cfg.Transport.AgentGID,
			OperationTimeout: time.Duration(cfg.Transport.OperationTimeoutMillis) * time.Millisecond}, nil
	}
	control, err := makeAuthority("coding", cfg.Coding.PrivateServices.ControlAddress)
	if err != nil {
		return empty, err
	}
	scanner, err := makeAuthority("scanner", cfg.Coding.PrivateServices.ScannerAddress)
	if err != nil {
		return empty, err
	}
	return codingV3Inputs{profile: p, binding: binding, control: control, scanner: scanner}, nil
}

// This is the actual Coding-v3 command selection, not a fallthrough to the
// legacy Docker driver. Both holds intentionally precede all side effects.
func runProviderCodingV3(ctx context.Context, cfg *config.ProviderProcessConfig) error {
	if ctx == nil || ctx.Err() != nil || cfg == nil || cfg.SchemaVersion != config.ProviderProductionSchemaV3 || cfg.Profile != config.ProviderProcessCodingShellProfile {
		return errCodingV3
	}
	if err := rejectUncomposedCodingV3(cfg); err != nil {
		return err
	}
	inputs, err := preflightProviderCodingV3(cfg)
	if err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(ctx, time.Duration(cfg.Postgres.StartupTimeoutSeconds)*time.Second)
	defer cancel()
	registry, err := rolematerials.NewSlice6ForDeploymentV2(cfg.Materials, "provider-runtime", inputs.profile, secretref.RoleProvider,
		[]secretref.Purpose{secretref.PurposePostgresRuntimeDSN, secretref.PurposeAdmissionVerification}, true, time.Now)
	if err != nil {
		return errCodingV3
	}
	defer registry.Close()
	pool, closePool, err := openProviderCodingV3Postgres(startup, ctx, cfg, inputs.profile, registry)
	if err != nil {
		return errCodingV3
	}
	defer closePool()
	if pool.Ping(startup) != nil || providerpostgres.VerifyRuntimeRole(startup, pool, cfg.Postgres.RuntimeRole) != nil || providerpostgres.VerifySchemaCompatibility(startup, pool) != nil {
		return errCodingV3
	}
	state, err := providerpostgres.New(pool, time.Duration(cfg.Postgres.OperationTimeoutSeconds)*time.Second)
	if err != nil {
		return errCodingV3
	}
	dependencies, err := newCodingV3Dependencies(startup, ctx, state, inputs)
	if err != nil {
		return err
	}
	defer dependencies.Close()
	// No Application constructor: it would start a mutation-producing lease
	// sweep before all required runtime ports are composed. No public API is served.
	return errCodingV3Execution
}

type codingV3Dependencies struct {
	control   *codingcontrol.TerminationCoordinator
	lifecycle *lifecyclecoordinator.Coordinator
	// Read-only eligibility, deliberately not an exec Executor or Application.
	execPreflight *codingcontrol.ExecPreflight
	// Durable intent only; no Executor, generic exec repository or worker.
	execIntents codingcontrol.ExecIntentRecorder
	// PG reservation evidence only; no Control permit or dispatch worker.
	execFences codingcontrol.ExecFenceRecorder
	malware    *artifactscanner.RemoteMalwareChecker
	active     *artifactstaging.PassiveJSONChecker
	close      func()
	once       sync.Once
}

func (d *codingV3Dependencies) Close() {
	if d != nil {
		d.once.Do(d.close)
	}
}

// Repository construction performs no initialization or recovery mutation.
// Begin/Finish are intentionally not registered with an automatic worker.
func newCodingV3Dependencies(startup, lifetime context.Context, state *providerpostgres.Store, in codingV3Inputs) (*codingV3Dependencies, error) {
	if startup == nil || lifetime == nil || startup.Err() != nil || lifetime.Err() != nil || state == nil || in.profile.Validate() != nil ||
		in.binding.Validate() != nil || in.binding.ProfileDigest != in.profile.ProfileDigest || in.profile.CodingTemplate.BindPlan(in.binding.Plan) != nil {
		return nil, errCodingV3
	}
	repository, err := providerpostgres.NewCodingLifecycleRepositoryWithPolicy(state, in.binding.Plan, in.binding.SpecBySlot, in.binding.ControlPolicyDigest)
	if err != nil {
		return nil, errCodingV3
	}
	owned, cancel := context.WithCancel(lifetime)
	stopStartup := context.AfterFunc(startup, cancel)
	defer stopStartup()
	client, err := codingcontroltransport.NewControlClientV2(owned, in.profile, in.control, in.binding.ControlPolicyDigest)
	if err != nil {
		cancel()
		return nil, errCodingV3
	}
	scanner, err := artifactscanner.NewRemoteMalwareCheckerV2(owned, in.profile, in.scanner)
	if err != nil {
		cancel()
		client.Close()
		return nil, errCodingV3
	}
	close := func() { cancel(); _ = scanner.Close(); client.Close() }
	coordinator, err := codingcontrol.NewTerminationReconciler(repository, client, client, systemAdmissionClock{}, codingcontrol.Expected{ProfileDigest: in.profile.ProfileDigest,
		ControlPolicyDigest: in.binding.ControlPolicyDigest, ProviderPrincipalDigest: in.binding.PeerPrincipalDigest})
	if err != nil {
		close()
		return nil, errCodingV3
	}
	readback, err := codingcontrol.NewCreateReadback(repository, client, systemAdmissionClock{}, codingcontrol.Expected{
		ProfileDigest: in.profile.ProfileDigest, ControlPolicyDigest: in.binding.ControlPolicyDigest, ProviderPrincipalDigest: in.binding.PeerPrincipalDigest})
	if err != nil {
		close()
		return nil, errCodingV3
	}
	create, err := lifecyclecoordinator.NewWithCodingOriginalAuthorityAndLease(repository,
		&codingV3CreatePort{client: client}, readback, coordinator, repository, systemAdmissionClock{})
	if err != nil || !stopStartup() || startup.Err() != nil || owned.Err() != nil {
		close()
		return nil, errCodingV3
	}
	preflight, err := codingcontrol.NewExecPreflight(repository, systemAdmissionClock{}, codingcontrol.Expected{
		ProfileDigest: in.profile.ProfileDigest, ControlPolicyDigest: in.binding.ControlPolicyDigest, ProviderPrincipalDigest: in.binding.PeerPrincipalDigest})
	if err != nil || startup.Err() != nil || owned.Err() != nil {
		close()
		return nil, errCodingV3
	}
	return &codingV3Dependencies{control: coordinator, lifecycle: create, execPreflight: preflight, execIntents: repository, execFences: repository, malware: scanner, active: &artifactstaging.PassiveJSONChecker{}, close: close}, nil
}

// The legacy Driver methods are closed even inside the candidate composition.
// Only the PG coordinator's same-call original authority reaches Control.
// No Docker endpoint, host root or caller-supplied runtime ID is accepted.
type codingV3CreatePort struct {
	client *codingcontroltransport.ControlClientV2
}

func (p *codingV3CreatePort) Create(context.Context, lifecycle.Sandbox) error {
	return errCodingV3Execution
}
func (p *codingV3CreatePort) Inspect(context.Context, string) (lifecyclecoordinator.RuntimeObservation, error) {
	return lifecyclecoordinator.RuntimeObservation{}, errCodingV3Execution
}
func (p *codingV3CreatePort) DispatchCodingCreateAuthority(ctx context.Context, authority dockercontrol.CodingCreateAuthority) error {
	if p == nil || p.client == nil {
		return errCodingV3Execution
	}
	return p.client.DispatchCodingCreateAuthority(ctx, authority)
}

var _ lifecyclecoordinator.Driver = (*codingV3CreatePort)(nil)
var _ lifecyclecoordinator.CodingAuthorityCreateDispatcher = (*codingV3CreatePort)(nil)
