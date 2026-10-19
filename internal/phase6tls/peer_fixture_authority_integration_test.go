//go:build linux && integration

package phase6tls

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
	"golang.org/x/sys/unix"
)

// This file is a test process fixture. It never supplies a production
// certificate-controller or Vault credential.
type peerFixtureAgentConfig struct {
	ProfilePath   string
	Subject       string
	SourcesPath   string
	RolePath      string
	PinsPath      string
	PinsDigest    string
	MappingDigest string
	RoleDigest    string
	IssuerPEM     []byte
	IssuerKeyPEM  []byte
	OwnCRLDER     []byte
	PeerStatePath string
	LeafFault     string
}

type peerFixtureAuthority struct {
	config    peerFixtureAgentConfig
	profile   phase6security.ProfileV2
	sources   phase6security.PeerCRLSources
	role      phase6security.PeerCRLRoleDocument
	binding   phase6security.TLSAgentBinding
	agent     phase6security.Principal
	subject   phase6security.Principal
	policy    workloadpki.Policy
	issuer    *x509.Certificate
	issuerDER []byte
}

// pins.json is emitted only by phase6security's complete-field test bridge.
// Its externally fixed original-byte hash is a test input, never a runtime
// Profile admission. The public v2 hold remains in effect.
type peerFixturePins struct {
	ProfileBytes  string
	SourceBytes   string
	MappingDigest string
	Roles         map[string]string
	RoleBytes     map[string]string
}

func peerFixtureDigest(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodePeerFixtureCanonical[T any](document []byte) (T, error) {
	var value T
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return value, workloadtlsagent.ErrUnavailable
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(document, canonical) {
		return value, workloadtlsagent.ErrUnavailable
	}
	return value, nil
}

func loadPeerFixtureAuthority(config peerFixtureAgentConfig) (*peerFixtureAuthority, error) {
	if config.Subject != "provider-runtime" && config.Subject != "provider-docker-control" ||
		config.ProfilePath == "" || config.SourcesPath == "" || config.RolePath == "" || config.PinsPath == "" ||
		config.MappingDigest == "" || config.RoleDigest == "" || config.PeerStatePath == "" ||
		config.LeafFault != "" && config.LeafFault != "uri" && config.LeafFault != "dns" && config.LeafFault != "eku" {
		return nil, workloadtlsagent.ErrUnavailable
	}
	pinsDocument, err := secretfile.Read(config.PinsPath, 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(pinsDocument)
	if peerFixtureDigest(pinsDocument) != config.PinsDigest {
		return nil, workloadtlsagent.ErrUnavailable
	}
	pins, err := decodePeerFixtureCanonical[peerFixturePins](pinsDocument)
	if err != nil || len(pins.Roles) != 2 || len(pins.RoleBytes) != 2 ||
		pins.Roles["provider-runtime"] == "" || pins.Roles["provider-docker-control"] == "" ||
		pins.RoleBytes["provider-runtime"] == "" || pins.RoleBytes["provider-docker-control"] == "" ||
		pins.MappingDigest != config.MappingDigest || pins.Roles[config.Subject] != config.RoleDigest {
		return nil, workloadtlsagent.ErrUnavailable
	}
	profileDocument, err := secretfile.Read(config.ProfilePath, 4<<20)
	if err != nil {
		return nil, err
	}
	defer clear(profileDocument)
	if peerFixtureDigest(profileDocument) != pins.ProfileBytes {
		return nil, workloadtlsagent.ErrUnavailable
	}
	profile, err := decodePeerFixtureCanonical[phase6security.ProfileV2](profileDocument)
	if err != nil || profile.Digest() != profile.ProfileDigest {
		return nil, workloadtlsagent.ErrUnavailable
	}
	review, err := phase6security.ReviewControlBootstrap(profileDocument)
	if err != nil || review.Admission != "held-not-a-permit" || review.ProfileDigest != profile.ProfileDigest ||
		review.ProfileBytesDigest != pins.ProfileBytes {
		return nil, workloadtlsagent.ErrUnavailable
	}
	if _, err := phase6security.DecodeV2(profileDocument); err == nil || profile.Validate() == nil {
		return nil, workloadtlsagent.ErrUnavailable
	}
	binding, agent, subject, err := peerFixtureBinding(profile, config.Subject)
	if err != nil || agent.AuthorizationPrincipal == nil || subject.AuthorizationPrincipal == nil || subject.TLS == nil ||
		binding.AgentDeployment != agent.Name || binding.SubjectDeployment != subject.Name ||
		binding.AgentPrincipalDigest != agent.PrincipalDigest || binding.SubjectPrincipalDigest != subject.PrincipalDigest ||
		binding.AgentUID != uint32(os.Getuid()) || binding.AgentGID != uint32(os.Getgid()) ||
		binding.SubjectUID != subject.UID || binding.SubjectGID != subject.GID {
		return nil, workloadtlsagent.ErrUnavailable
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, err
	}
	subjectGroup := false
	for _, group := range groups {
		if uint32(group) != binding.AgentGID && uint32(group) != binding.SubjectGID {
			return nil, workloadtlsagent.ErrUnavailable
		}
		subjectGroup = subjectGroup || uint32(group) == binding.SubjectGID
	}
	if !subjectGroup {
		return nil, workloadtlsagent.ErrUnavailable
	}
	sourcesDocument, err := secretfile.Read(config.SourcesPath, 128<<10)
	if err != nil {
		return nil, err
	}
	defer clear(sourcesDocument)
	if peerFixtureDigest(sourcesDocument) != pins.SourceBytes {
		return nil, workloadtlsagent.ErrUnavailable
	}
	sources, err := decodePeerFixtureCanonical[phase6security.PeerCRLSources](sourcesDocument)
	if err != nil || sources.Protocol != phase6security.PeerCRLSourcesProtocolID ||
		sources.Digest() != config.MappingDigest || sources.SecurityProfileDigest != profile.ProfileDigest {
		return nil, workloadtlsagent.ErrUnavailable
	}
	roleDocument, err := secretfile.Read(config.RolePath, 128<<10)
	if err != nil {
		return nil, err
	}
	defer clear(roleDocument)
	if peerFixtureDigest(roleDocument) != pins.RoleBytes[config.Subject] {
		return nil, workloadtlsagent.ErrUnavailable
	}
	role, err := decodePeerFixtureCanonical[phase6security.PeerCRLRoleDocument](roleDocument)
	if err != nil || role.Protocol != phase6security.PeerCRLRoleProtocolID || role.Digest() != config.RoleDigest || role.SecurityProfileDigest != profile.ProfileDigest ||
		role.SourceMappingDigest != config.MappingDigest || role.LocalPrincipalDigest != subject.PrincipalDigest {
		return nil, workloadtlsagent.ErrUnavailable
	}
	registry, err := peerFixtureRegistry(profile)
	if err != nil || registry.Validate(*agent.AuthorizationPrincipal) != nil ||
		registry.Validate(*subject.AuthorizationPrincipal) != nil {
		return nil, workloadtlsagent.ErrUnavailable
	}
	// The fixture has no certificate-controller request signing protocol. Its
	// ephemeral public key satisfies Policy's identity shape only; issuer
	// issuance is confined to this agent test process.
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	policy := workloadpki.Policy{ID: binding.IssuerPolicyID, Registry: registry,
		Requester: *agent.AuthorizationPrincipal, Subject: *subject.AuthorizationPrincipal,
		TrustDomain: subject.TLS.TrustDomain, URI: subject.TLS.URI,
		DNSNames: append([]string(nil), subject.TLS.DNSNames...), Usages: append([]string(nil), subject.TLS.Usages...),
		VaultRole: binding.IssuerVaultRole, IssuerSourceID: "general-peer", MaxTTLSeconds: subject.TLS.TTLSeconds,
		ExpectedUID: binding.AgentUID, ExpectedGID: binding.AgentGID, PublicKey: public}
	if policy.Validate() != nil {
		return nil, workloadtlsagent.ErrUnavailable
	}
	block, trailing := pem.Decode(config.IssuerPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, workloadtlsagent.ErrUnavailable
	}
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !issuer.IsCA || !issuer.BasicConstraintsValid ||
		issuer.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return nil, workloadtlsagent.ErrUnavailable
	}
	issuerDigest := sha256.Sum256(issuer.Raw)
	issuerHash := "sha256:" + hex.EncodeToString(issuerDigest[:])
	generalFound := false
	for _, source := range sources.Sources {
		if source.ID == "general-peer" && source.IssuerDigest == issuerHash {
			generalFound = true
		}
	}
	if !generalFound {
		return nil, workloadtlsagent.ErrUnavailable
	}
	list, err := x509.ParseRevocationList(config.OwnCRLDER)
	if err != nil {
		return nil, workloadtlsagent.ErrUnavailable
	}
	if _, err := workloadpki.VerifyCRLForIssuer(workloadpki.RevocationSnapshot{
		DER: config.OwnCRLDER, ThisUpdate: list.ThisUpdate, NextUpdate: list.NextUpdate}, issuer.Raw, time.Now().UTC()); err != nil {
		return nil, workloadtlsagent.ErrUnavailable
	}
	return &peerFixtureAuthority{config: config, profile: profile, sources: sources, role: role,
		binding: binding, agent: agent, subject: subject, policy: policy, issuer: issuer,
		issuerDER: bytes.Clone(issuer.Raw)}, nil
}

func peerFixtureBinding(profile phase6security.ProfileV2, name string) (phase6security.TLSAgentBinding, phase6security.Principal, phase6security.Principal, error) {
	var binding phase6security.TLSAgentBinding
	var agent, subject phase6security.Principal
	count := 0
	for _, candidate := range profile.TLSAgentBindings {
		if candidate.SubjectDeployment == name {
			binding = candidate
			count++
		}
	}
	for _, candidate := range profile.Principals {
		if candidate.Name == name {
			subject = candidate
		}
		if candidate.Name == binding.AgentDeployment {
			agent = candidate
		}
	}
	if count != 1 || binding.AgentDeployment == "" || agent.Name != binding.AgentDeployment || subject.Name != name {
		return phase6security.TLSAgentBinding{}, phase6security.Principal{}, phase6security.Principal{}, workloadtlsagent.ErrUnavailable
	}
	return binding, agent, subject, nil
}

func peerFixtureRegistry(profile phase6security.ProfileV2) (*securityprincipal.Registry, error) {
	brokers := map[string]securityprincipal.Role{}
	authorities := map[string]securityprincipal.Role{}
	for _, policy := range profile.EgressPolicies {
		if policy.Authority.AuthorizationName == "" {
			return nil, workloadtlsagent.ErrUnavailable
		}
		authorities[policy.Authority.AuthorizationName] = ""
	}
	for _, principal := range profile.Principals {
		if principal.Kind == "egress_broker" && principal.AuthorizationPrincipal != nil {
			identity := principal.AuthorizationPrincipal
			brokers[identity.Name] = identity.Role
		}
	}
	return securityprincipal.NewSlice6V2Registry(profile.EnvironmentDigest, profile.PrincipalProfileDigest, brokers, authorities)
}

func (a *peerFixtureAuthority) ReadPeerCRL(ctx context.Context, request workloadtlsagent.PeerCRLRequest) (string, []byte, []byte, time.Time, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || request.Validate(time.Now().UTC()) != nil ||
		request.ProfileDigest != a.profile.ProfileDigest || request.SourceMappingDigest != a.config.MappingDigest ||
		request.LocalPrincipalDigest != a.subject.PrincipalDigest || a.role.LocalPrincipalDigest != a.subject.PrincipalDigest ||
		a.role.SecurityProfileDigest != a.profile.ProfileDigest || a.role.SourceMappingDigest != a.config.MappingDigest {
		return "", nil, nil, time.Time{}, workloadtlsagent.ErrUnavailable
	}
	sourceID, matchingEdges := "", 0
	for _, edge := range a.sources.Edges {
		if edge.EdgeID == request.EdgeID && edge.LocalPrincipalDigest == request.LocalPrincipalDigest &&
			edge.Direction == request.Direction && edge.PeerAnchorID == request.PeerAnchorID {
			sourceID = edge.SourceID
			matchingEdges++
		}
	}
	if matchingEdges != 1 || sourceID != "general-peer" {
		return "", nil, nil, time.Time{}, workloadtlsagent.ErrUnavailable
	}
	matchingSources := 0
	for _, source := range a.sources.Sources {
		if source.ID == sourceID && source.IssuerDigest == request.IssuerDigest {
			matchingSources++
		}
	}
	if matchingSources != 1 {
		return "", nil, nil, time.Time{}, workloadtlsagent.ErrUnavailable
	}
	roleMatches := 0
	for _, edge := range a.role.Edges {
		if edge.EdgeID == request.EdgeID && edge.Direction == request.Direction &&
			edge.PeerAnchorID == request.PeerAnchorID && edge.IssuerDigest == request.IssuerDigest {
			roleMatches++
		}
	}
	if roleMatches != 1 {
		return "", nil, nil, time.Time{}, workloadtlsagent.ErrUnavailable
	}
	issuerHash := sha256.Sum256(a.issuerDER)
	if request.IssuerDigest != "sha256:"+hex.EncodeToString(issuerHash[:]) {
		return "", nil, nil, time.Time{}, workloadtlsagent.ErrUnavailable
	}
	state, err := readPeerFixtureState(ctx, a.config.PeerStatePath)
	if err != nil || state.Mode != "present" {
		return "", nil, nil, time.Time{}, workloadtlsagent.ErrUnavailable
	}
	if state.SourceID == "" {
		state.SourceID = "general-peer"
	}
	if state.SourceID != sourceID || len(state.CRLDER) == 0 {
		return "", nil, nil, time.Time{}, workloadtlsagent.ErrUnavailable
	}
	collectedAt := time.Now().UTC()
	if state.CollectedAt != "" {
		collectedAt, err = time.Parse(time.RFC3339Nano, state.CollectedAt)
		if err != nil {
			return "", nil, nil, time.Time{}, workloadtlsagent.ErrUnavailable
		}
	}
	return sourceID, bytes.Clone(a.issuerDER), state.CRLDER, collectedAt, nil
}

type peerFixtureState struct {
	Mode        string
	SourceID    string
	CRLDER      []byte
	CollectedAt string
}

func readPeerFixtureState(ctx context.Context, path string) (peerFixtureState, error) {
	if ctx.Err() != nil || path == "" || strings.IndexByte(path, 0) >= 0 {
		return peerFixtureState{}, workloadtlsagent.ErrUnavailable
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return peerFixtureState{}, err
	}
	f := os.NewFile(uintptr(fd), "peer-state")
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 512<<10 ||
		before.Mode().Perm()&0o022 != 0 {
		return peerFixtureState{}, workloadtlsagent.ErrUnavailable
	}
	document, err := io.ReadAll(io.LimitReader(f, 512<<10+1))
	if err != nil || int64(len(document)) != before.Size() || ctx.Err() != nil {
		clear(document)
		return peerFixtureState{}, workloadtlsagent.ErrUnavailable
	}
	defer clear(document)
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
		return peerFixtureState{}, workloadtlsagent.ErrUnavailable
	}
	var state peerFixtureState
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return peerFixtureState{}, workloadtlsagent.ErrUnavailable
	}
	return state, nil
}
