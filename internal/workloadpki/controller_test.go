package workloadpki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type policyIssuerFixtureAuthority struct {
	fakeCertificateAuthority
	selectedID   string
	defaultCalls int
}

func (f *policyIssuerFixtureAuthority) ValidatePolicyIssuers(policies []Policy) error {
	if len(policies) != 1 || policies[0].IssuerSourceID == "" {
		return ErrUnavailable
	}
	return nil
}

func (f *policyIssuerFixtureAuthority) PolicyRevocations(ctx context.Context, policy Policy) (RevocationSnapshot, error) {
	f.selectedID = policy.IssuerSourceID
	return f.fakeCertificateAuthority.Revocations(ctx)
}

func (f *policyIssuerFixtureAuthority) Revocations(context.Context) (RevocationSnapshot, error) {
	f.defaultCalls++
	return RevocationSnapshot{}, ErrUnavailable
}

func TestControllerProductionV1RevocationsSelectsAuthenticatedPolicyIssuer(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.policy.IssuerSourceID = "broker-source"
	authority := &policyIssuerFixtureAuthority{fakeCertificateAuthority: fakeCertificateAuthority{fixture: fixture}}
	controller := &Controller{authority: authority, controllerKeyID: fixture.controllerID,
		controllerKey: fixture.controllerPriv, now: func() time.Time { return fixture.now },
		peerCRLProfile: &phase6security.Profile{}}
	request, err := NewRevocationsRequest(fixture.policy, "request-crl-1",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		fixture.now.Add(30*time.Second), fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	response, err := controller.revocations(context.Background(), request, fixture.policy)
	if err != nil || response.Validate(request, fixture.policy, fixture.controllerID, fixture.controllerPub, fixture.now) != nil ||
		authority.selectedID != "broker-source" || authority.defaultCalls != 0 {
		t.Fatalf("policy-selected CRL = %#v, %v; source=%s default=%d", response, err, authority.selectedID, authority.defaultCalls)
	}
	response.Destroy()
}

type fakeCertificateAuthority struct {
	mu          sync.Mutex
	fixture     protocolFixture
	issueCalls  int
	revokeCalls []string
	issueErr    error
	crlErr      error
	revokeErr   error
}

func (f *fakeCertificateAuthority) Issue(context.Context, Policy, []byte, time.Duration) (IssuedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issueCalls++
	if f.issueErr != nil {
		return IssuedCertificate{}, f.issueErr
	}
	return IssuedCertificate{IssuerRevision: "vault-pki-test-1", CertificatePEM: append([]byte(nil), f.fixture.certificate...),
		IssuingCAPEM: append([]byte(nil), f.fixture.ca...), CAChainPEM: append([]byte(nil), f.fixture.ca...), Serial: f.fixture.serial,
		NotBefore: f.fixture.notBefore, NotAfter: f.fixture.notAfter}, nil
}

func (f *fakeCertificateAuthority) Revocations(context.Context) (RevocationSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.crlErr != nil {
		return RevocationSnapshot{}, f.crlErr
	}
	return RevocationSnapshot{IssuerRevision: "vault-crl-test-1", DER: append([]byte(nil), f.fixture.crl...),
		ThisUpdate: f.fixture.crlThis, NextUpdate: f.fixture.crlNext}, nil
}

func (f *fakeCertificateAuthority) Revoke(_ context.Context, serial string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revokeCalls = append(f.revokeCalls, serial)
	return nil
}

func TestControllerPersistsReplayCertificateAndRevocationAcrossRestart(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.policy.ExpectedUID, fixture.policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
	directory := securePKIDirectory(t)
	ledgerPath := filepath.Join(directory, "ledger.json")
	authority := &fakeCertificateAuthority{fixture: fixture}
	config := ControllerConfig{LedgerPath: ledgerPath, Policies: []Policy{fixture.policy}, Authority: authority,
		ControllerKeyID: fixture.controllerID, ControllerKey: fixture.controllerPriv, Now: func() time.Time { return fixture.now },
		MaximumActive: 2, MaximumLedgerAge: time.Hour}
	controller, err := NewController(config)
	if err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	request, err := NewIssueRequest(fixture.policy, "request-issue-1", nonce, fixture.now.Add(30*time.Second), 10*time.Minute, fixture.csr, fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	response, err := controller.Handle(context.Background(), request, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
	if err != nil || response.Validate(request, fixture.policy, fixture.controllerID, fixture.controllerPub, fixture.now) != nil {
		t.Fatalf("Handle(issue) = %#v, %v", response, err)
	}
	response.Destroy()
	replayed, err := controller.Handle(context.Background(), request, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
	if !errors.Is(err, ErrDenied) || replayed.Status != StatusDenied {
		t.Fatalf("replay response = %#v, %v", replayed, err)
	}
	controller.Close()

	controller, err = NewController(config)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if len(controller.ledger.Certificates) != 1 || controller.ledger.Certificates[0].State != certificateActive || len(controller.ledger.Replays) != 1 {
		t.Fatalf("restarted ledger = %#v", controller.ledger)
	}
	revocations, err := NewRevocationsRequest(fixture.policy, "request-crl-1", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), fixture.now.Add(30*time.Second), fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	crlResponse, err := controller.Handle(context.Background(), revocations, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
	if err != nil || crlResponse.Validate(revocations, fixture.policy, fixture.controllerID, fixture.controllerPub, fixture.now) != nil {
		t.Fatalf("Handle(revocations) = %#v, %v", crlResponse, err)
	}
	crlResponse.Destroy()
	revoke, err := NewRevokeRequest(fixture.policy, "request-revoke-1", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), fixture.now.Add(30*time.Second), fixture.serial, fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	revokeResponse, err := controller.Handle(context.Background(), revoke, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
	if err != nil || revokeResponse.Validate(revoke, fixture.policy, fixture.controllerID, fixture.controllerPub, fixture.now) != nil {
		t.Fatalf("Handle(revoke) = %#v, %v", revokeResponse, err)
	}
	if controller.ledger.Certificates[0].State != certificateRevoked || len(authority.revokeCalls) != 1 || authority.revokeCalls[0] != fixture.serial {
		t.Fatalf("revocation ledger=%#v calls=%#v", controller.ledger.Certificates[0], authority.revokeCalls)
	}
	if info, err := os.Lstat(ledgerPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("ledger mode = %#v, %v", info, err)
	}
}

func TestControllerRejectsWrongPurposeCertificateBeforeLedgerCommit(t *testing.T) {
	fixture := newProtocolFixture(t)
	policy, private := postgresPolicyFixture(t)
	policy.ExpectedUID, policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
	csr, key := testPostgresCSR(t, pkix.Name{CommonName: policy.Postgres.CommonName}, policy.URI, nil)
	issuerBlock, _ := pem.Decode(fixture.ca)
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	oldLeafBlock, _ := pem.Decode(fixture.certificate)
	oldLeaf, err := x509.ParseCertificate(oldLeafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(policy.URI)
	wrongCN := &x509.Certificate{SerialNumber: oldLeaf.SerialNumber, Subject: pkix.Name{},
		NotBefore: fixture.notBefore, NotAfter: fixture.notAfter, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{uri}}
	wrongDER, err := x509.CreateCertificate(rand.Reader, wrongCN, issuer, &key.PublicKey, fixture.caKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongDER})
	authority := &fakeCertificateAuthority{fixture: fixture} // Correct key/URI/issuer, but ordinary empty Subject.
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(securePKIDirectory(t), "ledger.json"),
		Policies: []Policy{policy}, Authority: authority, ControllerKeyID: fixture.controllerID,
		ControllerKey: fixture.controllerPriv, Now: func() time.Time { return fixture.now },
		MaximumActive: 2, MaximumLedgerAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	request, err := NewIssueRequest(policy, "postgres-issue-1",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), fixture.now.Add(30*time.Second),
		10*time.Minute, csr, private)
	if err != nil {
		t.Fatal(err)
	}
	response, err := controller.Handle(context.Background(), request, policy.ExpectedUID, policy.ExpectedGID)
	if !errors.Is(err, ErrUnavailable) || response.Status != StatusUnavailable ||
		len(controller.ledger.Certificates) != 0 || len(authority.revokeCalls) != 1 ||
		authority.revokeCalls[0] != fixture.serial {
		t.Fatalf("wrong-purpose certificate accepted: response=%+v err=%v ledger=%+v revokes=%+v",
			response, err, controller.ledger.Certificates, authority.revokeCalls)
	}
}

func TestControllerRejectsPeerSubstitutionAndFailsClosedOnAuthorityLoss(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.policy.ExpectedUID, fixture.policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
	authority := &fakeCertificateAuthority{fixture: fixture, issueErr: ErrUnavailable}
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(securePKIDirectory(t), "ledger.json"), Policies: []Policy{fixture.policy}, Authority: authority,
		ControllerKeyID: fixture.controllerID, ControllerKey: fixture.controllerPriv, Now: func() time.Time { return fixture.now }, MaximumActive: 2, MaximumLedgerAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	request, err := NewIssueRequest(fixture.policy, "request-issue-1", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), fixture.now.Add(30*time.Second), 10*time.Minute, fixture.csr, fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := controller.Handle(context.Background(), request, fixture.policy.ExpectedUID+1, fixture.policy.ExpectedGID)
	if !errors.Is(err, ErrDenied) || denied.Status != StatusDenied || len(controller.ledger.Replays) != 0 {
		t.Fatalf("peer substitution = %#v, %v ledger=%#v", denied, err, controller.ledger)
	}
	unavailable, err := controller.Handle(context.Background(), request, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
	if !errors.Is(err, ErrUnavailable) || unavailable.Status != StatusUnavailable || len(controller.ledger.Replays) != 1 {
		t.Fatalf("authority loss = %#v, %v ledger=%#v", unavailable, err, controller.ledger)
	}
}

func TestUnixClientControllerRoundTripAndSocketCleanup(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.policy.ExpectedUID, fixture.policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
	directory := securePKIDirectory(t)
	authority := &fakeCertificateAuthority{fixture: fixture}
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(directory, "ledger.json"), Policies: []Policy{fixture.policy}, Authority: authority,
		ControllerKeyID: fixture.controllerID, ControllerKey: fixture.controllerPriv, Now: time.Now, MaximumActive: 2, MaximumLedgerAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	socket := filepath.Join(securePKIDirectory(t), "controller.sock")
	server, err := Listen(ServerConfig{SocketPath: socket, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()), InternalSelf: true,
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), MaxConnections: 2, ReapInterval: time.Second}, controller)
	if err != nil {
		t.Fatal(err)
	}
	serverContext, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(serverContext) }()
	client, err := NewProductionClient(ClientConfig{SocketPath: socket, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()),
		DirectoryGID: uint32(os.Getgid()), InternalSelf: true, Policy: fixture.policy,
		AgentPrivateKey: fixture.agentPrivate, ControllerKeyID: fixture.controllerID, ControllerPublic: fixture.controllerPub,
		OperationTimeout: 3 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	issued, err := client.Issue(context.Background(), fixture.csr, 10*time.Minute)
	if err != nil || issued.Serial != fixture.serial {
		t.Fatalf("Issue() = %#v, %v", issued, err)
	}
	defer issued.Destroy()
	snapshot, err := client.Revocations(context.Background())
	if err != nil || !bytes.Equal(snapshot.DER, fixture.crl) {
		t.Fatalf("Revocations() = %#v, %v", snapshot, err)
	}
	snapshot.Destroy()
	if err := client.Revoke(context.Background(), issued.Serial); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server exit = %v", err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket cleanup = %v", err)
	}
}

func securePKIDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sr-pki-")
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if os.Chmod(directory, 0o700) != nil || os.Chown(directory, os.Getuid(), os.Getgid()) != nil {
		t.Fatal("prepare secure PKI directory")
	}
	if !validLedgerPath(filepath.Join(directory, "ledger.json")) {
		info, _ := os.Lstat(directory)
		t.Fatalf("invalid secure PKI directory path=%q mode=%v uid=%d gid=%d", directory, info.Mode(), os.Getuid(), os.Getgid())
	}
	return directory
}

func TestClientRejectsWrongControllerKey(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.policy.ExpectedUID, fixture.policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
	directory := securePKIDirectory(t)
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(directory, "ledger.json"), Policies: []Policy{fixture.policy}, Authority: &fakeCertificateAuthority{fixture: fixture},
		ControllerKeyID: fixture.controllerID, ControllerKey: fixture.controllerPriv, Now: time.Now, MaximumActive: 2, MaximumLedgerAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	socket := filepath.Join(securePKIDirectory(t), "controller.sock")
	server, err := Listen(ServerConfig{SocketPath: socket, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		InternalSelf: true, ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()),
		MaxConnections: 1, ReapInterval: time.Second}, controller)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewProductionClient(ClientConfig{SocketPath: socket, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()),
		DirectoryGID: uint32(os.Getgid()), InternalSelf: true, Policy: fixture.policy,
		AgentPrivateKey: fixture.agentPrivate, ControllerKeyID: fixture.controllerID, ControllerPublic: wrongPublic, OperationTimeout: 3 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Issue(context.Background(), fixture.csr, 10*time.Minute); err == nil {
		t.Fatal("wrong controller signing key was accepted")
	}
	cancel()
	_ = <-done
}
