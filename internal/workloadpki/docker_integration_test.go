//go:build integration

package workloadpki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

const dockerPKIImage = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"

func TestDockerPKIFixtureIssuesStrictCertificate(t *testing.T) {
	policies, _, _ := dockerPKIPolicies(t)
	policy := policies[0]
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse(policy.URI)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{},
		DNSNames: policy.DNSNames, URIs: []*url.URL{identity}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	issued, err := newDockerPKIAuthority(t).Issue(context.Background(), policy, csr, 2*time.Minute)
	if err != nil || validateAuthorityIssue(issued, time.Now().UTC(), 2*time.Minute) != nil {
		t.Fatalf("fixture authority issue = %v, serial=%q not_before=%s not_after=%s", err, issued.Serial, issued.NotBefore, issued.NotAfter)
	}
	defer issued.Destroy()
	response := Response{CertificatePEM: issued.CertificatePEM, IssuingCAPEM: issued.IssuingCAPEM,
		CAChainPEM: issued.CAChainPEM, Serial: issued.Serial, NotBefore: issued.NotBefore.Format(time.RFC3339Nano),
		NotAfter: issued.NotAfter.Format(time.RFC3339Nano)}
	request := Request{CSRPEM: csr, RequestedTTLSeconds: 120}
	if err := validateIssuedCertificate(response, request, policy, time.Now().UTC()); err != nil {
		t.Fatalf("fixture certificate rejected: %v", err)
	}
}

func TestDockerDistinctUIDTwoAgentCertificateController(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_PKI_SOCKET_DOCKER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_PKI_SOCKET_DOCKER=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	arch, err := dockerPKI(ctx, nil, "version", "--format", "{{.Server.Arch}}")
	arch = strings.TrimSpace(arch)
	if err != nil || (arch != "arm64" && arch != "amd64") {
		t.Fatalf("Docker architecture %q unavailable: %v", arch, err)
	}
	if _, err := dockerPKI(ctx, nil, "image", "inspect", dockerPKIImage); err != nil {
		t.Fatalf("pinned Docker image unavailable: %v", err)
	}
	fixture := filepath.Join(t.TempDir(), "pki-two-agent-test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-tags=integration", "-o", fixture, ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build Linux PKI test fixture: %v: %.2048s", buildErr, output)
	}
	binary, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	volumeA, volumeB, ledgerVolume, binaryVolume := "p6-pki-a-"+suffix, "p6-pki-b-"+suffix,
		"p6-pki-ledger-"+suffix, "p6-pki-binary-"+suffix
	container := "p6-pki-controller-" + suffix
	volumes := []string{}
	created := false
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if created {
			_, _ = dockerPKI(cleanupCtx, nil, "rm", "-f", container)
			if _, err := dockerPKI(cleanupCtx, nil, "inspect", container); err == nil {
				t.Error("PKI controller container remained")
			}
		}
		for _, volume := range volumes {
			if _, err := dockerPKI(cleanupCtx, nil, "volume", "rm", volume); err != nil {
				t.Errorf("remove PKI volume %s: %v", volume, err)
			}
			if _, err := dockerPKI(cleanupCtx, nil, "volume", "inspect", volume); err == nil {
				t.Errorf("PKI volume %s remained", volume)
			}
		}
	})
	for _, volume := range []string{volumeA, volumeB, ledgerVolume, binaryVolume} {
		if _, err := dockerPKI(ctx, nil, "volume", "create", volume); err != nil {
			t.Fatal(err)
		}
		volumes = append(volumes, volume)
	}
	for _, item := range []struct{ volume, ownership string }{
		{volumeA, "62001:62012"}, {volumeB, "62001:62013"}, {ledgerVolume, "62001:62011"},
	} {
		mode := "0710"
		if item.volume == ledgerVolume {
			mode = "0700"
		}
		if _, err := dockerPKI(ctx, nil, "run", "--rm", "--network", "none", "-v", item.volume+":/work",
			dockerPKIImage, "sh", "-c", "chown "+item.ownership+" /work && chmod "+mode+" /work"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dockerPKI(ctx, binary, "run", "--rm", "-i", "--network", "none", "-v", binaryVolume+":/work",
		dockerPKIImage, "sh", "-c", "cat > /work/fixture && chmod 0755 /work/fixture"); err != nil {
		t.Fatal(err)
	}
	mountA := "type=volume,src=" + volumeA + ",dst=/run/agent-a"
	mountB := "type=volume,src=" + volumeB + ",dst=/run/agent-b"
	mountLedger := "type=volume,src=" + ledgerVolume + ",dst=/run/ledger"
	mountBinary := "type=volume,src=" + binaryVolume + ",dst=/probe,readonly"
	if _, err := dockerPKI(ctx, nil, "run", "-d", "--name", container, "--network", "none", "--user", "62001:62011",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", mountA, "--mount", mountB,
		"--mount", mountLedger, "--mount", mountBinary, "-e", "SANDBOX_RUNTIME_PKI_CHILD=controller",
		dockerPKIImage, "/probe/fixture", "-test.run", "^TestDockerChildPKIController$"); err != nil {
		t.Fatal(err)
	}
	created = true
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		logs, logErr := dockerPKI(ctx, nil, "logs", container)
		if logErr == nil && strings.Contains(logs, "PKI_CONTROLLER_READY") {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		logs, _ := dockerPKI(ctx, nil, "logs", container)
		t.Fatalf("two-agent controller did not become ready: %.2048s", logs)
	}
	client := func(user, kind, expected string) {
		t.Helper()
		mount := mountA
		if kind == "b" {
			mount = mountB
		}
		output, err := dockerPKI(ctx, nil, "run", "--rm", "--network", "none", "--user", user,
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", mount+",readonly",
			"--mount", mountBinary, "-e", "SANDBOX_RUNTIME_PKI_CHILD=client", "-e", "SANDBOX_RUNTIME_PKI_KIND="+kind,
			"-e", "SANDBOX_RUNTIME_PKI_EXPECT="+expected,
			dockerPKIImage, "/probe/fixture", "-test.run", "^TestDockerChildPKIClient$")
		if err != nil {
			logs, _ := dockerPKI(ctx, nil, "logs", container)
			t.Fatalf("PKI client %s/%s: %v: %.2048s; controller logs: %.2048s", user, kind, err, output, logs)
		}
	}
	client("62002:62012", "a", "allow")
	client("62003:62013", "b", "allow")
	client("62002:62012", "b", "deny")
	client("62003:62013", "a", "deny")
	client("62004:62014", "a", "deny")
	client("62002:62012", "wrong-key", "deny")
	client("62002:62012", "half", "deny")
	if _, err := dockerPKI(ctx, nil, "kill", "--signal=TERM", container); err != nil {
		t.Fatal(err)
	}
	exit, err := dockerPKI(ctx, nil, "wait", container)
	if err != nil || strings.TrimSpace(exit) != "0" {
		logs, _ := dockerPKI(ctx, nil, "logs", container)
		t.Fatalf("controller exit %q, %v: %.2048s", exit, err, logs)
	}
	client("62002:62012", "a", "deny")
	t.Log("two distinct-UID agents, exclusive controller sockets, CSR issuance/renewal/revocation, cross-agent and wrong-key denial, half-frame timeout, cancellation and exact cleanup")
}

func dockerPKI(ctx context.Context, input []byte, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func dockerPKIPolicies(t *testing.T) ([]Policy, [2]ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	registry, err := securityprincipal.NewRegistryWithPolicyAuthorities(digest, digest,
		map[string]securityprincipal.Role{"product_egress_broker": securityprincipal.RoleProduct}, nil)
	if err != nil {
		t.Fatal(err)
	}
	makePrincipal := func(kind securityprincipal.Kind, name string, role securityprincipal.Role) securityprincipal.Principal {
		principal, principalErr := registry.New(kind, name, role, digest)
		if principalErr != nil {
			t.Fatal(principalErr)
		}
		return principal
	}
	privateA := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	privateB := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	controllerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	policies := []Policy{
		{ID: "product-tls", Registry: registry,
			Requester:   makePrincipal(securityprincipal.KindTLSAgent, "product_tls_agent", securityprincipal.RoleProduct),
			Subject:     makePrincipal(securityprincipal.KindRuntimeRole, "product", securityprincipal.RoleProduct),
			TrustDomain: "sandbox-runtime.test", URI: "spiffe://sandbox-runtime.test/product", Usages: []string{"client_auth", "server_auth"},
			VaultRole: "product-tls", MaxTTLSeconds: 300, ExpectedUID: 62002, ExpectedGID: 62012,
			PublicKey: privateA.Public().(ed25519.PublicKey)},
		{ID: "broker-tls", Registry: registry,
			Requester:   makePrincipal(securityprincipal.KindTLSAgent, "product_egress_broker_tls_agent", securityprincipal.RoleProduct),
			Subject:     makePrincipal(securityprincipal.KindEgressBroker, "product_egress_broker", securityprincipal.RoleProduct),
			TrustDomain: "sandbox-runtime.test", URI: "spiffe://sandbox-runtime.test/product-egress-broker", Usages: []string{"client_auth", "server_auth"},
			VaultRole: "broker-tls", MaxTTLSeconds: 300, ExpectedUID: 62003, ExpectedGID: 62013,
			PublicKey: privateB.Public().(ed25519.PublicKey)},
	}
	for _, policy := range policies {
		if err := policy.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	return policies, [2]ed25519.PrivateKey{privateA, privateB}, controllerPrivate
}

func TestDockerChildPKIController(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PKI_CHILD") != "controller" {
		t.Skip("Docker child only")
	}
	policies, _, controllerPrivate := dockerPKIPolicies(t)
	authority := newDockerPKIAuthority(t)
	controller, err := NewController(ControllerConfig{LedgerPath: "/run/ledger/ledger.json", Policies: policies,
		Authority: authority, ControllerKeyID: "controller-response", ControllerKey: controllerPrivate,
		Now: time.Now, MaximumActive: 2, MaximumLedgerAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	servers := make([]*Server, 0, 2)
	for _, value := range []struct {
		path string
		uid  uint32
		gid  uint32
	}{
		{"/run/agent-a/request.sock", 62002, 62012},
		{"/run/agent-b/request.sock", 62003, 62013},
	} {
		server, listenErr := Listen(ServerConfig{SocketPath: value.path, SocketUID: uint32(os.Getuid()),
			SocketGID: value.gid, ExpectedClientUID: value.uid, ExpectedClientGID: value.gid,
			MaxConnections: 4, ReapInterval: time.Second}, controller)
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		servers = append(servers, server)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	var wait sync.WaitGroup
	results := make(chan error, len(servers))
	for _, server := range servers {
		wait.Add(1)
		go func(value *Server) {
			defer wait.Done()
			results <- value.Serve(ctx)
		}(server)
	}
	fmt.Fprintln(os.Stdout, "PKI_CONTROLLER_READY")
	<-ctx.Done()
	for _, server := range servers {
		_ = server.Close()
	}
	wait.Wait()
	for range servers {
		if err := <-results; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

func TestDockerChildPKIClient(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PKI_CHILD") != "client" {
		t.Skip("Docker child only")
	}
	kind := os.Getenv("SANDBOX_RUNTIME_PKI_KIND")
	if kind == "half" {
		connection, err := net.DialTimeout("unix", "/run/agent-a/request.sock", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if _, err := connection.Write([]byte{0, 0}); err != nil {
			t.Fatal(err)
		}
		_ = connection.SetReadDeadline(time.Now().Add(4 * time.Second))
		var data [1]byte
		if _, err := connection.Read(data[:]); !errors.Is(err, io.EOF) {
			t.Fatalf("half-frame peer not closed: %v", err)
		}
		return
	}
	policies, agentPrivate, controllerPrivate := dockerPKIPolicies(t)
	index, socketPath := 0, "/run/agent-a/request.sock"
	if kind == "b" {
		index, socketPath = 1, "/run/agent-b/request.sock"
	}
	policy := policies[index]
	controllerPublic := controllerPrivate.Public().(ed25519.PublicKey)
	if kind == "wrong-key" {
		controllerPublic = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	}
	stage := "client-construction"
	client, err := NewProductionClient(ClientConfig{SocketPath: socketPath, ExpectedUID: 62001, ExpectedGID: 62011,
		DirectoryGID: uint32(os.Getgid()), Policy: policy, AgentPrivateKey: agentPrivate[index],
		ControllerKeyID: "controller-response", ControllerPublic: controllerPublic,
		OperationTimeout: 5 * time.Second, Now: time.Now})
	if err == nil {
		defer client.Close()
		privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		identity, parseErr := url.Parse(policy.URI)
		if keyErr != nil || parseErr != nil {
			t.Fatal("CSR fixture failed")
		}
		csrDER, createErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{},
			DNSNames: policy.DNSNames, URIs: []*url.URL{identity}}, privateKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
		var first IssuedCertificate
		stage = "first-issue"
		first, err = client.Issue(context.Background(), csr, 2*time.Minute)
		if err == nil {
			var renewed IssuedCertificate
			stage = "renewal"
			renewed, err = client.Issue(context.Background(), csr, 2*time.Minute)
			if err == nil && renewed.Serial == first.Serial {
				err = ErrUnavailable
			}
			if err == nil {
				stage = "revoke"
				err = client.Revoke(context.Background(), first.Serial)
			}
			if err == nil {
				var snapshot RevocationSnapshot
				stage = "revocation-snapshot"
				snapshot, err = client.Revocations(context.Background())
				snapshot.Destroy()
			}
			renewed.Destroy()
		}
		first.Destroy()
	}
	switch os.Getenv("SANDBOX_RUNTIME_PKI_EXPECT") {
	case "allow":
		if err != nil {
			t.Fatalf("authorized agent denied at %s: %v", stage, err)
		}
	case "deny":
		if err == nil {
			t.Fatal("wrong peer, crossed endpoint or stopped controller accepted")
		}
	default:
		t.Fatal("missing expected result")
	}
}

type dockerPKIAuthority struct {
	mu         sync.Mutex
	ca         *x509.Certificate
	key        *ecdsa.PrivateKey
	caPEM      []byte
	nextSerial int64
	crlNumber  int64
	revoked    map[string]*big.Int
}

func newDockerPKIAuthority(t *testing.T) *dockerPKIAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Docker PKI fixture CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: bytes.Repeat([]byte{1}, 20)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &dockerPKIAuthority{ca: ca, key: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		nextSerial: 0x1000000000000000, crlNumber: 1, revoked: make(map[string]*big.Int)}
}

func (a *dockerPKIAuthority) Issue(ctx context.Context, policy Policy, csrPEM []byte, ttl time.Duration) (IssuedCertificate, error) {
	if err := ctx.Err(); err != nil {
		return IssuedCertificate{}, err
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return IssuedCertificate{}, ErrUnavailable
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return IssuedCertificate{}, ErrUnavailable
	}
	a.mu.Lock()
	serial := big.NewInt(a.nextSerial)
	a.nextSerial++
	a.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	uri, err := url.Parse(policy.URI)
	if err != nil {
		return IssuedCertificate{}, ErrUnavailable
	}
	usages := make([]x509.ExtKeyUsage, 0, len(policy.Usages))
	for _, usage := range policy.Usages {
		if usage == "client_auth" {
			usages = append(usages, x509.ExtKeyUsageClientAuth)
		} else {
			usages = append(usages, x509.ExtKeyUsageServerAuth)
		}
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{}, NotBefore: now.Add(-time.Second),
		NotAfter: now.Add(ttl), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		DNSNames: append([]string(nil), policy.DNSNames...), URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, template, a.ca, csr.PublicKey, a.key)
	if err != nil {
		return IssuedCertificate{}, ErrUnavailable
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return IssuedCertificate{IssuerRevision: "docker-pki-1", CertificatePEM: certificatePEM,
		IssuingCAPEM: append([]byte(nil), a.caPEM...), CAChainPEM: append([]byte(nil), a.caPEM...),
		Serial: serialString(serial.Bytes()), NotBefore: template.NotBefore, NotAfter: template.NotAfter}, nil
}

func (a *dockerPKIAuthority) Revocations(ctx context.Context) (RevocationSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return RevocationSnapshot{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	entries := make([]x509.RevocationListEntry, 0, len(a.revoked))
	for _, serial := range a.revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: now.Add(-time.Second)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(a.crlNumber),
		ThisUpdate: now.Add(-time.Second), NextUpdate: now.Add(time.Minute), RevokedCertificateEntries: entries}, a.ca, a.key)
	if err != nil {
		return RevocationSnapshot{}, ErrUnavailable
	}
	a.crlNumber++
	return RevocationSnapshot{IssuerRevision: "docker-pki-1", DER: der,
		ThisUpdate: now.Add(-time.Second), NextUpdate: now.Add(time.Minute)}, nil
}

func (a *dockerPKIAuthority) Revoke(ctx context.Context, serial string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(serial, ":", ""))
	if err != nil || len(decoded) == 0 {
		return ErrUnavailable
	}
	a.mu.Lock()
	a.revoked[serial] = new(big.Int).SetBytes(decoded)
	a.mu.Unlock()
	return nil
}
