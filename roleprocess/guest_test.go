package roleprocess

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
)

func TestReadAuthorityRejectsUnknownTrailingAndUnsafeFiles(t *testing.T) {
	type document struct {
		Version int `json:"version"`
	}
	tests := []struct {
		name    string
		content string
		mode    os.FileMode
		link    bool
		wantErr string
	}{
		{name: "unknown field", content: `{"version":1,"extra":true}`, mode: 0o600, wantErr: "invalid"},
		{name: "trailing document", content: `{"version":1} {"version":2}`, mode: 0o600, wantErr: "trailing"},
		{name: "broad permissions", content: `{"version":1}`, mode: 0o644, wantErr: "private"},
		{name: "symlink", content: `{"version":1}`, mode: 0o600, link: true, wantErr: "private"},
		{name: "oversized", content: strings.Repeat("x", maxGuestAuthoritySize+1), mode: 0o600, wantErr: "private"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "authority")
			target := path
			if test.link {
				target = filepath.Join(directory, "target")
			}
			if err := os.WriteFile(target, []byte(test.content), test.mode); err != nil {
				t.Fatal(err)
			}
			if test.link {
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			var value document
			err := readAuthority(path, &value)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("readAuthority error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestLoadGuestAuthorityRejectsIdentityAndPolicyMismatches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*GuestCredentialAuthority, *GuestDependencyAuthority, *GuestPolicyAuthority)
	}{
		{name: "credential role", mutate: func(c *GuestCredentialAuthority, _ *GuestDependencyAuthority, _ *GuestPolicyAuthority) {
			c.Role = string(config.DataPlaneGateway)
		}},
		{name: "credential version", mutate: func(c *GuestCredentialAuthority, _ *GuestDependencyAuthority, _ *GuestPolicyAuthority) { c.Version++ }},
		{name: "missing guest id", mutate: func(c *GuestCredentialAuthority, _ *GuestDependencyAuthority, _ *GuestPolicyAuthority) {
			c.GuestID = ""
		}},
		{name: "dependency collision", mutate: func(_ *GuestCredentialAuthority, d *GuestDependencyAuthority, _ *GuestPolicyAuthority) {
			d.StateRoot = d.WorkspaceRoot
		}},
		{name: "policy backoff", mutate: func(_ *GuestCredentialAuthority, _ *GuestDependencyAuthority, p *GuestPolicyAuthority) {
			p.ReconnectBackoffMillis = 9
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := guestAuthorityFixture(t)
			test.mutate(&fixture.credential, &fixture.dependency, &fixture.policy)
			fixture.writeAuthorities(t)
			if _, err := LoadGuestAuthority(fixture.cfg); err == nil {
				t.Fatal("invalid Guest authority was accepted")
			}
		})
	}
}

func TestLoadGuestAuthorityRejectsMalformedPrivateKeyAndTLS(t *testing.T) {
	fixture := guestAuthorityFixture(t)
	fixture.writeAuthorities(t)
	if err := os.WriteFile(fixture.credential.PrivateKeyFile, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGuestAuthority(fixture.cfg); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("private key error = %v", err)
	}

	if err := os.WriteFile(fixture.credential.PrivateKeyFile, make([]byte, ed25519.PrivateKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.cfg.TLS.ClientCABundleFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGuestAuthority(fixture.cfg); err == nil || !strings.Contains(err.Error(), "trust bundle") {
		t.Fatalf("TLS trust error = %v", err)
	}
}

func TestGuestHTTPClientRequiresTLS13AndClientIdentity(t *testing.T) {
	fixture := guestAuthorityFixture(t)
	writeGuestClientTLS(t, fixture.cfg)
	fixture.writeAuthorities(t)
	authority, err := LoadGuestAuthority(fixture.cfg)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := authority.HTTPClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("Guest HTTP client did not configure TLS")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS minimum version = %d, want TLS 1.3", transport.TLSClientConfig.MinVersion)
	}
	if len(transport.TLSClientConfig.Certificates) != 1 || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("Guest HTTP client did not configure mTLS identity and trust")
	}
	clear(authority.PrivateKey)
}

type guestAuthorityFixtureState struct {
	cfg        *config.DataPlaneProcessConfig
	credential GuestCredentialAuthority
	dependency GuestDependencyAuthority
	policy     GuestPolicyAuthority
}

func guestAuthorityFixture(t *testing.T) guestAuthorityFixtureState {
	t.Helper()
	directory := t.TempDir()
	workspace := filepath.Join(directory, "workspace")
	state := filepath.Join(directory, "state")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := *config.GuestProcess
	cfg.Enabled = true
	cfg.Role = config.DataPlaneGuest
	cfg.OutboundURL = "wss://guest.example.test/agent"
	cfg.Public.Port, cfg.Private.Port = 0, 0
	cfg.TLS.ClientCABundleFile = filepath.Join(directory, "ca.pem")
	cfg.TLS.ClientCertificateFile = filepath.Join(directory, "client.crt")
	cfg.TLS.ClientPrivateKeyFile = filepath.Join(directory, "client.key")
	cfg.Authority.CredentialFile = filepath.Join(directory, "credential.json")
	cfg.Authority.DependencyFile = filepath.Join(directory, "dependency.json")
	cfg.Authority.PolicyFile = filepath.Join(directory, "policy.json")
	cfg.Authority.RecordingKeyRef = "kms://recording/guest"
	return guestAuthorityFixtureState{
		cfg:        &cfg,
		credential: GuestCredentialAuthority{Version: guestAuthorityVersion, Role: string(config.DataPlaneGuest), GuestID: "guest-1", BindingGeneration: 1, PrivateKeyFile: filepath.Join(directory, "guest.key")},
		dependency: GuestDependencyAuthority{Version: guestAuthorityVersion, Role: string(config.DataPlaneGuest), WorkspaceRoot: workspace, StateRoot: state, Mounts: []guestdevelopment.Mount{{Path: "/inputs", Mode: "ro"}, {Path: "/workspace", Mode: "rw"}, {Path: "/outputs", Mode: "rw"}, {Path: "/tmp", Mode: "rw"}}, Toolchains: []guestdevelopment.Toolchain{{ID: "posix-shell", Version: "test-1", Digest: testDigest("toolchain"), Executable: "/bin/sh"}}},
		policy:     GuestPolicyAuthority{Version: guestAuthorityVersion, Role: string(config.DataPlaneGuest), ReconnectBackoffMillis: 100},
	}
}

func (f guestAuthorityFixtureState) writeAuthorities(t *testing.T) {
	t.Helper()
	writeJSON0600(t, f.cfg.Authority.CredentialFile, f.credential)
	writeJSON0600(t, f.cfg.Authority.DependencyFile, f.dependency)
	writeJSON0600(t, f.cfg.Authority.PolicyFile, f.policy)
	if _, err := os.Stat(f.credential.PrivateKeyFile); os.IsNotExist(err) {
		if err := os.WriteFile(f.credential.PrivateKeyFile, make([]byte, ed25519.PrivateKeySize), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func writeJSON0600(t *testing.T, path string, value any) {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeGuestClientTLS(t *testing.T, cfg *config.DataPlaneProcessConfig) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, Subject: pkix.Name{CommonName: "guest-test-ca"}}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature, Subject: pkix.Name{CommonName: "guest-test"}}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCertificate, clientPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	writePrivate := func(path string, document []byte) {
		t.Helper()
		if err := os.WriteFile(path, document, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writePrivate(cfg.TLS.ClientCABundleFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	writePrivate(cfg.TLS.ClientCertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
	writePrivate(cfg.TLS.ClientPrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func testDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + fmt.Sprintf("%x", digest[:])
}
