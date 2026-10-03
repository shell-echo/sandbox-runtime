package roleprocess

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func TestPrivateRoleShutdownNormalizesClosedListener(t *testing.T) {
	if err := normalizeRoleShutdownError(fmt.Errorf("listener: %w", net.ErrClosed)); err != nil {
		t.Fatalf("closed listener shutdown = %v", err)
	}
	original := errors.New("shutdown failed")
	if err := normalizeRoleShutdownError(original); !errors.Is(err, original) {
		t.Fatalf("shutdown error = %v, want original", err)
	}
}

func TestGuestRoleHasProbeOnlyComposition(t *testing.T) {
	directory := t.TempDir()
	value := config.GuestProcess
	copy := *value
	copy.Enabled = true
	copy.Role = config.DataPlaneGuest
	copy.OutboundURL = "wss://guest.example.test/agent"
	copy.Public.Port, copy.Private.Port = 0, 0
	copy.TLS.ClientCABundleFile = filepath.Join(directory, "ca.pem")
	copy.TLS.ClientCertificateFile = filepath.Join(directory, "guest.crt")
	copy.TLS.ClientPrivateKeyFile = filepath.Join(directory, "guest.key")
	copy.Authority.CredentialFile = filepath.Join(directory, "credential")
	copy.Authority.DependencyFile = filepath.Join(directory, "dependency")
	copy.Authority.PolicyFile = filepath.Join(directory, "policy")
	copy.Authority.RecordingKeyRef = "kms://recording/guest"
	composition, err := New(context.Background(), &copy)
	if err != nil {
		t.Fatal(err)
	}
	if composition.public != nil || composition.private != nil || composition.probe == nil {
		t.Fatal("guest role must have only a process probe")
	}
}

func TestRoleReadinessNeverAdvertisesUncomposedApplication(t *testing.T) {
	directory := t.TempDir()
	value := *config.GuestProcess
	value.Enabled = true
	value.Role = config.DataPlaneGuest
	value.OutboundURL = "wss://guest.example.test/agent"
	value.Public.Port, value.Private.Port = 0, 0
	value.TLS.ClientCABundleFile = filepath.Join(directory, "guest-ca.pem")
	value.TLS.ClientCertificateFile = filepath.Join(directory, "guest.crt")
	value.TLS.ClientPrivateKeyFile = filepath.Join(directory, "guest.key")
	value.Authority.CredentialFile = filepath.Join(directory, "credential")
	value.Authority.DependencyFile = filepath.Join(directory, "dependency")
	value.Authority.PolicyFile = filepath.Join(directory, "policy")
	value.Authority.RecordingKeyRef = "kms://recording/guest"
	for _, path := range []string{value.Authority.CredentialFile, value.Authority.DependencyFile, value.Authority.PolicyFile} {
		if err := os.WriteFile(path, []byte("authority"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkReadiness(context.Background(), &value); err == nil {
		t.Fatal("uncomposed role advertised readiness")
	}
}

func TestApplicationGraphRequiresExplicitGuestLifecycle(t *testing.T) {
	directory := t.TempDir()
	value := *config.GuestProcess
	value.Enabled = true
	value.Role = config.DataPlaneGuest
	value.OutboundURL = "wss://guest.example.test/agent"
	value.Public.Port, value.Private.Port = 0, 0
	value.TLS.ClientCABundleFile = filepath.Join(directory, "guest-ca.pem")
	value.TLS.ClientCertificateFile = filepath.Join(directory, "guest.crt")
	value.TLS.ClientPrivateKeyFile = filepath.Join(directory, "guest.key")
	value.Authority.CredentialFile = filepath.Join(directory, "credential")
	value.Authority.DependencyFile = filepath.Join(directory, "dependency")
	value.Authority.PolicyFile = filepath.Join(directory, "policy")
	value.Authority.RecordingKeyRef = "kms://recording/guest"
	for _, path := range []string{value.Authority.CredentialFile, value.Authority.DependencyFile, value.Authority.PolicyFile} {
		if err := os.WriteFile(path, []byte("authority"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := NewWithGraph(context.Background(), &value, ApplicationGraph{
		Ready: func(context.Context) error { return nil },
	})
	if err == nil {
		t.Fatal("Guest graph without outbound lifecycle was accepted")
	}
}

func TestApplicationGraphUsesExplicitReadiness(t *testing.T) {
	directory := t.TempDir()
	value := *config.GuestProcess
	value.Enabled = true
	value.Role = config.DataPlaneGuest
	value.OutboundURL = "wss://guest.example.test/agent"
	value.Public.Port, value.Private.Port = 0, 0
	value.TLS.ClientCABundleFile = filepath.Join(directory, "guest-ca.pem")
	value.TLS.ClientCertificateFile = filepath.Join(directory, "guest.crt")
	value.TLS.ClientPrivateKeyFile = filepath.Join(directory, "guest.key")
	value.Authority.CredentialFile = filepath.Join(directory, "credential")
	value.Authority.DependencyFile = filepath.Join(directory, "dependency")
	value.Authority.PolicyFile = filepath.Join(directory, "policy")
	value.Authority.RecordingKeyRef = "kms://recording/guest"
	for _, path := range []string{value.Authority.CredentialFile, value.Authority.DependencyFile, value.Authority.PolicyFile} {
		if err := os.WriteFile(path, []byte("authority"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	readyCalls := 0
	graph := ApplicationGraph{
		Ready: func(context.Context) error { readyCalls++; return nil },
		Start: func(context.Context) error { return nil },
	}
	composition, err := NewWithGraph(context.Background(), &value, graph)
	if err != nil {
		t.Fatal(err)
	}
	if composition.graph == nil {
		t.Fatal("explicit Guest lifecycle was not composed")
	}
	if err := checkReadiness(context.Background(), &value, graph); err != nil {
		t.Fatalf("explicit graph readiness = %v", err)
	}
	if readyCalls != 1 {
		t.Fatalf("readiness calls = %d; want 1", readyCalls)
	}
}

func TestGuestV3RecordingSentinelReachesButCannotBypassGraph(t *testing.T) {
	if _, err := secretref.Parse(config.GuestV3NoRecordingReference); err == nil {
		t.Fatal("old readiness parser would not reject the Guest sentinel")
	}
	directory := t.TempDir()
	value := *config.GuestProcess
	value.Enabled = true
	value.Role = config.DataPlaneGuest
	value.SchemaVersion = config.DataPlaneProductionSchemaV3
	value.DeploymentLevel = config.ProviderProductionLevel
	value.Authority.CredentialFile = filepath.Join(directory, "credential")
	value.Authority.DependencyFile = filepath.Join(directory, "dependency")
	value.Authority.PolicyFile = filepath.Join(directory, "policy")
	value.Authority.RecordingKeyRef = config.GuestV3NoRecordingReference
	for _, path := range []string{value.Authority.CredentialFile, value.Authority.DependencyFile, value.Authority.PolicyFile} {
		if err := os.WriteFile(path, []byte("authority"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	called := 0
	graph := ApplicationGraph{Ready: func(context.Context) error { called++; return nil }}
	if err := checkReadiness(context.Background(), &value, graph); err != nil || called != 1 {
		t.Fatalf("Guest v3 sentinel did not reach graph: err=%v calls=%d", err, called)
	}
	value.Authority.RecordingKeyRef = "kms://recording/phase6/guest"
	if err := checkReadiness(context.Background(), &value, graph); err == nil || called != 1 {
		t.Fatalf("fake Guest v3 key reached graph: err=%v calls=%d", err, called)
	}
	value.Authority.RecordingKeyRef = config.GuestV3NoRecordingReference
	graph.Ready = func(context.Context) error { called++; return errors.New("disconnected") }
	if err := checkReadiness(context.Background(), &value, graph); err == nil || called != 2 {
		t.Fatalf("graph failure advertised readiness: err=%v calls=%d", err, called)
	}
}

func TestShutdownOnlyGraphParticipatesInLifecycle(t *testing.T) {
	closed := false
	graph := graphServer{shutdown: func(context.Context) error { closed = true; return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- graph.Startup(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := graph.Shutdown(context.Background()); err != nil || !closed {
		t.Fatalf("shutdown-only graph cleanup: closed=%v err=%v", closed, err)
	}
}
