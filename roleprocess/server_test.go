package roleprocess

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/config"
)

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
