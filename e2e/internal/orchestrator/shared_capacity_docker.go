package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type sharedValkey struct {
	containerID string
	name        string
	redisURL    string
	imageID     string
	platform    string
}

func dockerServerPlatform(ctx context.Context) (string, error) {
	value, err := runDockerCommand(ctx, "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}")
	if err != nil {
		return "", fmt.Errorf("inspect Docker server platform: %w", err)
	}
	platform := strings.TrimSpace(value)
	switch platform {
	case "linux/amd64", "linux/arm64":
		return platform, nil
	default:
		return "", fmt.Errorf("shared-capacity Docker platform %q is unsupported", platform)
	}
}

func startSharedValkey(
	ctx context.Context,
	runRoot string,
	image string,
	platform string,
	expectedChildDigest string,
	serverConfig string,
	aclConfig string,
	username string,
	password string,
) (*sharedValkey, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("shared-capacity process signals are unsupported on Windows")
	}
	pullPlatform := platform
	if platform == "linux/arm64" {
		pullPlatform = "linux/arm64/v8"
	}
	if err := verifyLockedValkeyIndex(ctx, image, platform, expectedChildDigest); err != nil {
		return nil, err
	}
	if _, err := runDockerCommand(ctx, "pull", "--platform", pullPlatform, image); err != nil {
		return nil, fmt.Errorf("pull locked Valkey image: %w", err)
	}
	inspection, err := runDockerCommand(ctx, "image", "inspect", image, "--format", "{{.Id}}|{{.Os}}/{{.Architecture}}")
	if err != nil {
		return nil, fmt.Errorf("inspect locked Valkey image: %w", err)
	}
	parts := strings.Split(strings.TrimSpace(inspection), "|")
	if len(parts) != 2 || parts[1] != platform || !strings.HasPrefix(parts[0], "sha256:") {
		return nil, fmt.Errorf("locked Valkey image inspection is invalid for %s", platform)
	}

	configRoot := filepath.Join(runRoot, "valkey")
	if err := os.MkdirAll(configRoot, 0o700); err != nil {
		return nil, err
	}
	serverPath := filepath.Join(configRoot, "valkey.conf")
	aclPath := filepath.Join(configRoot, "users.acl")
	if err := os.WriteFile(serverPath, []byte(serverConfig), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(aclPath, []byte(aclConfig), 0o600); err != nil {
		return nil, err
	}
	token, err := randomSecret("")
	if err != nil {
		return nil, err
	}
	name := "sandbox-runtime-shared-capacity-e2e-" + token[:16]
	mountServer := "type=bind,src=" + serverPath + ",dst=/etc/valkey/valkey.conf,readonly"
	mountACL := "type=bind,src=" + aclPath + ",dst=/etc/valkey/users.acl,readonly"
	containerUser := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	containerID, err := runDockerCommand(ctx,
		"run", "--detach", "--name", name,
		"--user", containerUser,
		"--label", "io.github.shell-echo.sandbox-runtime.managed=true",
		"--label", "io.github.shell-echo.sandbox-runtime.owner=shared-capacity-e2e",
		"--publish", "127.0.0.1::6379",
		"--mount", mountServer, "--mount", mountACL,
		image, "valkey-server", "/etc/valkey/valkey.conf", "--aclfile", "/etc/valkey/users.acl",
	)
	if err != nil {
		return nil, fmt.Errorf("start locked Valkey container: %w", err)
	}
	cleanupFailure := func(cause error) (*sharedValkey, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, cleanupErr := runDockerCommand(cleanupCtx, "rm", "--force", name)
		return nil, errors.Join(cause, cleanupErr)
	}
	portOutput, err := runDockerCommand(ctx, "port", name, "6379/tcp")
	if err != nil {
		return cleanupFailure(fmt.Errorf("inspect locked Valkey port: %w", err))
	}
	address := strings.TrimSpace(portOutput)
	if host, port, splitErr := net.SplitHostPort(address); splitErr != nil || host != "127.0.0.1" || port == "" {
		return cleanupFailure(errors.New("locked Valkey port is not bound to IPv4 loopback"))
	}
	return &sharedValkey{
		containerID: strings.TrimSpace(containerID), name: name,
		redisURL: "redis://" + username + ":" + password + "@" + address + "/0",
		imageID:  parts[0], platform: platform,
	}, nil
}

func verifyLockedValkeyIndex(ctx context.Context, image, platform, expectedChildDigest string) error {
	content, err := runDockerCommand(ctx, "buildx", "imagetools", "inspect", "--raw", image)
	if err != nil {
		return fmt.Errorf("inspect locked Valkey index: %w", err)
	}
	var index struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Manifests     []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
			Platform  struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant,omitempty"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil || index.SchemaVersion != 2 || index.MediaType != "application/vnd.oci.image.index.v1+json" {
		return errors.New("locked Valkey index document is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("locked Valkey index has trailing content")
	}
	wantOS, wantArchitecture, ok := strings.Cut(platform, "/")
	if !ok {
		return errors.New("locked Valkey platform is invalid")
	}
	matches := 0
	for _, manifest := range index.Manifests {
		if manifest.Platform.OS == wantOS && manifest.Platform.Architecture == wantArchitecture && manifest.Platform.Variant == "" {
			if manifest.MediaType != "application/vnd.oci.image.manifest.v1+json" || manifest.Digest != expectedChildDigest || manifest.Size <= 0 {
				return errors.New("locked Valkey platform manifest differs from the evidence lock")
			}
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("locked Valkey index has %d exact %s manifests, want 1", matches, platform)
	}
	return nil
}

func (v *sharedValkey) pause(ctx context.Context) error {
	if v == nil || v.name == "" {
		return errors.New("shared-capacity Valkey is unavailable")
	}
	_, err := runDockerCommand(ctx, "pause", v.name)
	return err
}

func (v *sharedValkey) unpause(ctx context.Context) error {
	if v == nil || v.name == "" {
		return errors.New("shared-capacity Valkey is unavailable")
	}
	_, err := runDockerCommand(ctx, "unpause", v.name)
	return err
}

func (v *sharedValkey) close(ctx context.Context) error {
	if v == nil || v.name == "" {
		return nil
	}
	_, err := runDockerCommand(ctx, "rm", "--force", v.name)
	if err != nil && !strings.Contains(err.Error(), "No such container") {
		return err
	}
	v.name = ""
	return nil
}
