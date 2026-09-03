// Package image validates the internal browser runtime image authority. It is
// not a Provider wire package and does not advertise the browser capability.
package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

const (
	ManifestPath            = "manifest.json"
	DockerfilePath          = "Dockerfile"
	EntrypointPath          = "entrypoint.sh"
	PublicationWorkflowPath = "../../../.github/workflows/browser-image.yml"
	SchemaVersion           = "sandbox.runtime/browser-image/v2"
	ProfileID               = "sandbox-runtime-browser-v1"
	RuntimeClassName        = "sandbox-runtime-browser"
	SourceRepository        = "docker.io/chromedp/headless-shell"
	BrowserBinary           = "/headless-shell/headless-shell"
	BrowserVersion          = "Chromium 151.0.7922.109"
	EndpointAddress         = "127.0.0.1"
	EndpointPort            = 9222
	SeccompPath             = "profiles/browser/image/chromium-seccomp.json"
	SeccompDigest           = "sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b"
	SeccompSource           = "https://github.com/microsoft/playwright/blob/ae935a43d9e376e4759548f6b3c6905c7b282333/utils/docker/seccomp_profile.json"
	MaxManifestBytes        = 64 << 10
	MaxSeccompBytes         = 64 << 10
	RequiredUID             = 1000
	RequiredGID             = 1000
)

var (
	ErrInvalidManifest = errors.New("invalid browser image manifest")
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Manifest struct {
	SchemaVersion    string     `json:"schema_version"`
	ProfileID        string     `json:"profile_id"`
	RuntimeClassName string     `json:"runtime_class_name"`
	Source           Source     `json:"source"`
	Browser          Browser    `json:"browser"`
	Launch           Launch     `json:"launch"`
	Security         Security   `json:"security"`
	Mounts           []Mount    `json:"mounts"`
	Network          Network    `json:"network"`
	Provenance       Provenance `json:"provenance"`
}

type Source struct {
	Repository  string              `json:"repository"`
	Tag         string              `json:"tag"`
	IndexDigest string              `json:"index_digest"`
	Manifests   map[string]Platform `json:"manifests"`
}

type Platform struct {
	Digest       string `json:"digest"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

type Browser struct {
	Binary   string   `json:"binary"`
	Version  string   `json:"version"`
	Protocol string   `json:"protocol"`
	Endpoint Endpoint `json:"endpoint"`
}

type Endpoint struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Public  bool   `json:"public"`
}

type Launch struct {
	Arguments       []string `json:"arguments"`
	UserArguments   string   `json:"user_arguments"`
	SandboxRequired bool     `json:"sandbox_required"`
}

type Security struct {
	UID                        int            `json:"uid"`
	GID                        int            `json:"gid"`
	RootFilesystem             string         `json:"root_filesystem"`
	NoNewPrivileges            bool           `json:"no_new_privileges"`
	Capabilities               string         `json:"capabilities"`
	BrowserSandbox             string         `json:"browser_sandbox"`
	UserNamespacesRequired     bool           `json:"user_namespaces_required"`
	SeccompProfile             SeccompProfile `json:"seccomp_profile"`
	ContainerIsolationRequired bool           `json:"container_isolation_required"`
}

type SeccompProfile struct {
	Path                   string   `json:"path"`
	Digest                 string   `json:"digest"`
	DerivedFrom            string   `json:"derived_from"`
	AllowedSandboxSyscalls []string `json:"allowed_sandbox_syscalls"`
}

type Mount struct {
	Path     string `json:"path"`
	Mode     string `json:"mode"`
	Required bool   `json:"required"`
}

type Network struct {
	Mode                  string `json:"mode"`
	EgressGatewayRequired bool   `json:"egress_gateway_required"`
	EndpointLoopbackOnly  bool   `json:"endpoint_loopback_only"`
}

type Provenance struct {
	UpstreamSource                         string `json:"upstream_source"`
	UpstreamIndexDigest                    string `json:"upstream_index_digest"`
	BuildContext                           string `json:"build_context"`
	ReproducibleInputs                     bool   `json:"reproducible_inputs"`
	AttestationRequiredBeforeAdvertisement bool   `json:"attestation_required_before_advertisement"`
}

func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Manifest{}, fmt.Errorf("read browser image manifest: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (Manifest, error) {
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: document size is invalid", ErrInvalidManifest)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w: decode: %v", ErrInvalidManifest, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return Manifest{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidManifest)
	} else if !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("%w: trailing input: %v", ErrInvalidManifest, err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion || m.ProfileID != ProfileID || m.RuntimeClassName != RuntimeClassName {
		return fmt.Errorf("%w: schema/profile/runtime class identity is invalid", ErrInvalidManifest)
	}
	if err := validatePinnedImage(m.Source.Repository, m.Source.IndexDigest); err != nil {
		return fmt.Errorf("%w: source: %v", ErrInvalidManifest, err)
	}
	if m.Source.Tag != "latest" || len(m.Source.Manifests) != 2 {
		return fmt.Errorf("%w: source tag or platform matrix is invalid", ErrInvalidManifest)
	}
	for platform, want := range map[string]struct {
		architecture string
		variant      string
	}{"linux/amd64": {architecture: "amd64"}, "linux/arm64/v8": {architecture: "arm64", variant: "v8"}} {
		got, ok := m.Source.Manifests[platform]
		if !ok || got.Architecture != want.architecture || got.Variant != want.variant || !digestPattern.MatchString(got.Digest) {
			return fmt.Errorf("%w: platform manifest %q is invalid", ErrInvalidManifest, platform)
		}
	}
	if m.Browser.Binary != BrowserBinary || m.Browser.Version != BrowserVersion || m.Browser.Protocol != "cdp" {
		return fmt.Errorf("%w: browser binary authority is invalid", ErrInvalidManifest)
	}
	if m.Browser.Endpoint != (Endpoint{Address: EndpointAddress, Port: EndpointPort, Public: false}) {
		return fmt.Errorf("%w: browser endpoint must be private loopback", ErrInvalidManifest)
	}
	wantArgs := []string{"--headless", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check", "--user-data-dir=/tmp/browser-cache/profile", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=9222"}
	if len(m.Launch.Arguments) != len(wantArgs) || strings.Join(m.Launch.Arguments, "\x00") != strings.Join(wantArgs, "\x00") || m.Launch.UserArguments != "rejected" || !m.Launch.SandboxRequired {
		return fmt.Errorf("%w: launch policy is invalid", ErrInvalidManifest)
	}
	if m.Security.UID != RequiredUID || m.Security.GID != RequiredGID || m.Security.RootFilesystem != "read_only" || !m.Security.NoNewPrivileges || m.Security.Capabilities != "drop_all" || m.Security.BrowserSandbox != "user_namespace" || !m.Security.UserNamespacesRequired || !m.Security.ContainerIsolationRequired {
		return fmt.Errorf("%w: security policy is invalid", ErrInvalidManifest)
	}
	if m.Security.SeccompProfile.Path != SeccompPath || m.Security.SeccompProfile.Digest != SeccompDigest || m.Security.SeccompProfile.DerivedFrom != SeccompSource || strings.Join(m.Security.SeccompProfile.AllowedSandboxSyscalls, "\x00") != "chroot\x00clone\x00setns\x00unshare" {
		return fmt.Errorf("%w: seccomp profile authority is invalid", ErrInvalidManifest)
	}
	if len(m.Mounts) != 2 || m.Mounts[0] != (Mount{Path: "/workspace", Mode: "rw", Required: true}) || m.Mounts[1] != (Mount{Path: "/tmp", Mode: "rw", Required: true}) {
		return fmt.Errorf("%w: stable mounts are invalid", ErrInvalidManifest)
	}
	if m.Network != (Network{Mode: "restricted", EgressGatewayRequired: true, EndpointLoopbackOnly: true}) {
		return fmt.Errorf("%w: network policy is invalid", ErrInvalidManifest)
	}
	if m.Provenance.UpstreamSource == "" || m.Provenance.BuildContext != "profiles/browser/image" || !m.Provenance.ReproducibleInputs || !m.Provenance.AttestationRequiredBeforeAdvertisement || m.Provenance.UpstreamIndexDigest != m.Source.IndexDigest || !strings.HasPrefix(m.Provenance.UpstreamSource, "https://") {
		return fmt.Errorf("%w: provenance is incomplete", ErrInvalidManifest)
	}
	return nil
}

func VerifySeccompProfile(path string, expectedDigest string) error {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("read browser seccomp profile: %w", err)
	}
	if len(data) == 0 || len(data) > MaxSeccompBytes {
		return fmt.Errorf("%w: seccomp profile size is invalid", ErrInvalidManifest)
	}
	var profile struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("%w: seccomp profile decode: %v", ErrInvalidManifest, err)
	}
	if profile.DefaultAction != "SCMP_ACT_ERRNO" || len(profile.Syscalls) == 0 || profile.Syscalls[0].Action != "SCMP_ACT_ALLOW" || strings.Join(profile.Syscalls[0].Names, "\x00") != "chroot\x00clone\x00setns\x00unshare" {
		return fmt.Errorf("%w: seccomp sandbox rule is invalid", ErrInvalidManifest)
	}
	sum := sha256.Sum256(data)
	if actual := fmt.Sprintf("sha256:%x", sum); actual != expectedDigest {
		return fmt.Errorf("%w: seccomp profile digest %s does not match %s", ErrInvalidManifest, actual, expectedDigest)
	}
	return nil
}

func validatePinnedImage(repositoryName, imageDigest string) error {
	named, err := reference.ParseNormalizedNamed(repositoryName + "@" + imageDigest)
	if err != nil {
		return errors.New("source repository or digest is invalid")
	}
	digested, ok := named.(reference.Digested)
	if !ok || digested.Digest().Algorithm() != digest.SHA256 || digested.Digest().Validate() != nil {
		return errors.New("source must be pinned by sha256")
	}
	if repositoryName != SourceRepository || !digestPattern.MatchString(imageDigest) {
		return errors.New("source repository or digest is not allowed")
	}
	return nil
}
