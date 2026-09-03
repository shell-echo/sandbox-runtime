// Package image validates the internal browser runtime image authority. It is
// not a Provider wire package and does not advertise the browser capability.
package image

import (
	"bytes"
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
	ManifestPath     = "manifest.json"
	DockerfilePath   = "Dockerfile"
	EntrypointPath   = "entrypoint.sh"
	SchemaVersion    = "sandbox.runtime/browser-image/v1"
	ProfileID        = "sandbox-runtime-browser-v1"
	RuntimeClassName = "sandbox-runtime-browser"
	SourceRepository = "docker.io/chromedp/headless-shell"
	BrowserBinary    = "/headless-shell/headless-shell"
	BrowserVersion   = "Chromium 151.0.7922.109"
	EndpointAddress  = "127.0.0.1"
	EndpointPort     = 9222
	MaxManifestBytes = 64 << 10
	RequiredUID      = 1000
	RequiredGID      = 1000
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
	Arguments           []string `json:"arguments"`
	UserArguments       string   `json:"user_arguments"`
	DevelopmentOverride string   `json:"development_override"`
}

type Security struct {
	UID                        int    `json:"uid"`
	GID                        int    `json:"gid"`
	RootFilesystem             string `json:"root_filesystem"`
	NoNewPrivileges            bool   `json:"no_new_privileges"`
	Capabilities               string `json:"capabilities"`
	BrowserSandbox             string `json:"browser_sandbox"`
	ContainerIsolationRequired bool   `json:"container_isolation_required"`
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
	wantArgs := []string{"--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=9222"}
	if len(m.Launch.Arguments) != len(wantArgs) || strings.Join(m.Launch.Arguments, "\x00") != strings.Join(wantArgs, "\x00") || m.Launch.UserArguments != "rejected" || m.Launch.DevelopmentOverride != "BROWSER_RUNTIME_ALLOW_UNSANDBOXED=1" {
		return fmt.Errorf("%w: launch policy is invalid", ErrInvalidManifest)
	}
	if m.Security.UID != RequiredUID || m.Security.GID != RequiredGID || m.Security.RootFilesystem != "read_only" || !m.Security.NoNewPrivileges || m.Security.Capabilities != "drop_all" || m.Security.BrowserSandbox != "disabled" || !m.Security.ContainerIsolationRequired {
		return fmt.Errorf("%w: security policy is invalid", ErrInvalidManifest)
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
