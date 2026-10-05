package dockercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"
)

var ErrInvalidCodingDaemon = errors.New("invalid private Coding Docker daemon observation")

// CodingDaemonObservation discloses only domain-separated digests and the
// normalized supported platform. It does not expose Docker's raw daemon ID,
// root path or full Info response, and is not authentication or a quiescence
// proof by itself. The real Control service must separately bind its one
// frozen client/endpoint transport and authenticated deployment scope.
type CodingDaemonObservation struct {
	IdentityDigest    string
	EnvironmentDigest string
	Platform          string
}

type codingInfoReader interface {
	Info(context.Context, client.InfoOptions) (client.SystemInfoResult, error)
}

// ObserveCodingDaemon reads only the necessary Info fields through one
// caller-owned frozen Docker client. endpointScopeDigest must be derived from
// the operator's existing authenticated endpoint/deployment configuration;
// passing a fixture digest establishes component behavior only.
func ObserveCodingDaemon(ctx context.Context, api codingInfoReader,
	endpointScopeDigest string) (CodingDaemonObservation, error) {
	if ctx == nil || ctx.Err() != nil || api == nil || !controlDigest.MatchString(endpointScopeDigest) {
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	result, err := api.Info(ctx, client.InfoOptions{})
	if err != nil || ctx.Err() != nil {
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	return projectCodingDaemonInfo(result.Info, endpointScopeDigest)
}

func projectCodingDaemonInfo(info system.Info, endpointScopeDigest string) (CodingDaemonObservation, error) {
	if !controlDigest.MatchString(endpointScopeDigest) || !validOpaqueDaemonField(info.ID, 512) ||
		info.OSType != "linux" || !validOpaqueDaemonField(info.ServerVersion, 128) ||
		!validCodingRootDir(info.DockerRootDir) {
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	platform := ""
	switch info.Architecture {
	case "aarch64":
		platform = "linux/arm64/v8"
	case "x86_64":
		platform = "linux/amd64"
	default:
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	identity, err := json.Marshal(struct {
		ID                  string `json:"id"`
		EndpointScopeDigest string `json:"endpoint_scope_digest"`
	}{info.ID, endpointScopeDigest})
	if err != nil {
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	rootDigest := digest(append([]byte("sandbox-runtime/docker-control-coding-root-dir/v1\x00"), []byte(info.DockerRootDir)...))
	environment, err := json.Marshal(struct {
		OSType        string `json:"os_type"`
		Platform      string `json:"platform"`
		RootDirDigest string `json:"root_dir_digest"`
		Version       string `json:"server_version"`
	}{info.OSType, platform, rootDigest, info.ServerVersion})
	if err != nil {
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	return CodingDaemonObservation{
		IdentityDigest:    digest(append([]byte("sandbox-runtime/docker-control-coding-daemon-identity/v1\x00"), identity...)),
		EnvironmentDigest: digest(append([]byte("sandbox-runtime/docker-control-coding-daemon-environment/v1\x00"), environment...)),
		Platform:          platform,
	}, nil
}

func validOpaqueDaemonField(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validCodingRootDir(root string) bool {
	return validOpaqueDaemonField(root, 4096) && path.IsAbs(root) && path.Clean(root) == root
}

func (o CodingDaemonObservation) MatchBinding(binding CodingReceiptBinding) error {
	if binding.Validate() != nil || o.IdentityDigest != binding.DaemonDigest ||
		o.EnvironmentDigest != binding.DaemonEnvironmentDigest ||
		o.Platform != binding.RuntimePlatform {
		return ErrInvalidCodingDaemon
	}
	return nil
}

// ObserveCodingDaemonAround brackets one read-only inventory using the same
// client. A changed identity/environment, a failed Info call, cancellation or
// inventory error cannot be converted into an absence observation. It never
// authorizes a mutation or release; daemon-side late effects need a separate
// external quiescence/fence proof.
func ObserveCodingDaemonAround(ctx context.Context, api codingInfoReader,
	binding CodingReceiptBinding, inventory func(context.Context) error) (CodingDaemonObservation, error) {
	if ctx == nil || ctx.Err() != nil || api == nil || inventory == nil {
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	before, err := ObserveCodingDaemon(ctx, api, binding.EndpointScopeDigest)
	if err != nil || before.MatchBinding(binding) != nil {
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	if err := inventory(ctx); err != nil || ctx.Err() != nil {
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	after, err := ObserveCodingDaemon(ctx, api, binding.EndpointScopeDigest)
	if err != nil || after != before || after.MatchBinding(binding) != nil {
		return CodingDaemonObservation{}, ErrInvalidCodingDaemon
	}
	return after, nil
}
