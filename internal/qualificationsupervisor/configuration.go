package qualificationsupervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"runtime"

	"github.com/gowebpki/jcs"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

var ErrConfiguration = errors.New("adapter configuration preflight failed")

// LocationConfiguration is static operator input, not an invocation or wire
// DTO. Do not populate it from secrets, generated correlations or caller state.
// The upstream origin of these strings remains a trusted operator assertion.
type LocationConfiguration struct {
	ProfilePath          string `json:"profile_path"`
	ProviderOrigin       string `json:"provider_origin"`
	GatewayProbeEndpoint string `json:"gateway_probe_endpoint"`
	CallerStateRoot      string `json:"caller_state_root"`
	WorkingDirectory     string `json:"working_directory"`
	EvidenceRoot         string `json:"evidence_root"`
}

// PreparedConfiguration is an immutable lexical snapshot that also owns the
// not-yet-started shared run budget. It is NOT a process-start permit or the
// final adapter_configuration evidence commitment: descriptor-backed profile
// and directory checks are still required. Raw locations must never be
// included in sanitized evidence or diagnostics.
type PreparedConfiguration struct {
	locations LocationConfiguration
	digest    string
	budget    *runBudget
}

// PrepareConfiguration does no filesystem access, network I/O, credential
// acquisition, directory creation or process execution. All six strings are
// copied without normalization, so later phases can use exactly the same bytes.
func PrepareConfiguration(ctx context.Context, input LocationConfiguration) (*PreparedConfiguration, error) {
	if !supportedPlatform(runtime.GOOS) {
		return nil, ErrUnsupportedPlatform
	}
	if ctx == nil {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if qualificationadapterprotocol.ValidateSupervisorLocations(input.ProfilePath, input.ProviderOrigin,
		input.GatewayProbeEndpoint, input.CallerStateRoot, input.WorkingDirectory, input.EvidenceRoot) != nil {
		return nil, ErrConfiguration
	}
	document, err := json.Marshal(input)
	if err != nil {
		return nil, ErrConfiguration
	}
	canonical, err := jcs.Transform(document)
	if err != nil {
		return nil, ErrConfiguration
	}
	sum := sha256.Sum256(canonical)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &PreparedConfiguration{locations: input, digest: "sha256:" + hex.EncodeToString(sum[:]), budget: newRunBudget(ctx)}, nil
}

// Locations returns a copy for local preflight, never for sanitized evidence.
func (c *PreparedConfiguration) Locations() LocationConfiguration { return c.locations }

// Digest returns the RFC 8785 full-document SHA-256 of these six fields only.
// This preliminary location digest does not identify an entire adapter config.
func (c *PreparedConfiguration) Digest() string { return c.digest }

// Matches requires byte-identical fields; canonical-equivalent replacements
// and changes to any path are not accepted between phases.
func (c *PreparedConfiguration) Matches(input LocationConfiguration) bool {
	return c != nil && c.digest != "" && c.locations == input
}
