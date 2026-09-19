package image

import "errors"

const (
	PublishedRepository                = "ghcr.io/shell-echo/sandbox-runtime-desktop"
	PublishedDigest                    = "sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300"
	PublishedAMD64Digest               = "sha256:ae1b71855f879066caf73f1056039d52b796d936a19f4b34a58a5565dd89609b"
	PublishedARM64V8Digest             = "sha256:e5d01e272f87df8dc693ba81d85bce2a154ae541ac0166177a9290a005928505"
	PublishedSourceCommit              = "e4a940bda6c5172a78d0dbe40963ca1a99911976"
	PublishedTag                       = "sha-e4a940bda6c5172a78d0dbe40963ca1a99911976"
	PublishedWorkflow                  = "github.com/shell-echo/sandbox-runtime/.github/workflows/desktop-image.yml"
	PublishedRepositoryName            = "shell-echo/sandbox-runtime"
	PublishedRunnerPolicy              = "deny-self-hosted-runners"
	PublishedRegistryAttestationDigest = "sha256:2abf3a1c0304bac70f3118d4b16c193cc1cf2abaa83c144efdd15a365998faf8"
	PublishedRunID                     = int64(35447651328)
	PublishedAttestationID             = int64(48643717)
	PublishedTransparencyLogIndex      = int64(2892645362)
)

var ErrInvalidPublication = errors.New("invalid Desktop image publication evidence")

type PublishedPlatform struct {
	Platform string
	Digest   string
}

// Publication is the exact signed Desktop image evidence accepted by the
// repository for later runtime-adapter selection. A newer publication must
// update this authority and pass its own release gate; mutable tags are never
// accepted.
type Publication struct {
	Repository                string
	Digest                    string
	Tag                       string
	SourceCommit              string
	Workflow                  string
	RepositoryName            string
	RunnerPolicy              string
	RegistryAttestationDigest string
	RunID                     int64
	AttestationID             int64
	TransparencyLogIndex      int64
	RuntimeProfileID          string
	Platforms                 []PublishedPlatform
}

func LockedPublication() Publication {
	return Publication{
		Repository: PublishedRepository, Digest: PublishedDigest, Tag: PublishedTag,
		SourceCommit: PublishedSourceCommit, Workflow: PublishedWorkflow,
		RepositoryName: PublishedRepositoryName, RunnerPolicy: PublishedRunnerPolicy,
		RegistryAttestationDigest: PublishedRegistryAttestationDigest,
		RunID:                     PublishedRunID, AttestationID: PublishedAttestationID,
		TransparencyLogIndex: PublishedTransparencyLogIndex, RuntimeProfileID: ProfileID,
		Platforms: []PublishedPlatform{
			{Platform: "linux/amd64", Digest: PublishedAMD64Digest},
			{Platform: "linux/arm64/v8", Digest: PublishedARM64V8Digest},
		},
	}
}

func (p Publication) Image() string { return p.Repository + "@" + p.Digest }

func (p Publication) Validate() error {
	want := LockedPublication()
	if p.Repository != want.Repository || p.Digest != want.Digest || p.Tag != want.Tag ||
		p.SourceCommit != want.SourceCommit || p.Workflow != want.Workflow ||
		p.RepositoryName != want.RepositoryName || p.RunnerPolicy != want.RunnerPolicy ||
		p.RegistryAttestationDigest != want.RegistryAttestationDigest ||
		p.RunID != want.RunID || p.AttestationID != want.AttestationID ||
		p.TransparencyLogIndex != want.TransparencyLogIndex ||
		p.RuntimeProfileID != want.RuntimeProfileID || len(p.Platforms) != len(want.Platforms) {
		return ErrInvalidPublication
	}
	for index := range want.Platforms {
		if p.Platforms[index] != want.Platforms[index] {
			return ErrInvalidPublication
		}
	}
	return nil
}
