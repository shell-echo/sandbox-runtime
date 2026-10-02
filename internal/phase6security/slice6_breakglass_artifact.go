package phase6security

import "regexp"

const (
	Slice6BreakGlassCarrierIndexDigest    = "sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
	Slice6BreakGlassCarrierManifestDigest = "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c"
	Slice6BreakGlassCarrierConfigDigest   = "sha256:1087dfd14fa77fe3bd102f39d42ee9c7e183876bd1a65f38fe2c18198ae976b4"
	Slice6BreakGlassBuildParameters       = "CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local GOFLAGS= GOPROXY=off GOSUMDB=off GOWORK=off go build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid="
)

var slice6BreakGlassRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Slice6BreakGlassExecutableArtifact is the one local-gate binary-bind
// authority shared by eight finite task templates. It is explicitly not a
// claim that the executable is contained in the Alpine OCI layer.
type Slice6BreakGlassExecutableArtifact struct {
	ID                            string `json:"id"`
	SourceRevision                string `json:"source_revision"`
	SourceTreeDigest              string `json:"source_tree_digest"`
	Toolchain                     string `json:"toolchain"`
	ToolchainDigest               string `json:"toolchain_digest"`
	BuildTarget                   string `json:"build_target"`
	BuildParameters               string `json:"build_parameters"`
	Platform                      string `json:"platform"`
	BinaryDigest                  string `json:"binary_digest"`
	BinaryBytes                   int64  `json:"binary_bytes"`
	ContainerPath                 string `json:"container_path"`
	CarrierReference              string `json:"carrier_reference"`
	CarrierIndexDigest            string `json:"carrier_index_digest"`
	CarrierSelectedManifestDigest string `json:"carrier_selected_manifest_digest"`
	CarrierConfigDigest           string `json:"carrier_config_digest"`
	CarrierPlatform               string `json:"carrier_platform"`
}

func VerifySlice6BreakGlassExecutableArtifact(profile Profile) error {
	a := profile.BreakGlassExecutableArtifact
	if a.ID != "break-glass-operator" || !slice6BreakGlassRevisionPattern.MatchString(a.SourceRevision) ||
		profile.Revision != "slice6-"+a.SourceRevision ||
		!digestPattern.MatchString(a.SourceTreeDigest) || a.Toolchain != "go1.26.8" ||
		!digestPattern.MatchString(a.ToolchainDigest) ||
		a.BuildTarget != "./cmd/phase6-break-glass-operator" ||
		a.BuildParameters != Slice6BreakGlassBuildParameters || a.Platform != "linux/arm64/v8" ||
		!digestPattern.MatchString(a.BinaryDigest) || a.BinaryBytes < 1 || a.BinaryBytes > 32<<20 ||
		a.ContainerPath != "/phase6-break-glass-operator" ||
		a.CarrierReference != slice6BreakGlassImage ||
		a.CarrierIndexDigest != Slice6BreakGlassCarrierIndexDigest ||
		a.CarrierSelectedManifestDigest != Slice6BreakGlassCarrierManifestDigest ||
		a.CarrierConfigDigest != Slice6BreakGlassCarrierConfigDigest ||
		a.CarrierPlatform != "linux/arm64/v8" || len(profile.BreakGlassOperatorTasks) != 8 {
		return errSlice6DesiredInventory
	}
	for _, task := range profile.BreakGlassOperatorTasks {
		if task.ExecutableArtifactID != a.ID || task.Executable != a.ContainerPath ||
			task.ImageReference != a.CarrierReference ||
			task.ExecutableMount != (Mount{Target: a.ContainerPath, Kind: "read_only_executable",
				ReadOnly: true, StorageID: "break-glass-operator-source-binary"}) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
