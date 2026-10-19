package phase6process

import "github.com/shell-echo/sandbox-runtime/internal/trustanchor"

const ProbePath = "/usr/local/bin/control-process-observe"

type ProbeObservation struct {
	Digest string `json:"digest"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
}
type ProbeReport struct {
	Admission          string             `json:"admission"`
	ProfileBytesDigest string             `json:"profile_bytes_digest"`
	Deployment         string             `json:"deployment"`
	Stage              string             `json:"stage"`
	Observation        Observation        `json:"observation"`
	Probe              *ProbeObservation  `json:"probe,omitempty"`
	Source             *SourceObservation `json:"source,omitempty"`
}

// SourceObservation is private descriptive evidence, never an admission token.
// Only the source collector produces it from retained FDs and live Docker reads.
type SourceObservation struct {
	Protocol           string            `json:"protocol"`
	ProfileBytesDigest string            `json:"profile_bytes_digest"`
	Namespace          string            `json:"namespace"`
	Intent             string            `json:"intent"`
	Seal               string            `json:"seal"`
	Root               string            `json:"root"`
	Volumes            string            `json:"volumes"`
	Inventory          string            `json:"inventory"`
	ProcessSession     string            `json:"process_session"`
	Trust              *TrustObservation `json:"trust,omitempty"`
}

type AnchorObservation struct {
	ID           string                           `json:"id"`
	StorageID    string                           `json:"storage_id"`
	VolumeDigest string                           `json:"volume_digest"`
	Artifact     trustanchor.DirectoryObservation `json:"artifact"`
}

type TrustObservation struct {
	Anchors []AnchorObservation `json:"anchors"`
}
