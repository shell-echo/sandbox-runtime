// Package controldelivery verifies a post-observation signature solely for
// held Control process delivery. It has no Store, runtime or admission API.
package controldelivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6process"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"time"
)

const Protocol = phase6security.ControlDeliveryObservationProtocol
const Scope = "held-control-process-delivery"
const SourceProtocol = phase6security.ControlSourceObservationProtocol
const SourceScope = "held-control-source-observation"
const TrustProtocol = phase6security.ControlTrustObservationProtocol
const TrustScope = "held-control-trust-observation"
const MaxFrame = 64 << 10

var ErrUnavailable = errors.New("held Control delivery unavailable")

type Challenge struct {
	Protocol           string                           `json:"protocol"`
	Scope              string                           `json:"scope"`
	Startup            phase6fdloader.StartupBinding    `json:"startup"`
	KeyID              string                           `json:"key_id"`
	ProfileBytesDigest string                           `json:"profile_bytes_digest"`
	ProfileDigest      string                           `json:"profile_digest"`
	Deployment         string                           `json:"deployment"`
	Challenge          string                           `json:"challenge"`
	IssuedAt           int64                            `json:"issued_at"`
	ExpiresAt          int64                            `json:"expires_at"`
	Process            phase6process.Observation        `json:"process"`
	Probe              phase6process.ProbeObservation   `json:"probe"`
	Source             *phase6process.SourceObservation `json:"source,omitempty"`
}
type Reply struct {
	Protocol                  string `json:"protocol"`
	Scope                     string `json:"scope"`
	ChallengeDigest           string `json:"challenge_digest"`
	OperatorObservationDigest string `json:"operator_observation_digest"`
	Signature                 []byte `json:"signature"`
}
type Receipt struct {
	Protocol                  string `json:"protocol"`
	Scope                     string `json:"scope"`
	Admission                 string `json:"admission"`
	ChallengeDigest           string `json:"challenge_digest"`
	OperatorObservationDigest string `json:"operator_observation_digest"`
}

func Digest(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func isDigest(s string) bool {
	if len(s) != 71 || s[:7] != "sha256:" {
		return false
	}
	b, e := hex.DecodeString(s[7:])
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s[7:]
}
func Domain(target string) (protocol, scope string) {
	switch target {
	case phase6security.ControlDeliveryTarget:
		return Protocol, Scope
	case phase6security.ControlSourceTarget:
		return SourceProtocol, SourceScope
	case phase6security.ControlTrustTarget:
		return TrustProtocol, TrustScope
	}
	return "", ""
}
func sourceShape(c Challenge) bool {
	if c.Startup.Target == phase6security.ControlDeliveryTarget {
		return c.Source == nil
	}
	s := c.Source
	protocol, _ := Domain(c.Startup.Target)
	if !phase6security.ControlObservesSource(c.Startup.Target) || s == nil || s.Protocol != protocol || s.ProfileBytesDigest != c.ProfileBytesDigest || s.Namespace == "" || !isDigest(s.Intent) || !isDigest(s.Seal) || !isDigest(s.Root) || !isDigest(s.Volumes) || !isDigest(s.Inventory) || !isDigest(s.ProcessSession) {
		return false
	}
	if c.Startup.Target == phase6security.ControlSourceTarget {
		return s.Trust == nil
	}
	if s.Trust == nil || len(s.Trust.Anchors) != 2 {
		return false
	}
	for i, id := range []string{"internal-client-ca", "internal-server-ca"} {
		a := s.Trust.Anchors[i]
		v := a.Artifact
		if a.ID != id || a.StorageID == "" || !isDigest(a.VolumeDigest) || !isDigest(v.BundleDigest) || v.MountID == 0 || v.Directory.Inode == 0 || v.File.Inode == 0 || v.Directory.Mode != 0555 || v.File.Mode != 0444 || v.Directory.UID != 0 || v.Directory.GID != 0 || v.File.UID != 0 || v.File.GID != 0 || v.File.Size < 1 || v.File.Size > 256<<10 {
			return false
		}
	}
	return true
}
func SigningBytes(c Challenge, r Reply) ([]byte, error) {
	protocol, scope := Domain(c.Startup.Target)
	b, e := json.Marshal(c)
	if protocol == "" || c.Protocol != protocol || c.Scope != scope || !sourceShape(c) || e != nil || r.Protocol != protocol || r.Scope != scope || r.ChallengeDigest != Digest(b) || !isDigest(r.OperatorObservationDigest) {
		return nil, ErrUnavailable
	}
	// Versioned domain + full challenge + independently collected host digest.
	return json.Marshal(struct {
		Domain                    string    `json:"domain"`
		Challenge                 Challenge `json:"challenge"`
		OperatorObservationDigest string    `json:"operator_observation_digest"`
	}{protocol + "/" + scope, c, r.OperatorObservationDigest})
}
func ValidateChallenge(c Challenge, review phase6security.ControlBootstrapReview, now time.Time) (phase6security.ControlServiceIdentityV1, error) {
	var zero phase6security.ControlServiceIdentityV1
	b := review.Bootstrap
	protocol, scope := Domain(b.Target)
	versionOK := b.Protocol == phase6security.ControlDeliveryBootstrapProtocol && b.Target == phase6security.ControlDeliveryTarget || b.Protocol == phase6security.ControlSourceBootstrapProtocol && b.Target == phase6security.ControlSourceTarget
	versionOK = versionOK || b.Protocol == phase6security.ControlTrustBootstrapProtocol && b.Target == phase6security.ControlTrustTarget
	if c.Source != nil {
		s, r := c.Source, review.Source
		if r == nil || s.Namespace != r.Source.Intent.Namespace || s.Intent != r.Source.IntentDigest || s.Seal != r.Source.SealDigest {
			return zero, ErrUnavailable
		}
		if s.Trust != nil {
			if len(r.TrustAnchors) != 2 || len(s.Trust.Anchors) != 2 {
				return zero, ErrUnavailable
			}
			for i, a := range r.TrustAnchors {
				v := s.Trust.Anchors[i]
				if v.ID != a.ID || v.StorageID != a.StorageID || v.Artifact.BundleDigest != a.BundleDigest {
					return zero, ErrUnavailable
				}
			}
		}
	}
	if !versionOK || protocol == "" || c.Startup.Target != b.Target || !sourceShape(c) || c.Protocol != protocol || c.Scope != scope || len(c.Startup.ContainerID) != 64 || c.Startup.Validate(c.Startup.ContainerID[:12]) != nil || c.KeyID != b.KeyID || c.ProfileBytesDigest != review.ProfileBytesDigest || c.ProfileDigest != review.ProfileDigest || !isDigest("sha256:"+c.Challenge) || c.IssuedAt <= 0 || c.ExpiresAt-c.IssuedAt != 120 || now.Unix() < c.IssuedAt || now.Unix() >= c.ExpiresAt {
		return zero, ErrUnavailable
	}
	for _, s := range review.Services {
		if s.Launch.Target == b.Target && s.Principal.Name == c.Deployment {
			if phase6process.Verify(c.Process, s, "role") != nil || c.Probe.Digest != s.Launch.ProbeDigest || c.Probe.Inode == 0 || c.Probe.Size <= 0 || c.Probe.Size > 128<<20 {
				return zero, ErrUnavailable
			}
			return s, nil
		}
	}
	return zero, ErrUnavailable
}
