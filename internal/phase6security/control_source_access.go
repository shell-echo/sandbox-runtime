package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

const ControlSourceIntentProtocol = "sandbox-runtime.phase6-control-source-intent.v1"
const ControlSourceAccessProtocol = "sandbox-runtime.phase6-control-source-access.v1"
const ControlSourceSocketTarget = "/run/control-storage-docker.sock"

type ControlSourceDevice struct {
	Host        string `json:"host"`
	Target      string `json:"target"`
	Permissions string `json:"permissions"`
}

// An independent pre-seal preimage: no seal, full Profile digest, or mutable
// Docker session identity. It describes required permissions, never a permit.
type ControlSourceIntentV1 struct {
	Protocol         string   `json:"protocol"`
	Namespace        string   `json:"namespace"`
	PrincipalDigest  string   `json:"principal_digest"`
	ImageLocation    string   `json:"image_location"`
	ImageKind        string   `json:"image_kind"`
	ImageReference   string   `json:"image_reference"`
	ImageDigest      string   `json:"image_digest"`
	ImagePlatform    string   `json:"image_platform"`
	ImageManifest    string   `json:"image_manifest"`
	ImageConfig      string   `json:"image_config"`
	UID              uint32   `json:"uid"`
	GID              uint32   `json:"gid"`
	Groups           []uint32 `json:"groups"`
	BackingStorageID string   `json:"backing_storage_id"`
	BackingTarget    string   `json:"backing_target"`
	BackingReadOnly  bool     `json:"backing_read_only"`
	// SealedImageBytes is the allocated image size, NOT a backing-volume quota.
	SealedImageBytes int64                 `json:"sealed_image_bytes"`
	SourceProtocol   string                `json:"source_protocol"`
	SourceUID        uint32                `json:"source_uid"`
	SourceGID        uint32                `json:"source_gid"`
	DirectoryMode    uint32                `json:"directory_mode"`
	FileMode         uint32                `json:"file_mode"`
	SelectedDevice   string                `json:"selected_device"`
	Devices          []ControlSourceDevice `json:"devices"`
	SocketSource     string                `json:"socket_source"`
	SocketTarget     string                `json:"socket_target"`
	SocketReadOnly   bool                  `json:"socket_read_only"`
}

type ControlSourceAccessV1 struct {
	Protocol     string                `json:"protocol"`
	Intent       ControlSourceIntentV1 `json:"intent"`
	IntentDigest string                `json:"intent_digest"`
	SealDigest   string                `json:"seal_digest"`
}

func NewControlSourceIntentV1(namespace string, control Principal, socketSource string) (ControlSourceIntentV1, error) {
	if !codingNamespaceID.MatchString(namespace) || control.Name != "provider-docker-control" || control.Kind != "docker_control" || control.UID != 57010 || control.GID != 57011 || !digestPattern.MatchString(control.PrincipalDigest) ||
		!validImageIdentity(control.ImageLocation, control.ImageIdentityKind, control.ImageReference, control.ImageDigest, control.ImagePlatform, control.ImageSelectedManifestDigest, control.ImageConfigDigest) || (socketSource != "/var/run/docker.sock" && socketSource != "/run/host-services/docker.proxy.sock") {
		return ControlSourceIntentV1{}, ErrInvalidProfile
	}
	v := ControlSourceIntentV1{Protocol: ControlSourceIntentProtocol, Namespace: namespace, PrincipalDigest: control.PrincipalDigest, ImageLocation: control.ImageLocation, ImageKind: control.ImageIdentityKind, ImageReference: control.ImageReference, ImageDigest: control.ImageDigest, ImagePlatform: control.ImagePlatform, ImageManifest: control.ImageSelectedManifestDigest, ImageConfig: control.ImageConfigDigest, UID: 57010, GID: 57011, Groups: []uint32{0}, BackingStorageID: "control-backing-" + namespace, BackingTarget: controlstorage.SourceMountPath, BackingReadOnly: true, SealedImageBytes: 1 << 30, SourceProtocol: "sandbox-runtime.control-backend-source-provision.v2", SourceGID: 57011, DirectoryMode: 0o750, FileMode: 0o640, SelectedDevice: "/dev/loop7", SocketSource: socketSource, SocketTarget: ControlSourceSocketTarget, SocketReadOnly: true}
	for i := 0; i < 8; i++ {
		path := fmt.Sprintf("/dev/loop%d", i)
		v.Devices = append(v.Devices, ControlSourceDevice{path, path, "r"})
	}
	return v, nil
}

func (v ControlSourceIntentV1) Digest() (string, error) {
	p := Principal{Name: "provider-docker-control", Kind: "docker_control", UID: v.UID, GID: v.GID, PrincipalDigest: v.PrincipalDigest, ImageLocation: v.ImageLocation, ImageIdentityKind: v.ImageKind, ImageReference: v.ImageReference, ImageDigest: v.ImageDigest, ImagePlatform: v.ImagePlatform, ImageSelectedManifestDigest: v.ImageManifest, ImageConfigDigest: v.ImageConfig}
	want, e := NewControlSourceIntentV1(v.Namespace, p, v.SocketSource)
	if e != nil || !reflect.DeepEqual(v, want) {
		return "", ErrInvalidProfile
	}
	data, _ := json.Marshal(v)
	sum := sha256.Sum256(append([]byte(ControlSourceIntentProtocol+"\x00"), data...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func sourceTargetsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func (p ProfileV2) validateControlSourceAccess(control Principal) error {
	a := p.DockerControl.SourceAccess
	if a == nil {
		return nil
	}
	if p.CodingExecution == nil || a.Protocol != ControlSourceAccessProtocol || !digestPattern.MatchString(a.SealDigest) {
		return ErrInvalidProfile
	}
	want, e := NewControlSourceIntentV1(p.CodingExecution.Receipt.Namespace, control, a.Intent.SocketSource)
	d, de := a.Intent.Digest()
	if e != nil || de != nil || d != a.IntentDigest || !reflect.DeepEqual(want, a.Intent) || !control.HostDevices || !exactPolicyMount(control, "control_source", want.BackingTarget, want.BackingStorageID, true) {
		return ErrInvalidProfile
	}
	for i, m := range control.Mounts {
		for _, other := range control.Mounts[i+1:] {
			if sourceTargetsOverlap(m.Target, other.Target) || m.StorageID != "" && m.StorageID == other.StorageID {
				return ErrInvalidProfile
			}
		}
	}
	for _, principal := range p.Principals {
		for _, m := range principal.Mounts {
			if principal.Name != control.Name && (m.StorageID == want.BackingStorageID || sourceTargetsOverlap(m.Target, want.BackingTarget) || sourceTargetsOverlap(m.Target, want.SocketTarget)) {
				return ErrInvalidProfile
			}
		}
	}
	return nil
}

// ControlSourceReview is descriptive operator output, NOT a capability. No
// production Store, ledger, executor or command accepts it as admission.
type ControlSourceReview struct {
	TrustAnchors   []TrustAnchor          `json:"trust_anchors,omitempty"`
	Protocol       string                 `json:"protocol"`
	Admission      string                 `json:"admission"`
	ProfileDigest  string                 `json:"profile_digest"`
	TemplateDigest string                 `json:"template_digest"`
	Source         ControlSourceAccessV1  `json:"source"`
	Control        Principal              `json:"control"`
	Networks       []ControlSourceNetwork `json:"networks"`
}
type ControlSourceNetwork struct {
	Network Network `json:"network"`
	Address string  `json:"address"`
}

// ReviewControlSourceProfile checks the COMPLETE declared Profile chain and
// canonical encoding, while deliberately retaining the public admission hold.
// It is suitable for read-only planning only, not deployment or TLS readiness.
func ReviewControlSourceProfile(document []byte) (ControlSourceReview, error) {
	p, e := decodeV2Canonical(document)
	if e != nil || p.DockerControl.SourceAccess == nil || p.validateFields() != nil {
		return ControlSourceReview{}, ErrInvalidProfile
	}
	r := ControlSourceReview{Protocol: "sandbox-runtime.control-source-review.v1", Admission: "held-not-a-permit", ProfileDigest: p.ProfileDigest, Source: *p.DockerControl.SourceAccess}
	if p.controlTrustDirectories() {
		for _, a := range p.TrustAnchors {
			if a.MountDirectory != "" {
				r.TrustAnchors = append(r.TrustAnchors, a)
			}
		}
	}
	r.TemplateDigest, _ = p.CodingExecution.Template.Digest()
	for _, c := range p.Principals {
		if c.Name == p.DockerControl.Deployment {
			r.Control = c
		}
	}
	for _, n := range p.Networks {
		for _, scope := range p.DockerControl.Endpoints {
			if n.Name != scope.Network {
				continue
			}
			for _, edge := range p.TrustEdges {
				if edge.ID == scope.EdgeID {
					a, _ := netip.ParseAddrPort(edge.TargetAddress)
					r.Networks = append(r.Networks, ControlSourceNetwork{n, a.Addr().String()})
				}
			}
		}
	}
	return r, nil
}

// ReviewControlSourceIntent checks the standalone canonical pre-seal document.
// It needs no placeholder seal or full Profile, and grants no provisioning right.
func ReviewControlSourceIntent(document []byte) (ControlSourceIntentV1, string, error) {
	var intent ControlSourceIntentV1
	if len(document) == 0 || len(document) > 16384 || json.Unmarshal(document, &intent) != nil {
		return intent, "", ErrInvalidProfile
	}
	data, _ := json.Marshal(intent)
	if string(data) != string(document) {
		return ControlSourceIntentV1{}, "", ErrInvalidProfile
	}
	digest, e := intent.Digest()
	return intent, digest, e
}
