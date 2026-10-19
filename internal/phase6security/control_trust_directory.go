package phase6security

import "slices"

// The v4 directory layout is an explicit observation prerequisite, never
// production admission. Frozen v1 and earlier v2 source targets keep files.
func (p ProfileV2) controlTrustDirectories() bool {
	b := p.DockerControl.OperatorBootstrap
	return b != nil && b.Protocol == ControlTrustBootstrapProtocol && b.Target == ControlTrustTarget
}

func validControlTrustDirectory(a TrustAnchor, enabled bool) bool {
	if !enabled || a.ID != "internal-client-ca" && a.ID != "internal-server-ca" {
		return a.MountDirectory == ""
	}
	return a.MountDirectory == "/run/trust/"+a.ID && a.TargetPath == a.MountDirectory+"/bundle.pem" && a.OwnerUID == 0 && a.OwnerGID == 0
}

func (p ProfileV2) validateControlTrustDirectories() error {
	enabled := p.controlTrustDirectories()
	count := 0
	for _, a := range p.TrustAnchors {
		if !validControlTrustDirectory(a, enabled) {
			return ErrInvalidProfile
		}
		if a.MountDirectory == "" {
			continue
		}
		count++
		for _, other := range p.TrustAnchors {
			if other.ID != a.ID && sourceTargetsOverlap(trustAnchorMountTarget(other), a.MountDirectory) {
				return ErrInvalidProfile
			}
		}
		for _, principal := range p.Principals {
			for _, m := range principal.Mounts {
				if m.StorageID != a.StorageID && !sourceTargetsOverlap(m.Target, a.MountDirectory) {
					continue
				}
				if !slices.Contains(a.Consumers, principal.Name) || m.Kind != "trust_anchor" || m.Target != a.MountDirectory || m.StorageID != a.StorageID || !m.ReadOnly || m.MaxBytes != 0 {
					return ErrInvalidProfile
				}
			}
		}
	}
	if enabled && count != 2 || !enabled && count != 0 {
		return ErrInvalidProfile
	}
	return nil
}
