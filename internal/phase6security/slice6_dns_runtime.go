package phase6security

import (
	"slices"
)

const (
	slice6DNSImageIndex  = "sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286"
	slice6DNSARMManifest = "sha256:9a631b1e34491f93a35334bc02d8ae190f16224be41689c7f42cc1711a95fe3a"
)

func Slice6DNSRuntimePolicy(resources Resources) DNSRuntimePolicy {
	return DNSRuntimePolicy{UID: 65532, GID: 65532,
		DroppedCapabilities: []string{"ALL"}, AddedCapabilities: []string{"CAP_NET_BIND_SERVICE"},
		NoNewPrivileges: true, ReadOnlyRootFilesystem: true, SeccompMode: 2,
		Resources: resources, InspectorTarget: "/phase6-dns-status-inspector", InspectorReadOnly: true}
}

// VerifySlice6DNSRuntimePolicy pins the only external capability exception
// to the original stock CoreDNS arm64 image and finite, source-bound limits.
// It never changes the Principal zero-CapAdd invariant.
func VerifySlice6DNSRuntimePolicy(profile Profile) error {
	if profile.Validate() != nil {
		return errSlice6DesiredInventory
	}
	count := 0
	for _, service := range profile.External {
		if service.Name != "dns" {
			if service.DNSRuntime != nil {
				return errSlice6DesiredInventory
			}
			continue
		}
		count++
		policy := service.DNSRuntime
		if policy == nil || service.ImageReference != "docker.io/coredns/coredns@"+slice6DNSImageIndex ||
			service.ImageDigest != slice6DNSImageIndex || service.ImageIdentityKind != ImageIdentityOCIIndex ||
			service.ImagePlatform != "linux/arm64/v8" || service.ImageSelectedManifestDigest != slice6DNSARMManifest ||
			policy.UID != 65532 || policy.GID != 65532 ||
			!slices.Equal(policy.DroppedCapabilities, []string{"ALL"}) ||
			!slices.Equal(policy.AddedCapabilities, []string{"CAP_NET_BIND_SERVICE"}) ||
			!policy.NoNewPrivileges || !policy.ReadOnlyRootFilesystem || policy.SeccompMode != 2 ||
			!validSlice6CapacityLimit(policy.Resources) || policy.HostNetwork || policy.HostPublish ||
			policy.InspectorTarget != "/phase6-dns-status-inspector" || !policy.InspectorReadOnly {
			return errSlice6DesiredInventory
		}
	}
	if count != 1 {
		return errSlice6DesiredInventory
	}
	return nil
}
