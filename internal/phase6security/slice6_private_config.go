package phase6security

import (
	"path"
	"slices"
	"strings"
)

const (
	Slice6PrivateConfigDirectory  = "/run/phase6/config"
	Slice6PrivateConfigMaxBytes   = 4 << 20
	Slice6ProfileConfigFile       = "profile.json"
	Slice6PeerCRLSourcesFile      = "peer-crl-sources.json"
	Slice6PeerCRLRoleFile         = "peer-crl-role.json"
	Slice6PostgresPeerCRLRoleFile = "postgres-peer-crl-role.json"
	Slice6StartupAuthorityFile    = "startup-authority.json"
	Slice6CredentialAuthorityFile = "credential-authority.json"
	Slice6DependencyAuthorityFile = "dependency-authority.json"
	Slice6PolicyAuthorityFile     = "policy-authority.json"
)

// Slice6PrivateConfigMount enumerates only final deployments that actually
// call VerifyFile. The file list is a closed startup input manifest, not a
// hash of Profile bytes (which would create a digest cycle).
func Slice6PrivateConfigMount(deployment string) (Mount, bool) {
	target, known := slice6DesiredImageTargets[deployment]
	if !known || target == "break-glass-controller" || target == Slice6BrowserPublishedImage ||
		target == Slice6DesktopCandidateImage {
		return Mount{}, false
	}
	files := []string{Slice6ProfileConfigFile}
	switch target {
	case "workload-tls-agent", "certificate-controller":
		files = append(files, Slice6PeerCRLSourcesFile)
	case "core", "browser-action-ingress", "browser-executor-backend", "desktop-executor-backend", "egress-policy-broker":
		switch deployment {
		case "product-runtime", "gateway-runtime", "provider-runtime", "provider-browser-runtime", "provider-desktop-runtime":
			files = append(files, Slice6PeerCRLRoleFile)
			files = append(files, Slice6PostgresPeerCRLRoleFile)
		case "product-migration-job", "provider-migration-job", "provider-browser-migration-job", "provider-desktop-migration-job":
			files = append(files, Slice6PostgresPeerCRLRoleFile)
		default:
			files = append(files, Slice6PeerCRLRoleFile)
		}
	}
	switch deployment {
	case "browser-executor-backend", "desktop-executor-backend", "public-ingress-relay", "browser-action-ingress-runtime":
		files = append(files, Slice6StartupAuthorityFile)
	case "gateway-runtime", "guest-runtime", "browser-runtime-role", "desktop-runtime-role":
		files = append(files, Slice6CredentialAuthorityFile, Slice6DependencyAuthorityFile, Slice6PolicyAuthorityFile)
	}
	slices.Sort(files)
	return Mount{Target: Slice6PrivateConfigDirectory, Kind: "private_config", ReadOnly: true,
		MaxBytes: Slice6PrivateConfigMaxBytes, StorageID: deployment + "-private-config",
		PrivateFiles: strings.Join(files, ",")}, true
}

// Slice6PrivateConfigFileLimit applies the existing strict decoder bounds to
// each reviewed static file purpose, including the four argv authority inputs.
func Slice6PrivateConfigFileLimit(deployment, filename string) (int64, bool) {
	mount, ok := Slice6PrivateConfigMount(deployment)
	if !ok || !slices.Contains(strings.Split(mount.PrivateFiles, ","), filename) {
		return 0, false
	}
	switch filename {
	case Slice6ProfileConfigFile:
		return 2 << 20, true
	case Slice6PeerCRLSourcesFile, Slice6PeerCRLRoleFile, Slice6PostgresPeerCRLRoleFile:
		return 128 << 10, true
	case Slice6StartupAuthorityFile:
		if deployment == "browser-executor-backend" || deployment == "desktop-executor-backend" {
			return 64 << 10, true
		}
		return 16 << 10, true
	case Slice6CredentialAuthorityFile, Slice6DependencyAuthorityFile, Slice6PolicyAuthorityFile:
		return 64 << 10, true
	default:
		return 0, false
	}
}

func AttachSlice6PrivateConfigMounts(principals []Principal) ([]Principal, error) {
	result := slices.Clone(principals)
	for index := range result {
		mount, needed := Slice6PrivateConfigMount(result[index].Name)
		if !needed {
			continue
		}
		result[index].Mounts = append(slices.Clone(result[index].Mounts), mount)
	}
	if VerifySlice6PrivateConfigMounts(Profile{Principals: result}) != nil {
		return nil, errSlice6DesiredInventory
	}
	return result, nil
}

// VerifySlice6PrivateConfigMounts closes per-deployment storage identity,
// target, file purposes and sharing, including overlaps with other kinds.
func VerifySlice6PrivateConfigMounts(profile Profile) error {
	if len(profile.Principals) != len(slice6DesiredImageTargets) {
		return errSlice6DesiredInventory
	}
	seenNames := make(map[string]bool, len(profile.Principals))
	seenStorage := make(map[string]bool, len(profile.Principals))
	for _, principal := range profile.Principals {
		want, needed := Slice6PrivateConfigMount(principal.Name)
		if seenNames[principal.Name] || slice6DesiredImageTargets[principal.Name] == "" {
			return errSlice6DesiredInventory
		}
		seenNames[principal.Name] = true
		if needed {
			var budget int64
			for _, filename := range strings.Split(want.PrivateFiles, ",") {
				limit, ok := Slice6PrivateConfigFileLimit(principal.Name, filename)
				if !ok {
					return errSlice6DesiredInventory
				}
				budget += limit
			}
			if budget > want.MaxBytes {
				return errSlice6DesiredInventory
			}
		}
		found := 0
		for _, mount := range principal.Mounts {
			if mount.Kind == "private_config" || mount.Target == Slice6PrivateConfigDirectory ||
				strings.HasPrefix(mount.Target, Slice6PrivateConfigDirectory+"/") ||
				strings.HasPrefix(Slice6PrivateConfigDirectory, mount.Target+"/") {
				if !needed || mount != want {
					return errSlice6DesiredInventory
				}
				found++
			}
			if mount.Kind != "private_config" && mount.PrivateFiles != "" {
				return errSlice6DesiredInventory
			}
		}
		if needed && found != 1 || !needed && found != 0 || seenStorage[want.StorageID] && needed {
			return errSlice6DesiredInventory
		}
		if needed {
			seenStorage[want.StorageID] = true
		}
	}
	for _, principal := range profile.Principals {
		for _, mount := range principal.Mounts {
			if mount.Kind == "private_config" {
				continue
			}
			if seenStorage[mount.StorageID] {
				return errSlice6DesiredInventory
			}
		}
	}
	return nil
}

// VerifySlice6PrivateConfigPath binds a command's private file input to its
// own observed config volume and one declared purpose. It never accepts an
// arbitrary absolute path merely because the file content decodes.
func VerifySlice6PrivateConfigPath(profile Profile, deployment, filename, actualPath string) error {
	if VerifySlice6PrivateConfigMounts(profile) != nil || filename == "" ||
		actualPath != path.Join(Slice6PrivateConfigDirectory, filename) {
		return errSlice6DesiredInventory
	}
	want, ok := Slice6PrivateConfigMount(deployment)
	if !ok || !slices.Contains(strings.Split(want.PrivateFiles, ","), filename) {
		return errSlice6DesiredInventory
	}
	for _, principal := range profile.Principals {
		if principal.Name == deployment && slices.Contains(principal.Mounts, want) {
			return nil
		}
	}
	return errSlice6DesiredInventory
}

// VerifySlice6ProfileForDeployment combines the existing strict private-file
// decoder with the final deployment's fixed, exclusive config-file path.
func VerifySlice6ProfileForDeployment(actualPath, deployment string) (Profile, error) {
	profile, err := VerifyFile(actualPath)
	if err != nil || VerifySlice6PrivateConfigPath(profile, deployment, Slice6ProfileConfigFile, actualPath) != nil {
		return Profile{}, ErrInvalidProfile
	}
	return profile, nil
}

// VerifySlice6PeerCRLRoleForDeployment keeps ordinary and PostgreSQL-purpose
// derivatives in distinct, owner-specific file slots before decoding bytes.
func VerifySlice6PeerCRLRoleForDeployment(actualPath, deployment, filename string, profile Profile,
	expectedMappingDigest, expectedRoleDigest string) (PeerCRLRoleDocument, error) {
	if filename != Slice6PeerCRLRoleFile && filename != Slice6PostgresPeerCRLRoleFile ||
		VerifySlice6PrivateConfigPath(profile, deployment, filename, actualPath) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	return VerifyPeerCRLRoleFile(actualPath, profile, expectedMappingDigest, expectedRoleDigest)
}
