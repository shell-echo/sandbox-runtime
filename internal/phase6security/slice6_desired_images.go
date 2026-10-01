package phase6security

import (
	"sort"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

// The local gate must not infer an executable from a principal's broad kind
// or from whichever image happened to be loaded. Every approved deployment
// has one reviewed build target or a separately locked sandbox image source.
const (
	Slice6BrowserPublishedImage = "browser-published"
	Slice6DesktopCandidateImage = "desktop-candidate"
)

var slice6DesiredImageTargets = map[string]string{
	"product-runtime": "core", "gateway-runtime": "core",
	"provider-runtime": "core", "provider-browser-runtime": "core", "provider-desktop-runtime": "core",
	"guest-runtime": "core", "browser-runtime-role": "core", "desktop-runtime-role": "core",
	"product-migration-job": "core", "provider-migration-job": "core",
	"provider-browser-migration-job": "core", "provider-desktop-migration-job": "core",
	"browser-action-ingress-runtime":                 "browser-action-ingress",
	"browser-executor-backend":                       "browser-executor-backend",
	"desktop-executor-backend":                       "desktop-executor-backend",
	"product-tls-agent":                              "workload-tls-agent",
	"provider-tls-agent":                             "workload-tls-agent",
	"provider-browser-tls-agent":                     "workload-tls-agent",
	"provider-desktop-tls-agent":                     "workload-tls-agent",
	"provider-browser-postgres-tls-agent":            "workload-tls-agent",
	"provider-desktop-postgres-tls-agent":            "workload-tls-agent",
	"product-postgres-tls-agent":                     "workload-tls-agent",
	"gateway-postgres-tls-agent":                     "workload-tls-agent",
	"provider-postgres-tls-agent":                    "workload-tls-agent",
	"product-migration-postgres-tls-agent":           "workload-tls-agent",
	"provider-migration-postgres-tls-agent":          "workload-tls-agent",
	"provider-browser-migration-postgres-tls-agent":  "workload-tls-agent",
	"provider-desktop-migration-postgres-tls-agent":  "workload-tls-agent",
	"gateway-tls-agent":                              "workload-tls-agent",
	"browser-action-ingress-tls-agent":               "workload-tls-agent",
	"guest-tls-agent":                                "workload-tls-agent",
	"browser-tls-agent":                              "workload-tls-agent",
	"desktop-tls-agent":                              "workload-tls-agent",
	"browser-executor-tls-agent":                     "workload-tls-agent",
	"desktop-executor-tls-agent":                     "workload-tls-agent",
	"browser-action-ingress-agent-tls-agent":         "workload-tls-agent",
	"gateway-agent-tls-agent":                        "workload-tls-agent",
	"guest-agent-tls-agent":                          "workload-tls-agent",
	"product-migration-agent-tls-agent":              "workload-tls-agent",
	"product-runtime-agent-tls-agent":                "workload-tls-agent",
	"provider-browser-runtime-agent-tls-agent":       "workload-tls-agent",
	"provider-desktop-runtime-agent-tls-agent":       "workload-tls-agent",
	"provider-migration-agent-tls-agent":             "workload-tls-agent",
	"provider-browser-migration-agent-tls-agent":     "workload-tls-agent",
	"provider-desktop-migration-agent-tls-agent":     "workload-tls-agent",
	"provider-runtime-agent-tls-agent":               "workload-tls-agent",
	"egress-broker-product-tls-agent":                "workload-tls-agent",
	"egress-broker-gateway-tls-agent":                "workload-tls-agent",
	"egress-broker-browser-action-ingress-tls-agent": "workload-tls-agent",
	"egress-broker-provider-browser-tls-agent":       "workload-tls-agent",
	"egress-broker-provider-desktop-tls-agent":       "workload-tls-agent",
	"product-runtime-agent":                          "workload-material-agent",
	"provider-runtime-agent":                         "workload-material-agent",
	"provider-browser-runtime-agent":                 "workload-material-agent",
	"provider-desktop-runtime-agent":                 "workload-material-agent",
	"gateway-agent":                                  "workload-material-agent",
	"browser-action-ingress-agent":                   "workload-material-agent",
	"guest-agent":                                    "workload-material-agent",
	"product-migration-agent":                        "workload-material-agent",
	"provider-migration-agent":                       "workload-material-agent",
	"provider-browser-migration-agent":               "workload-material-agent",
	"provider-desktop-migration-agent":               "workload-material-agent",
	"workload-credential-controller":                 "workload-credential-controller-v2",
	"break-glass-controller":                         "break-glass-controller",
	"certificate-controller":                         "certificate-controller",
	"egress-broker-product":                          "egress-policy-broker",
	"egress-broker-gateway":                          "egress-policy-broker",
	"egress-broker-browser-action-ingress":           "egress-policy-broker",
	"egress-broker-provider-browser":                 "egress-policy-broker",
	"egress-broker-provider-desktop":                 "egress-policy-broker",
	"egress-policy-authority-product":                "egress-policy-state-authority",
	"egress-policy-authority-gateway":                "egress-policy-state-authority",
	"egress-policy-authority-browser-action-ingress": "egress-policy-state-authority",
	"egress-policy-authority-provider-browser":       "egress-policy-state-authority",
	"egress-policy-authority-provider-desktop":       "egress-policy-state-authority",
	"public-ingress-relay":                           "phase6-ingress-relay",
	"browser-sandbox-runtime":                        Slice6BrowserPublishedImage,
	"desktop-sandbox-runtime":                        Slice6DesktopCandidateImage,
}

// Slice6DesiredDeploymentNames exposes a copy of the reviewed deployment
// inventory for the gate-owned profile builder. It is desired configuration,
// never a Docker observation or an operator-supplied expansion point.
func Slice6DesiredDeploymentNames() []string {
	return slice6ApprovedDeploymentNames()
}

// Slice6DesiredLocalRoleTargets is the exact set of repository command images
// required before a complete local profile can be frozen. Browser and Desktop
// have separately verified image authorities.
func Slice6DesiredLocalRoleTargets() []string {
	seen := make(map[string]bool)
	for _, target := range slice6DesiredImageTargets {
		if target != Slice6BrowserPublishedImage && target != Slice6DesktopCandidateImage {
			seen[target] = true
		}
	}
	targets := make([]string, 0, len(seen))
	for target := range seen {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}

// Slice6DesiredImageTarget names the repository build target, or the exact
// separately verified Browser/Desktop sandbox image source. Unknown names
// fail closed and do not acquire a default core executable.
func Slice6DesiredImageTarget(deployment string) (string, error) {
	target, ok := slice6DesiredImageTargets[deployment]
	if !ok || slice6ApprovedDeploymentKinds[deployment] == "" {
		return "", errSlice6DesiredInventory
	}
	return target, nil
}

// VerifySlice6DesiredImageLocations selects one reviewed same-host candidate:
// static repository commands and Desktop are local source-bound candidates;
// Browser retains the exact separately published immutable image. ADR 0055
// permits a separately reviewed local Browser candidate, but this inventory
// has not selected or proved one. This is admission only, not a supply-chain
// or running-container observation.
func VerifySlice6DesiredImageLocations(profile Profile) error {
	if profile.Validate() != nil || len(profile.Principals) != len(slice6DesiredImageTargets) ||
		len(slice6DesiredImageTargets) != len(slice6ApprovedDeploymentKinds) {
		return errSlice6DesiredInventory
	}
	for _, principal := range profile.Principals {
		target, err := Slice6DesiredImageTarget(principal.Name)
		if err != nil {
			return errSlice6DesiredInventory
		}
		location := "local"
		if target == Slice6BrowserPublishedImage {
			location = "registry"
		}
		if principal.ImageLocation != location || principal.Kind != slice6ApprovedDeploymentKinds[principal.Name] ||
			(location == "local" && principal.ImageIdentityKind == ImageIdentityLocalConfig) {
			return errSlice6DesiredInventory
		}
		if target == Slice6BrowserPublishedImage &&
			(principal.ImageReference != browserimage.LockedPublication().Image() ||
				principal.ImageDigest != browserimage.PublishedDigest ||
				principal.ImageIdentityKind != ImageIdentityOCIIndex) {
			return errSlice6DesiredInventory
		}
		if target == Slice6BrowserPublishedImage {
			manifest, err := browserimage.LockedPublication().SelectedManifest(principal.ImagePlatform)
			if err != nil || principal.ImageSelectedManifestDigest != manifest {
				return errSlice6DesiredInventory
			}
		}
	}
	return nil
}
