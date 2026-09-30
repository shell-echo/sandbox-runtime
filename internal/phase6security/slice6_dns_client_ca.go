package phase6security

import "slices"

var slice6DNSBrokerSubjects = []string{
	"egress-broker-browser-action-ingress",
	"egress-broker-gateway",
	"egress-broker-product",
	"egress-broker-provider-browser",
	"egress-broker-provider-desktop",
}

func Slice6DNSBrokerSubjects() []string {
	return slices.Clone(slice6DNSBrokerSubjects)
}

// VerifySlice6DNSClientCA closes the final external DNS client trust to one
// source-bound broker-only issuer. It is desired configuration, not proof
// that stock CoreDNS loaded those exact bytes or rejected another issuer.
func VerifySlice6DNSClientCA(profile Profile) error {
	if profile.Validate() != nil {
		return errSlice6DesiredInventory
	}
	count := 0
	for _, service := range profile.External {
		if service.Name != "dns" {
			if service.DNSClientCA != nil {
				return errSlice6DesiredInventory
			}
			continue
		}
		count++
		ca := service.DNSClientCA
		if ca == nil || ca.ArtifactID != "dns-broker-client-ca" ||
			!slices.Equal(ca.AllowedSubjects, slice6DNSBrokerSubjects) {
			return errSlice6DesiredInventory
		}
	}
	if count != 1 {
		return errSlice6DesiredInventory
	}
	return nil
}
