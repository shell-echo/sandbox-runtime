package dockercontrol

import "testing"

func TestCodingSelectedImagePlatformIsTemplateBound(t *testing.T) {
	for _, value := range []struct {
		osName, architecture, variant, expected string
		allow                                   bool
	}{
		{"linux", "arm64", "v8", "linux/arm64/v8", true},
		{"linux", "arm64", "", "linux/arm64/v8", true},
		{"linux", "amd64", "", "linux/amd64", true},
		{"linux", "amd64", "v8", "linux/amd64", false},
		{"linux", "arm64", "v9", "linux/arm64/v8", false},
		{"linux", "arm64", "v8", "linux/amd64", false},
		{"windows", "amd64", "", "linux/amd64", false},
		{"linux", "amd64", "", "linux/386", false},
	} {
		if got := codingSelectedPlatformMatches(value.osName, value.architecture, value.variant, value.expected); got != value.allow {
			t.Fatalf("platform matching differed for %q/%q/%q -> %q: %t", value.osName,
				value.architecture, value.variant, value.expected, got)
		}
	}
}
