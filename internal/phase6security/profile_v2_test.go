package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestProfileV2HasIndependentClosedWireAndDigest(t *testing.T) {
	partial := ProfileV2{Protocol: ProtocolIDV2, Version: VersionV2,
		Revision: "slice6-v2-test", EnvironmentDigest: testDigest("v2-environment"),
		PrincipalProfileDigest: testDigest("v2-principals"),
		DockerControl: DockerControlAuthorityV2{Deployment: "provider-docker-control",
			DaemonSocketPath: v2DaemonSocketPath, SupplementaryGIDs: []uint32{0}},
		SandboxGatewayLimits: map[string]Resources{"browser-sandbox-runtime": {
			MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16}},
	}
	partial.ProfileDigest = partial.Digest()
	unsigned := partial
	unsigned.ProfileDigest = ""
	document, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/phase6-security-profile/v2\x00"), document...))
	if partial.ProfileDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("v2 digest domain mismatch")
	}
	canonical, err := json.Marshal(partial)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decodeV2Canonical(canonical)
	if err != nil || parsed.ProfileDigest != partial.ProfileDigest {
		t.Fatalf("v2 canonical parser rejected its own known fields: %v", err)
	}
	if _, err := DecodeV2(canonical); err == nil {
		t.Fatal("partial v2 profile became runnable")
	}
	if _, err := Decode(canonical); err == nil {
		t.Fatal("v1 decoder accepted v2")
	}
	changed := partial
	changed.DockerControl.SupplementaryGIDs = []uint32{0, 1}
	if changed.Digest() == partial.ProfileDigest {
		t.Fatal("v2 Control supplementary authority omitted from digest")
	}
	changed = partial
	changed.SandboxGatewayLimits = map[string]Resources{"browser-sandbox-runtime": {
		MemoryBytes: 128 << 20, CPUMillis: 100, PIDs: 16}}
	if changed.Digest() == partial.ProfileDigest {
		t.Fatal("v2 resource authority omitted from digest")
	}
	for name, altered := range map[string][]byte{
		"duplicate":    append(append([]byte{}, canonical[:len(canonical)-1]...), []byte(`,"version":2}`)...),
		"unknown":      append(append([]byte{}, canonical[:len(canonical)-1]...), []byte(`,"fallback_v1":true}`)...),
		"leading byte": append([]byte(" "), canonical...),
		"trailing":     append(append([]byte{}, canonical...), []byte("{}")...),
		"oversize":     bytes.Repeat([]byte{'x'}, maxBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeV2Canonical(altered); err == nil {
				t.Fatal("noncanonical or unsafe v2 bytes accepted")
			}
		})
	}
	legacy := validProfile()
	legacyDocument, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeV2(legacyDocument); err == nil {
		t.Fatal("v2 decoder accepted v1")
	}
}
