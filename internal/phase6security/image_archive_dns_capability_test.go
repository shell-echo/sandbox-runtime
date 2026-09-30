package phase6security

import (
	"encoding/binary"
	"testing"
)

func TestCoreDNSFileCapabilityRejectsPrivilegeDrift(t *testing.T) {
	value := make([]byte, 20)
	binary.LittleEndian.PutUint32(value[:4], 0x02000001)
	binary.LittleEndian.PutUint32(value[4:8], 0x400)
	if !validCoreDNSFileCapability(value) {
		t.Fatal("exact NET_BIND_SERVICE-only file capability rejected")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"no effective flag": func(v []byte) []byte { v[0] = 0; return v },
		"extra permitted":   func(v []byte) []byte { v[5] |= 0x10; return v },
		"inheritable":       func(v []byte) []byte { v[8] = 1; return v },
		"high permitted":    func(v []byte) []byte { v[12] = 1; return v },
		"truncated":         func(v []byte) []byte { return v[:19] },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(append([]byte(nil), value...))
			if validCoreDNSFileCapability(candidate) {
				t.Fatal("drifted CoreDNS file capability admitted")
			}
		})
	}
}
