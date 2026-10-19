package controlstorage

import "testing"

func TestDedicatedLoopRequiresHardLimitAndPersistentExactBacking(t *testing.T) {
	b := dedicatedTestBackend()
	base := map[string]string{"size": "2097152", "ro": "0", "loop/backing_file": b.BackingFile, "loop/offset": "0", "loop/sizelimit": "1073741824", "loop/autoclear": "0", "loop/partscan": "0", "loop/dio": "0"}
	if verifyDedicatedLoopFacts(b, base) != nil {
		t.Fatal("synthetic bounded mapping rejected")
	}
	for key, values := range map[string][]string{
		"size": {"2097153", "2097151", "18446744073709551615"}, "ro": {"1"}, "loop/backing_file": {b.BackingFile + " (deleted)", "/other/receipt.ext4"},
		"loop/offset": {"4096"}, "loop/sizelimit": {"0", "1073741825"}, "loop/autoclear": {"1"}, "loop/partscan": {"1"}, "loop/dio": {"1"},
	} {
		for _, value := range values {
			t.Run(key+"="+value, func(t *testing.T) {
				f := map[string]string{}
				for k, v := range base {
					f[k] = v
				}
				f[key] = value
				if verifyDedicatedLoopFacts(b, f) == nil {
					t.Fatal("unsafe mapping accepted")
				}
			})
		}
	}
}
