package phase6fdloader

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeClosedStartupEnvelope(t *testing.T) {
	container := strings.Repeat("a", 64)
	expected := Expected{RunID: strings.Repeat("b", 32), Target: "certificate-controller",
		Nonce: strings.Repeat("c", 32), ContainerHostname: container[:12]}
	valid := Envelope{Protocol: ProtocolID, RunID: expected.RunID, Target: expected.Target,
		ContainerID: container, Nonce: expected.Nonce, Config: []byte(`{"protocol":"test"}`),
		Files: []PrivateFile{{3, bytes.Repeat([]byte{1}, 64)}, {4, bytes.Repeat([]byte{2}, 64)},
			{5, []byte("private-test-key")}, {6, bytes.Repeat([]byte{3}, 64)}}}
	encode := func(value Envelope) []byte {
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	accepted, err := Decode(bytes.NewReader(encode(valid)), expected)
	if err != nil || !bytes.Equal(accepted.Config, valid.Config) || len(accepted.Files) != 4 {
		t.Fatalf("valid startup envelope = %#v, %v", accepted, err)
	}
	accepted.Destroy()
	if len(accepted.Config) != 0 || len(accepted.Files) != 0 {
		t.Fatal("decoded private fields retained after Destroy")
	}
	tests := map[string]func() []byte{
		"wrong run":    func() []byte { v := valid; v.RunID = strings.Repeat("d", 32); return encode(v) },
		"wrong target": func() []byte { v := valid; v.Target = "workload-tls-agent"; return encode(v) },
		"wrong nonce":  func() []byte { v := valid; v.Nonce = strings.Repeat("d", 32); return encode(v) },
		"wrong ID":     func() []byte { v := valid; v.ContainerID = strings.Repeat("d", 64); return encode(v) },
		"duplicate FD": func() []byte {
			v := valid
			v.Files = append([]PrivateFile(nil), valid.Files...)
			v.Files[1].FD = 3
			return encode(v)
		},
		"missing FD": func() []byte { v := valid; v.Files = valid.Files[:3]; return encode(v) },
		"short key": func() []byte {
			v := valid
			v.Files = append([]PrivateFile(nil), valid.Files...)
			v.Files[0].Data = []byte("short")
			return encode(v)
		},
		"unknown member": func() []byte {
			return bytes.Replace(encode(valid), []byte(`"protocol":`), []byte(`"unexpected":1,"protocol":`), 1)
		},
		"duplicate member": func() []byte {
			return bytes.Replace(encode(valid), []byte(`"protocol":`), []byte(`"protocol":"sandbox-runtime.phase6-fd-startup.v1","protocol":`), 1)
		},
		"trailing frame":          func() []byte { return append(encode(valid), encode(valid)...) },
		"noncanonical whitespace": func() []byte { return append(encode(valid), '\n') },
		"truncated":               func() []byte { document := encode(valid); return document[:len(document)-1] },
		"oversized":               func() []byte { return bytes.Repeat([]byte{'a'}, MaxEnvelopeBytes+1) },
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if decoded, err := Decode(bytes.NewReader(document()), expected); err == nil {
				decoded.Destroy()
				t.Fatal("invalid startup envelope was accepted")
			}
		})
	}
}

func TestSpecificationForIsClosedAndOrdered(t *testing.T) {
	for _, target := range []string{"certificate-controller", "workload-credential-controller-v2", "workload-material-agent",
		"workload-tls-agent", "break-glass-controller", "egress-policy-state-authority"} {
		spec, ok := SpecificationFor(target)
		if !ok || spec.Target != target || spec.MaxConfigBytes < 1 || len(spec.Descriptors) == 0 {
			t.Fatalf("missing fixed FD target %q", target)
		}
		for index, descriptor := range spec.Descriptors {
			if descriptor.FD != index+3 || descriptor.Purpose == "" || descriptor.MaxBytes < 1 {
				t.Fatalf("invalid fixed FD table for %q", target)
			}
		}
	}
	for _, target := range []string{"", "core", "browser-executor-backend", "workload-credential-controller"} {
		if _, ok := SpecificationFor(target); ok {
			t.Fatalf("unexpected loader target %q", target)
		}
	}
}
